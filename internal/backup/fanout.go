package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultFanOutStall is how long a branch may go without accepting a write
// before it is detached.
const DefaultFanOutStall = 10 * time.Minute

// fanOutSegment bounds how much of one Write a branch must take within a
// single stall window, so a slow but moving upload is not mistaken for a
// stuck one just because the engine wrote a large chunk.
const fanOutSegment = 256 << 10

// ErrAllBranchesFailed is what FanOut.Write returns once no destination is
// left to receive the stream.
var ErrAllBranchesFailed = errors.New("every destination failed")

// errUploadEnded is what a branch's pipe fails with when its upload returned
// before the stream ended.
var errUploadEnded = errors.New("upload returned before the stream ended")

// Branch is one destination of a fan-out: Upload reads the whole stream from
// r and returns when it has stored it (or failed). The context is cancelled
// when the branch is detached, so Upload must honour it.
type Branch struct {
	Name   string
	Upload func(ctx context.Context, r io.Reader) error
}

// BranchResult is how one branch ended. Bytes is what the branch accepted.
type BranchResult struct {
	Name  string
	Bytes int64
	Err   error
}

// eofReader records whether the upload read the stream to its end, so an
// upload that returns nil without having seen EOF is not taken for a success.
type eofReader struct {
	r   io.Reader
	eof atomic.Bool
}

func (e *eofReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		e.eof.Store(true)
	}
	return n, err
}

type fanBranch struct {
	name   string
	pr     *io.PipeReader
	pw     *io.PipeWriter
	cancel context.CancelFunc
	done   chan struct{} // closed when Upload has returned
	upErr  error         // Upload's result; valid once done is closed
	bytes  int64         // touched only by the branch's write goroutine, one Write at a time

	once     sync.Once
	detached atomic.Bool // set after detErr and stalled are written
	detErr   error
	stalled  bool
}

// detach takes the branch out of the stream: its pipe is closed with err so
// a blocked write or read returns, and its context is cancelled so an upload
// that is not reading can still return. Only the first call counts.
func (b *fanBranch) detach(err error, stalled bool) {
	b.once.Do(func() {
		b.detErr, b.stalled = err, stalled
		b.detached.Store(true)
		b.cancel()
		_ = b.pw.CloseWithError(err)
	})
}

// write feeds p to the branch. Every segment must be accepted within stall,
// otherwise the branch is detached with stallErr. Once the last segment is
// in, the branch can no longer be detached by this write's timer.
func (b *fanBranch) write(p []byte, stall time.Duration, stallErr error) {
	var mu sync.Mutex
	finished := false
	t := time.AfterFunc(stall, func() {
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			b.detach(stallErr, true)
		}
	})
	defer t.Stop()
	for len(p) > 0 {
		n, err := b.pw.Write(p[:min(len(p), fanOutSegment)])
		b.bytes += int64(n)
		if err != nil {
			b.detach(err, false)
			return
		}
		p = p[n:]
		if len(p) == 0 {
			break
		}
		if !t.Stop() {
			// The timer fired while the segment went through; detach waits
			// for the callback if it is still running.
			b.detach(stallErr, true)
			return
		}
		t.Reset(stall)
	}
	mu.Lock()
	finished = true
	mu.Unlock()
}

// FanOut is an io.Writer that streams the same bytes to several uploads at
// once, each through its own pipe. A branch that fails or stalls is detached
// and never holds up the others; the slowest live branch sets the pace, so
// nothing is buffered beyond the chunk being written. Write and Close must
// not be called concurrently.
type FanOut struct {
	branches    []*fanBranch
	stall       time.Duration
	stallErr    error // a branch refused a write for stall
	endStallErr error // a branch did not finish after the end of the stream
	closeOnce   sync.Once
	results     []BranchResult
}

// NewFanOut starts one upload per branch. stall is how long a branch may
// refuse a write before it is detached (0 means DefaultFanOutStall).
func NewFanOut(ctx context.Context, branches []Branch, stall time.Duration) *FanOut {
	if stall <= 0 {
		stall = DefaultFanOutStall
	}
	f := &FanOut{
		stall:       stall,
		stallErr:    fmt.Errorf("stalled: no progress for %s", stall),
		endStallErr: fmt.Errorf("stalled: upload did not finish within %s after the end of the stream", stall),
	}
	for _, br := range branches {
		bctx, cancel := context.WithCancel(ctx)
		pr, pw := io.Pipe()
		b := &fanBranch{name: br.Name, pr: pr, pw: pw, cancel: cancel, done: make(chan struct{})}
		f.branches = append(f.branches, b)
		go func() {
			defer close(b.done)
			er := &eofReader{r: pr}
			err := br.Upload(bctx, er)
			if err == nil && !er.eof.Load() {
				err = errUploadEnded
			}
			b.upErr = err
			if err == nil {
				err = errUploadEnded // a write after this must fail, not block
			}
			_ = pr.CloseWithError(err)
		}()
	}
	return f
}

// Write sends p to every live branch and returns when all of them have taken
// it or been detached. It fails only when no branch is left; the error wraps
// ErrAllBranchesFailed and the error of the first branch in branch order.
func (f *FanOut) Write(p []byte) (int, error) {
	var wg sync.WaitGroup
	for _, b := range f.branches {
		if b.detached.Load() {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.write(p, f.stall, f.stallErr)
		}()
	}
	wg.Wait()
	var first error
	for _, b := range f.branches {
		if !b.detached.Load() {
			return len(p), nil
		}
		if first == nil {
			first = b.detErr
		}
	}
	if first == nil {
		return 0, ErrAllBranchesFailed
	}
	return 0, fmt.Errorf("%w: %w", ErrAllBranchesFailed, first)
}

// Close ends the stream for every live branch (with err, or EOF when nil),
// waits until every upload has returned and reports how each branch ended,
// in branch order. A live branch gets at most the stall duration, shared by
// all of them, to finish after the end of the stream; one that does not is
// cancelled and reported as stalled. With a non-nil err no branch reports
// success. It is safe to call more than once.
func (f *FanOut) Close(err error) []BranchResult {
	f.closeOnce.Do(func() {
		live := make([]bool, len(f.branches))
		for i, b := range f.branches {
			if !b.detached.Load() {
				live[i] = true
				_ = b.pw.CloseWithError(err) // nil → EOF
			}
		}
		grace, cancelGrace := context.WithTimeout(context.Background(), f.stall)
		defer cancelGrace()
		for i, b := range f.branches {
			if live[i] {
				select {
				case <-b.done:
				case <-grace.Done():
					select {
					case <-b.done:
					default:
						b.detach(f.endStallErr, true)
					}
				}
			}
			<-b.done // detached branches had their context cancelled
			b.cancel()
			r := BranchResult{Name: b.name, Bytes: b.bytes, Err: b.upErr}
			if b.detached.Load() && (b.stalled || r.Err == nil) {
				r.Err = b.detErr
			}
			if r.Err == nil {
				r.Err = err
			}
			f.results = append(f.results, r)
		}
	})
	return f.results
}
