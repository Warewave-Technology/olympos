package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sink is an upload that collects everything it reads.
type sink struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	done atomic.Bool
}

func (s *sink) upload(_ context.Context, r io.Reader) error {
	defer s.done.Store(true)
	var b bytes.Buffer
	_, err := io.Copy(&b, r)
	s.mu.Lock()
	s.buf.Write(b.Bytes())
	s.mu.Unlock()
	return err
}

func (s *sink) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// writeChunks feeds data to f in chunk-sized writes, as an engine would.
func writeChunks(f *FanOut, data []byte, chunk int) error {
	for len(data) > 0 {
		n := min(chunk, len(data))
		if _, err := f.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func TestFanOutAllSucceed(t *testing.T) {
	data := randomBytes(t, 64<<10)
	sinks := []*sink{{}, {}, {}}
	branches := make([]Branch, len(sinks))
	for i, s := range sinks {
		branches[i] = Branch{Name: string(rune('a' + i)), Upload: s.upload}
	}
	f := NewFanOut(context.Background(), branches, 0)
	if err := writeChunks(f, data, 8<<10); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := f.Close(nil)
	if len(res) != 3 {
		t.Fatalf("results = %d, want 3", len(res))
	}
	for i, r := range res {
		if r.Name != branches[i].Name {
			t.Errorf("result %d name = %q, want %q", i, r.Name, branches[i].Name)
		}
		if r.Err != nil {
			t.Errorf("branch %s: %v", r.Name, r.Err)
		}
		if r.Bytes != int64(len(data)) {
			t.Errorf("branch %s bytes = %d, want %d", r.Name, r.Bytes, len(data))
		}
		if !bytes.Equal(sinks[i].bytes(), data) {
			t.Errorf("branch %s received different bytes", r.Name)
		}
	}
}

func TestFanOutOneFailsMidStream(t *testing.T) {
	data := randomBytes(t, 64<<10)
	boom := errors.New("boom")
	a, c := &sink{}, &sink{}
	b := Branch{Name: "b", Upload: func(_ context.Context, r io.Reader) error {
		if _, err := io.ReadFull(r, make([]byte, 1<<10)); err != nil {
			return err
		}
		return boom
	}}
	f := NewFanOut(context.Background(), []Branch{
		{Name: "a", Upload: a.upload}, b, {Name: "c", Upload: c.upload},
	}, 0)
	if err := writeChunks(f, data, 8<<10); err != nil {
		t.Fatalf("a failing branch must not fail Write: %v", err)
	}
	res := f.Close(nil)
	if res[0].Err != nil || res[2].Err != nil {
		t.Fatalf("healthy branches failed: a=%v c=%v", res[0].Err, res[2].Err)
	}
	if !errors.Is(res[1].Err, boom) {
		t.Fatalf("b err = %v, want boom", res[1].Err)
	}
	if res[1].Bytes < 1<<10 || res[1].Bytes >= int64(len(data)) {
		t.Errorf("b bytes = %d, want within [1KiB, 64KiB)", res[1].Bytes)
	}
	for _, i := range []int{0, 2} {
		if res[i].Bytes != int64(len(data)) {
			t.Errorf("%s bytes = %d, want %d", res[i].Name, res[i].Bytes, len(data))
		}
	}
	if !bytes.Equal(a.bytes(), data) || !bytes.Equal(c.bytes(), data) {
		t.Error("healthy branches did not receive the full stream")
	}
}

func TestFanOutAllFail(t *testing.T) {
	boom := errors.New("boom")
	failing := func(_ context.Context, _ io.Reader) error { return boom }
	f := NewFanOut(context.Background(), []Branch{
		{Name: "a", Upload: failing}, {Name: "b", Upload: failing},
	}, 0)
	_, err := f.Write(randomBytes(t, 4<<10))
	if !errors.Is(err, ErrAllBranchesFailed) {
		t.Fatalf("Write err = %v, want ErrAllBranchesFailed", err)
	}
	if !errors.Is(err, boom) {
		t.Errorf("Write err = %v, want it to wrap the first branch error", err)
	}
	// Once nothing is left, later writes keep failing the same way.
	if _, err := f.Write([]byte("x")); !errors.Is(err, ErrAllBranchesFailed) {
		t.Errorf("second Write err = %v, want ErrAllBranchesFailed", err)
	}
	for _, r := range f.Close(err) {
		if !errors.Is(r.Err, boom) {
			t.Errorf("branch %s err = %v, want boom", r.Name, r.Err)
		}
	}
}

// testStall is the stall window for tests that must see a stall fire: wide
// enough that healthy branches are not falsely detached on a slow, loaded
// -race runner, short enough to keep the tests quick.
const testStall = 250 * time.Millisecond

func TestFanOutStall(t *testing.T) {
	data := randomBytes(t, 64<<10)
	a, c := &sink{}, &sink{}
	var stalledReturned atomic.Bool
	stalled := Branch{Name: "stalled", Upload: func(ctx context.Context, _ io.Reader) error {
		// Never reads; only the detach (context cancel) lets it go.
		<-ctx.Done()
		stalledReturned.Store(true)
		return ctx.Err()
	}}
	f := NewFanOut(context.Background(), []Branch{
		{Name: "a", Upload: a.upload}, stalled, {Name: "c", Upload: c.upload},
	}, testStall)
	if err := writeChunks(f, data, 8<<10); err != nil {
		t.Fatalf("write: %v", err)
	}
	closed := make(chan []BranchResult, 1)
	go func() { closed <- f.Close(nil) }()
	var res []BranchResult
	select {
	case res = <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	if res[0].Err != nil || res[2].Err != nil {
		t.Fatalf("healthy branches failed: a=%v c=%v", res[0].Err, res[2].Err)
	}
	if res[1].Err == nil || !strings.HasPrefix(res[1].Err.Error(), "stalled: no progress for "+testStall.String()) {
		t.Fatalf("stalled err = %v", res[1].Err)
	}
	if res[1].Bytes != 0 {
		t.Errorf("stalled bytes = %d, want 0", res[1].Bytes)
	}
	if !stalledReturned.Load() {
		t.Error("Close returned before the stalled upload did")
	}
	if !bytes.Equal(a.bytes(), data) || !bytes.Equal(c.bytes(), data) {
		t.Error("healthy branches did not receive the full stream")
	}
}

func TestFanOutCloseWithError(t *testing.T) {
	errX := errors.New("engine failed")
	var mu sync.Mutex
	seen := map[string]error{}
	mk := func(name string) Branch {
		return Branch{Name: name, Upload: func(_ context.Context, r io.Reader) error {
			_, err := io.Copy(io.Discard, r)
			mu.Lock()
			seen[name] = err
			mu.Unlock()
			return err
		}}
	}
	f := NewFanOut(context.Background(), []Branch{mk("a"), mk("b"), mk("c")}, 0)
	if _, err := f.Write(randomBytes(t, 4<<10)); err != nil {
		t.Fatal(err)
	}
	res := f.Close(errX)
	mu.Lock()
	defer mu.Unlock()
	for _, r := range res {
		if !errors.Is(seen[r.Name], errX) {
			t.Errorf("upload %s read err = %v, want errX", r.Name, seen[r.Name])
		}
		if !errors.Is(r.Err, errX) {
			t.Errorf("result %s err = %v, want errX", r.Name, r.Err)
		}
	}
}

// The slowest live branch sets the pace: Write does not return until every
// live branch has taken the chunk.
func TestFanOutSlowBranchSetsPace(t *testing.T) {
	release := make(chan struct{})
	fast := &sink{}
	slow := Branch{Name: "slow", Upload: func(_ context.Context, r io.Reader) error {
		<-release
		_, err := io.Copy(io.Discard, r)
		return err
	}}
	f := NewFanOut(context.Background(), []Branch{{Name: "fast", Upload: fast.upload}, slow}, time.Minute)
	wrote := make(chan error, 1)
	go func() {
		_, err := f.Write(randomBytes(t, 4<<10))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		t.Fatalf("Write returned (%v) while a live branch had not accepted the chunk", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Write did not return after the slow branch resumed")
	}
	for _, r := range f.Close(nil) {
		if r.Err != nil || r.Bytes != 4<<10 {
			t.Errorf("branch %s: err=%v bytes=%d", r.Name, r.Err, r.Bytes)
		}
	}
}

// An upload that returns nil before the stream ended is a failed branch,
// not a silent success.
func TestFanOutUploadReturnsEarly(t *testing.T) {
	data := randomBytes(t, 32<<10)
	a := &sink{}
	early := Branch{Name: "early", Upload: func(_ context.Context, r io.Reader) error {
		_, err := io.ReadFull(r, make([]byte, 1<<10))
		return err
	}}
	f := NewFanOut(context.Background(), []Branch{{Name: "a", Upload: a.upload}, early}, 0)
	if err := writeChunks(f, data, 8<<10); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := f.Close(nil)
	if res[0].Err != nil {
		t.Fatalf("a: %v", res[0].Err)
	}
	if !errors.Is(res[1].Err, errUploadEnded) {
		t.Fatalf("early branch err = %v, want errUploadEnded", res[1].Err)
	}
	if !bytes.Equal(a.bytes(), data) {
		t.Error("a did not receive the full stream")
	}
}

// An upload that returns nil without ever seeing EOF is a failure, even when
// no write ran into its closed pipe (it returned after the last byte).
func TestFanOutNilWithoutEOF(t *testing.T) {
	data := randomBytes(t, 4<<10)
	b := Branch{Name: "b", Upload: func(_ context.Context, r io.Reader) error {
		_, err := io.ReadFull(r, make([]byte, len(data)))
		return err
	}}
	f := NewFanOut(context.Background(), []Branch{b}, 0)
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	res := f.Close(nil)
	if !errors.Is(res[0].Err, errUploadEnded) {
		t.Fatalf("err = %v, want errUploadEnded", res[0].Err)
	}
}

// When the engine fails, no branch may report success, even one that
// swallowed the error and returned nil.
func TestFanOutCloseWithErrorNoSuccess(t *testing.T) {
	errX := errors.New("engine failed")
	swallow := Branch{Name: "swallow", Upload: func(_ context.Context, r io.Reader) error {
		_, _ = io.Copy(io.Discard, r)
		return nil
	}}
	f := NewFanOut(context.Background(), []Branch{swallow}, 0)
	if _, err := f.Write(randomBytes(t, 1<<10)); err != nil {
		t.Fatal(err)
	}
	if res := f.Close(errX); res[0].Err == nil {
		t.Fatal("branch reported success although the stream failed")
	}
}

// A branch that reads steadily but slowly is not stalled, even when one Write
// carries far more than it can take within a single stall window.
func TestFanOutMultiSegmentSlowReader(t *testing.T) {
	data := randomBytes(t, 2<<20)
	var got bytes.Buffer
	slow := Branch{Name: "slow", Upload: func(_ context.Context, r io.Reader) error {
		buf := make([]byte, 128<<10)
		for {
			n, err := r.Read(buf)
			got.Write(buf[:n])
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			time.Sleep(30 * time.Millisecond)
		}
	}}
	fast := &sink{}
	// 8 segments x ~60ms each (two 128 KiB reads per 256 KiB segment) is ~480ms
	// in total, above the 400ms stall, while each segment stays far below it.
	f := NewFanOut(context.Background(), []Branch{slow, {Name: "fast", Upload: fast.upload}}, 400*time.Millisecond)
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, r := range f.Close(nil) {
		if r.Err != nil || r.Bytes != int64(len(data)) {
			t.Errorf("branch %s: err=%v bytes=%d", r.Name, r.Err, r.Bytes)
		}
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Error("slow branch received different bytes")
	}
}

// A branch that stops reading partway is detached, keeping what it accepted.
func TestFanOutStallAfterSomeBytes(t *testing.T) {
	data := randomBytes(t, 64<<10)
	a := &sink{}
	partial := Branch{Name: "partial", Upload: func(ctx context.Context, r io.Reader) error {
		if _, err := io.ReadFull(r, make([]byte, 8<<10)); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	f := NewFanOut(context.Background(), []Branch{{Name: "a", Upload: a.upload}, partial}, testStall)
	if err := writeChunks(f, data, 8<<10); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := f.Close(nil)
	if res[0].Err != nil {
		t.Fatalf("a: %v", res[0].Err)
	}
	if res[1].Err == nil || !strings.HasPrefix(res[1].Err.Error(), "stalled:") {
		t.Fatalf("partial err = %v", res[1].Err)
	}
	if res[1].Bytes != 8<<10 {
		t.Errorf("partial bytes = %d, want %d", res[1].Bytes, 8<<10)
	}
}

// An upload that hangs after reading the whole stream (finalizing) must not
// hang Close: it is cancelled after the stall duration and reported.
func TestFanOutStallAfterEOF(t *testing.T) {
	data := randomBytes(t, 16<<10)
	a, c := &sink{}, &sink{}
	var returned atomic.Bool
	hang := Branch{Name: "hang", Upload: func(ctx context.Context, r io.Reader) error {
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
		<-ctx.Done()
		returned.Store(true)
		return ctx.Err()
	}}
	f := NewFanOut(context.Background(), []Branch{{Name: "a", Upload: a.upload}, hang, {Name: "c", Upload: c.upload}}, testStall)
	if err := writeChunks(f, data, 8<<10); err != nil {
		t.Fatalf("write: %v", err)
	}
	closed := make(chan []BranchResult, 1)
	go func() { closed <- f.Close(nil) }()
	var res []BranchResult
	select {
	case res = <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	if res[0].Err != nil || res[2].Err != nil {
		t.Fatalf("healthy branches failed: a=%v c=%v", res[0].Err, res[2].Err)
	}
	want := "stalled: upload did not finish within " + testStall.String() + " after the end of the stream"
	if res[1].Err == nil || !strings.HasPrefix(res[1].Err.Error(), want) {
		t.Fatalf("hang err = %v", res[1].Err)
	}
	if res[1].Bytes != int64(len(data)) {
		t.Errorf("hang bytes = %d, want %d", res[1].Bytes, len(data))
	}
	if !returned.Load() {
		t.Error("Close returned before the hung upload did")
	}
}

func TestFanOutContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := Branch{Name: "a", Upload: func(ctx context.Context, r io.Reader) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	f := NewFanOut(ctx, []Branch{b}, time.Minute)
	cancel()
	_, err := f.Write(randomBytes(t, 1<<10))
	if !errors.Is(err, ErrAllBranchesFailed) {
		t.Fatalf("Write err = %v, want ErrAllBranchesFailed", err)
	}
	res := f.Close(err)
	if !errors.Is(res[0].Err, context.Canceled) {
		t.Errorf("branch err = %v, want context.Canceled", res[0].Err)
	}
}

// An upload that ignores its context and never returns (a hard NFS mount
// whose server is gone blocks write/fsync in the kernel) must not hang
// Close: the branch is abandoned after the detach bound and reported as
// stalled, and the healthy branches still succeed.
func TestFanOutUploadIgnoresContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		read bool // reads the whole stream, then hangs (finalizing)
	}{{"before reading", false}, {"after the stream", true}} {
		t.Run(tc.name, func(t *testing.T) {
			data := randomBytes(t, 16<<10)
			a, c := &sink{}, &sink{}
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			hung := Branch{Name: "nfs", Upload: func(_ context.Context, r io.Reader) error {
				if tc.read {
					if _, err := io.Copy(io.Discard, r); err != nil {
						return err
					}
				}
				<-release // ignores ctx, like a write blocked in the kernel
				return nil
			}}
			f := NewFanOut(context.Background(), []Branch{{Name: "a", Upload: a.upload}, hung, {Name: "c", Upload: c.upload}}, testStall)
			f.abandon = testStall
			if err := writeChunks(f, data, 8<<10); err != nil {
				t.Fatalf("write: %v", err)
			}
			closed := make(chan []BranchResult, 1)
			go func() { closed <- f.Close(nil) }()
			var res []BranchResult
			select {
			case res = <-closed:
			case <-time.After(10 * time.Second):
				t.Fatal("Close did not return")
			}
			if res[0].Err != nil || res[2].Err != nil {
				t.Fatalf("healthy branches failed: a=%v c=%v", res[0].Err, res[2].Err)
			}
			if res[1].Err == nil || !strings.HasPrefix(res[1].Err.Error(), "stalled:") || !strings.Contains(res[1].Err.Error(), "did not return") {
				t.Fatalf("hung err = %v", res[1].Err)
			}
			if !bytes.Equal(a.bytes(), data) || !bytes.Equal(c.bytes(), data) {
				t.Error("healthy branches did not receive the full stream")
			}
		})
	}
}
