// Package tunnel contains the byte-pipe plumbing shared by the server
// gateway and the agent: a TunnelFrame stream is bridged to a net.Conn,
// optionally zstd-compressed per frame ("compressed" transfer mode).
package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// FrameSize is the maximum raw payload per frame.
const FrameSize = 64 << 10

// Stream is the common shape of the client and server Tunnel streams.
type Stream interface {
	Send(*pb.TunnelFrame) error
	Recv() (*pb.TunnelFrame, error)
}

// Limits bound a tunnel's lifetime (SPEC §7).
type Limits struct {
	Idle     time.Duration // default 5 min
	Lifetime time.Duration // default 6 h
}

func (l Limits) withDefaults() Limits {
	if l.Idle == 0 {
		l.Idle = 5 * time.Minute
	}
	if l.Lifetime == 0 {
		l.Lifetime = 6 * time.Hour
	}
	return l
}

var (
	encOnce sync.Once
	enc     *zstd.Encoder
	dec     *zstd.Decoder
)

func codecs() (*zstd.Encoder, *zstd.Decoder) {
	encOnce.Do(func() {
		enc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
		dec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(4*FrameSize))
	})
	return enc, dec
}

// Counters report bytes that crossed the tunnel stream (after compression).
type Counters struct {
	WireIn, WireOut atomic.Int64
}

// Total returns wire bytes in both directions.
func (c *Counters) Total() int64 { return c.WireIn.Load() + c.WireOut.Load() }

// Bridge pumps bytes between local and stream until either side closes or a
// limit is hit. closeSend is called once when local reaches EOF (to end the
// stream's send side). Bridge returns when both directions are done.
func Bridge(local net.Conn, s Stream, compressed bool, lim Limits, c *Counters, closeSend func()) error {
	lim = lim.withDefaults()
	var e, d = codecs()
	var lastActivity atomic.Int64
	touch := func() { lastActivity.Store(time.Now().UnixNano()) }
	touch()

	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done); _ = local.Close() }) }

	// Watchdog: idle timeout and max lifetime.
	go func() {
		start := time.Now()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				if now.Sub(start) > lim.Lifetime || now.Sub(time.Unix(0, lastActivity.Load())) > lim.Idle {
					finish()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Add(2)
	// local -> stream
	go func() {
		defer wg.Done()
		buf := make([]byte, FrameSize)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				touch()
				payload := buf[:n]
				if compressed {
					payload = e.EncodeAll(payload, make([]byte, 0, n/2))
				}
				if serr := s.Send(&pb.TunnelFrame{Data: payload}); serr != nil {
					upErr = serr
					finish()
					return
				}
				if c != nil {
					c.WireOut.Add(int64(len(payload)))
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
					upErr = err
				}
				_ = s.Send(&pb.TunnelFrame{Close: true})
				if closeSend != nil {
					closeSend()
				}
				return
			}
		}
	}()
	// stream -> local
	go func() {
		defer wg.Done()
		defer finish()
		for {
			f, err := s.Recv()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					downErr = err
				}
				return
			}
			touch()
			if len(f.Data) > 0 {
				if c != nil {
					c.WireIn.Add(int64(len(f.Data)))
				}
				data := f.Data
				if compressed {
					data, err = d.DecodeAll(f.Data, nil)
					if err != nil {
						downErr = err
						return
					}
				}
				if _, err := local.Write(data); err != nil {
					return
				}
			}
			if f.Close {
				// Peer finished sending; half-close where supported.
				if hc, ok := local.(interface{ CloseWrite() error }); ok {
					_ = hc.CloseWrite()
					continue
				}
				return
			}
		}
	}()
	wg.Wait()
	finish()
	if upErr != nil {
		return upErr
	}
	return downErr
}
