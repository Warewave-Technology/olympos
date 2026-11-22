// Package tunnelbridge exposes an agent tunnel to a local tool process
// (pg_dump, pg_restore, clickhouse-client): a 127.0.0.1 listener whose
// connections are each piped to a new tunnel. No address from the
// environment or DNS is used; the tool only ever reaches the tunnel.
package tunnelbridge

import (
	"context"
	"io"
	"net"
	"sync"
)

// Bridge is a 127.0.0.1 listener whose connections are piped to tunnels.
// It accepts at most max connections (one tool process), then stops
// listening.
type Bridge struct {
	l      net.Listener
	dial   func(ctx context.Context) (net.Conn, error)
	max    int
	ctx    context.Context
	cancel func()
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  []net.Conn
	err    error
}

// errReporter is a tunnel connection that records why it refused traffic
// (the PostgreSQL authentication guard); Err reports it after the pipe.
type errReporter interface{ Err() error }

// Start listens on 127.0.0.1:0 and dials a tunnel for each accepted
// connection, up to max (at least 1).
func Start(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), max int) (*Bridge, error) {
	if max < 1 {
		max = 1
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	bctx, cancel := context.WithCancel(ctx)
	b := &Bridge{l: l, dial: dial, max: max, ctx: bctx, cancel: cancel}
	b.wg.Add(1)
	go b.accept()
	return b, nil
}

// Port is the local port the tool connects to.
func (b *Bridge) Port() int { return b.l.Addr().(*net.TCPAddr).Port }

// Err is the last tunnel failure: a dial error, or the refusal a tunnel
// connection recorded (a connection with an Err() error method). Call it
// after Close for the final value.
func (b *Bridge) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *Bridge) setErr(err error) {
	b.mu.Lock()
	b.err = err
	b.mu.Unlock()
}

func (b *Bridge) track(c net.Conn) {
	b.mu.Lock()
	b.conns = append(b.conns, c)
	b.mu.Unlock()
}

func (b *Bridge) accept() {
	defer b.wg.Done()
	for i := 0; i < b.max; i++ {
		c, err := b.l.Accept()
		if err != nil {
			return
		}
		b.track(c)
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer c.Close()
			t, err := b.dial(b.ctx)
			if err != nil {
				b.setErr(err)
				return
			}
			b.track(t)
			defer t.Close()
			pipe(c, t)
			if r, ok := t.(errReporter); ok && r.Err() != nil {
				b.setErr(r.Err())
			}
		}()
	}
	_ = b.l.Close()
}

// pipe copies both ways and returns when either side is done.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// Close stops listening, closes every connection and waits for the pipes.
func (b *Bridge) Close() {
	b.cancel()
	_ = b.l.Close()
	b.mu.Lock()
	for _, c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}
