package tunnelbridge_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/tunnelbridge"
)

// echoServer answers every connection with what it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func local(t *testing.T, b *tunnelbridge.Bridge) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(b.Port()), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBridgePipesAndStopsAtMax(t *testing.T) {
	addr := echoServer(t)
	dials := 0
	b, err := tunnelbridge.Start(context.Background(), func(ctx context.Context) (net.Conn, error) {
		dials++
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for i := 0; i < 2; i++ {
		c := local(t, b)
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo %d: %q %v", i, buf, err)
		}
		c.Close()
	}
	// The listener closes after max connections.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(b.Port()), time.Second)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("third connection accepted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	b.Close()
	if dials != 2 || b.Err() != nil {
		t.Fatalf("dials %d err %v", dials, b.Err())
	}
}

// refusingConn records a refusal like the PostgreSQL authentication guard.
type refusingConn struct{ net.Conn }

var errRefused = errors.New("refused")

func (refusingConn) Err() error { return errRefused }

func TestBridgeReportsDialAndConnErrors(t *testing.T) {
	dialErr := errors.New("no tunnel")
	b, err := tunnelbridge.Start(context.Background(), func(context.Context) (net.Conn, error) { return nil, dialErr }, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := local(t, b)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(make([]byte, 1))
	c.Close()
	b.Close()
	if !errors.Is(b.Err(), dialErr) {
		t.Fatalf("err %v", b.Err())
	}

	addr := echoServer(t)
	b, err = tunnelbridge.Start(context.Background(), func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		return refusingConn{c}, err
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	c = local(t, b)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	b.Close()
	if !errors.Is(b.Err(), errRefused) {
		t.Fatalf("err %v", b.Err())
	}
}
