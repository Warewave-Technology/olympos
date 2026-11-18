package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

const canaryPW = "canary-plaintext-PW-91c2"

// fakePG is a PostgreSQL server without TLS that answers every startup with
// one authentication request and records every byte the clients send.
type fakePG struct {
	l    net.Listener
	auth []byte // the R message body (code + data)
	mu   sync.Mutex
	got  bytes.Buffer
}

func newFakePG(t *testing.T, code uint32, data []byte) *fakePG {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePG{l: l, auth: binary.BigEndian.AppendUint32(nil, code)}
	f.auth = append(f.auth, data...)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakePG) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	f.record(hdr)
	if bytes.Equal(hdr, sslRequest) {
		_, _ = c.Write([]byte{'N'})
		hdr = hdr[:4]
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		f.record(hdr)
		rest := make([]byte, binary.BigEndian.Uint32(hdr)-4)
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
		f.record(rest)
	} else {
		rest := make([]byte, binary.BigEndian.Uint32(hdr[:4])-8)
		if _, err := io.ReadFull(c, rest); err != nil {
			return
		}
		f.record(rest)
	}
	msg := append([]byte{'R'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(f.auth)))...)
	_, _ = c.Write(append(msg, f.auth...))
	// Whatever the client answers (a password message if unguarded).
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		f.record(buf[:n])
		if err != nil {
			return
		}
	}
}

func (f *fakePG) record(b []byte) {
	f.mu.Lock()
	f.got.Write(b)
	f.mu.Unlock()
}

func (f *fakePG) bytes() []byte {
	time.Sleep(200 * time.Millisecond) // let the server goroutines record the last reads
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.got.Bytes()...)
}

func fakeContext(f *fakePG, useTLS bool) backup.EngineContext {
	raw, _ := json.Marshal(map[string]any{"databases": []string{"shop"}})
	return backup.EngineContext{
		Target:        backup.TargetInfo{ID: "t1", Namespace: "db", Service: "orders-pg", Port: 5432, Engine: "postgresql", TLSServerName: "orders-pg.db.svc"},
		TLSServerName: "orders-pg.db.svc",
		UseTLS:        useTLS,
		Options:       raw,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", f.l.Addr().String())
		},
		Credential: func(ctx context.Context) (backup.Credential, error) {
			return backup.Credential{Username: "backup", Secret: []byte(canaryPW)}, nil
		},
	}
}

// F1: in e2e-tls mode a target without TLS that asks for cleartext or MD5
// never receives the password (nor its MD5 hash), on the pgx path.
func TestGuardRefusesPlaintextMethods(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
		data []byte
		want string
	}{
		{"md5", 5, []byte{1, 2, 3, 4}, "an MD5 password"},
		{"cleartext", 3, nil, "a cleartext password"},
		{"sasl-plus-only", 10, []byte("SCRAM-SHA-256-PLUS\x00\x00"), "SASL without SCRAM-SHA-256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakePG(t, tc.code, tc.data)
			e := &Engine{DumpDir: t.TempDir()}
			_, err := e.Run(context.Background(), fakeContext(f, true), io.Discard)
			if !errors.Is(err, ErrPlaintextPassword) || !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "Enable TLS on the target") || !strings.Contains(err.Error(), "compressed") {
				t.Fatalf("run error: %v", err)
			}
			ct, _ := e.TestConnection(context.Background(), fakeContext(f, true))
			if ct.OK || !strings.Contains(ct.Error, tc.want) {
				t.Fatalf("connection test: %+v", ct)
			}
			got := f.bytes()
			if bytes.Contains(got, []byte(canaryPW)) || bytes.Contains(got, []byte("SCRAM")) || bytes.Contains(got, []byte("md5")) {
				t.Fatalf("password message reached the target: %q", got)
			}
		})
	}
}

// The libpq path (pg_dump through the bridge) is guarded the same way.
func TestGuardRefusesOnBridge(t *testing.T) {
	pgDump, err := exec.LookPath("pg_dump")
	if err != nil {
		for _, d := range []string{"/opt/homebrew/opt/libpq/bin", "/usr/lib/postgresql/17/bin", "/usr/lib/postgresql/16/bin"} {
			if p := filepath.Join(d, "pg_dump"); executable(p) {
				pgDump, err = p, nil
			}
		}
	}
	if err != nil {
		t.Skip("pg_dump not found")
	}
	f := newFakePG(t, 5, []byte{9, 9, 9, 9})
	ec := fakeContext(f, true)
	s := &session{ec: ec, cred: backup.Credential{Username: "backup", Secret: []byte(canaryPW)}, guard: true}
	tmp := t.TempDir()
	env, err := s.childEnv(tmp)
	if err != nil {
		t.Fatal(err)
	}
	ssl, _ := s.sslParams(tmp, 16)
	err = s.runTool(context.Background(), pgDump, []string{"--format=custom", "--schema-only"}, s.conninfo("shop", ssl), env, io.Discard)
	if !errors.Is(err, ErrPlaintextPassword) {
		t.Fatalf("pg_dump error: %v", err)
	}
	if got := f.bytes(); bytes.Contains(got, []byte("md5")) || bytes.Contains(got, []byte(canaryPW)) {
		t.Fatalf("pg_dump sent the password: %q", got)
	}
}

// Compressed transfer mode is unchanged: no guard, the client answers.
func TestNoGuardInCompressedMode(t *testing.T) {
	f := newFakePG(t, 5, []byte{1, 2, 3, 4})
	e := &Engine{DumpDir: t.TempDir()}
	_, err := e.Run(context.Background(), fakeContext(f, false), io.Discard)
	if errors.Is(err, ErrPlaintextPassword) {
		t.Fatalf("guarded in compressed mode: %v", err)
	}
	if got := f.bytes(); !bytes.Contains(got, []byte("md5")) {
		t.Fatalf("expected an MD5 password message in compressed mode, got %q", got)
	}
}

func TestGuardScan(t *testing.T) {
	r := func(code uint32, data []byte) []byte {
		body := append(binary.BigEndian.AppendUint32(nil, code), data...)
		return append(append([]byte{'R'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))...), body...)
	}
	ok := r(0, nil)
	params := append([]byte{'S'}, binary.BigEndian.AppendUint32(nil, 4+4)...)
	params = append(params, 'a', 0, 'b', 0)
	// SCRAM handshake, then AuthenticationOk and server messages split
	// across reads: all bytes pass through unchanged.
	stream := append(append(append(append(r(10, []byte("SCRAM-SHA-256\x00\x00")), r(11, []byte("r=x"))...), r(12, []byte("v=y"))...), ok...), params...)
	a, b := net.Pipe()
	go func() {
		for i := 0; i < len(stream); i += 3 {
			_, _ = a.Write(stream[i:min(i+3, len(stream))])
		}
		_ = a.Close()
	}()
	got, err := io.ReadAll(guardAuth(b))
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatalf("pass-through: %v %q", err, got)
	}
}
