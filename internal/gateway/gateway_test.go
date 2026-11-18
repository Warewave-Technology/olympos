package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/testutil"
	"github.com/Warewave-Technology/olympos/internal/tunnel"
)

type env struct {
	gw   *gateway.Gateway
	addr string
	ca   *pki.CA
}

func start(t *testing.T) *env {
	t.Helper()
	db := testutil.DB(t)
	ca := pki.NewForTest()
	gw := gateway.New(db, ca, slog.New(slog.NewTextHandler(io.Discard, nil)))
	der, key, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := gw.GRPCServer(gw.TLSConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return &env{gw: gw, addr: l.Addr().String(), ca: ca}
}

func (e *env) newCluster(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	var id uuid.UUID
	if err := e.gw.DB.QueryRow(context.Background(), `INSERT INTO clusters (name) VALUES ($1) RETURNING id`, "c-"+uuid.NewString()[:8]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	token := "olyb_" + uuid.NewString()
	if _, err := e.gw.DB.Exec(context.Background(), `INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at) VALUES ($1,$2, now() + interval '1 hour')`,
		id, gateway.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	return id, token
}

func (e *env) dial(t *testing.T, cert *tls.Certificate) pb.AgentGatewayClient {
	t.Helper()
	cfg := &tls.Config{RootCAs: e.ca.Pool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewAgentGatewayClient(conn)
}

func enroll(t *testing.T, c pb.AgentGatewayClient, token string) (*tls.Certificate, *pb.EnrollResponse, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "spoofed-cluster"}}, key)
	resp, err := c.Enroll(context.Background(), &pb.EnrollRequest{BootstrapToken: token, CsrDer: csr})
	if err != nil {
		return nil, nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{resp.CertDer}, PrivateKey: key}, resp, nil
}

// fakeAgent answers OpenTunnel for one known target by echoing bytes.
func fakeAgent(t *testing.T, ctx context.Context, c pb.AgentGatewayClient, clusterID, knownTarget string) pb.AgentGateway_ControlClient {
	t.Helper()
	ctl, err := c.Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{ClusterId: clusterID, AgentVersion: "test",
		Capabilities: &pb.Capabilities{MaxTunnels: 4}}}}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			m, err := ctl.Recv()
			if err != nil {
				return
			}
			ot := m.GetOpenTunnel()
			if ot == nil {
				continue
			}
			if ot.TargetId != knownTarget {
				_ = ctl.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_TunnelRejected{TunnelRejected: &pb.TunnelRejected{TunnelId: ot.TunnelId, Reason: "unknown target"}}})
				continue
			}
			go func() {
				st, err := c.Tunnel(ctx)
				if err != nil {
					return
				}
				_ = st.Send(&pb.TunnelFrame{TunnelId: ot.TunnelId})
				a, b := net.Pipe()
				go func() { _, _ = io.Copy(a, a) }() // echo server
				_ = tunnel.Bridge(b, st, ot.Compressed, tunnel.Limits{}, nil, func() { _ = st.CloseSend() })
			}()
		}
	}()
	return ctl
}

func waitConnected(t *testing.T, gw *gateway.Gateway, id uuid.UUID) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if gw.Connected(id) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("agent did not connect")
}

func TestEnrollIdentityAndSingleUseToken(t *testing.T) {
	e := start(t)
	id, token := e.newCluster(t)
	c := e.dial(t, nil)
	cert, resp, err := enroll(t, c, token)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if resp.ClusterId != id.String() || leaf.Subject.CommonName != id.String() {
		t.Fatalf("identity must come from server, got CN %q", leaf.Subject.CommonName)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("validity %v", d)
	}
	if _, _, err := enroll(t, c, token); err == nil {
		t.Fatal("bootstrap token reused")
	}
	if _, _, err := enroll(t, c, "olyb_wrong"); err == nil {
		t.Fatal("unknown token accepted")
	}
}

func TestControlRequiresClientCert(t *testing.T) {
	e := start(t)
	c := e.dial(t, nil)
	ctl, err := c.Control(context.Background())
	if err == nil {
		_ = ctl.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{}}})
		_, err = ctl.Recv()
	}
	if err == nil {
		t.Fatal("control stream without client cert accepted")
	}
}

func TestTunnelEchoCompressedAndUnknownTargetRejected(t *testing.T) {
	e := start(t)
	id, token := e.newCluster(t)
	cert, _, err := enroll(t, e.dial(t, nil), token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeAgent(t, ctx, e.dial(t, cert), id.String(), "known-target")
	waitConnected(t, e.gw, id)

	for _, compressed := range []bool{false, true} {
		conn, err := e.gw.Dial(ctx, id, "known-target", gateway.DialOptions{Compressed: compressed})
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello through the tunnel, hello through the tunnel, hello through the tunnel")
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != string(msg) {
			t.Fatalf("echo: %q %v", buf, err)
		}
		if _, port, err := net.SplitHostPort(conn.LocalAddr().String()); err != nil || port == "" {
			t.Fatalf("tunnel LocalAddr must look like host:port, got %q", conn.LocalAddr())
		}
		if conn.WireBytes() == 0 {
			t.Fatal("wire bytes not counted")
		}
		conn.Close()
	}

	_, err = e.gw.Dial(ctx, id, "attacker-chosen-host:5432", gateway.DialOptions{})
	if !errors.Is(err, gateway.ErrTunnelRejected) {
		t.Fatalf("unknown target must be rejected, got %v", err)
	}
}

func TestRevokeDropsStreamAndDeniesReconnect(t *testing.T) {
	e := start(t)
	id, token := e.newCluster(t)
	cert, _, err := enroll(t, e.dial(t, nil), token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl := fakeAgent(t, ctx, e.dial(t, cert), id.String(), "x")
	waitConnected(t, e.gw, id)
	if err := e.gw.Revoke(ctx, e.gw.DB, id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for e.gw.Connected(id) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if e.gw.Connected(id) {
		t.Fatal("stream not dropped after revoke")
	}
	_ = ctl
	// Reconnect with the same certificate must fail.
	c2, err := e.dial(t, cert).Control(ctx)
	if err == nil {
		_ = c2.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{ClusterId: id.String()}}})
		_, err = c2.Recv()
	}
	if err == nil {
		t.Fatal("revoked certificate accepted")
	}
}

func TestHelloClusterMismatchRejected(t *testing.T) {
	e := start(t)
	id, token := e.newCluster(t)
	cert, _, err := enroll(t, e.dial(t, nil), token)
	if err != nil {
		t.Fatal(err)
	}
	_ = id
	ctl, err := e.dial(t, cert).Control(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = ctl.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{ClusterId: uuid.NewString()}}})
	if _, err := ctl.Recv(); err == nil {
		t.Fatal("hello with foreign cluster id accepted")
	}
}

// F18: after a snapshot with generation G, only G+1, G+2, … are applied; a
// gap (or a diff before any snapshot) is dropped and a resync is requested.
func TestInventoryGenerations(t *testing.T) {
	e := start(t)
	var mu sync.Mutex
	var applied []string
	e.gw.Hooks.Inventory = func(_ context.Context, _ uuid.UUID, s *pb.InventorySnapshot) error {
		mu.Lock()
		applied = append(applied, fmt.Sprintf("snap:%d", s.Generation))
		mu.Unlock()
		return nil
	}
	e.gw.Hooks.InventoryDiff = func(_ context.Context, _ uuid.UUID, d *pb.InventoryDiff) error {
		mu.Lock()
		applied = append(applied, fmt.Sprintf("diff:%d", d.Generation))
		mu.Unlock()
		return nil
	}
	e.gw.Hooks.TargetDelete = func(_ context.Context, _ uuid.UUID, id string) error {
		mu.Lock()
		applied = append(applied, "del:"+id)
		mu.Unlock()
		return nil
	}
	id, token := e.newCluster(t)
	cert, _, err := enroll(t, e.dial(t, nil), token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctl, err := e.dial(t, cert).Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resyncs := make(chan struct{}, 4)
	go func() {
		for {
			m, err := ctl.Recv()
			if err != nil {
				return
			}
			if m.GetResync() != nil {
				resyncs <- struct{}{}
			}
		}
	}()
	send := func(m *pb.AgentMessage) {
		t.Helper()
		if err := ctl.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	diff := func(g uint64) *pb.AgentMessage {
		return &pb.AgentMessage{Msg: &pb.AgentMessage_InventoryDiff{InventoryDiff: &pb.InventoryDiff{Generation: g}}}
	}
	send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{ClusterId: id.String()}}})
	send(diff(4)) // before any snapshot
	send(&pb.AgentMessage{Msg: &pb.AgentMessage_Inventory{Inventory: &pb.InventorySnapshot{Generation: 10}}})
	send(diff(11))
	send(&pb.AgentMessage{Msg: &pb.AgentMessage_TargetDelete{TargetDelete: &pb.TargetDelete{TargetId: "t", Generation: 12}}})
	send(diff(14)) // gap
	send(diff(15)) // still out of order: dropped, no second resync
	send(&pb.AgentMessage{Msg: &pb.AgentMessage_Inventory{Inventory: &pb.InventorySnapshot{Generation: 20}}})
	send(diff(21))
	send(diff(0)) // agent without generations
	want := "snap:10,diff:11,del:t,snap:20,diff:21,diff:0"
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		got := strings.Join(applied, ",")
		mu.Unlock()
		if got == want {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("applied %s, want %s", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(resyncs); n != 2 {
		t.Fatalf("resync requests: %d, want 2 (before the first snapshot, then the gap)", n)
	}
}
