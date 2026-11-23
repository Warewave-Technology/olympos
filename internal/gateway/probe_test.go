package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func (e *env) dialProbe(t *testing.T, cert *tls.Certificate) pb.ProbeGatewayClient {
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
	return pb.NewProbeGatewayClient(conn)
}

// fakeProbe is one probe stream with its own HPKE key.
type fakeProbe struct {
	key  hpke.PrivateKey
	pub  []byte
	runs chan *pb.RunScenario
	done chan error
}

func connectProbe(t *testing.T, ctx context.Context, c pb.ProbeGatewayClient, clusterID string, maxConc int32) (*fakeProbe, error) {
	t.Helper()
	key, err := spec.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()
	st, err := c.Connect(ctx)
	if err != nil {
		return nil, err
	}
	if err := st.Send(&pb.ProbeMessage{Msg: &pb.ProbeMessage_Hello{Hello: &pb.ProbeHello{ProbeVersion: "test", ClusterId: clusterID,
		HpkePublicKey: pub, MaxConcurrency: maxConc}}}); err != nil {
		return nil, err
	}
	p := &fakeProbe{key: key, pub: pub, runs: make(chan *pb.RunScenario, 8), done: make(chan error, 1)}
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				p.done <- err
				return
			}
			if r := m.GetRun(); r != nil {
				p.runs <- r
			}
		}
	}()
	return p, nil
}

// refusedProbe connects and waits for the server's answer.
func refusedProbe(t *testing.T, c pb.ProbeGatewayClient, clusterID string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := connectProbe(t, ctx, c, clusterID, 1)
	if err != nil {
		return err
	}
	select {
	case err := <-p.done:
		return err
	case <-time.After(2 * time.Second):
		return nil
	}
}

// renewProbe renews with cert on ProbeGateway.
func (e *env) renewProbe(t *testing.T, cert *tls.Certificate) (*tls.Certificate, error) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	resp, err := e.dialProbe(t, cert).RenewCert(context.Background(), &pb.RenewCertRequest{CsrDer: csr})
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{resp.CertDer}, PrivateKey: key}, nil
}

func serialOf(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return pki.SerialHex(leaf.SerialNumber)
}

// probeSerials returns the cluster's current and previous probe serials.
func (e *env) probeSerials(t *testing.T, id uuid.UUID) (cur, prev string) {
	t.Helper()
	if err := e.gw.DB.QueryRow(context.Background(), `SELECT probe_cert_serial, probe_prev_cert_serial FROM clusters WHERE id = $1`, id).
		Scan(&cur, &prev); err != nil {
		t.Fatal(err)
	}
	return cur, prev
}

func (e *env) isRevoked(t *testing.T, serial string) bool {
	t.Helper()
	var ok bool
	if err := e.gw.DB.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM revoked_certs WHERE serial = $1)`, serial).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func waitProbes(t *testing.T, gw *gateway.Gateway, id uuid.UUID, n *atomic.Int32, want int32) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if n.Load() >= want {
			if _, ok := gw.ProbeConnected(id); ok {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d probe streams connected, want %d", n.Load(), want)
}

func waitGone(t *testing.T, what string, connected func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for connected() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if connected() {
		t.Fatalf("%s not dropped", what)
	}
}

func countConnects(gw *gateway.Gateway) *atomic.Int32 {
	var n atomic.Int32
	gw.ProbeHooks.Connected = func(context.Context, uuid.UUID, *pb.ProbeHello) error {
		n.Add(1)
		return nil
	}
	return &n
}

func probeConnected(gw *gateway.Gateway, id uuid.UUID) func() bool {
	return func() bool { _, ok := gw.ProbeConnected(id); return ok }
}

// An agent identity reaches nothing of ProbeGateway.
func TestAgentIdentityRefusedByProbeGateway(t *testing.T) {
	e := start(t)
	id, agent, _ := e.enrolled(t)
	c := e.dialProbe(t, agent)
	wantCode(t, "Connect", refusedProbe(t, c, id.String()), codes.PermissionDenied)
	if _, ok := e.gw.ProbeConnected(id); ok {
		t.Fatal("agent identity attached as a probe")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	_, err := c.RenewCert(context.Background(), &pb.RenewCertRequest{CsrDer: csr})
	wantCode(t, "ProbeGateway.RenewCert", err, codes.PermissionDenied)
	// No client certificate at all.
	wantCode(t, "Connect without a certificate", refusedProbe(t, e.dialProbe(t, nil), id.String()), codes.Unauthenticated)
}

func TestProbeHelloChecked(t *testing.T) {
	e := start(t)
	id, _, probe := e.enrolled(t)
	c := e.dialProbe(t, probe)
	wantCode(t, "foreign cluster id", refusedProbe(t, c, uuid.NewString()), codes.PermissionDenied)

	st, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Send(&pb.ProbeMessage{Msg: &pb.ProbeMessage_Hello{Hello: &pb.ProbeHello{ClusterId: id.String(), HpkePublicKey: []byte("short")}}})
	_, err = st.Recv()
	wantCode(t, "bad hpke key", err, codes.InvalidArgument)
}

// Revoking the probe alone leaves the agent working.
func TestRevokeProbeAlone(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	var agentConnects atomic.Int32
	e.gw.Hooks.Connected = func(context.Context, uuid.UUID, *pb.Hello) error {
		agentConnects.Add(1)
		return nil
	}
	id, agent, beforeRenew := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The probe renewed once: only the current serial gets revoked, and the
	// older certificate is still unexpired.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	resp, err := e.dialProbe(t, beforeRenew).RenewCert(ctx, &pb.RenewCertRequest{CsrDer: csr})
	if err != nil {
		t.Fatal(err)
	}
	probe := &tls.Certificate{Certificate: [][]byte{resp.CertDer}, PrivateKey: key}
	fakeAgent(t, ctx, e.dial(t, agent), id.String(), "x")
	waitConnected(t, e.gw, id)
	pc := e.dialProbe(t, probe)
	if _, err := connectProbe(t, ctx, pc, id.String(), 1); err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 1)

	if err := e.gw.RevokeProbe(ctx, e.gw.DB, id); err != nil {
		t.Fatal(err)
	}
	waitGone(t, "probe stream", probeConnected(e.gw, id))
	wantCode(t, "revoked probe reconnects", refusedProbe(t, pc, id.String()), codes.PermissionDenied)
	// Refused by probe_status: its serial is not in revoked_certs.
	wantCode(t, "pre-renewal probe certificate", refusedProbe(t, e.dialProbe(t, beforeRenew), id.String()), codes.PermissionDenied)
	_, err = e.dialProbe(t, beforeRenew).RenewCert(ctx, &pb.RenewCertRequest{CsrDer: csr})
	wantCode(t, "revoked probe renews", err, codes.PermissionDenied)

	if !e.gw.Connected(id) {
		t.Fatal("revoking the probe dropped the agent")
	}
	// A new agent stream is still accepted (and wins, as before).
	fakeAgent(t, ctx, e.dial(t, agent), id.String(), "x")
	for i := 0; agentConnects.Load() < 2; i++ {
		if i == 200 {
			t.Fatal("agent cannot reconnect after the probe was revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitConnected(t, e.gw, id)

	var probeStatus, clusterStatus string
	var revoked bool
	leaf, _ := x509.ParseCertificate(probe.Certificate[0])
	if err := e.gw.DB.QueryRow(ctx, `SELECT probe_status, status, EXISTS(SELECT 1 FROM revoked_certs WHERE serial = $2) FROM clusters WHERE id = $1`,
		id, pki.SerialHex(leaf.SerialNumber)).Scan(&probeStatus, &clusterStatus, &revoked); err != nil {
		t.Fatal(err)
	}
	if probeStatus != "revoked" || clusterStatus == "revoked" || !revoked {
		t.Fatalf("probe_status %q, status %q, serial revoked %v", probeStatus, clusterStatus, revoked)
	}

	// "Install probe" again: a fresh probe-only token makes a new identity.
	fresh, _, err := enrollAs(t, e.dial(t, nil), e.newToken(t, id, []string{"probe"}, time.Hour), pb.EnrollRole_ENROLL_ROLE_PROBE)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectProbe(t, ctx, e.dialProbe(t, fresh), id.String(), 1); err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 2) // the fresh certificate is accepted
	wantCode(t, "old probe certificate after reinstall", refusedProbe(t, pc, id.String()), codes.PermissionDenied)
	// probe_status is no longer 'revoked', and this serial was never put in
	// revoked_certs: only "current serial only" refuses it.
	wantCode(t, "pre-renewal probe certificate after reinstall", refusedProbe(t, e.dialProbe(t, beforeRenew), id.String()), codes.PermissionDenied)
	// The certificates from before the revoke can never renew either.
	for name, c := range map[string]*tls.Certificate{"revoked": probe, "pre-renewal": beforeRenew} {
		_, err := e.renewProbe(t, c)
		wantCode(t, name+" certificate renews after reinstall", err, codes.PermissionDenied)
	}

	if err := e.gw.RevokeProbe(ctx, e.gw.DB, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown cluster: %v", err)
	}
}

// Revoking the cluster revokes both identities.
func TestRevokeClusterRevokesBoth(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, agent, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeAgent(t, ctx, e.dial(t, agent), id.String(), "x")
	waitConnected(t, e.gw, id)
	pc := e.dialProbe(t, probe)
	for range 2 { // two probe replicas
		if _, err := connectProbe(t, ctx, pc, id.String(), 1); err != nil {
			t.Fatal(err)
		}
	}
	waitProbes(t, e.gw, id, n, 2)

	if err := e.gw.Revoke(ctx, e.gw.DB, id); err != nil {
		t.Fatal(err)
	}
	waitGone(t, "agent stream", func() bool { return e.gw.Connected(id) })
	waitGone(t, "probe streams", probeConnected(e.gw, id))
	wantCode(t, "probe after cluster revoke", refusedProbe(t, pc, id.String()), codes.PermissionDenied)

	var probeStatus string
	var revoked int
	if err := e.gw.DB.QueryRow(ctx, `SELECT probe_status, (SELECT count(*) FROM revoked_certs WHERE cluster_id = $1) FROM clusters WHERE id = $1`, id).
		Scan(&probeStatus, &revoked); err != nil {
		t.Fatal(err)
	}
	if probeStatus != "revoked" || revoked != 2 {
		t.Fatalf("probe_status %q, revoked serials %d, want revoked and 2", probeStatus, revoked)
	}
}

func TestProbeRenewCert(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, _, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var agentSerialBefore string
	if err := e.gw.DB.QueryRow(ctx, `SELECT cert_serial FROM clusters WHERE id = $1`, id).Scan(&agentSerialBefore); err != nil {
		t.Fatal(err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	resp, err := e.dialProbe(t, probe).RenewCert(ctx, &pb.RenewCertRequest{CsrDer: csr})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(resp.CertDer)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != id.String()+"/probe" {
		t.Fatalf("renewed CN %q", leaf.Subject.CommonName)
	}
	var probeSerial, agentSerial string
	if err := e.gw.DB.QueryRow(ctx, `SELECT probe_cert_serial, cert_serial FROM clusters WHERE id = $1`, id).Scan(&probeSerial, &agentSerial); err != nil {
		t.Fatal(err)
	}
	if probeSerial != pki.SerialHex(leaf.SerialNumber) || agentSerial != agentSerialBefore {
		t.Fatalf("probe serial %q (want %q), agent serial %q (want %q)", probeSerial, pki.SerialHex(leaf.SerialNumber), agentSerial, agentSerialBefore)
	}
	renewed := &tls.Certificate{Certificate: [][]byte{resp.CertDer}, PrivateKey: key}
	// Only the current certificate may connect: the one it replaced is
	// refused at once.
	wantCode(t, "superseded probe certificate", refusedProbe(t, e.dialProbe(t, probe), id.String()), codes.PermissionDenied)
	if _, prev := e.probeSerials(t, id); prev != serialOf(t, probe) {
		t.Fatalf("previous serial %q, want the replaced one", prev)
	}
	if _, err := connectProbe(t, ctx, e.dialProbe(t, renewed), id.String(), 1); err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 1) // the current certificate is accepted
	// Once the new certificate connected, the old one can no longer renew.
	if _, prev := e.probeSerials(t, id); prev != "" {
		t.Fatalf("previous serial %q kept after a connect with the new certificate", prev)
	}
	_, err = e.renewProbe(t, probe)
	wantCode(t, "old certificate renews after the new one connected", err, codes.PermissionDenied)
	// The renewed certificate is still a probe identity only.
	_, err = e.dial(t, renewed).RenewCert(ctx, &pb.RenewCertRequest{CsrDer: csr})
	wantCode(t, "renewed probe on AgentGateway", err, codes.PermissionDenied)
}

// A renewal whose answer was lost is retried with the old certificate. The
// old certificate still cannot connect, and the certificate that never
// arrived is refused once the retry replaced it.
func TestProbeLostRenewalRetried(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, _, s1 := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lost, err := e.renewProbe(t, s1) // the agent never receives this one
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, "old certificate connects", refusedProbe(t, e.dialProbe(t, s1), id.String()), codes.PermissionDenied)

	s3, err := e.renewProbe(t, s1)
	if err != nil {
		t.Fatalf("retried renewal: %v", err)
	}
	if cur, prev := e.probeSerials(t, id); cur != serialOf(t, s3) || prev != serialOf(t, s1) {
		t.Fatalf("after the retry: current %q previous %q, want %q %q", cur, prev, serialOf(t, s3), serialOf(t, s1))
	}
	wantCode(t, "old certificate connects after the retry", refusedProbe(t, e.dialProbe(t, s1), id.String()), codes.PermissionDenied)
	wantCode(t, "lost certificate connects", refusedProbe(t, e.dialProbe(t, lost), id.String()), codes.PermissionDenied)
	_, err = e.renewProbe(t, lost)
	wantCode(t, "lost certificate renews", err, codes.PermissionDenied)

	if _, err := connectProbe(t, ctx, e.dialProbe(t, s3), id.String(), 1); err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 1)
	_, err = e.renewProbe(t, s1)
	wantCode(t, "old certificate renews after the new one connected", err, codes.PermissionDenied)
}

// RevokeProbe and a fresh probe enrollment revoke both serials of a
// renewal that was never confirmed, and clear the previous one.
func TestProbeReplacedIdentityRevokesBothSerials(t *testing.T) {
	e := start(t)
	ctx := context.Background()
	for _, how := range []string{"revoke", "reinstall"} {
		t.Run(how, func(t *testing.T) {
			id, _, s1 := e.enrolled(t)
			s2, err := e.renewProbe(t, s1) // not yet confirmed by a connect
			if err != nil {
				t.Fatal(err)
			}
			if how == "revoke" {
				if err := e.gw.RevokeProbe(ctx, e.gw.DB, id); err != nil {
					t.Fatal(err)
				}
			}
			fresh, _, err := enrollAs(t, e.dial(t, nil), e.newToken(t, id, []string{"probe"}, time.Hour), pb.EnrollRole_ENROLL_ROLE_PROBE)
			if err != nil {
				t.Fatal(err)
			}
			if cur, prev := e.probeSerials(t, id); cur != serialOf(t, fresh) || prev != "" {
				t.Fatalf("after %s: current %q previous %q", how, cur, prev)
			}
			for name, c := range map[string]*tls.Certificate{"replaced": s1, "unconfirmed": s2} {
				if !e.isRevoked(t, serialOf(t, c)) {
					t.Fatalf("%s serial not revoked", name)
				}
				_, err := e.renewProbe(t, c)
				wantCode(t, name+" certificate renews", err, codes.PermissionDenied)
			}
		})
	}
}

// SendRun builds each run for the stream it goes out on: the credentials
// open with that stream's key and no other.
func TestSendRunSealsForChosenSession(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, _, probe := e.enrolled(t)
	if _, err := e.gw.SendRun(id, serialOf(t, probe), func(gateway.ProbeInfo) (*pb.RunScenario, error) {
		t.Fatal("build called with no probe")
		return nil, nil
	}); !errors.Is(err, gateway.ErrProbeOffline) {
		t.Fatalf("no probe: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc := e.dialProbe(t, probe)
	a, err := connectProbe(t, ctx, pc, id.String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := connectProbe(t, ctx, pc, id.String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 2)
	byKey := map[string]*fakeProbe{string(a.pub): a, string(b.pub): b}

	secret := []byte("s3cr3t-bearer")
	send := func(runID string) gateway.ProbeInfo {
		t.Helper()
		info, err := e.gw.SendRun(id, serialOf(t, probe), func(info gateway.ProbeInfo) (*pb.RunScenario, error) {
			enc, ct, err := spec.SealCredentials(info.PublicKey, runID, id.String(), []spec.RunCredential{{
				ID: uuid.New(), Kind: "bearer", BoundHosts: []string{"api.example.com"}, Secret: spec.NewSecret(append([]byte(nil), secret...)),
			}})
			if err != nil {
				return nil, err
			}
			return &pb.RunScenario{RunId: runID, ScenarioJson: []byte(`{}`), Credentials: &pb.SealedCredentials{Enc: enc, Ciphertext: ct}}, nil
		})
		if err != nil {
			t.Fatalf("SendRun %s: %v", runID, err)
		}
		return info
	}
	// receive checks the run reached the stream whose key it was sealed to,
	// opens there, and does not open with the other stream's key.
	receive := func(info gateway.ProbeInfo, runID string) {
		t.Helper()
		to, other := byKey[string(info.PublicKey)], a
		if to == nil {
			t.Fatal("SendRun reported a key no stream has")
		}
		if to == a {
			other = b
		}
		select {
		case r := <-to.runs:
			if r.RunId != runID {
				t.Fatalf("got run %s, want %s", r.RunId, runID)
			}
			creds, err := spec.OpenCredentials(to.key, runID, id.String(), r.Credentials.Enc, r.Credentials.Ciphertext)
			if err != nil {
				t.Fatalf("chosen stream cannot open its run: %v", err)
			}
			if string(creds[0].Secret.Bytes()) != string(secret) {
				t.Fatal("secret changed in transit")
			}
			spec.ZeroCredentials(creds)
			if _, err := spec.OpenCredentials(other.key, runID, id.String(), r.Credentials.Enc, r.Credentials.Ciphertext); err == nil {
				t.Fatal("another stream's key opened the run")
			}
		case r := <-other.runs:
			t.Fatalf("run %s went to a stream it was not sealed for", r.RunId)
		case <-time.After(3 * time.Second):
			t.Fatalf("run %s not delivered", runID)
		}
	}

	first := send("run-1")
	receive(first, "run-1")
	if first.InFlight != 1 || first.MaxConcurrency != 1 || first.Version != "test" {
		t.Fatalf("first info %+v", first)
	}
	// The first stream is full: the next run goes to the other one.
	second := send("run-2")
	receive(second, "run-2")
	if second.SessionID == first.SessionID {
		t.Fatal("second run went to the full stream")
	}
	if _, err := e.gw.SendRun(id, serialOf(t, probe), func(gateway.ProbeInfo) (*pb.RunScenario, error) {
		t.Fatal("build called with every stream full")
		return nil, nil
	}); !errors.Is(err, gateway.ErrProbeBusy) {
		t.Fatalf("every stream full: %v", err)
	}

	// RunDone frees the first stream again.
	e.gw.RunDone(id, first.SessionID)
	third := send("run-3")
	receive(third, "run-3")
	if third.SessionID != first.SessionID {
		t.Fatal("run did not go to the freed stream")
	}

	// A failing build sends nothing and keeps no reservation.
	e.gw.RunDone(id, third.SessionID)
	boom := errors.New("boom")
	if _, err := e.gw.SendRun(id, serialOf(t, probe), func(gateway.ProbeInfo) (*pb.RunScenario, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("build error: %v", err)
	}
	receive(send("run-4"), "run-4")

	cancel()
	waitGone(t, "probe streams", probeConnected(e.gw, id))
	if _, err := e.gw.SendRun(id, serialOf(t, probe), func(gateway.ProbeInfo) (*pb.RunScenario, error) { return nil, nil }); !errors.Is(err, gateway.ErrProbeOffline) {
		t.Fatalf("after disconnect: %v", err)
	}
}

// Results and rejections reach the hooks with the certificate's cluster.
func TestProbeResultHooks(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	got := make(chan string, 4)
	e.gw.ProbeHooks.Result = func(_ context.Context, c uuid.UUID, r *pb.RunResult) { got <- "result:" + c.String() + ":" + r.RunId }
	e.gw.ProbeHooks.Rejected = func(_ context.Context, c uuid.UUID, r *pb.RunRejected) {
		got <- "rejected:" + c.String() + ":" + r.RunId + ":" + r.Reason
	}
	disconnected := make(chan uuid.UUID, 1)
	e.gw.ProbeHooks.Disconnected = func(c uuid.UUID) { disconnected <- c }
	id, _, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, _ := spec.GenerateKey()
	st, err := e.dialProbe(t, probe).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*pb.ProbeMessage{
		{Msg: &pb.ProbeMessage_Hello{Hello: &pb.ProbeHello{ClusterId: id.String(), HpkePublicKey: key.PublicKey().Bytes(), MaxConcurrency: 2}}},
		{Msg: &pb.ProbeMessage_Result{Result: &pb.RunResult{RunId: "r1", Status: "passed"}}},
		{Msg: &pb.ProbeMessage_Rejected{Rejected: &pb.RunRejected{RunId: "r2", Reason: "busy"}}},
	} {
		if err := st.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"result:" + id.String() + ":r1", "rejected:" + id.String() + ":r2:busy"} {
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("hook got %s, want %s", g, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("hook not called for %s", want)
		}
	}
	waitProbes(t, e.gw, id, n, 1)
	_ = st.CloseSend()
	select {
	case c := <-disconnected:
		if c != id {
			t.Fatalf("disconnected %s", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnected hook not called")
	}
}

// ProbeSessionAlive follows one stream: true while it is open, false once it
// ended, and false for an id no stream has.
func TestProbeSessionAlive(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, _, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := connectProbe(t, ctx, e.dialProbe(t, probe), id.String(), 2); err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 1)
	info, _ := e.gw.ProbeConnected(id)
	if !e.gw.ProbeSessionAlive(id, info.SessionID) {
		t.Fatal("open stream not alive")
	}
	if e.gw.ProbeSessionAlive(id, info.SessionID+1) || e.gw.ProbeSessionAlive(uuid.New(), info.SessionID) {
		t.Fatal("unknown stream alive")
	}
	cancel()
	waitGone(t, "probe stream", func() bool { return e.gw.ProbeSessionAlive(id, info.SessionID) })
}

// A stream that connected with a certificate renewed since stays open
// until the probe reconnects, but gets no run: SendRun and ProbeStream use
// only the streams of the serial they are given, the cluster's current
// one, so that no run is sealed to the key of a stream that is going away.
func TestSendRunSkipsStreamsOfARenewedCertificate(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, _, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	old, err := connectProbe(t, ctx, e.dialProbe(t, probe), id.String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 1)
	oldSerial := serialOf(t, probe)
	if info, ok := e.gw.ProbeStream(id, oldSerial); !ok || info.CertSerial != oldSerial {
		t.Fatalf("stream of the current certificate: %+v %v", info, ok)
	}
	if _, ok := e.gw.ProbeStream(id, ""); ok {
		t.Fatal("ProbeStream with no serial found a stream")
	}

	renewed, err := e.renewProbe(t, probe)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := e.probeSerials(t, id)
	if cur != serialOf(t, renewed) {
		t.Fatalf("current serial %s, want the renewed one", cur)
	}
	// The old stream is still attached, but not for the current serial.
	if _, ok := e.gw.ProbeConnected(id); !ok {
		t.Fatal("old stream dropped by the renewal")
	}
	if _, ok := e.gw.ProbeStream(id, cur); ok {
		t.Fatal("old stream offered for the renewed certificate")
	}
	if _, err := e.gw.SendRun(id, cur, func(gateway.ProbeInfo) (*pb.RunScenario, error) {
		t.Error("build called for the stream of a renewed certificate")
		return nil, nil
	}); !errors.Is(err, gateway.ErrProbeOffline) {
		t.Fatalf("SendRun with only an old stream: %v", err)
	}
	if _, err := e.gw.SendRun(id, "", func(gateway.ProbeInfo) (*pb.RunScenario, error) {
		t.Error("build called with no serial")
		return nil, nil
	}); !errors.Is(err, gateway.ErrProbeOffline) {
		t.Fatalf("SendRun with no serial: %v", err)
	}

	// The probe reconnects with the new certificate: runs go there only.
	fresh, err := connectProbe(t, ctx, e.dialProbe(t, renewed), id.String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 2)
	for i := range 3 {
		runID := fmt.Sprintf("run-%d", i)
		info, err := e.gw.SendRun(id, cur, func(info gateway.ProbeInfo) (*pb.RunScenario, error) {
			if !bytes.Equal(info.PublicKey, fresh.pub) {
				t.Errorf("run %s built for the old stream's key", runID)
			}
			return &pb.RunScenario{RunId: runID}, nil
		})
		if err != nil || info.CertSerial != cur {
			t.Fatalf("SendRun %s: %+v %v", runID, info, err)
		}
		select {
		case r := <-fresh.runs:
			if r.RunId != runID {
				t.Fatalf("got %s, want %s", r.RunId, runID)
			}
		case r := <-old.runs:
			t.Fatalf("run %s went to the stream of the renewed certificate", r.RunId)
		case <-time.After(3 * time.Second):
			t.Fatalf("run %s not delivered", runID)
		}
	}
}
