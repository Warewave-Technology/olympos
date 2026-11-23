package probe

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// waitFor bounds every wait in these tests.
const waitFor = 10 * time.Second

// fakeGateway is an in-test ProbeGateway: gRPC over TLS with a test CA,
// requiring a client certificate from the same CA, as the real gateway
// does. Like the real one, it accepts only the current probe certificate
// (accept), wants the hello first and within helloTimeout, and checks the
// hello's cluster id and HPKE key.
type fakeGateway struct {
	pb.UnimplementedProbeGatewayServer
	t       *testing.T
	addr    string
	streams chan *gwStream

	mu     sync.Mutex
	accept string // the only serial accepted; "" accepts any
}

const helloTimeout = 2 * time.Second

// gwStream is one probe stream as the gateway sees it.
type gwStream struct {
	hello  *pb.ProbeHello
	serial string
	in     chan *pb.ProbeMessage
	out    chan *pb.ServerProbeMessage
	done   chan struct{}
	end    context.CancelFunc
}

func newFakeGateway(t *testing.T, ca *testCA) *fakeGateway {
	t.Helper()
	g := &fakeGateway{t: t, streams: make(chan *gwStream, 16)}
	srvCert := ca.leaf(t, []string{"gateway.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterProbeGatewayServer(s, g)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	g.addr = lis.Addr().String()
	return g
}

func (g *fakeGateway) setAccept(serial string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.accept = serial
}

func (g *fakeGateway) Connect(st pb.ProbeGateway_ConnectServer) error {
	p, ok := peer.FromContext(st.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "no client certificate")
	}
	leaf := ti.State.PeerCertificates[0]
	serial := fmt.Sprintf("%x", leaf.SerialNumber)
	g.mu.Lock()
	accept := g.accept
	g.mu.Unlock()
	if accept != "" && serial != accept {
		return status.Error(codes.PermissionDenied, "probe certificate superseded")
	}
	first, err := recvFirst(st, helloTimeout)
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "first message must be ProbeHello")
	}
	if want := strings.TrimSuffix(leaf.Subject.CommonName, "/probe"); hello.ClusterId != want {
		return status.Error(codes.PermissionDenied, "hello cluster id does not match certificate")
	}
	if _, err := ecdh.X25519().NewPublicKey(hello.HpkePublicKey); err != nil {
		return status.Error(codes.InvalidArgument, "hpke_public_key must be a raw X25519 public key")
	}
	ctx, cancel := context.WithCancel(st.Context())
	defer cancel()
	gs := &gwStream{hello: hello, serial: serial, in: make(chan *pb.ProbeMessage, 64),
		out: make(chan *pb.ServerProbeMessage, 64), done: make(chan struct{}), end: cancel}
	defer close(gs.done)
	g.streams <- gs
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				cancel()
				return
			}
			gs.in <- m
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Aborted, "session closed")
		case m := <-gs.out:
			if err := st.Send(m); err != nil {
				return err
			}
		}
	}
}

func recvFirst(st pb.ProbeGateway_ConnectServer, d time.Duration) (*pb.ProbeMessage, error) {
	type res struct {
		m   *pb.ProbeMessage
		err error
	}
	ch := make(chan res, 1)
	go func() { m, err := st.Recv(); ch <- res{m, err} }()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-time.After(d):
		return nil, status.Error(codes.DeadlineExceeded, "no hello in time")
	}
}

// next waits for the next probe stream.
func (g *fakeGateway) next(t *testing.T) *gwStream {
	t.Helper()
	select {
	case gs := <-g.streams:
		return gs
	case <-time.After(waitFor):
		t.Fatal("no probe stream")
		return nil
	}
}

// noStream checks that no stream arrives for d.
func (g *fakeGateway) noStream(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case gs := <-g.streams:
		t.Fatalf("unexpected probe stream (serial %s)", gs.serial)
	case <-time.After(d):
	}
}

func (gs *gwStream) send(m *pb.ServerProbeMessage) { gs.out <- m }

func (gs *gwStream) run(r *pb.RunScenario) {
	gs.send(&pb.ServerProbeMessage{Msg: &pb.ServerProbeMessage_Run{Run: r}})
}

// recv waits for the next message from the probe, skipping pongs.
func (gs *gwStream) recv(t *testing.T) *pb.ProbeMessage {
	t.Helper()
	for {
		select {
		case m := <-gs.in:
			if m.GetPong() != nil {
				continue
			}
			return m
		case <-gs.done:
			t.Fatal("stream ended while waiting for a message")
		case <-time.After(waitFor):
			t.Fatal("no message from the probe")
		}
	}
}

func (gs *gwStream) result(t *testing.T) *pb.RunResult {
	t.Helper()
	m := gs.recv(t)
	if m.GetResult() == nil {
		t.Fatalf("want a RunResult, got %v", m)
	}
	return m.GetResult()
}

func (gs *gwStream) rejected(t *testing.T, runID, reason string) {
	t.Helper()
	m := gs.recv(t)
	r := m.GetRejected()
	if r == nil || r.RunId != runID || r.Reason != reason {
		t.Fatalf("want run %s rejected with %s, got %v", runID, reason, m)
	}
}

func (gs *gwStream) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-gs.done:
	case <-time.After(waitFor):
		t.Fatal("stream did not end")
	}
}

// probeCert is a probe client certificate as the agent writes it.
type probeCert struct {
	certPEM, keyPEM []byte
	serial          string
}

func (ca *testCA) probeCert(t *testing.T, clusterID string) probeCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: clusterID + "/probe", Organization: []string{"olympos-probe"}},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return probeCert{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}),
		serial:  fmt.Sprintf("%x", serial),
	}
}

func (ca *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

var identityVersion atomic.Int64

// writeIdentity writes the identity files the way the kubelet updates a
// Secret volume: the files go into a new timestamped directory, the
// "..data" symlink is swapped to it in one rename, and the visible files
// are symlinks through "..data" that never change themselves.
func writeIdentity(t *testing.T, dir string, pc probeCert, caPEM []byte) {
	t.Helper()
	ver := fmt.Sprintf("..v%d", identityVersion.Add(1))
	if err := os.Mkdir(filepath.Join(dir, ver), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{identityCertFile: pc.certPEM, identityKeyFile: pc.keyPEM, identityCAFile: caPEM} {
		if err := os.WriteFile(filepath.Join(dir, ver, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(ver, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, identityDataLink)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{identityCertFile, identityKeyFile, identityCAFile} {
		link := filepath.Join(dir, name)
		if _, err := os.Lstat(link); err == nil {
			continue
		}
		if err := os.Symlink(filepath.Join(identityDataLink, name), link); err != nil {
			t.Fatal(err)
		}
	}
}

// syncBuffer collects log output.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// probeEnv is a Client connected to a fakeGateway, with a fake resolver
// and network for its runs.
type probeEnv struct {
	gw        *fakeGateway
	ca        *testCA
	dir       string
	clusterID string
	cert      probeCert
	client    *Client
	res       *fakeResolver
	net       *fakeNet
	logs      *syncBuffer
	runDone   chan error
	apps      int
	// zeroed receives each run's credentials once they were zeroed.
	zeroed chan []spec.RunCredential
}

type envOpt func(*probeEnv)

// withoutIdentity starts the probe before the identity files exist.
func withoutIdentity() envOpt { return func(e *probeEnv) { e.cert = probeCert{} } }

func withSilence(d time.Duration) envOpt { return func(e *probeEnv) { e.client.silence = d } }

func withConcurrency(n int) envOpt {
	return func(e *probeEnv) {
		e.client.cfg.MaxConcurrency = n
		e.client.sem = make(chan struct{}, n)
	}
}

func withRunFunc(f func(*Runner, context.Context, *spec.Scenario, []spec.RunCredential) *pb.RunResult) envOpt {
	return func(e *probeEnv) { e.client.runFunc = f }
}

func newProbeEnv(t *testing.T, opts ...envOpt) *probeEnv {
	t.Helper()
	ca := newTestCA(t)
	e := &probeEnv{
		gw: newFakeGateway(t, ca), ca: ca, dir: t.TempDir(), clusterID: uuid.NewString(),
		res: newFakeResolver(), net: newFakeNet(), logs: &syncBuffer{}, runDone: make(chan error, 1),
		zeroed: make(chan []spec.RunCredential, 64),
	}
	e.cert = ca.probeCert(t, e.clusterID)
	log := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ident := NewIdentity(e.dir, log)
	ident.poll = 50 * time.Millisecond
	cfg := Config{Server: e.gw.addr, ServerName: "gateway.test", IdentityDir: e.dir, MaxConcurrency: DefaultMaxConcurrency}
	e.client = NewClient(cfg, ident, e.res, testRedactor(t), log)
	e.client.net = e.net.dial
	e.client.minBackoff = 20 * time.Millisecond
	e.client.afterRun = func(c []spec.RunCredential) { e.zeroed <- c }
	for _, o := range opts {
		o(e)
	}
	if e.cert.certPEM != nil {
		writeIdentity(t, e.dir, e.cert, ca.pem())
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { e.runDone <- e.client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-e.runDone:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(waitFor):
			t.Error("Run did not return")
		}
	})
	return e
}

// running checks that Run has not returned.
func (e *probeEnv) running(t *testing.T) {
	t.Helper()
	select {
	case err := <-e.runDone:
		t.Fatalf("Run returned: %v", err)
	default:
	}
}

// app serves h as https-less http://<name>.example.test.
func (e *probeEnv) app(t *testing.T, name string, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	e.apps++
	ip := fmt.Sprintf("203.0.113.%d", 10+e.apps)
	e.host(name+".example.test", ip, srv)
	return "http://" + name + ".example.test/"
}

func (e *probeEnv) host(name, ip string, srv *httptest.Server) {
	(&env{res: e.res, net: e.net}).host(name, ip, srv)
}

func allowlist(version int64) *pb.AllowlistSnapshot {
	return &pb.AllowlistSnapshot{Version: version, Rules: []*pb.AllowRule{{Pattern: "example.test", Kind: "suffix"}}}
}

func scenarioJSON(t *testing.T, s *spec.Scenario) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// okRun is a run of one GET to url that wants a 200.
func okRun(t *testing.T, url string) *pb.RunScenario {
	t.Helper()
	return &pb.RunScenario{
		RunId:        uuid.NewString(),
		ScenarioJson: scenarioJSON(t, scenario(httpStep(url, assertion(spec.SubjectStatusCode, spec.OpEquals, "200")))),
		Allowlist:    allowlist(3),
	}
}

func seal(t *testing.T, pub []byte, runID, clusterID string, creds ...spec.RunCredential) *pb.SealedCredentials {
	t.Helper()
	enc, ct, err := spec.SealCredentials(pub, runID, clusterID, creds)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.SealedCredentials{Enc: enc, Ciphertext: ct}
}

func ok200() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestClientResultArrives(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	if gs.hello.ProbeVersion != Version || gs.hello.ClusterId != e.clusterID || gs.hello.MaxConcurrency != DefaultMaxConcurrency {
		t.Fatalf("hello = %v", gs.hello)
	}
	if gs.serial != e.cert.serial {
		t.Fatalf("connected with serial %s, want %s", gs.serial, e.cert.serial)
	}

	const token = "tok-9f3a7c1e5b2d4e6f8a0b"
	rec := &headerRecorder{}
	url := e.app(t, "api", rec)
	cred := bearer(token, "suffix:example.test")
	run := &pb.RunScenario{
		RunId: uuid.NewString(),
		ScenarioJson: scenarioJSON(t, scenario(withCred(
			httpStep(url, assertion(spec.SubjectStatusCode, spec.OpEquals, "200")), cred))),
		Allowlist: allowlist(3),
		Test:      true,
	}
	run.Credentials = seal(t, gs.hello.HpkePublicKey, run.RunId, e.clusterID, cred)
	gs.run(run)

	res := gs.result(t)
	if res.RunId != run.RunId || res.ProbeVersion != Version {
		t.Fatalf("result run %q version %q", res.RunId, res.ProbeVersion)
	}
	wantPassed(t, res)
	reqs := rec.requests()
	if len(reqs) != 1 || reqs[0].Header.Get("Authorization") != "Bearer "+token {
		t.Fatalf("the credential did not reach the server: %v", reqs)
	}

	// The credentials the probe opened were zeroed after the run.
	select {
	case creds := <-e.zeroed:
		if len(creds) != 1 {
			t.Fatalf("run had %d credentials", len(creds))
		}
		for _, c := range creds {
			if c.Secret != nil || c.Username != nil {
				t.Fatal("credentials not zeroed after the run")
			}
		}
	case <-time.After(waitFor):
		t.Fatal("run did not end")
	}

	// Nothing of the scenario or the credential was logged.
	logs := e.logs.String()
	for _, s := range []string{token, "api.example.test", `"steps"`} {
		if strings.Contains(logs, s) {
			t.Fatalf("logs contain %q:\n%s", s, logs)
		}
	}
	if !strings.Contains(logs, run.RunId) {
		t.Fatalf("logs do not name the run:\n%s", logs)
	}
}

func TestClientPingPong(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	// Not ready until the server has spoken: the gateway checks the hello
	// and the identity after Connect returned.
	if e.client.Connected() {
		t.Fatal("ready before the first server message")
	}
	gs.send(&pb.ServerProbeMessage{Msg: &pb.ServerProbeMessage_Ping{Ping: &pb.Ping{UnixNano: 42}}})
	select {
	case m := <-gs.in:
		if m.GetPong() == nil || m.GetPong().UnixNano != 42 {
			t.Fatalf("want Pong 42, got %v", m)
		}
	case <-time.After(waitFor):
		t.Fatal("no pong")
	}
	if !e.client.Connected() || !strings.Contains(e.logs.String(), "connected to olympos") {
		t.Fatal("not ready after the first server message")
	}
	gs.end()
	gs.waitDone(t)
	deadline := time.Now().Add(waitFor)
	for e.client.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("still ready after the stream ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestClientRunnerPanicFailsOnlyTheRun(t *testing.T) {
	const canary = "panic-canary-3c1f"
	e := newProbeEnv(t, withConcurrency(1), withRunFunc(
		func(r *Runner, ctx context.Context, s *spec.Scenario, creds []spec.RunCredential) *pb.RunResult {
			if s.Name == "panic" {
				panic(canary)
			}
			return r.Run(ctx, s, creds)
		}))
	gs := e.gw.next(t)
	url := e.app(t, "app", ok200())

	sc := scenario(httpStep(url, assertion(spec.SubjectStatusCode, spec.OpEquals, "200")))
	sc.Name = "panic"
	cred := bearer("tok-panic-secret", "suffix:example.test")
	r := &pb.RunScenario{RunId: uuid.NewString(), ScenarioJson: scenarioJSON(t, sc), Allowlist: allowlist(1)}
	r.Credentials = seal(t, gs.hello.HpkePublicKey, r.RunId, e.clusterID, cred)
	gs.run(r)

	res := gs.result(t)
	if res.RunId != r.RunId || res.Status != StatusError || res.FailureReason != RunnerPanic || res.ProbeVersion != Version {
		t.Fatalf("result = %v", res)
	}
	select {
	case creds := <-e.zeroed:
		if len(creds) != 1 || creds[0].Secret != nil || creds[0].Username != nil {
			t.Fatal("credentials not zeroed after the panic")
		}
	case <-time.After(waitFor):
		t.Fatal("run did not end")
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "runner panic") || strings.Contains(logs, canary) {
		t.Fatalf("want the panic logged without its value:\n%s", logs)
	}

	// The process lives on, and the one slot is free again.
	e.running(t)
	next := okRun(t, url)
	gs.run(next)
	res = gs.result(t)
	if res.RunId != next.RunId {
		t.Fatalf("result for %s, want %s", res.RunId, next.RunId)
	}
	wantPassed(t, res)
}

func TestClientNewKeyPerStream(t *testing.T) {
	e := newProbeEnv(t)
	url := e.app(t, "app", ok200())
	keys := map[string]bool{}
	var prev *gwStream
	for range 3 {
		gs := e.gw.next(t)
		k := string(gs.hello.HpkePublicKey)
		if keys[k] {
			t.Fatal("a stream reused the HPKE key of an earlier stream")
		}
		keys[k] = true
		if prev != nil {
			// A run sealed to the previous stream's key cannot be opened
			// on this one.
			r := okRun(t, url)
			r.Credentials = seal(t, prev.hello.HpkePublicKey, r.RunId, e.clusterID, bearer("t", "suffix:example.test"))
			gs.run(r)
			gs.rejected(t, r.RunId, RejectCredentialsUnreadable)
		}
		gs.end()
		gs.waitDone(t)
		prev = gs
	}
	e.running(t)
}

func TestClientCredentialsSealedElsewhereRefused(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	url := e.app(t, "app", ok200())
	cred := bearer("secret-value", "suffix:example.test")

	other, err := spec.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, mk := range map[string]func(r *pb.RunScenario) *pb.SealedCredentials{
		"another key": func(r *pb.RunScenario) *pb.SealedCredentials {
			return seal(t, other.PublicKey().Bytes(), r.RunId, e.clusterID, cred)
		},
		"another run": func(r *pb.RunScenario) *pb.SealedCredentials {
			return seal(t, gs.hello.HpkePublicKey, uuid.NewString(), e.clusterID, cred)
		},
		"another cluster": func(r *pb.RunScenario) *pb.SealedCredentials {
			return seal(t, gs.hello.HpkePublicKey, r.RunId, uuid.NewString(), cred)
		},
		"changed": func(r *pb.RunScenario) *pb.SealedCredentials {
			s := seal(t, gs.hello.HpkePublicKey, r.RunId, e.clusterID, cred)
			s.Ciphertext[0] ^= 1
			return s
		},
		"empty": func(*pb.RunScenario) *pb.SealedCredentials { return &pb.SealedCredentials{} },
	} {
		r := okRun(t, url)
		r.Credentials = mk(r)
		gs.run(r)
		t.Run(name, func(t *testing.T) { gs.rejected(t, r.RunId, RejectCredentialsUnreadable) })
	}
	// A refused run does not count against the limit.
	r := okRun(t, url)
	gs.run(r)
	wantPassed(t, gs.result(t))
}

func TestClientStaleOrMissingAllowlistRefused(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	if gs.hello.AllowlistVersion != 0 {
		t.Fatalf("first hello allowlist_version = %d, want 0", gs.hello.AllowlistVersion)
	}
	url := e.app(t, "app", ok200())
	try := func(a *pb.AllowlistSnapshot) *pb.RunScenario {
		r := okRun(t, url)
		r.Allowlist = a
		gs.run(r)
		return r
	}

	r := try(nil)
	gs.rejected(t, r.RunId, RejectAllowlistStale)
	r = try(&pb.AllowlistSnapshot{Version: 0, Rules: allowlist(1).Rules})
	gs.rejected(t, r.RunId, RejectAllowlistStale)
	r = try(&pb.AllowlistSnapshot{Version: 6, Rules: []*pb.AllowRule{{Pattern: "example.test", Kind: "regex"}}})
	gs.rejected(t, r.RunId, RejectAllowlistStale)

	try(allowlist(5))
	wantPassed(t, gs.result(t))
	r = try(allowlist(4))
	gs.rejected(t, r.RunId, RejectAllowlistStale)
	try(allowlist(5))
	wantPassed(t, gs.result(t))

	// The highest version outlives the stream.
	gs.end()
	gs = e.gw.next(t)
	if gs.hello.AllowlistVersion != 5 {
		t.Fatalf("hello allowlist_version = %d, want 5", gs.hello.AllowlistVersion)
	}
	r = try(allowlist(4))
	gs.rejected(t, r.RunId, RejectAllowlistStale)
}

func TestClientInvalidScenario(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	for name, body := range map[string][]byte{
		"not json": []byte("{"),
		"invalid":  scenarioJSON(t, &spec.Scenario{Name: "x", Type: spec.TypeHTTPFlow}),
		"bad header": scenarioJSON(t, func() *spec.Scenario {
			s := scenario(httpStep("http://app.example.test/"))
			s.Steps[0].HTTP.Headers = map[string]string{"X-Leak-Canary": "v\n"}
			return s
		}()),
	} {
		r := &pb.RunScenario{RunId: uuid.NewString(), ScenarioJson: body, Allowlist: allowlist(1)}
		gs.run(r)
		t.Run(name, func(t *testing.T) { gs.rejected(t, r.RunId, RejectInvalidScenario) })
	}
	logs := e.logs.String()
	if !strings.Contains(logs, `"steps.0.http.headers"`) || strings.Contains(logs, "Canary") {
		t.Fatalf("want the field path without the header name:\n%s", logs)
	}
}

func TestClientBusy(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	release := make(chan struct{})
	var arrived atomic.Int32
	url := e.app(t, "slow", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))

	ids := map[string]bool{}
	for range DefaultMaxConcurrency {
		r := okRun(t, url)
		ids[r.RunId] = true
		gs.run(r)
	}
	extra := okRun(t, url)
	gs.run(extra)
	gs.rejected(t, extra.RunId, RejectBusy)

	close(release)
	for range DefaultMaxConcurrency {
		res := gs.result(t)
		if !ids[res.RunId] {
			t.Fatalf("result for unknown or repeated run %s", res.RunId)
		}
		delete(ids, res.RunId)
		wantPassed(t, res)
	}
	if n := arrived.Load(); n != DefaultMaxConcurrency {
		t.Fatalf("%d requests reached the server, want %d", n, DefaultMaxConcurrency)
	}
	// The slots are free again.
	r := okRun(t, url)
	gs.run(r)
	wantPassed(t, gs.result(t))
}

func TestClientDuplicateRunIgnored(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	var hits atomic.Int32
	dupURL := e.app(t, "dup", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	url := e.app(t, "other", ok200())

	dup := okRun(t, dupURL)
	gs.run(dup)
	if res := gs.result(t); res.RunId != dup.RunId {
		t.Fatalf("result for %s, want %s", res.RunId, dup.RunId)
	}
	gs.run(dup)
	// Messages on the stream are handled in order: once the next run's
	// result is back, the duplicate was seen and dropped.
	next := okRun(t, url)
	gs.run(next)
	if res := gs.result(t); res.RunId != next.RunId {
		t.Fatalf("result for %s, want %s (the duplicate ran)", res.RunId, next.RunId)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("the duplicated run ran %d times", n)
	}
	// Also on a later stream.
	gs.end()
	gs = e.gw.next(t)
	gs.run(dup)
	next = okRun(t, url)
	gs.run(next)
	if res := gs.result(t); res.RunId != next.RunId {
		t.Fatalf("result for %s, want %s (the duplicate ran)", res.RunId, next.RunId)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("the duplicated run ran %d times", n)
	}
}

func TestRunIDsBounded(t *testing.T) {
	r := newRunIDs(3)
	for _, id := range []string{"a", "b", "c", "d"} {
		r.add(id)
	}
	if r.has("a") || !r.has("b") || !r.has("d") || len(r.set) != 3 {
		t.Fatalf("set = %v", r.set)
	}
}

func TestClientStreamEndCancelsRuns(t *testing.T) {
	e := newProbeEnv(t)
	gs := e.gw.next(t)
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	slow := e.app(t, "slow", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
		cancelled <- struct{}{}
	}))
	fast := e.app(t, "fast", ok200())

	r := okRun(t, slow)
	gs.run(r)
	select {
	case <-started:
	case <-time.After(waitFor):
		t.Fatal("run did not start")
	}
	gs.end()
	select {
	case <-cancelled:
	case <-time.After(waitFor):
		t.Fatal("the run was not cancelled with its stream")
	}
	select {
	case <-e.zeroed:
	case <-time.After(waitFor):
		t.Fatal("the cancelled run did not end")
	}

	// Its result is not sent on the next stream.
	gs = e.gw.next(t)
	next := okRun(t, fast)
	gs.run(next)
	if res := gs.result(t); res.RunId != next.RunId {
		t.Fatalf("result for %s on the new stream, want %s", res.RunId, next.RunId)
	}
}

func TestClientSilenceWatchdog(t *testing.T) {
	e := newProbeEnv(t, withSilence(300*time.Millisecond))
	gs := e.gw.next(t)
	// The gateway says nothing: the probe gives the stream up and dials
	// again.
	gs.waitDone(t)
	gs = e.gw.next(t)
	// Traffic keeps a stream open.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				gs.send(&pb.ServerProbeMessage{Msg: &pb.ServerProbeMessage_Ping{Ping: &pb.Ping{UnixNano: 1}}})
			}
		}
	}()
	select {
	case <-gs.done:
		t.Fatal("stream closed although pings arrived")
	case <-time.After(time.Second):
	}
}

func TestClientReloadsIdentity(t *testing.T) {
	e := newProbeEnv(t)
	e.gw.setAccept(e.cert.serial)
	gs := e.gw.next(t)
	if gs.serial != e.cert.serial {
		t.Fatalf("connected with %s, want %s", gs.serial, e.cert.serial)
	}

	// The agent renews: from now on the server accepts only the new
	// certificate, and the agent writes it to the Secret.
	renewed := e.ca.probeCert(t, e.clusterID)
	e.gw.setAccept(renewed.serial)
	writeIdentity(t, e.dir, renewed, e.ca.pem())

	// The probe closes the old stream and dials again with the new
	// certificate, without a restart.
	gs.waitDone(t)
	gs2 := e.gw.next(t)
	if gs2.serial != renewed.serial {
		t.Fatalf("reconnected with %s, want the renewed %s", gs2.serial, renewed.serial)
	}
	if bytes.Equal(gs2.hello.HpkePublicKey, gs.hello.HpkePublicKey) {
		t.Fatal("the new stream reused the HPKE key")
	}
	e.running(t)
	url := e.app(t, "app", ok200())
	gs2.run(okRun(t, url))
	wantPassed(t, gs2.result(t))
	if !strings.Contains(e.logs.String(), "probe identity changed") {
		t.Fatalf("change not logged:\n%s", e.logs.String())
	}
}

func TestClientWaitsForIdentity(t *testing.T) {
	e := newProbeEnv(t, withoutIdentity())
	e.gw.noStream(t, 300*time.Millisecond)
	if !strings.Contains(e.logs.String(), "waiting for the probe identity") {
		t.Fatalf("wait not logged:\n%s", e.logs.String())
	}
	e.running(t)
	e.cert = e.ca.probeCert(t, e.clusterID)
	writeIdentity(t, e.dir, e.cert, e.ca.pem())
	gs := e.gw.next(t)
	if gs.serial != e.cert.serial {
		t.Fatalf("connected with %s, want %s", gs.serial, e.cert.serial)
	}
}

func TestIdentityKeepsLastGoodFiles(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	id := uuid.NewString()
	pc := ca.probeCert(t, id)
	writeIdentity(t, dir, pc, ca.pem())
	ident := NewIdentity(dir, nil)
	ident.reload()
	cur, changed := ident.current()
	if cur == nil || cur.clusterID != id || cur.serial != pc.serial {
		t.Fatalf("identity = %+v", cur)
	}

	// Same content: no change.
	writeIdentity(t, dir, pc, ca.pem())
	ident.reload()
	select {
	case <-changed:
		t.Fatal("rewriting the same files reported a change")
	default:
	}

	// A key that does not match, then a CA file without a certificate: the
	// last good identity stays.
	other := ca.probeCert(t, id)
	writeIdentity(t, dir, probeCert{certPEM: other.certPEM, keyPEM: pc.keyPEM}, ca.pem())
	ident.reload()
	if cur2, _ := ident.current(); cur2 != cur {
		t.Fatal("a key that does not match replaced the good identity")
	}
	writeIdentity(t, dir, pc, []byte("not a pem"))
	ident.reload()
	if cur2, _ := ident.current(); cur2 != cur {
		t.Fatal("a broken identity replaced the good one")
	}
	select {
	case <-changed:
		t.Fatal("a broken identity reported a change")
	default:
	}
}

func TestParseIdentityWantsProbeCN(t *testing.T) {
	ca := newTestCA(t)
	pc := ca.probeCert(t, "not-a-uuid")
	if _, err := parseIdentity(pc.certPEM, pc.keyPEM, ca.pem()); err == nil {
		t.Fatal("a CN that is not <uuid>/probe was accepted")
	}
	srv := ca.leaf(t, []string{"agent.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	kd, _ := x509.MarshalPKCS8PrivateKey(srv.PrivateKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	if _, err := parseIdentity(certPEM, keyPEM, ca.pem()); err == nil {
		t.Fatal("a certificate without the probe CN was accepted")
	}
}

func TestServeHealth(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	lis.Close()
	var ready atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServeHealth(ctx, addr, ready.Load, nil) }()
	get := func(path string) int {
		for range 100 {
			resp, err := http.Get("http://" + addr + path)
			if err == nil {
				resp.Body.Close()
				return resp.StatusCode
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("health endpoint not up")
		return 0
	}
	if c := get("/healthz"); c != http.StatusOK {
		t.Fatalf("/healthz = %d", c)
	}
	if c := get("/readyz"); c != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before connecting = %d", c)
	}
	ready.Store(true)
	if c := get("/readyz"); c != http.StatusOK {
		t.Fatalf("/readyz connected = %d", c)
	}
	if err := ServeHealth(ctx, "0.0.0.0:8082", ready.Load, nil); err == nil {
		t.Fatal("a non-localhost health address was accepted")
	}
}

func TestConfigFromEnv(t *testing.T) {
	for _, k := range []string{"OLYMPOS_SERVER_NAME", "OLYMPOS_PROBE_IDENTITY_DIR", "OLYMPOS_PROBE_MAX_CONCURRENCY",
		"OLYMPOS_HEALTH_ADDR", "KUBERNETES_SERVICE_HOST"} {
		t.Setenv(k, "")
	}
	t.Setenv("OLYMPOS_SERVER", "olympos.example.com:8443")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerName != "olympos.example.com" || c.IdentityDir != DefaultIdentityDir || c.MaxConcurrency != 20 ||
		c.HealthAddr != "127.0.0.1:8082" || len(c.APIServer) != 0 {
		t.Fatalf("defaults = %+v", c)
	}

	t.Setenv("OLYMPOS_SERVER_NAME", "gw.example.com")
	t.Setenv("OLYMPOS_PROBE_IDENTITY_DIR", "/id")
	t.Setenv("OLYMPOS_PROBE_MAX_CONCURRENCY", "5")
	t.Setenv("OLYMPOS_HEALTH_ADDR", "[::1]:9000")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	c, err = ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerName != "gw.example.com" || c.IdentityDir != "/id" || c.MaxConcurrency != 5 || c.HealthAddr != "[::1]:9000" ||
		len(c.APIServer) != 1 || c.APIServer[0].String() != "10.96.0.1" {
		t.Fatalf("config = %+v", c)
	}

	for k, v := range map[string]string{
		"OLYMPOS_HEALTH_ADDR":           "0.0.0.0:8082",
		"OLYMPOS_PROBE_MAX_CONCURRENCY": "0",
		"KUBERNETES_SERVICE_HOST":       "kubernetes.default",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("%s=%s accepted", k, v)
			}
		})
	}
	t.Setenv("OLYMPOS_SERVER", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("missing OLYMPOS_SERVER accepted")
	}
}
