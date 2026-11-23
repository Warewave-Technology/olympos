package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

var (
	detOnce sync.Once
	det     *sensitive.Detector
	detErr  error
)

func testRedactor(t testing.TB) *sensitive.Redactor {
	t.Helper()
	detOnce.Do(func() { det, detErr = sensitive.NewDetector() })
	if detErr != nil {
		t.Fatal(detErr)
	}
	return &sensitive.Redactor{D: det}
}

// fakeResolver answers from a table. Each name has a list of answers, one
// per lookup; the last one repeats. It records every name it was asked.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	records map[string]map[string][]string // name → type → records
	calls   map[string]int
	asked   []string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]netip.Addr{}, records: map[string]map[string][]string{}, calls: map[string]int{}}
}

// set gives name (absolute, with the dot) one answer per lookup.
func (f *fakeResolver) set(name string, answers ...[]netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[name] = answers
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	n := f.calls[host]
	f.calls[host]++
	as, ok := f.answers[host]
	if !ok || len(as) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if n >= len(as) {
		n = len(as) - 1
	}
	var out []netip.Addr
	for _, a := range as[n] {
		if network == "ip4" && !a.Unmap().Is4() || network == "ip6" && a.Unmap().Is4() {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeResolver) LookupRecords(_ context.Context, name, rtype string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, name)
	f.calls[name]++
	if strings.HasPrefix(name, "fail.") {
		return nil, errors.New("server failure")
	}
	return f.records[name][rtype], nil
}

func (f *fakeResolver) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

// fakeNet maps the IPs the dialer connects to onto local listeners, and
// records every address dialed.
type fakeNet struct {
	mu     sync.Mutex
	routes map[netip.Addr]string
	dialed []string
}

func newFakeNet() *fakeNet { return &fakeNet{routes: map[netip.Addr]string{}} }

func (n *fakeNet) route(ip string, to string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes[netip.MustParseAddr(ip)] = to
}

func (n *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, errors.New("fakeNet: dialed a name, not an address: " + addr)
	}
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	to, ok := n.routes[ap.Addr()]
	n.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, to)
}

func (n *fakeNet) dialedAddrs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dialed...)
}

// env is a runner with a fake resolver and network.
type env struct {
	t      *testing.T
	res    *fakeResolver
	net    *fakeNet
	dialer *Dialer
	runner *Runner
	ca     *testCA
}

func newEnv(t *testing.T, rules ...hostallow.Rule) *env {
	t.Helper()
	if len(rules) == 0 {
		rules = []hostallow.Rule{{Pattern: "example.test", Kind: hostallow.Suffix}}
	}
	e := &env{t: t, res: newFakeResolver(), net: newFakeNet(), ca: newTestCA(t)}
	e.dialer = &Dialer{
		Allow:     hostallow.List{Version: 7, Rules: rules},
		Resolver:  e.res,
		APIServer: []netip.Addr{netip.MustParseAddr("10.96.0.1")},
		Net:       e.net.dial,
	}
	e.runner = &Runner{Dialer: e.dialer, Redactor: testRedactor(t), rootCAs: e.ca.pool}
	return e
}

// host makes name resolve to ip and routes ip to srv.
func (e *env) host(name, ip string, srv *httptest.Server) {
	e.res.set(name+".", []netip.Addr{netip.MustParseAddr(ip)})
	if srv != nil {
		e.net.route(ip, srv.Listener.Addr().String())
	}
}

func (e *env) run(s *spec.Scenario, creds ...spec.RunCredential) *pb.RunResult {
	e.t.Helper()
	return e.runner.Run(context.Background(), s, creds)
}

// scenario wraps steps into a valid scenario; positions are set.
func scenario(steps ...spec.Step) *spec.Scenario {
	for i := range steps {
		steps[i].Position = i
	}
	typ := spec.TypeHTTPFlow
	return &spec.Scenario{
		ID: uuid.NewString(), Name: "t", Type: typ, IntervalSeconds: 60, TimeoutSeconds: 30,
		StoreResponses: true, Steps: steps,
	}
}

func httpStep(url string, as ...spec.Assertion) spec.Step {
	return spec.Step{Kind: spec.KindHTTP, HTTP: &spec.HTTPSpec{Method: "GET", URL: url, FollowRedirects: true}, Assertions: as}
}

func assertion(subject, op, value string) spec.Assertion {
	return spec.Assertion{Subject: subject, Operator: op, Value: value}
}

func secret(s string) *spec.Secret { return spec.NewSecret([]byte(s)) }

// bearer is a bearer credential; bound are hostallow.FormatRule strings.
func bearer(token string, bound ...string) spec.RunCredential {
	return spec.RunCredential{ID: uuid.New(), Kind: spec.CredBearer, BoundHosts: bound, Secret: secret(token)}
}

func withCred(st spec.Step, c spec.RunCredential) spec.Step {
	id := c.ID
	st.CredentialID = &id
	return st
}

// wantCode checks the run failed at step pos with code.
func wantCode(t *testing.T, res *pb.RunResult, pos int32, code string) {
	t.Helper()
	if res.Status == StatusPassed || res.FailedStep != pos || !strings.HasPrefix(res.FailureReason, code+": ") {
		t.Fatalf("want step %d to fail with %s, got status %s step %d reason %q", pos, code, res.Status, res.FailedStep, res.FailureReason)
	}
}

func wantPassed(t *testing.T, res *pb.RunResult) {
	t.Helper()
	if res.Status != StatusPassed {
		var details []string
		for _, s := range res.Steps {
			for _, a := range s.Assertions {
				if !a.Passed {
					details = append(details, a.Subject+" "+a.Operator+" "+a.Expected+" (actual "+a.Actual+")")
				}
			}
		}
		t.Fatalf("run %s: %q %v", res.Status, res.FailureReason, details)
	}
}

// headerRecorder is a handler that records the request headers.
type headerRecorder struct {
	mu   sync.Mutex
	reqs []*http.Request
	h    http.HandlerFunc
}

func (h *headerRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.reqs = append(h.reqs, r.Clone(context.Background()))
	h.mu.Unlock()
	if h.h != nil {
		h.h(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *headerRecorder) requests() []*http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*http.Request(nil), h.reqs...)
}

// testCA issues certificates for TLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t testing.TB) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leaf issues a server certificate for names, valid from notBefore to
// notAfter.
func (ca *testCA) leaf(t testing.TB, names []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer starts an HTTPS test server with cert.
func tlsServer(t *testing.T, cert tls.Certificate, maxVersion uint16, h http.Handler) *httptest.Server {
	t.Helper()
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVersion}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}
