package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func ips(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

// Review Focus 1: the resolver answers an allowed IP first and the
// metadata address on every later lookup. The step resolves once, as an
// absolute name, and every connection (redirect hops to the same host
// included) goes to the first answer.
func TestResolveOnceAndDialFirstIP(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	e.res.set("api.example.test.",
		ips("203.0.113.10", "203.0.113.11"),
		ips("169.254.169.254"))
	e.net.route("203.0.113.10", srv.Listener.Addr().String())

	res := e.run(scenario(httpStep("http://API.Example.Test/start", assertion(spec.SubjectStatusCode, spec.OpEquals, "200"))))
	wantPassed(t, res)
	if n := e.res.callCount("api.example.test."); n != 1 {
		t.Fatalf("lookups = %d, want 1", n)
	}
	if got := e.net.dialedAddrs(); len(got) != 2 || got[0] != "203.0.113.10:80" || got[1] != "203.0.113.10:80" {
		t.Fatalf("dialed %v", got)
	}
	if res.Steps[0].RemoteIp != "203.0.113.10" {
		t.Fatalf("remote ip %q", res.Steps[0].RemoteIp)
	}
	// The name asked is the normalized, absolute name: no search list.
	if e.res.asked[0] != "api.example.test." {
		t.Fatalf("asked %q", e.res.asked[0])
	}

	// The resolver really rebinds: a fresh resolution is refused.
	if _, err := e.dialer.Resolve(context.Background(), "api.example.test"); codeOf(err) != CodeIPDenied {
		t.Fatalf("second Resolve: %v", err)
	}
}

// DialContext dials by IP, in answer order, and never passes the name on.
func TestDialContextDialsCheckedIPs(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	e.res.set("api.example.test.", ips("203.0.113.10", "203.0.113.11"))
	e.net.route("203.0.113.11", srv.Listener.Addr().String()) // the first refuses
	c, err := e.dialer.DialContext(context.Background(), "tcp", "api.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := e.net.dialedAddrs(); !slices.Equal(got, []string{"203.0.113.10:443", "203.0.113.11:443"}) {
		t.Fatalf("dialed %v", got)
	}
	if _, err := e.dialer.DialContext(context.Background(), "udp", "api.example.test:53"); codeOf(err) != CodeConnectError {
		t.Fatalf("udp: %v", err)
	}
}

// Review Focus 1: a name with any denied answer fails whole, with
// ip_denied, and nothing is dialed.
func TestDeniedIPInAnswer(t *testing.T) {
	for name, answers := range map[string][]netip.Addr{
		"mapped metadata":  ips("203.0.113.10", "::ffff:169.254.169.254"),
		"metadata first":   ips("169.254.169.254", "203.0.113.10"),
		"loopback last":    ips("203.0.113.10", "203.0.113.11", "127.0.0.1"),
		"nat64 metadata":   ips("64:ff9b::a9fe:a9fe"),
		"aws ipv6":         ips("fd00:ec2::254"),
		"link-local v6":    ips("fe80::1"),
		"unspecified":      ips("0.0.0.0"),
		"siit loopback":    ips("::ffff:0:127.0.0.1"),
		"alibaba metadata": ips("100.100.100.200"),
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			srv := httptest.NewServer(http.NotFoundHandler())
			t.Cleanup(srv.Close)
			e.res.set("api.example.test.", answers)
			e.net.route("203.0.113.10", srv.Listener.Addr().String())
			res := e.run(scenario(httpStep("http://api.example.test/")))
			wantCode(t, res, 0, CodeIPDenied)
			if d := e.net.dialedAddrs(); len(d) != 0 {
				t.Fatalf("dialed %v", d)
			}
		})
	}

	// Names that pass Normalize but point at local or metadata addresses
	// are stopped by the answer check.
	for _, host := range []string{"metadata.google.internal", "localhost.localdomain"} {
		e := newEnv(t, hostallow.Rule{Pattern: host, Kind: hostallow.Exact})
		e.res.set(host+".", ips("169.254.169.254", "127.0.0.1"))
		if _, err := e.dialer.Resolve(context.Background(), host); codeOf(err) != CodeIPDenied {
			t.Fatalf("%s: %v", host, err)
		}
	}
}

// Review Focus 1: the Kubernetes API service address is denied, and its
// names never reach the resolver even when a rule would match them.
func TestKubernetesAPIIPDenied(t *testing.T) {
	e := newEnv(t,
		hostallow.Rule{Pattern: "example.test", Kind: hostallow.Suffix},
		hostallow.Rule{Pattern: "cluster.local", Kind: hostallow.Suffix})
	e.res.set("api.example.test.", ips("10.96.0.1"))
	_, err := e.dialer.Resolve(context.Background(), "api.example.test")
	if codeOf(err) != CodeIPDenied || !strings.Contains(err.Error(), hostallow.ReasonKubernetesAPI) {
		t.Fatalf("API service IP: %v", err)
	}
	e.res.set("api2.example.test.", ips("::ffff:10.96.0.1"))
	if _, err := e.dialer.Resolve(context.Background(), "api2.example.test"); codeOf(err) != CodeIPDenied {
		t.Fatalf("mapped API service IP: %v", err)
	}
	for _, h := range []string{"kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local", "127.1", "169.254.169.254", "[::1]", "localhost"} {
		if _, err := e.dialer.Resolve(context.Background(), h); codeOf(err) != CodeHostNotAllowed {
			t.Fatalf("%s: %v", h, err)
		}
	}
	if len(e.res.asked) != 2 {
		t.Fatalf("resolver asked %v", e.res.asked)
	}
}

func TestResolveRefusesUnlistedAndInvalid(t *testing.T) {
	e := newEnv(t)
	for _, h := range []string{"evil.example.org", "example.test.evil.io", "a b.example.test", "", "notexample.test"} {
		if _, err := e.dialer.Resolve(context.Background(), h); codeOf(err) != CodeHostNotAllowed {
			t.Fatalf("%q: %v", h, err)
		}
	}
	if _, err := e.dialer.Resolve(context.Background(), "missing.example.test"); codeOf(err) != CodeDNSError {
		t.Fatalf("missing: %v", err)
	}
	if len(e.res.asked) != 1 {
		t.Fatalf("resolver asked %v", e.res.asked)
	}
}
