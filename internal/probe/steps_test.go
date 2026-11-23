package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func tlsStepOf(host string, port int, sni string, as ...spec.Assertion) spec.Step {
	return spec.Step{Kind: spec.KindTLS, TLS: &spec.TLSSpec{Host: host, Port: port, SNI: sni}, Assertions: as}
}

func tcpStepOf(host string, port int, as ...spec.Assertion) spec.Step {
	return spec.Step{Kind: spec.KindTCP, TCP: &spec.TCPSpec{Host: host, Port: port}, Assertions: as}
}

func dnsStepOf(name, rtype string, as ...spec.Assertion) spec.Step {
	return spec.Step{Kind: spec.KindDNS, DNS: &spec.DNSSpec{Name: name, RecordType: rtype}, Assertions: as}
}

func TestTLSStep(t *testing.T) {
	now := time.Now()
	e := newEnv(t)
	valid := e.ca.leaf(t, []string{"api.example.test"}, now.Add(-time.Hour), now.Add(30*24*time.Hour+time.Hour))
	expired := e.ca.leaf(t, []string{"old.example.test"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour-time.Hour))
	wrongName := e.ca.leaf(t, []string{"other.example.test"}, now.Add(-time.Hour), now.Add(10*24*time.Hour))
	unknownCA := newTestCA(t).leaf(t, []string{"rogue.example.test"}, now.Add(-time.Hour), now.Add(10*24*time.Hour))

	e.host("api.example.test", "203.0.113.10", tlsServer(t, valid, 0, nil))
	e.host("tls12.example.test", "203.0.113.11", tlsServer(t, e.ca.leaf(t, []string{"tls12.example.test"}, now.Add(-time.Hour), now.Add(24*time.Hour)), tls.VersionTLS12, nil))
	e.host("old.example.test", "203.0.113.12", tlsServer(t, expired, 0, nil))
	e.host("wrong.example.test", "203.0.113.13", tlsServer(t, wrongName, 0, nil))
	e.host("rogue.example.test", "203.0.113.14", tlsServer(t, unknownCA, 0, nil))

	for name, tc := range map[string]struct {
		step spec.Step
		pass bool
	}{
		"valid": {tlsStepOf("api.example.test", 443, "",
			assertion(spec.SubjectTLSDaysLeft, spec.OpGreaterThan, "29"),
			assertion(spec.SubjectTLSDaysLeft, spec.OpLessThan, "31"),
			assertion(spec.SubjectChainValid, spec.OpEquals, "true"),
			assertion(spec.SubjectHostnameMatches, spec.OpEquals, "true"),
			assertion(spec.SubjectTLSVersion, spec.OpEquals, "1.3")), true},
		"valid defaults":  {tlsStepOf("api.example.test", 443, ""), true},
		"min version ok":  {tlsStepOf("tls12.example.test", 443, "", assertion(spec.SubjectTLSVersion, spec.OpGreaterThan, "1.1")), true},
		"min version low": {tlsStepOf("tls12.example.test", 443, "", assertion(spec.SubjectTLSVersion, spec.OpGreaterThan, "1.2")), false},
		"expired": {tlsStepOf("old.example.test", 443, "",
			assertion(spec.SubjectChainValid, spec.OpEquals, "false"),
			assertion(spec.SubjectHostnameMatches, spec.OpEquals, "true"),
			assertion(spec.SubjectTLSDaysLeft, spec.OpLessThan, "0")), true},
		"expired defaults": {tlsStepOf("old.example.test", 443, ""), false},
		"wrong name": {tlsStepOf("wrong.example.test", 443, "",
			assertion(spec.SubjectChainValid, spec.OpEquals, "true"),
			assertion(spec.SubjectHostnameMatches, spec.OpEquals, "false")), true},
		"wrong name defaults": {tlsStepOf("wrong.example.test", 443, ""), false},
		"sni picks the name": {tlsStepOf("wrong.example.test", 443, "other.example.test",
			assertion(spec.SubjectHostnameMatches, spec.OpEquals, "true")), true},
		"unknown CA": {tlsStepOf("rogue.example.test", 443, "",
			assertion(spec.SubjectChainValid, spec.OpEquals, "false"),
			assertion(spec.SubjectHostnameMatches, spec.OpEquals, "true")), true},
	} {
		t.Run(name, func(t *testing.T) {
			res := e.run(scenario(tc.step))
			if tc.pass {
				wantPassed(t, res)
			} else {
				wantCode(t, res, 0, CodeAssertionFailed)
			}
			if st := res.Steps[0]; st.Timings.TlsUs <= 0 || st.RemoteIp == "" || len(st.ResponseExcerpt) == 0 {
				t.Fatalf("step result %v", st)
			}
		})
	}

	// The SNI name must be on the allowlist too.
	res := e.run(scenario(tlsStepOf("api.example.test", 443, "evil.example.org")))
	wantCode(t, res, 0, CodeHostNotAllowed)

	// Not TLS at all: a tls_error.
	plain := server(t, http.NotFoundHandler())
	e.host("plain.example.test", "203.0.113.15", plain)
	wantCode(t, e.run(scenario(tlsStepOf("plain.example.test", 443, ""))), 0, CodeTLSError)
}

func TestDNSStep(t *testing.T) {
	e := newEnv(t)
	e.res.records["svc.example.test."] = map[string][]string{
		"A":   {"192.0.2.1", "192.0.2.2"},
		"TXT": {"v=spf1 -all"},
	}
	ok := []spec.Step{
		dnsStepOf("svc.example.test", "A",
			assertion(spec.SubjectRecordCount, spec.OpEquals, "2"),
			assertion(spec.SubjectRecord, spec.OpContains, "192.0.2.2"),
			assertion(spec.SubjectRecord, spec.OpEquals, "192.0.2.1"),
			assertion(spec.SubjectLatencyMS, spec.OpLessThan, "5000")),
		dnsStepOf("SVC.example.test.", "TXT", assertion(spec.SubjectRecord, spec.OpMatches, `^v=spf1`)),
		dnsStepOf("missing.example.test", "A", assertion(spec.SubjectRecordCount, spec.OpEquals, "0")),
		dnsStepOf("svc.example.test", "AAAA"),
	}
	res := e.run(scenario(ok...))
	if res.Steps[3].Status != StatusFailed || res.Steps[0].Status != StatusPassed || res.Steps[1].Status != StatusPassed || res.Steps[2].Status != StatusPassed {
		t.Fatalf("statuses: %v", res.Steps)
	}
	if got := res.Steps[0].Assertions[0].Actual; got != "2" {
		t.Fatalf("record_count actual %q", got)
	}
	for _, n := range e.res.asked {
		if n != "svc.example.test." && n != "missing.example.test." {
			t.Fatalf("asked %q", n)
		}
	}
	wantCode(t, e.run(scenario(dnsStepOf("svc.example.org", "A"))), 0, CodeHostNotAllowed)
	wantCode(t, e.run(scenario(dnsStepOf("fail.example.test", "A"))), 0, CodeDNSError)
	wantCode(t, e.run(scenario(dnsStepOf("svc.example.test", "A", assertion(spec.SubjectRecord, spec.OpContains, "203.")))), 0, CodeAssertionFailed)
}

func TestTCPStep(t *testing.T) {
	e := newEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	e.res.set("db.example.test.", ips("203.0.113.50"))
	e.net.route("203.0.113.50", ln.Addr().String())
	e.res.set("closed.example.test.", ips("203.0.113.51")) // no route: refused

	wantPassed(t, e.run(scenario(tcpStepOf("db.example.test", 5432,
		assertion(spec.SubjectConnects, spec.OpEquals, "true"),
		assertion(spec.SubjectLatencyMS, spec.OpLessThan, "5000")))))
	wantPassed(t, e.run(scenario(tcpStepOf("db.example.test", 5432))))
	if d := e.net.dialedAddrs(); d[0] != "203.0.113.50:5432" {
		t.Fatalf("dialed %v", d)
	}
	wantPassed(t, e.run(scenario(tcpStepOf("closed.example.test", 1, assertion(spec.SubjectConnects, spec.OpEquals, "false")))))
	wantCode(t, e.run(scenario(tcpStepOf("closed.example.test", 1))), 0, CodeConnectError)
	wantCode(t, e.run(scenario(tcpStepOf("closed.example.test", 1, assertion(spec.SubjectConnects, spec.OpEquals, "true")))), 0, CodeAssertionFailed)
	// A denied answer is an error even when the step expects no connection.
	e.res.set("meta.example.test.", ips("169.254.169.254"))
	wantCode(t, e.run(scenario(tcpStepOf("meta.example.test", 80, assertion(spec.SubjectConnects, spec.OpEquals, "false")))), 0, CodeIPDenied)
}

func TestStepRetries(t *testing.T) {
	for _, tc := range []struct {
		retries, failFirst int
		wantHits           int32
		pass               bool
	}{
		{retries: 2, failFirst: 2, wantHits: 3, pass: true},
		{retries: 1, failFirst: 2, wantHits: 2, pass: false},
		{retries: 0, failFirst: 0, wantHits: 1, pass: true},
		{retries: 9, failFirst: 5, wantHits: 3, pass: false}, // capped at MaxStepRetries
	} {
		e := newEnv(t)
		var hits atomic.Int32
		e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if int(hits.Add(1)) <= tc.failFirst {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		})))
		s := scenario(httpStep("http://api.example.test/", assertion(spec.SubjectStatusCode, spec.OpEquals, "200")))
		s.StepRetries = tc.retries
		res := e.run(s)
		if (res.Status == StatusPassed) != tc.pass || hits.Load() != tc.wantHits {
			t.Fatalf("%+v: status %s, hits %d", tc, res.Status, hits.Load())
		}
	}

	// Policy errors are not retried.
	e := newEnv(t)
	s := scenario(httpStep("http://api.example.org/"))
	s.StepRetries = 2
	wantCode(t, e.run(s), 0, CodeHostNotAllowed)
	e.res.set("meta.example.test.", ips("169.254.169.254"))
	s = scenario(httpStep("http://meta.example.test/"))
	s.StepRetries = 2
	wantCode(t, e.run(s), 0, CodeIPDenied)
	if n := e.res.callCount("meta.example.test."); n != 1 {
		t.Fatalf("denied name resolved %d times", n)
	}
	// Connection errors are.
	e.res.set("down.example.test.", ips("203.0.113.99"))
	s = scenario(httpStep("http://down.example.test/"))
	s.StepRetries = 2
	wantCode(t, e.run(s), 0, CodeConnectError)
	if n := len(e.net.dialedAddrs()); n != 3 {
		t.Fatalf("dialed %d times", n)
	}
}

// The flow stops at the first step that does not pass; the rest are
// skipped, and failed_step names it (position 0 included).
func TestFlowStopsAtFirstFailure(t *testing.T) {
	e := newEnv(t)
	var third atomic.Int32
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		case "/third":
			third.Add(1)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})))
	res := e.run(scenario(
		httpStep("http://api.example.test/ok"),
		httpStep("http://api.example.test/bad", assertion(spec.SubjectStatusCode, spec.OpEquals, "200")),
		httpStep("http://api.example.test/third"),
	))
	wantCode(t, res, 1, CodeAssertionFailed)
	if res.Status != StatusFailed || len(res.Steps) != 3 || res.Steps[0].Status != StatusPassed ||
		res.Steps[1].Status != StatusFailed || res.Steps[2].Status != StatusSkipped || third.Load() != 0 {
		t.Fatalf("result %v", res)
	}
	if !strings.Contains(res.FailureReason, "status_code equals 200") || res.Steps[1].Error == "" {
		t.Fatalf("reason %q, step error %q", res.FailureReason, res.Steps[1].Error)
	}

	res = e.run(scenario(httpStep("http://evil.example.org/"), httpStep("http://api.example.test/ok")))
	wantCode(t, res, 0, CodeHostNotAllowed)
	if res.Status != StatusError || res.Steps[1].Status != StatusSkipped {
		t.Fatalf("result %v", res)
	}
	if res.StartedUnixMs == 0 || res.FinishedUnixMs < res.StartedUnixMs {
		t.Fatalf("times %d %d", res.StartedUnixMs, res.FinishedUnixMs)
	}
}

func TestRunTimeout(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	e.host("slow.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})))
	s := scenario(httpStep("http://slow.example.test/"), httpStep("http://slow.example.test/"))
	s.TimeoutSeconds = 1
	s.StepRetries = 2
	start := time.Now()
	res := e.run(s)
	wantCode(t, res, 0, CodeTimeout)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
	if res.Steps[1].Status != StatusSkipped {
		t.Fatalf("second step %s", res.Steps[1].Status)
	}
}

// A value extracted by a later step is scrubbed from an earlier step's
// excerpt too, including a first half left where the excerpt was cut.
func TestLaterExtractScrubbedFromEarlierExcerpt(t *testing.T) {
	const late = "LATEVALUE-0123456789"
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/one" {
			// The value repeats past the excerpt limit, so the cut lands
			// inside one of them for some padding.
			w.Header().Set("Content-Type", "text/plain")
			pad := len(r.URL.Query().Get("pad"))
			fmt.Fprintf(w, "%s%s", strings.Repeat("p", pad), strings.Repeat(late+" ", 200))
			return
		}
		fmt.Fprintf(w, `{"v":%q}`, late)
	})))
	// value + space has period 21, so the 21 paddings put the cut at
	// every offset inside the value once.
	for pad := 0; pad <= len(late); pad++ {
		one := httpStep("http://api.example.test/one?pad=" + strings.Repeat("x", pad))
		two := httpStep("http://api.example.test/two")
		two.Extracts = []spec.Extract{{Name: "v", Source: spec.SourceJSONPath, Expr: "v"}}
		res := e.run(scenario(one, two))
		wantPassed(t, res)
		for _, st := range res.Steps {
			ex := string(st.ResponseExcerpt)
			if strings.Contains(ex, late) {
				t.Fatalf("pad %d: step %d excerpt keeps the value", pad, st.Position)
			}
			for i := 1; i < len(late); i++ {
				if strings.HasSuffix(ex, late[:i]) {
					t.Fatalf("pad %d: step %d excerpt ends with %q", pad, st.Position, late[:i])
				}
			}
		}
		if ex := res.Steps[0].ResponseExcerpt; !strings.HasSuffix(string(ex), " ") && !strings.HasSuffix(string(ex), "]") {
			t.Fatalf("pad %d: excerpt ends %q", pad, ex[len(ex)-20:])
		}
	}
}

func TestTrimLiteralTail(t *testing.T) {
	lits := [][]byte{[]byte("SECRETVALUE"), []byte("zz")}
	for in, want := range map[string]string{
		"abc SECR":   "abc ",
		"abc SECRET": "abc ",
		"abc S":      "abc ",
		"abc z":      "abc ",
		"abc ":       "abc ",
		"SECRETVAL":  "",
		"abc SEX":    "abc SEX",
	} {
		if got := string(trimLiteralTail([]byte(in), lits)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := cutUTF8([]byte("aé"), 2); string(got) != "a" {
		t.Errorf("cutUTF8 split a rune: %q", got)
	}
}

func TestInvalidStepAndNilScenario(t *testing.T) {
	e := newEnv(t)
	res := e.run(scenario(spec.Step{Kind: spec.KindHTTP}))
	wantCode(t, res, 0, CodeInvalidRequest)
	res = e.runner.Run(context.Background(), nil, nil)
	if res.Status != StatusError {
		t.Fatalf("nil scenario: %v", res)
	}
}

// The allowlist must not be bypassed through odd host spellings.
func TestHostSpellings(t *testing.T) {
	e := newEnv(t, hostallow.Rule{Pattern: "api.example.test", Kind: hostallow.Exact})
	e.res.set("api.example.test.", ips("203.0.113.10"))
	for _, h := range []string{"api.example.test.evil.io", "api.example.test@evil.io", "evil.io#api.example.test"} {
		if _, err := e.dialer.Resolve(context.Background(), h); codeOf(err) != CodeHostNotAllowed {
			t.Errorf("%q: %v", h, err)
		}
	}
	if a, err := e.dialer.Resolve(context.Background(), "API.example.test."); err != nil || a[0] != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("trailing dot: %v %v", a, err)
	}
}
