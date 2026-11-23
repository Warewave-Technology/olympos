package probe

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

const leakCanary = "CANARYtoken1234567890"

// resultHolds reports whether the marshalled result holds s.
func resultHolds(t *testing.T, res proto.Message, s string) bool {
	t.Helper()
	wire, _ := proto.Marshal(res)
	text, _ := protojson.Marshal(res)
	return bytes.Contains(wire, []byte(s)) || bytes.Contains(text, []byte(s))
}

// A bound host that echoes the credential cannot hand it to an extract:
// the extract fails with credential_error, the variable is not kept, and
// the next step (to an unbound host) never runs.
func TestExtractCannotCaptureCredential(t *testing.T) {
	for name, ex := range map[string]spec.Extract{
		"header":         {Name: "tok", Source: spec.SourceHeader, Expr: "X-Echo"},
		"regex":          {Name: "tok", Source: spec.SourceRegex, Expr: `Bearer (\S+)`},
		"json base64":    {Name: "tok", Source: spec.SourceJSONPath, Expr: "b64"},
		"json lowercase": {Name: "tok", Source: spec.SourceJSONPath, Expr: "lower"},
		"json piece":     {Name: "tok", Source: spec.SourceJSONPath, Expr: "piece"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				tok := strings.TrimPrefix(auth, "Bearer ")
				w.Header().Set("X-Echo", auth)
				fmt.Fprintf(w, `{"b64":%q,"lower":%q,"piece":%q,"note":"you are %s here"}`,
					base64.StdEncoding.EncodeToString([]byte(tok)), strings.ToLower(tok), tok[3:15], auth)
			})))
			b := &headerRecorder{}
			e.host("b.example.test", "203.0.113.2", server(t, b))
			cred := bearer(leakCanary, "exact:a.example.test")
			s1 := withCred(httpStep("http://a.example.test/"), cred)
			s1.Extracts = []spec.Extract{ex}
			s2 := httpStep("http://b.example.test/?q=${tok}")
			s2.HTTP.Headers = map[string]string{"X-Leak": "${tok}"}
			res := e.run(scenario(s1, s2), cred)
			wantCode(t, res, 0, CodeCredentialError)
			if !strings.Contains(res.FailureReason, "extract tok") || len(res.Steps[0].ExtractedNames) != 0 {
				t.Fatalf("reason %q, names %v", res.FailureReason, res.Steps[0].ExtractedNames)
			}
			if len(b.requests()) != 0 || res.Steps[1].Status != StatusSkipped {
				t.Fatal("the unbound host was called")
			}
			if resultHolds(t, res, leakCanary) || resultHolds(t, res, strings.ToLower(leakCanary)) {
				t.Fatal("the result holds the credential")
			}
		})
	}
}

// Before every request and redirect hop, a request that would carry a
// credential to a host outside its bound hosts is refused: in the query,
// in the host name (never resolved), or in a header or body.
func TestRequestCarryingCredentialRefused(t *testing.T) {
	for name, loc := range map[string]func(tok string) string{
		"query": func(tok string) string { return "http://b.example.test/?t=" + url.QueryEscape(tok) },
		"path":  func(tok string) string { return "http://b.example.test/" + tok },
		"host":  func(tok string) string { return "http://" + tok + ".example.test/" },
		"basic b64": func(tok string) string {
			return "http://b.example.test/?x=" + base64.StdEncoding.EncodeToString([]byte("Bearer "+tok))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, loc(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), http.StatusFound)
			})))
			b := &headerRecorder{}
			e.host("b.example.test", "203.0.113.2", server(t, b))
			cred := bearer(leakCanary, "exact:a.example.test")
			res := e.run(scenario(withCred(httpStep("http://a.example.test/"), cred)), cred)
			wantCode(t, res, 0, CodeCredentialError)
			if len(b.requests()) != 0 {
				t.Fatal("the unbound host was called")
			}
			for _, n := range e.res.asked {
				if strings.Contains(strings.ToLower(n), strings.ToLower(leakCanary)) {
					t.Fatalf("the credential was sent to the resolver: %q", n)
				}
			}
			if resultHolds(t, res, leakCanary) || resultHolds(t, res, strings.ToLower(leakCanary)) {
				t.Fatal("the result holds the credential")
			}
		})
	}

	// The check itself, on headers and bodies, for a credential of the run
	// that the step does not even use.
	e := newEnv(t)
	cs := newCredSet([]spec.RunCredential{bearer(leakCanary, "exact:a.example.test")})
	defer cs.close()
	for _, tc := range []struct {
		host, header, body string
		refused            bool
	}{
		{host: "b.example.test", header: "x " + leakCanary, refused: true},
		{host: "b.example.test", body: `{"t":"` + leakCanary + `"}`, refused: true},
		{host: "b.example.test", body: url.QueryEscape("pre " + leakCanary), refused: true},
		{host: "a.example.test", header: leakCanary, body: leakCanary, refused: false},
		{host: "b.example.test", header: "nothing", body: "nothing", refused: false},
	} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+tc.host+"/", strings.NewReader(tc.body))
		req.Header.Set("X-H", tc.header)
		err := cs.checkRequest(req)
		if (err != nil) != tc.refused || err != nil && codeOf(err) != CodeCredentialError {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	_ = e
}

// A step may not set Accept-Encoding (Go would then hand back the body
// still compressed); without it the transport decompresses and the
// excerpt is redacted. A body that stays encoded is never shown.
func TestCompressedResponses(t *testing.T) {
	e := newEnv(t)
	gz := func(w http.ResponseWriter, enc, text string) {
		w.Header().Set("Content-Encoding", enc)
		w.Header().Set("Content-Type", "text/plain")
		zw := gzip.NewWriter(w)
		_, _ = io.WriteString(zw, text)
		_ = zw.Close()
	}
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/odd":
			gz(w, "x-gzip-custom", "you sent "+auth)
		case strings.Contains(r.Header.Get("Accept-Encoding"), "gzip"):
			gz(w, "gzip", "you sent "+auth)
		default:
			fmt.Fprintf(w, "you sent %s", auth)
		}
	})))
	cred := bearer(leakCanary, "exact:a.example.test")

	st := withCred(httpStep("http://a.example.test/"), cred)
	st.HTTP.Headers = map[string]string{"Accept-Encoding": "gzip"}
	wantCode(t, e.run(scenario(st), cred), 0, CodeInvalidRequest)

	res := e.run(scenario(withCred(httpStep("http://a.example.test/", assertion(spec.SubjectBody, spec.OpContains, "you sent")), cred)), cred)
	wantPassed(t, res)
	if ex := res.Steps[0].ResponseExcerpt; !bytes.Contains(ex, []byte("you sent Bearer [redacted]")) || bytes.Contains(ex, []byte(leakCanary)) {
		t.Fatalf("decompressed excerpt %q", ex)
	}

	res = e.run(scenario(withCred(httpStep("http://a.example.test/odd", assertion(spec.SubjectBody, spec.OpLengthGreaterThan, "0")), cred)), cred)
	wantPassed(t, res)
	ex := res.Steps[0].ResponseExcerpt
	i := bytes.Index(ex, []byte("\r\n\r\n"))
	if i < 0 || string(ex[i+4:]) != encodedBody || res.Steps[0].Assertions[0].Actual != encodedBody {
		t.Fatalf("encoded body shown: %q / %q", ex, res.Steps[0].Assertions[0].Actual)
	}
}

// Sizes are checked again once the variables are substituted.
func TestSizeLimitsAfterSubstitution(t *testing.T) {
	e := newEnv(t)
	got := &headerRecorder{}
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v" {
			fmt.Fprintf(w, `{"v":%q}`, strings.Repeat("A", 8000))
			return
		}
		got.ServeHTTP(w, r)
	})))
	for name, mk := range map[string]func(*spec.Step){
		"body": func(st *spec.Step) {
			st.HTTP.Method = "POST"
			st.HTTP.Body = strings.Repeat("${v}", 4000)
		},
		"url": func(st *spec.Step) { st.HTTP.URL = "http://a.example.test/p?a=${v}&b=${v}" },
		"one header": func(st *spec.Step) {
			st.HTTP.Headers = map[string]string{"X-A": "${v}${v}"}
		},
		"all headers": func(st *spec.Step) {
			st.HTTP.Headers = map[string]string{"X-A": "${v}", "X-B": "${v}", "X-C": "${v}", "X-D": "${v}", "X-E": "${v}"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			first := httpStep("http://a.example.test/v")
			first.Extracts = []spec.Extract{{Name: "v", Source: spec.SourceJSONPath, Expr: "v"}}
			next := httpStep("http://a.example.test/post")
			mk(&next)
			wantCode(t, e.run(scenario(first, next)), 1, CodeInvalidRequest)
		})
	}
	if len(got.requests()) != 0 {
		t.Fatal("an oversized request was sent")
	}
	// Within the limits, it goes.
	first := httpStep("http://a.example.test/v")
	first.Extracts = []spec.Extract{{Name: "v", Source: spec.SourceJSONPath, Expr: "v"}}
	next := httpStep("http://a.example.test/post")
	next.HTTP.Method, next.HTTP.Body = "POST", "${v}${v}"
	next.HTTP.Headers = map[string]string{"X-A": "${v}"}
	wantPassed(t, e.run(scenario(first, next)))
}

// A credential reflected into a redirect host comes back lower-cased in
// the error text; that form is scrubbed too, and "no such host" is not
// taken for a name/value pair.
func TestLowercasedCredentialInError(t *testing.T) {
	const canary = "CanaryTOKENabcXYZ987"
	e := newEnv(t)
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.URL.Query().Get("h")+".example.test/", http.StatusFound)
	})))
	// The host is not the credential, so the leak check lets it through
	// to the resolver; the error names it.
	res := e.run(scenario(httpStep("http://a.example.test/?h=missing-host")))
	wantCode(t, res, 0, CodeDNSError)
	if strings.Contains(res.FailureReason, "[redacted] such host") || !strings.Contains(res.FailureReason, "no such host") {
		t.Fatalf("reason %q", res.FailureReason)
	}
	cred := bearer(canary, "exact:a.example.test")
	l := newCredSet([]spec.RunCredential{cred})
	defer l.close()
	msg := []byte("dns_error: " + strings.ToLower(canary) + ".example.test could not be resolved")
	if out, _ := finalize(msg, l.lits.all(), maxMessage); bytes.Contains(bytes.ToLower(out), []byte(strings.ToLower(canary))) {
		t.Fatalf("lower-cased credential kept: %q", out)
	}
}

// base64 of a longer text that contains the credential (at offsets 1 and
// 2 mod 3, as in base64("Bearer " + token)) is scrubbed.
func TestShiftedBase64Scrubbed(t *testing.T) {
	e := newEnv(t)
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(auth, "Bearer ")
		fmt.Fprintf(w, "a=%s\nb=%s\nc=%s\n",
			base64.StdEncoding.EncodeToString([]byte(auth)),
			base64.StdEncoding.EncodeToString([]byte("x"+tok+"y")),
			base64.URLEncoding.EncodeToString([]byte("xy"+tok)))
	})))
	cred := bearer(leakCanary, "exact:a.example.test")
	res := e.run(scenario(withCred(httpStep("http://a.example.test/"), cred)), cred)
	wantPassed(t, res)
	ex := res.Steps[0].ResponseExcerpt
	for _, line := range bytes.Split(ex, []byte("\n")) {
		k, v, ok := bytes.Cut(line, []byte("="))
		if !ok || len(k) != 1 {
			continue
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			if dec, err := enc.DecodeString(string(v)); err == nil && bytes.Contains(dec, []byte(leakCanary)) {
				t.Fatalf("%s: base64 of the credential kept: %q", k, line)
			}
		}
		if !bytes.Contains(v, []byte("[redacted]")) {
			t.Fatalf("%s: nothing scrubbed: %q", k, line)
		}
	}
}

// With store_responses off, header, body and JSON actual values are not
// reported either.
func TestActualsNotStored(t *testing.T) {
	e := newEnv(t)
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Info", "internal-detail")
		fmt.Fprint(w, `{"user":"alice"}`)
	})))
	s := scenario(httpStep("http://a.example.test/",
		assertion("header:X-Info", spec.OpContains, "internal"),
		assertion(spec.SubjectBody, spec.OpContains, "alice"),
		assertion("json:user", spec.OpEquals, "alice"),
		assertion(spec.SubjectStatusCode, spec.OpEquals, "200")))
	s.StoreResponses = false
	res := e.run(s)
	wantPassed(t, res)
	as := res.Steps[0].Assertions
	for i := 0; i < 3; i++ {
		if as[i].Actual != notStored {
			t.Errorf("%s actual %q", as[i].Subject, as[i].Actual)
		}
	}
	if as[3].Actual != "200" {
		t.Errorf("status actual %q", as[3].Actual)
	}
}
