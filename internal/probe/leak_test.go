package probe

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
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
			if !strings.Contains(res.FailureReason, "echoes a credential, so no extract is kept (tok)") || len(res.Steps[0].ExtractedNames) != 0 {
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

// fragExtracts takes n pieces of size bytes each of the echoed bearer
// token, as an attacker would to get past a check on whole values.
func fragExtracts(n, size int) []spec.Extract {
	var ex []spec.Extract
	for i := 0; i < n; i++ {
		ex = append(ex, spec.Extract{Name: fmt.Sprintf("p%d", i), Source: spec.SourceRegex, Expr: fmt.Sprintf(`Bearer .{%d}(.{%d})`, i*size, size)})
	}
	return ex
}

func joinRefs(n int, sep string) string {
	var parts []string
	for i := 0; i < n; i++ {
		parts = append(parts, fmt.Sprintf("${p%d}", i))
	}
	return strings.Join(parts, sep)
}

// Ruling P10: a response that echoes a credential gives no extracts, so no
// piece of it, however small and in whatever order, reaches another host
// or comes back into the result through the echo host.
func TestEchoedCredentialGivesNoExtracts(t *testing.T) {
	echo := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "you are %s; frag=%s", r.Header.Get("Authorization"), r.Header.Get("X-Frag"))
		})
	}
	cases := map[string]func(e *env, cred spec.RunCredential) (spec.Step, spec.Step){
		"7-byte pieces to an unbound host": func(e *env, cred spec.RunCredential) (spec.Step, spec.Step) {
			s1 := withCred(httpStep("http://a.example.test/"), cred)
			s1.Extracts = fragExtracts(3, 7)
			s2 := httpStep("http://b.example.test/")
			s2.HTTP.Headers = map[string]string{"X-Leak": joinRefs(3, "-")}
			return s1, s2
		},
		"pieces reversed in a path": func(e *env, cred spec.RunCredential) (spec.Step, spec.Step) {
			s1 := withCred(httpStep("http://a.example.test/"), cred)
			s1.Extracts = fragExtracts(3, 7)
			return s1, httpStep("http://b.example.test/${p2}${p1}${p0}")
		},
		"3-byte pieces back to the echo host": func(e *env, cred spec.RunCredential) (spec.Step, spec.Step) {
			s1 := withCred(httpStep("http://a.example.test/"), cred)
			s1.Extracts = fragExtracts(7, 3)
			s2 := withCred(httpStep("http://a.example.test/"), cred)
			s2.HTTP.Headers = map[string]string{"X-Frag": joinRefs(7, ".")}
			return s1, s2
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			a := &headerRecorder{h: echo().ServeHTTP}
			e.host("a.example.test", "203.0.113.1", server(t, a))
			b := &headerRecorder{}
			e.host("b.example.test", "203.0.113.2", server(t, b))
			cred := bearer(leakCanary, "exact:a.example.test")
			s1, s2 := mk(e, cred)
			res := e.run(scenario(s1, s2), cred)
			wantCode(t, res, 0, CodeCredentialError)
			if len(b.requests()) != 0 || len(a.requests()) != 1 || res.Steps[1].Status != StatusSkipped {
				t.Fatalf("a second request was sent")
			}
			if len(res.Steps[0].ExtractedNames) != 0 {
				t.Fatalf("names %v", res.Steps[0].ExtractedNames)
			}
		})
	}

	// The OAuth2 access token, once fetched, counts as a credential too.
	t.Run("OAuth2 token pieces", func(t *testing.T) {
		e := newEnv(t)
		now := time.Now()
		e.host("token.example.test", "203.0.113.40", tlsServer(t, e.ca.leaf(t, []string{"token.example.test"}, now.Add(-time.Hour), now.Add(time.Hour)), 0,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"access_token":"CANARY-oauth-access-token","token_type":"Bearer"}`)
			})))
		e.host("api.example.test", "203.0.113.10", server(t, echo()))
		b := &headerRecorder{}
		e.host("b.example.test", "203.0.113.2", server(t, b))
		cred := spec.RunCredential{ID: uuid.New(), Kind: spec.CredOAuth2, BoundHosts: []string{"exact:api.example.test", "exact:token.example.test"},
			Username: secret("client-1"), Secret: secret("CANARY-client-secret"), TokenURL: "https://token.example.test/oauth/token"}
		s1 := withCred(httpStep("http://api.example.test/a"), cred)
		s1.Extracts = fragExtracts(3, 7)
		s2 := httpStep("http://b.example.test/")
		s2.HTTP.Headers = map[string]string{"X-Leak": joinRefs(3, "-")}
		wantCode(t, e.run(scenario(s1, s2), cred), 0, CodeCredentialError)
		if len(b.requests()) != 0 {
			t.Fatal("the unbound host was called")
		}
	})

	// Echoes in lower-case percent-encoding are detected too.
	t.Run("lower-hex percent echo", func(t *testing.T) {
		const tok = "CANARY/tok+en=value"
		e := newEnv(t)
		e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Keep the letters as they are, lower only the hex digits.
			v := url.QueryEscape(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			v = strings.NewReplacer("%2F", "%2f", "%2B", "%2b", "%3D", "%3d").Replace(v)
			fmt.Fprintf(w, `{"echo":%q,"id":"order-1"}`, v)
		})))
		cred := bearer(tok, "exact:a.example.test")
		s1 := withCred(httpStep("http://a.example.test/"), cred)
		s1.Extracts = []spec.Extract{{Name: "id", Source: spec.SourceJSONPath, Expr: "id"}}
		wantCode(t, e.run(scenario(s1), cred), 0, CodeCredentialError)
	})

	// A value that only decoding reveals (a JSON \u escape) is refused by
	// the value check behind the echo check.
	t.Run("decoded value", func(t *testing.T) {
		e := newEnv(t)
		e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"t":"C%s"}`, leakCanary[1:])
		})))
		cred := bearer(leakCanary, "exact:a.example.test")
		s1 := withCred(httpStep("http://a.example.test/"), cred)
		s1.Extracts = []spec.Extract{{Name: "t", Source: spec.SourceJSONPath, Expr: "t"}}
		res := e.run(scenario(s1), cred)
		wantCode(t, res, 0, CodeCredentialError)
		if len(res.Steps[0].ExtractedNames) != 0 {
			t.Fatalf("names %v", res.Steps[0].ExtractedNames)
		}
	})
}

// The basic user name and the OAuth2 client id are not secrets: they are
// scrubbed from reports but do not trip the leak checks. Nor does an
// extracted id that happens to be part of a structured token.
func TestNonSecretsDoNotTripLeakChecks(t *testing.T) {
	e := newEnv(t)
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		fmt.Fprintf(w, `{"user":%q,"id":"order-12345678"}`, u)
	})))
	status := &headerRecorder{}
	e.host("status.example.test", "203.0.113.2", server(t, status))
	basic := spec.RunCredential{ID: uuid.New(), Kind: spec.CredBasic, BoundHosts: []string{"exact:a.example.test"},
		Username: secret("monitoring"), Secret: secret("S3cretPassw0rd!")}

	// An ordinary URL that contains the user name, to another host.
	wantPassed(t, e.run(scenario(withCred(httpStep("http://a.example.test/me"), basic), httpStep("http://status.example.test/monitoring/health")), basic))
	if len(status.requests()) != 1 {
		t.Fatal("the status host was not called")
	}
	// Extracting the user name, and using it (on the bound host: a
	// variable from a credentialed step stays there, P11).
	s1 := withCred(httpStep("http://a.example.test/me"), basic)
	s1.Extracts = []spec.Extract{{Name: "u", Source: spec.SourceJSONPath, Expr: "user"}}
	res := e.run(scenario(s1, httpStep("http://a.example.test/${u}")), basic)
	wantPassed(t, res)
	if resultHolds(t, res, "monitoring") {
		t.Fatal("the user name is not scrubbed from the result")
	}
	// An id that is a substring of a bearer token the response does not
	// echo.
	tok := bearer("tok_order-12345678_live", "exact:a.example.test")
	s1 = withCred(httpStep("http://a.example.test/me"), tok)
	s1.Extracts = []spec.Extract{{Name: "id", Source: spec.SourceJSONPath, Expr: "id"}}
	wantPassed(t, e.run(scenario(s1), tok))
}

// A body that is not UTF-8 (compressed without a Content-Encoding header,
// or any binary) is shown only as its size, in the excerpt and in body
// actual values.
func TestBinaryBodyNotShown(t *testing.T) {
	gzipped := func(s string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(s))
		_ = zw.Close()
		return buf.Bytes()
	}
	for _, enc := range []string{"", "identity, gzip", "GZIP", "x-gzip", "gzip, identity"} {
		t.Run("encoding "+enc, func(t *testing.T) {
			e := newEnv(t)
			var n int
			e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if enc != "" {
					w.Header().Set("Content-Encoding", enc)
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				b := gzipped("echo " + r.Header.Get("Authorization"))
				n = len(b)
				_, _ = w.Write(b)
			})))
			cred := bearer(leakCanary, "exact:a.example.test")
			res := e.run(scenario(withCred(httpStep("http://a.example.test/", assertion(spec.SubjectBody, spec.OpLengthGreaterThan, "0")), cred)), cred)
			ex := res.Steps[0].ResponseExcerpt
			i := bytes.Index(ex, []byte("\r\n\r\n"))
			body, actual := string(ex[i+4:]), res.Steps[0].Assertions[0].Actual
			if bytes.Contains(ex, []byte{0x1f, 0x8b}) || strings.Contains(actual, "\x1f\x8b") {
				t.Fatalf("compressed bytes shown: %q / %q", ex, actual)
			}
			// Go decodes gzip (in any case) itself; any other encoding
			// stays encoded and is not shown; no header leaves binary.
			want := map[string]string{
				"":               binaryBody(n),
				"GZIP":           "echo Bearer [redacted]",
				"identity, gzip": encodedBody, "x-gzip": encodedBody, "gzip, identity": encodedBody,
			}[enc]
			if body != want || actual != want {
				t.Fatalf("body %q actual %q, want %q", body, actual, want)
			}
		})
	}
	for in, want := range map[string]bool{"plain": true, "é": true, "aé"[:2]: true, "": true, "\x1f\x8b\x08": false, "a\xffb": false} {
		if got := isText([]byte(in)); got != want {
			t.Errorf("isText(%q) = %v", in, got)
		}
	}
}

// Ruling P11: a variable extracted by a credentialed step, or derived from
// one, may only be sent to the bound hosts of every credential in its
// taint: on the first request and on every redirect hop.
func TestTaintedVariableStaysOnBoundHosts(t *testing.T) {
	setup := func(t *testing.T) (*env, *headerRecorder, spec.RunCredential) {
		e := newEnv(t)
		e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/hop":
				http.Redirect(w, r, "http://b.example.test/landing", http.StatusFound)
			default:
				fmt.Fprint(w, `{"sid":"session-abc-123","v":"derived-value-9"}`)
			}
		})))
		b := &headerRecorder{h: func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"v":"from-b"}`) }}
		e.host("b.example.test", "203.0.113.2", server(t, b))
		return e, b, bearer(leakCanary, "exact:a.example.test")
	}
	login := func(cred spec.RunCredential) spec.Step {
		s := withCred(httpStep("http://a.example.test/login"), cred)
		s.Extracts = []spec.Extract{{Name: "sid", Source: spec.SourceJSONPath, Expr: "sid"}}
		return s
	}

	t.Run("bound host", func(t *testing.T) {
		e, b, cred := setup(t)
		next := httpStep("http://a.example.test/use?s=${sid}")
		wantPassed(t, e.run(scenario(login(cred), next), cred))
		if len(b.requests()) != 0 {
			t.Fatal("b called")
		}
	})
	t.Run("unbound host", func(t *testing.T) {
		e, b, cred := setup(t)
		next := httpStep("http://b.example.test/")
		next.HTTP.Headers = map[string]string{"X-S": "${sid}"}
		wantCode(t, e.run(scenario(login(cred), next), cred), 1, CodeCredentialError)
		if len(b.requests()) != 0 {
			t.Fatal("the unbound host got a tainted variable")
		}
	})
	t.Run("redirect hop", func(t *testing.T) {
		e, b, cred := setup(t)
		next := httpStep("http://a.example.test/hop?s=${sid}")
		wantCode(t, e.run(scenario(login(cred), next), cred), 1, CodeCredentialError)
		if len(b.requests()) != 0 {
			t.Fatal("the redirect hop reached the unbound host")
		}
	})
	t.Run("inherited", func(t *testing.T) {
		e, b, cred := setup(t)
		derive := httpStep("http://a.example.test/derive?s=${sid}") // no credential of its own
		derive.Extracts = []spec.Extract{{Name: "d", Source: spec.SourceJSONPath, Expr: "v"}}
		leak := httpStep("http://b.example.test/${d}")
		wantCode(t, e.run(scenario(login(cred), derive, leak), cred), 2, CodeCredentialError)
		if len(b.requests()) != 0 {
			t.Fatal("a derived variable reached the unbound host")
		}
	})
	t.Run("untainted goes anywhere", func(t *testing.T) {
		e, b, cred := setup(t)
		free := httpStep("http://b.example.test/")
		free.Extracts = []spec.Extract{{Name: "v", Source: spec.SourceJSONPath, Expr: "v"}}
		wantPassed(t, e.run(scenario(free, withCred(httpStep("http://a.example.test/${v}"), cred), httpStep("http://b.example.test/${v}")), cred))
		if len(b.requests()) != 2 {
			t.Fatal("b not called twice")
		}
	})
}

// Ruling P12: a tainted value of minExtractLiteral bytes or more is
// scrubbed from every excerpt and actual value; a shorter one is not, so
// that an id such as "1" leaves "HTTP/1.1 200 OK", dates and prices
// readable. P11 still keeps it on the bound hosts.
func TestTaintedValuesScrubbedFromMinimumLength(t *testing.T) {
	run := func(t *testing.T, id string) *pb.RunResult {
		e := newEnv(t)
		e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Date", "Mon, 23 Nov 2026 10:11:12 GMT")
			if r.URL.Path == "/catalog" {
				fmt.Fprintf(w, `{"items":[{"id":%q}],"total":1}`, id)
				return
			}
			fmt.Fprintf(w, `{"item":%q,"price":10.15,"updated":"2026-11-23"}`, strings.TrimPrefix(r.URL.Path, "/items/"))
		})))
		cred := bearer(leakCanary, "exact:a.example.test")
		one := withCred(httpStep("http://a.example.test/catalog"), cred)
		one.Extracts = []spec.Extract{{Name: "item", Source: spec.SourceJSONPath, Expr: "$.items[0].id"}}
		two := httpStep("http://a.example.test/items/${item}", assertion(spec.SubjectStatusCode, spec.OpEquals, "200"))
		res := e.run(scenario(one, two), cred)
		wantPassed(t, res)
		return res
	}

	t.Run("short id stays readable", func(t *testing.T) {
		res := run(t, "1")
		for _, sr := range res.Steps {
			ex := string(sr.ResponseExcerpt)
			for _, want := range []string{"HTTP/1.1 200 OK", "Mon, 23 Nov 2026 10:11:12 GMT"} {
				if !strings.Contains(ex, want) {
					t.Errorf("step %d excerpt lacks %q: %q", sr.Position, want, ex)
				}
			}
		}
		if ex := string(res.Steps[1].ResponseExcerpt); !strings.Contains(ex, `"price":10.15,"updated":"2026-11-23"`) {
			t.Errorf("price or date garbled: %q", ex)
		}
	})
	t.Run("long id scrubbed", func(t *testing.T) {
		res := run(t, "Qz7k")
		if resultHolds(t, res, "Qz7k") {
			t.Fatal("a 4-byte tainted value is in the result")
		}
	})
}

// Ruling P12: a bound server that saw the credential in one step can hand
// it back to a later step that does not attach it. Extracts from a
// response of a bound host are tainted with that credential all the same,
// so they stay on its bound hosts; the static check agrees.
func TestBoundHostResponsesAreTainted(t *testing.T) {
	setup := func(t *testing.T, mode string) (*env, *headerRecorder, spec.RunCredential) {
		var mu sync.Mutex
		var last string
		e := newEnv(t)
		e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			switch r.URL.Path {
			case "/record":
				last = r.Header.Get("Authorization")
			case "/hop":
				http.Redirect(w, r, "http://a.example.test/last", http.StatusFound)
			default:
				b := []byte(last)
				if mode == "reversed" {
					slices.Reverse(b)
				}
				fmt.Fprintf(w, `{"last":%q}`, b)
			}
		})))
		b := &headerRecorder{}
		e.host("b.example.test", "203.0.113.2", server(t, b))
		e.host("c.example.test", "203.0.113.3", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://a.example.test/last", http.StatusFound)
		})))
		return e, b, bearer(leakCanary, "exact:a.example.test")
	}
	steps := func(cred spec.RunCredential, readURL, useURL string) *spec.Scenario {
		s1 := withCred(httpStep("http://a.example.test/record"), cred)
		s2 := httpStep(readURL) // no credential, no tainted variable
		s2.Extracts = []spec.Extract{{Name: "v", Source: spec.SourceJSONPath, Expr: "last"}}
		s3 := httpStep(useURL)
		s3.HTTP.Headers = map[string]string{"X-Leak": "${v}"}
		return scenario(s1, s2, s3)
	}
	bounds := func(cred spec.RunCredential) map[uuid.UUID][]hostallow.Rule {
		r, err := hostallow.ParseRule(cred.BoundHosts[0])
		if err != nil {
			t.Fatal(err)
		}
		return map[uuid.UUID][]hostallow.Rule{cred.ID: {r}}
	}

	for _, mode := range []string{"verbatim", "reversed"} {
		t.Run(mode+" to an unbound host", func(t *testing.T) {
			e, b, cred := setup(t, mode)
			sc := steps(cred, "http://a.example.test/last", "http://b.example.test/")
			if f := spec.ValidateTaint(sc, bounds(cred)); !strings.Contains(f["steps.2.http.headers.X-Leak"], cred.ID.String()) {
				t.Errorf("static check: %v", f)
			}
			res := e.run(sc, cred)
			if res.Status == StatusPassed || len(b.requests()) != 0 {
				t.Fatalf("the unbound host got a value from a bound host's response: %s %q", res.Status, res.FailureReason)
			}
			if !strings.HasPrefix(res.FailureReason, CodeCredentialError+": ") {
				t.Fatalf("reason %q", res.FailureReason)
			}
		})
	}
	t.Run("redirect hop onto a bound host", func(t *testing.T) {
		e, b, cred := setup(t, "reversed")
		res := e.run(steps(cred, "http://c.example.test/", "http://b.example.test/"), cred)
		wantCode(t, res, 2, CodeCredentialError)
		if len(b.requests()) != 0 {
			t.Fatal("a value read through a redirect to a bound host reached the unbound host")
		}
	})
	t.Run("back to the bound host", func(t *testing.T) {
		e, _, cred := setup(t, "reversed")
		sc := steps(cred, "http://a.example.test/last", "http://a.example.test/use")
		if f := spec.ValidateTaint(sc, bounds(cred)); len(f) != 0 {
			t.Errorf("static check refuses a bound use: %v", f)
		}
		wantPassed(t, e.run(sc, cred))
	})
}

// Ruling P12: the taint comes from the references spec.StepVars reads, so
// a template whose references do not parse is refused: "${${tok}" would
// otherwise substitute ${tok} outside the taint.
func TestUnparsedReferenceRefused(t *testing.T) {
	e := newEnv(t)
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"session":"sess-abcdef123456"}`)
	})))
	b := &headerRecorder{}
	e.host("b.example.test", "203.0.113.2", server(t, b))
	cred := bearer(leakCanary, "exact:a.example.test")
	for _, tc := range []struct{ name, url, header, body string }{
		{"header", "http://b.example.test/", "${${tok}", ""},
		{"url", "http://b.example.test/${${tok}", "", ""},
		{"body", "http://b.example.test/", "", "x=${${tok}"},
		{"unclosed", "http://b.example.test/", "${tok", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s1 := withCred(httpStep("http://a.example.test/"), cred)
			s1.Extracts = []spec.Extract{{Name: "tok", Source: spec.SourceJSONPath, Expr: "session"}}
			s2 := httpStep(tc.url)
			if tc.header != "" {
				s2.HTTP.Headers = map[string]string{"X-Leak": tc.header}
			}
			if tc.body != "" {
				s2.HTTP.Method, s2.HTTP.Body = "POST", tc.body
			}
			wantCode(t, e.run(scenario(s1, s2), cred), 1, CodeInvalidRequest)
		})
	}
	if len(b.requests()) != 0 {
		t.Fatal("a step with an unparsed reference was sent")
	}
}

// Range and If-Range are reserved: a step cannot take a response apart.
func TestRangeHeadersReserved(t *testing.T) {
	e := newEnv(t)
	got := &headerRecorder{}
	e.host("a.example.test", "203.0.113.1", server(t, got))
	for _, h := range []string{"Range", "If-Range", "range"} {
		st := httpStep("http://a.example.test/")
		st.HTTP.Headers = map[string]string{h: "bytes=0-6"}
		wantCode(t, e.run(scenario(st)), 0, CodeInvalidRequest)
	}
	if len(got.requests()) != 0 {
		t.Fatal("request sent")
	}
}

// A body that is encoded, binary or UTF-16 gives no regex or JSON path
// extracts (it may hide an echo the checks cannot read); header extracts
// still work, and such a body is never shown.
func TestNonTextBodyGivesNoBodyExtracts(t *testing.T) {
	utf16 := func(s string) []byte {
		var out []byte
		for _, c := range []byte(s) {
			out = append(out, c, 0)
		}
		return out
	}
	gz := func(s string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(s))
		_ = zw.Close()
		return buf.Bytes()
	}
	for name, tc := range map[string]struct {
		enc  string
		body func(auth string) []byte
	}{
		"utf-16":             {"", func(a string) []byte { return utf16("you are " + a) }},
		"gzip no header":     {"", func(a string) []byte { return gz("you are " + a) }},
		"x-gzip not decoded": {"x-gzip", func(a string) []byte { return gz("you are " + a) }},
		"br":                 {"br", func(a string) []byte { return gz("you are " + a) }},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.enc != "" {
					w.Header().Set("Content-Encoding", tc.enc)
				}
				w.Header().Set("X-Id", "id-42")
				echo := r.Header.Get("Authorization")
				if r.URL.Path == "/quiet" {
					echo = "nothing to see"
				}
				_, _ = w.Write(tc.body(echo))
			})))
			cred := bearer(leakCanary, "exact:a.example.test")
			for _, src := range []string{spec.SourceRegex, spec.SourceJSONPath} {
				st := withCred(httpStep("http://a.example.test/"), cred)
				expr := `(?s)(.+)`
				if src == spec.SourceJSONPath {
					expr = "x"
				}
				st.Extracts = []spec.Extract{{Name: "z", Source: src, Expr: expr}}
				res := e.run(scenario(st), cred)
				wantCode(t, res, 0, CodeCredentialError)
				ex := res.Steps[0].ResponseExcerpt
				if bytes.Contains(bytes.ReplaceAll(ex, []byte{0}, nil), []byte(leakCanary)) || bytes.Contains(ex, []byte{0x1f, 0x8b}) {
					t.Fatalf("body shown: %q", ex)
				}
			}
			// A header extract from a binary body that echoes nothing.
			st := withCred(httpStep("http://a.example.test/quiet"), cred)
			st.Extracts = []spec.Extract{{Name: "id", Source: spec.SourceHeader, Expr: "X-Id"}}
			wantPassed(t, e.run(scenario(st), cred))
		})
	}
}

// Echoes are matched after decoding JSON \u escapes (either case) and
// percent-encoding; and a short secret is matched in its own case only.
func TestEchoMatchedAfterDecoding(t *testing.T) {
	const tok = "CANARYab+cd/ef+gh/ij0123=="
	for name, enc := range map[string]func(string) string{
		".NET \\u002B": func(s string) string { return strings.ReplaceAll(s, "+", `+`) },
		"all \\u lower": func(s string) string {
			var b strings.Builder
			for _, c := range []byte(s) {
				fmt.Fprintf(&b, `\u%04x`, c)
			}
			return b.String()
		},
		"all \\U upper hex": func(s string) string {
			var b strings.Builder
			for _, c := range []byte(s) {
				fmt.Fprintf(&b, `\u%04X`, c)
			}
			return b.String()
		},
		"escaped slash": func(s string) string { return strings.ReplaceAll(s, "/", `\/`) },
		"percent":       func(s string) string { return url.PathEscape(s) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := enc(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
				w.Header().Set("X-Seen", v)
				// Not valid JSON as a whole, so the JSON pass does not
				// decode it for the scrub.
				fmt.Fprintf(w, `seen "%s" {`, v)
			})))
			cred := bearer(tok, "exact:a.example.test")
			st := withCred(httpStep("http://a.example.test/", assertion("header:X-Seen", spec.OpExists, "")), cred)
			st.Extracts = []spec.Extract{{Name: "t", Source: spec.SourceRegex, Expr: `seen "([^"]+)"`}}
			res := e.run(scenario(st), cred)
			wantCode(t, res, 0, CodeCredentialError)
			// Without extracts, the excerpt still hides what decodes to
			// the credential.
			st.Extracts = nil
			res = e.run(scenario(st), cred)
			wantPassed(t, res)
			ex := res.Steps[0].ResponseExcerpt
			check := newCredSet([]spec.RunCredential{bearer(tok, "exact:a.example.test")})
			defer check.close()
			if check.holdsCredential(ex) || !bytes.Contains(ex, []byte("X-Seen: [redacted]")) || res.Steps[0].Assertions[0].Actual != "[redacted]" {
				t.Fatalf("excerpt %q actual %q", ex, res.Steps[0].Assertions[0].Actual)
			}
			if strings.HasPrefix(name, "all") && !bytes.Contains(ex, []byte(echoedBody)) {
				t.Fatalf("escaped echo not hidden: %q", ex)
			}
		})
	}

	// A short, common-word password does not match a capitalized word.
	e := newEnv(t)
	e.host("a.example.test", "203.0.113.1", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"service":"Monitoring API","id":"42"}`)
	})))
	cred := spec.RunCredential{ID: uuid.New(), Kind: spec.CredBasic, BoundHosts: []string{"exact:a.example.test"},
		Username: secret("probe"), Secret: secret("monitor")}
	st := withCred(httpStep("http://a.example.test/"), cred)
	st.Extracts = []spec.Extract{{Name: "id", Source: spec.SourceJSONPath, Expr: "id"}}
	wantPassed(t, e.run(scenario(st), cred))
	// A long secret is still found lower-cased.
	if !newCredSet([]spec.RunCredential{bearer("LongSecretValue99", "exact:a.example.test")}).holdsCredential([]byte("x longsecretvalue99 y")) {
		t.Fatal("lower-cased long secret not found")
	}
}
