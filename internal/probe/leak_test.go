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
	"time"

	"github.com/google/uuid"
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
	// Extracting the user name, and using it elsewhere.
	s1 := withCred(httpStep("http://a.example.test/me"), basic)
	s1.Extracts = []spec.Extract{{Name: "u", Source: spec.SourceJSONPath, Expr: "user"}}
	res := e.run(scenario(s1, httpStep("http://status.example.test/${u}")), basic)
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
