package probe

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/Warewave-Technology/olympos/internal/sensitive"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func redirectTo(loc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, loc, http.StatusFound) }
}

func server(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Review Focus 2: a redirect to the metadata address, as a literal or
// behind an allowlisted name, fails the step and is never dialed.
func TestRedirectToMetadataBlocked(t *testing.T) {
	for _, tc := range []struct{ loc, code string }{
		{"http://169.254.169.254/latest/meta-data/", CodeRedirectBlocked},
		{"http://[::ffff:169.254.169.254]/", CodeRedirectBlocked},
		{"http://meta.example.test/latest/meta-data/", CodeIPDenied},
		{"http://kubernetes.default.svc/api", CodeRedirectBlocked},
	} {
		t.Run(tc.loc, func(t *testing.T) {
			e := newEnv(t)
			e.host("api.example.test", "203.0.113.10", server(t, redirectTo(tc.loc)))
			e.res.set("meta.example.test.", ips("169.254.169.254"))
			e.net.route("169.254.169.254", "127.0.0.1:1")
			res := e.run(scenario(httpStep("http://api.example.test/")))
			wantCode(t, res, 0, tc.code)
			for _, d := range e.net.dialedAddrs() {
				if strings.HasPrefix(d, "169.254.") {
					t.Fatalf("dialed %s", d)
				}
			}
		})
	}
}

// Review Focus 2: a redirect to a host off the allowlist is blocked before
// it is resolved.
func TestRedirectToNonAllowedHostBlocked(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, redirectTo("http://evil.example.org/steal")))
	e.res.set("evil.example.org.", ips("203.0.113.66"))
	res := e.run(scenario(httpStep("http://api.example.test/")))
	wantCode(t, res, 0, CodeRedirectBlocked)
	if e.res.callCount("evil.example.org.") != 0 {
		t.Fatal("the blocked host was resolved")
	}
	// Other schemes are blocked too.
	e.host("ftp.example.test", "203.0.113.11", server(t, redirectTo("ftp://api.example.test/x")))
	res = e.run(scenario(httpStep("http://ftp.example.test/")))
	wantCode(t, res, 0, CodeRedirectBlocked)
}

// Without follow_redirects the 302 itself is the response.
func TestRedirectNotFollowed(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, redirectTo("http://evil.example.org/")))
	st := httpStep("http://api.example.test/", assertion(spec.SubjectStatusCode, spec.OpEquals, "302"),
		assertion("header:Location", spec.OpContains, "evil"))
	st.HTTP.FollowRedirects = false
	wantPassed(t, e.run(scenario(st)))
}

// Binding note 5: at most 5 redirects; the 6th is refused.
func TestRedirectChainLimit(t *testing.T) {
	for hops, want := range map[int]string{5: "", 6: CodeRedirectBlocked} {
		e := newEnv(t)
		e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
			if n < hops {
				http.Redirect(w, r, "/"+strconv.Itoa(n+1), http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		})))
		res := e.run(scenario(httpStep("http://api.example.test/0", assertion(spec.SubjectStatusCode, spec.OpEquals, "200"))))
		if want == "" {
			wantPassed(t, res)
		} else {
			wantCode(t, res, 0, want)
		}
	}
}

// Review Focus 2: a redirect to an allowlisted host outside the
// credential's bound hosts carries no Authorization, no Cookie and not the
// credential's own header.
func TestCredentialDroppedOnRedirectToUnboundHost(t *testing.T) {
	creds := map[string]spec.RunCredential{
		"bearer": bearer("CANARY-bearer-1", "exact:api.example.test"),
		"basic": {ID: uuid.New(), Kind: spec.CredBasic, BoundHosts: []string{"exact:api.example.test"},
			Username: secret("probe-user"), Secret: secret("CANARY-basic-pw")},
		"header": {ID: uuid.New(), Kind: spec.CredHeader, BoundHosts: []string{"exact:api.example.test"},
			HeaderName: "X-Partner-Key", Secret: secret("CANARY-header-1")},
	}
	// Go's client keeps Authorization and Cookie on a redirect to a
	// subdomain; the probe removes them there too.
	for _, target := range []string{"other.example.org", "sub.api.example.test"} {
		for kind, cred := range creds {
			t.Run(kind+" to "+target, func(t *testing.T) {
				e := newEnv(t)
				unbound := &headerRecorder{}
				bound := &headerRecorder{h: redirectTo("http://" + target + "/landing")}
				e.host("api.example.test", "203.0.113.10", server(t, bound))
				e.host(target, "203.0.113.20", server(t, unbound))
				e.dialer.Allow.Rules = append(e.dialer.Allow.Rules, rule("other.example.org"))
				st := withCred(httpStep("http://api.example.test/"), cred)
				st.HTTP.Headers = map[string]string{"Cookie": "sid=CANARY-cookie", "Proxy-Authorization": "Basic CANARY-proxy"}
				wantPassed(t, e.run(scenario(st), cred))

				first := bound.requests()
				if len(first) != 1 || first[0].Header.Get(credHeaderName(cred)) == "" || first[0].Header.Get("Cookie") == "" {
					t.Fatalf("the bound host did not get the credential: %v", first)
				}
				got := unbound.requests()
				if len(got) != 1 {
					t.Fatalf("unbound host requests: %d", len(got))
				}
				for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Partner-Key", "Referer"} {
					if v := got[0].Header.Get(h); v != "" {
						t.Errorf("unbound host got %s: %q", h, v)
					}
				}
			})
		}
	}
}

// credHeaderName is the header a credential sets.
func credHeaderName(c spec.RunCredential) string {
	if c.Kind == spec.CredHeader {
		return c.HeaderName
	}
	return "Authorization"
}

// A credential goes only to its bound hosts: exact and wildcard bounds.
func TestCredentialOnlyOnBoundHosts(t *testing.T) {
	e := newEnv(t)
	a, b, w := &headerRecorder{}, &headerRecorder{}, &headerRecorder{}
	e.host("api.example.test", "203.0.113.10", server(t, a))
	e.host("other.example.test", "203.0.113.20", server(t, b))
	e.host("x.dev.example.test", "203.0.113.30", server(t, w))
	cred := bearer("CANARY-bound-token", "exact:api.example.test", "wildcard:*.dev.example.test")
	basic := spec.RunCredential{ID: uuid.New(), Kind: spec.CredBasic, BoundHosts: []string{"exact:api.example.test"},
		Username: secret("u"), Secret: secret("p@ss:w")}
	s := scenario(
		withCred(httpStep("http://api.example.test/"), cred),
		withCred(httpStep("http://other.example.test/"), cred),
		withCred(httpStep("http://x.dev.example.test/"), cred),
		withCred(httpStep("http://api.example.test/basic"), basic),
	)
	// A step's own Authorization header is replaced on bound hosts and
	// removed elsewhere.
	s.Steps[1].HTTP.Headers = map[string]string{"Authorization": "Bearer step-header"}
	wantPassed(t, e.run(s, cred, basic))
	if got := a.requests()[0].Header.Get("Authorization"); got != "Bearer CANARY-bound-token" {
		t.Fatalf("bound host: %q", got)
	}
	if got := b.requests()[0].Header.Get("Authorization"); got != "" {
		t.Fatalf("unbound host: %q", got)
	}
	if got := w.requests()[0].Header.Get("Authorization"); got != "Bearer CANARY-bound-token" {
		t.Fatalf("wildcard-bound host: %q", got)
	}
	u, p, ok := a.requests()[1].BasicAuth()
	if !ok || u != "u" || p != "p@ss:w" {
		t.Fatalf("basic: %q %q %v", u, p, ok)
	}
}

// Bound hosts carry their kind and match like allowlist rules: a suffix
// bound includes its apex, a wildcard bound does not, an exact bound is
// that host only; a bound that does not parse refuses the credential.
func TestBoundHostKinds(t *testing.T) {
	hosts := []string{"example.test", "api.example.test", "x.api.example.test", "other.example.test"}
	for _, tc := range []struct {
		bound string
		want  map[string]bool // host → gets the credential
	}{
		{"suffix:api.example.test", map[string]bool{"api.example.test": true, "x.api.example.test": true}},
		{"wildcard:*.api.example.test", map[string]bool{"x.api.example.test": true}},
		{"exact:api.example.test", map[string]bool{"api.example.test": true}},
		{"suffix:example.test", map[string]bool{"example.test": true, "api.example.test": true, "x.api.example.test": true, "other.example.test": true}},
	} {
		t.Run(tc.bound, func(t *testing.T) {
			e := newEnv(t)
			recs := map[string]*headerRecorder{}
			var steps []spec.Step
			cred := bearer("CANARY-kind-token", tc.bound)
			for i, h := range hosts {
				recs[h] = &headerRecorder{}
				e.host(h, fmt.Sprintf("203.0.113.%d", 10+i), server(t, recs[h]))
				steps = append(steps, withCred(httpStep("http://"+h+"/"), cred))
			}
			wantPassed(t, e.run(scenario(steps...), cred))
			for _, h := range hosts {
				got := recs[h].requests()[0].Header.Get("Authorization") == "Bearer CANARY-kind-token"
				if got != tc.want[h] {
					t.Errorf("%s: credential attached = %v, want %v", h, got, tc.want[h])
				}
			}
		})
	}

	for _, bad := range [][]string{
		{"api.example.test"},                // no kind
		{"exact:api.example.test", "*.x.y"}, // one bad entry refuses all
		{"prefix:api.example.test"},
		{"wildcard:api.example.test"},
		{"exact:127.0.0.1"},
		{"suffix:test"},
		{},
	} {
		e := newEnv(t)
		rec := &headerRecorder{}
		e.host("api.example.test", "203.0.113.10", server(t, rec))
		cred := bearer("CANARY-bad-bound", bad...)
		res := e.run(scenario(withCred(httpStep("http://api.example.test/"), cred)), cred)
		wantCode(t, res, 0, CodeCredentialError)
		if len(rec.requests()) != 0 {
			t.Errorf("%q: request sent", bad)
		}
	}
}

// A step that names a credential the run does not carry fails.
func TestMissingCredential(t *testing.T) {
	e := newEnv(t)
	srv := &headerRecorder{}
	e.host("api.example.test", "203.0.113.10", server(t, srv))
	res := e.run(scenario(withCred(httpStep("http://api.example.test/"), bearer("x", "exact:api.example.test"))))
	wantCode(t, res, 0, CodeCredentialError)
	if len(srv.requests()) != 0 {
		t.Fatal("request sent")
	}
}

// The canary bearer token comes back in the body, in Set-Cookie, in a
// JSON access_token, base64-encoded and URL-encoded; a session token is
// extracted from a response that does not echo the credential (one that
// does gives no extracts, TestExtractCannotCaptureCredential) and used in
// the next step, which echoes both. Nothing in the marshalled result
// holds either.
func TestCanaryNeverInResult(t *testing.T) {
	const canary = "CANARY-tok/en+Value=42"
	const extracted = "EXTRACTED-session-9f8e7d"
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(auth, "Bearer ")
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: url.QueryEscape(tok)})
			w.Header().Set("X-Echo", auth)
			w.Header().Set("X-Echo-B64", base64.StdEncoding.EncodeToString([]byte(tok)))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":%q,"note":"got %s","enc":%q,"b64":%q,"session":{"id":%q}}`,
				tok, tok, url.QueryEscape(tok), base64.RawURLEncoding.EncodeToString([]byte(tok)), extracted)
		case "/session":
			fmt.Fprintf(w, `{"session":{"id":%q}}`, extracted)
		case "/use":
			fmt.Fprintf(w, "you sent %s and %s, q=%s", r.Header.Get("X-Session"), auth, r.URL.Query().Get("s"))
		}
	})))
	cred := bearer(canary, "exact:api.example.test")
	login := withCred(httpStep("http://api.example.test/login",
		assertion(spec.SubjectBody, spec.OpContains, canary),
		assertion("header:X-Echo", spec.OpContains, "Bearer"),
		assertion("header:Set-Cookie", spec.OpExists, ""),
		assertion("header:X-Echo-B64", spec.OpExists, ""),
		assertion("json:access_token", spec.OpEquals, canary),
		assertion("json:note", spec.OpContains, "got"),
		assertion("json:session.id", spec.OpEquals, extracted),
	), cred)
	session := withCred(httpStep("http://api.example.test/session"), cred)
	session.Extracts = []spec.Extract{{Name: "sess", Source: spec.SourceJSONPath, Expr: "session.id"}}
	use := withCred(httpStep("http://api.example.test/use?s=${sess}",
		assertion(spec.SubjectBody, spec.OpContains, extracted)), cred)
	use.HTTP.Headers = map[string]string{"X-Session": "${sess}"}
	res := e.run(scenario(login, session, use), cred)
	wantPassed(t, res)
	if got := res.Steps[1].ExtractedNames; len(got) != 1 || got[0] != "sess" {
		t.Fatalf("extracted names %v", got)
	}
	if len(res.Steps[0].ResponseExcerpt) == 0 || !bytes.Contains(res.Steps[0].ResponseExcerpt, []byte(sensitive.Redacted)) {
		t.Fatalf("excerpt %q", res.Steps[0].ResponseExcerpt)
	}
	leaks := []string{canary, extracted, url.QueryEscape(canary), url.PathEscape(canary),
		base64.StdEncoding.EncodeToString([]byte(canary)), base64.RawURLEncoding.EncodeToString([]byte(canary)),
		"CANARY", "EXTRACTED"}
	wire, _ := proto.Marshal(res)
	text, _ := protojson.Marshal(res)
	for _, l := range leaks {
		if bytes.Contains(wire, []byte(l)) || bytes.Contains(text, []byte(l)) {
			t.Errorf("result holds %q:\n%s", l, text)
		}
	}
}

// OAuth2 client credentials: the token is fetched once per run through the
// same dialer, sent only to bound hosts, and never reported.
func TestOAuth2Credential(t *testing.T) {
	const token = "CANARY-oauth-access-token"
	var fetches atomic.Int32
	e := newEnv(t)
	now := time.Now()
	tokenCert := e.ca.leaf(t, []string{"token.example.test"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	e.host("token.example.test", "203.0.113.40", tlsServer(t, tokenCert, 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		id, sec, ok := r.BasicAuth()
		_ = r.ParseForm()
		if !ok || id != "client-1" || sec != "CANARY-client-secret" || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "read write" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":300}`, token)
	})))
	api := &headerRecorder{h: func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}}
	e.host("api.example.test", "203.0.113.10", server(t, api))
	cred := spec.RunCredential{ID: uuid.New(), Kind: spec.CredOAuth2, BoundHosts: []string{"exact:api.example.test", "exact:token.example.test"},
		Username: secret("client-1"), Secret: secret("CANARY-client-secret"),
		TokenURL: "https://token.example.test/oauth/token", Scopes: "read write"}
	s := scenario(
		withCred(httpStep("http://api.example.test/a", assertion(spec.SubjectBody, spec.OpContains, token)), cred),
		withCred(httpStep("http://api.example.test/b"), cred),
	)
	res := e.run(s, cred)
	wantPassed(t, res)
	if fetches.Load() != 1 {
		t.Fatalf("token fetched %d times", fetches.Load())
	}
	for _, r := range api.requests() {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("api got %q", r.Header.Get("Authorization"))
		}
	}
	text, _ := protojson.Marshal(res)
	if bytes.Contains(text, []byte("CANARY")) {
		t.Fatalf("result holds a canary: %s", text)
	}

	// A token URL outside the bound hosts is refused, and so is one that
	// is not https: the client secret would travel in clear.
	unbound := cred
	unbound.BoundHosts = []string{"exact:api.example.test"}
	res = e.run(scenario(withCred(httpStep("http://api.example.test/a"), unbound)), unbound)
	wantCode(t, res, 0, CodeCredentialError)
	plain := cred
	plain.TokenURL = "http://token.example.test/oauth/token"
	res = e.run(scenario(withCred(httpStep("http://api.example.test/a"), plain)), plain)
	wantCode(t, res, 0, CodeCredentialError)
	if fetches.Load() != 1 {
		t.Fatal("token fetched from an unbound host or over http")
	}
}

// Binding note 6: proxy environment variables are ignored.
func TestProxyEnvIgnored(t *testing.T) {
	var proxied atomic.Int32
	proxy := server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	wantPassed(t, e.run(scenario(httpStep("http://api.example.test/", assertion(spec.SubjectStatusCode, spec.OpEquals, "200")))))
	if proxied.Load() != 0 {
		t.Fatal("the request went through the proxy")
	}
}

// The body is read up to 1 MiB, and the excerpt is at most 2 KiB.
func TestResponseReadCap(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := bytes.Repeat([]byte("abcdefghij"), 1024)
		for i := 0; i < 2<<20/len(chunk); i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})))
	res := e.run(scenario(httpStep("http://api.example.test/",
		assertion(spec.SubjectBody, spec.OpLengthGreaterThan, strconv.Itoa(spec.MaxResponseRead-1)),
		assertion(spec.SubjectBody, spec.OpLengthGreaterThan, strconv.Itoa(spec.MaxResponseRead)))))
	st := res.Steps[0]
	if len(st.Assertions) != 2 || !st.Assertions[0].Passed || st.Assertions[1].Passed {
		t.Fatalf("assertions %v", st.Assertions)
	}
	if n := len(st.ResponseExcerpt); n == 0 || n > spec.MaxExcerpt {
		t.Fatalf("excerpt is %d bytes", n)
	}
	if n := len(st.Assertions[0].Actual); n > maxActual {
		t.Fatalf("actual is %d bytes", n)
	}
}

// With store_responses off there is no excerpt.
func TestNoExcerptWhenResponsesNotStored(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello")
	})))
	s := scenario(httpStep("http://api.example.test/"))
	s.StoreResponses = false
	res := e.run(s)
	wantPassed(t, res)
	if len(res.Steps[0].ResponseExcerpt) != 0 {
		t.Fatalf("excerpt %q", res.Steps[0].ResponseExcerpt)
	}
}

// Binding note 4: a variable that carries CR/LF into a header value is
// refused, and the request is never sent.
func TestHeaderInjectionThroughVariable(t *testing.T) {
	e := newEnv(t)
	second := &headerRecorder{}
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"v":"ok\r\nX-Injected: 1","n":"a\u0000b"}`)
	})))
	e.host("next.example.test", "203.0.113.11", server(t, second))
	for _, ex := range []string{"v", "n"} {
		first := httpStep("http://api.example.test/")
		first.Extracts = []spec.Extract{{Name: "x", Source: spec.SourceJSONPath, Expr: ex}}
		next := httpStep("http://next.example.test/")
		next.HTTP.Headers = map[string]string{"X-Val": "pre-${x}"}
		res := e.run(scenario(first, next))
		wantCode(t, res, 1, CodeInvalidRequest)
	}
	if len(second.requests()) != 0 {
		t.Fatal("the request was sent")
	}
}

// Binding note 4: the URL's scheme, host and port must be the template's
// after substitution, even for a template Validate would refuse.
func TestURLHostChangeRefused(t *testing.T) {
	vars := map[string]string{"h": "evil.example.org", "p": "@evil.example.org/", "port": "8443", "path": "a/b?c=d#e"}
	for _, tmpl := range []string{
		"https://${h}/x",
		"https://api.example.test${p}",
		"https://api.example.test:${port}/",
		"${h}://api.example.test/",
	} {
		if _, err := buildURL(tmpl, vars); codeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: %v", tmpl, err)
		}
	}
	u, err := buildURL("https://api.example.test/${path}", vars)
	if err != nil || u.Host != "api.example.test" || u.Path != "/a/b" {
		t.Fatalf("path variable: %v %v", u, err)
	}

	// And through a run: the host never reaches the resolver.
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"h":"evil.example.org"}`)
	})))
	first := httpStep("http://api.example.test/")
	first.Extracts = []spec.Extract{{Name: "h", Source: spec.SourceJSONPath, Expr: "h"}}
	wantCode(t, e.run(scenario(first, httpStep("http://${h}/"))), 1, CodeInvalidRequest)
	if e.res.callCount("evil.example.org.") != 0 {
		t.Fatal("the substituted host was resolved")
	}
}

// HTTPS: the certificate is verified against the roots, and tls_days_left
// comes from it.
func TestHTTPSVerifiesAndReportsDaysLeft(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	good := tlsServer(t, e.ca.leaf(t, []string{"api.example.test"}, now.Add(-time.Hour), now.Add(40*24*time.Hour+time.Hour)), 0, nil)
	e.host("api.example.test", "203.0.113.10", good)
	wantPassed(t, e.run(scenario(httpStep("https://api.example.test/",
		assertion(spec.SubjectTLSDaysLeft, spec.OpEquals, "40")))))

	other := newTestCA(t)
	bad := tlsServer(t, other.leaf(t, []string{"api.example.test"}, now.Add(-time.Hour), now.Add(time.Hour)), 0, nil)
	e.host("bad.example.test", "203.0.113.11", bad)
	wantCode(t, e.run(scenario(httpStep("https://bad.example.test/"))), 0, CodeTLSError)
}

// Assertion actual values are redacted like the excerpt and cut to 200
// bytes.
func TestAssertionActualRedactedAndCut(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc")
		w.Header().Set("X-Long", strings.Repeat("y", 500))
		fmt.Fprint(w, `{"client_secret":"hide-me","nested":{"password":"pw"},"list":[1,2,3]}`)
	})))
	res := e.run(scenario(httpStep("http://api.example.test/",
		assertion("header:Set-Cookie", spec.OpContains, "sid"),
		assertion("header:X-Long", spec.OpContains, "y"),
		assertion("json:client_secret", spec.OpEquals, "hide-me"),
		assertion("json:nested.password", spec.OpExists, ""),
		assertion("json:list", spec.OpLengthGreaterThan, "2"),
		assertion(spec.SubjectBody, spec.OpContains, "hide-me"),
	)))
	wantPassed(t, res)
	as := res.Steps[0].Assertions
	want := []string{sensitive.Redacted, strings.Repeat("y", maxActual), sensitive.Redacted, sensitive.Redacted, "[1,2,3]"}
	for i, w := range want {
		if as[i].Actual != w {
			t.Errorf("assertion %d actual %q, want %q", i, as[i].Actual, w)
		}
	}
	if strings.Contains(as[5].Actual, "hide-me") {
		t.Errorf("body actual %q", as[5].Actual)
	}
}

func TestJSONAssertions(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"n":1.0,"s":"hello","b":true,"z":null,"a":[{"id":"x"}],"o":{"k":1}}`)
	})))
	ok := []spec.Assertion{
		assertion("json:n", spec.OpEquals, "1"),
		assertion("json:n", spec.OpLessThan, "2"),
		assertion("json:n", spec.OpGreaterThan, "0.5"),
		assertion("json:s", spec.OpMatches, "^h.*o$"),
		assertion("json:s", spec.OpLengthGreaterThan, "4"),
		assertion("json:b", spec.OpEquals, "true"),
		assertion("json:z", spec.OpEquals, "null"),
		assertion("json:a[0].id", spec.OpEquals, "x"),
		assertion("json:o", spec.OpEquals, `{"k":1}`),
		assertion("json:missing", spec.OpNotEquals, "x"),
		assertion("json:$.a", spec.OpExists, ""),
	}
	wantPassed(t, e.run(scenario(httpStep("http://api.example.test/", ok...))))
	for _, bad := range []spec.Assertion{
		assertion("json:missing", spec.OpExists, ""),
		assertion("json:s", spec.OpGreaterThan, "1"),
		assertion("json:n", spec.OpNotEquals, "1"),
	} {
		res := e.run(scenario(httpStep("http://api.example.test/", bad)))
		wantCode(t, res, 0, CodeAssertionFailed)
	}
}

// An extract that finds nothing fails its step.
func TestExtractMissingFails(t *testing.T) {
	e := newEnv(t)
	e.host("api.example.test", "203.0.113.10", server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Id", "abcd-1234")
		fmt.Fprint(w, `{"a":1} token=tok-5678`)
	})))
	ok := httpStep("http://api.example.test/")
	ok.Extracts = []spec.Extract{
		{Name: "h", Source: spec.SourceHeader, Expr: "x-id"},
		{Name: "r", Source: spec.SourceRegex, Expr: `token=(\S+)`},
	}
	next := httpStep("http://api.example.test/${h}/${r}")
	wantPassed(t, e.run(scenario(ok, next)))

	bad := httpStep("http://api.example.test/")
	bad.Extracts = []spec.Extract{{Name: "x", Source: spec.SourceJSONPath, Expr: "nope"}}
	wantCode(t, e.run(scenario(bad)), 0, CodeAssertionFailed)
}

// rule is an exact allowlist rule.
func rule(host string) hostallow.Rule { return hostallow.Rule{Pattern: host, Kind: hostallow.Exact} }

// A header credential that names a reserved header is never sent (the
// server refuses it at save; spec.ReservedCredentialHeader is the one
// list): the step ends credential_error before any request.
func TestReservedCredentialHeaderRefused(t *testing.T) {
	for _, name := range []string{"Range", "accept-encoding", "If-Range", "Content-Type", "TE"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			srv := &headerRecorder{}
			e.host("api.example.test", "203.0.113.10", server(t, srv))
			cred := spec.RunCredential{ID: uuid.New(), Kind: spec.CredHeader, BoundHosts: []string{"exact:api.example.test"},
				HeaderName: name, Secret: secret("CANARY-reserved-1")}
			res := e.run(scenario(withCred(httpStep("http://api.example.test/"), cred)), cred)
			wantCode(t, res, 0, CodeCredentialError)
			if len(srv.requests()) != 0 {
				t.Fatal("request sent")
			}
		})
	}
}
