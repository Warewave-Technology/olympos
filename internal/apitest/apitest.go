// Package apitest spins up the HTTP API against a fresh database for
// integration tests, with helpers to sign in as principals with grants.
package apitest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// TenantID used by test principals.
const TenantID = "00000000-0000-0000-0000-0000000000aa"

// Env is a running API.
type Env struct {
	T        testing.TB
	DB       *store.DB
	Srv      *httptest.Server
	Gateway  *gateway.Gateway
	CA       *pki.CA
	KV       *secrets.LocalKeyVault
	Envelope *secrets.Envelope
	HMAC     *secrets.Fingerprinter
	Log      *slog.Logger
	LogBuf   *bytes.Buffer
}

// Options customize New.
type Options struct {
	// Modules builds extra API modules given the env (DB, gateway, ...).
	Modules func(e *Env) []server.Module
	// Directory overrides the principal directory (default: local DB).
	Directory server.Directory
}

// New starts the API. Logs are captured in LogBuf (redacted) for canary checks.
func New(t testing.TB, opt Options) *Env {
	t.Helper()
	db := testutil.DB(t)
	buf := &bytes.Buffer{}
	log := slog.New(secrets.NewRedactingHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	fp, _ := secrets.NewFingerprinter(bytes.Repeat([]byte{42}, 32))
	e := &Env{T: t, DB: db, CA: pki.NewForTest(), KV: kv, Envelope: &secrets.Envelope{KV: kv}, HMAC: fp, Log: log, LogBuf: buf}
	e.Gateway = gateway.New(db, e.CA, log)
	dir := opt.Directory
	if dir == nil {
		dir = server.LocalDirectory{DB: db}
	}
	s := &server.Server{DB: db, Log: log, TenantID: TenantID, DevMode: true, InsecureCookies: true, Directory: dir,
		SPA: fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}}
	s.Modules = append(s.Modules, &inventory.API{DB: db, Log: log, Gateway: e.Gateway, CA: e.CA, GatewayURL: "gw.test:8443"})
	if opt.Modules != nil {
		s.Modules = append(s.Modules, opt.Modules(e)...)
	}
	e.Srv = httptest.NewServer(s.Handler())
	t.Cleanup(e.Srv.Close)
	return e
}

// Principal creates a principal with the given grants ("role" or "role@scope").
func (e *Env) Principal(name string, userType string, grants ...string) authz.Principal {
	e.T.Helper()
	ctx := context.Background()
	p, err := authz.UpsertPrincipal(ctx, e.DB, authz.Principal{TenantID: TenantID, ObjectID: uuid.NewString(), UPN: name + "@contoso.com",
		DisplayName: name, UserType: userType, AccountEnabled: true})
	if err != nil {
		e.T.Fatal(err)
	}
	for _, g := range grants {
		role, scope := g, "all"
		for i := range g {
			if g[i] == '@' {
				role, scope = g[:i], g[i+1:]
			}
		}
		sc, err := authz.ParseScope(scope)
		if err != nil {
			e.T.Fatal(err)
		}
		if _, err := e.DB.Exec(ctx, `INSERT INTO grants (principal_id, role, scope_selector) VALUES ($1,$2,$3)`, p.ID, role, sc.String()); err != nil {
			e.T.Fatal(err)
		}
	}
	return p
}

// Client is a signed-in browser session.
type Client struct {
	e    *Env
	HTTP *http.Client
	CSRF string
	P    authz.Principal
}

// Login signs in via the dev login and returns a client with cookies + CSRF.
func (e *Env) Login(p authz.Principal) *Client {
	e.T.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(e.Srv.URL + "/auth/dev-login?oid=" + url.QueryEscape(p.ObjectID))
	if err != nil {
		e.T.Fatal(err)
	}
	resp.Body.Close()
	c := &Client{e: e, HTTP: hc, P: p}
	u, _ := url.Parse(e.Srv.URL)
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "olympos_csrf" {
			c.CSRF = ck.Value
		}
	}
	return c
}

// Do sends a JSON request and decodes the response into out (if non-nil).
func (c *Client) Do(method, path string, body, out any) int {
	c.e.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.Srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.CSRF != "" {
		req.Header.Set("X-CSRF-Token", c.CSRF)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.e.T.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.e.T.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode
}

// Raw returns status and body.
func (c *Client) Raw(method, path string, body any) (int, string) {
	var m json.RawMessage
	code := c.Do(method, path, body, &m)
	return code, string(m)
}
