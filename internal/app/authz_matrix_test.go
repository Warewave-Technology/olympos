//go:build dev

package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/config"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/targetid"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

const matrixTenant = "00000000-0000-0000-0000-0000000000aa"

// TestAuthzMatrix (F11) walks EVERY /api/v1 route of the production module
// wiring and calls it as:
//   - a principal without grants: never 2xx (403 at the session check);
//   - a viewer scoped to env=other: never 2xx on an object of the env=prod
//     cluster and never a write; lists may answer 200 but must not leak
//     the prod objects;
//   - a viewer scoped to env=prod (missing role): never 2xx on a write.
func TestAuthzMatrix(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`olympos:
  devMode: true
  publicURL: http://olympos.test
  agentGatewayURL: gw.test:8443
  keyVault: {provider: local, name: test, localDir: `+dir+`/kv}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	kv := &secrets.LocalKeyVault{Dir: filepath.Join(dir, "kv")}
	fp, _ := secrets.NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	d := &Deps{Cfg: cfg, Log: log, DB: db, KV: kv, Envelope: &secrets.Envelope{KV: kv}, HMAC: fp, CA: pki.NewForTest()}
	d.Gateway = gateway.New(db, d.CA, log)
	d.Inventory = &inventory.Service{DB: db, Log: log}
	srv := &server.Server{DB: db, Log: log, TenantID: matrixTenant, DevMode: true, InsecureCookies: true,
		Directory: server.LocalDirectory{DB: db}, SPA: fstest.MapFS{"index.html": {Data: []byte("spa")}}}
	srv.Modules = append(srv.Modules, &inventory.API{DB: db, Log: log, Gateway: d.Gateway, CA: d.CA, GatewayURL: "gw.test:8443"})
	for _, f := range moduleFactories {
		w, err := f(d)
		if err != nil {
			t.Fatal(err)
		}
		srv.Modules = append(srv.Modules, w.Modules...)
	}
	h := srv.Handler()
	ts := httptest.NewServer(h)
	defer ts.Close()

	// One object of each kind on the env=prod cluster (and global ones).
	ids := seedProd(t, db)
	principal := func(name string, grants ...string) *http.Client {
		p, err := authz.UpsertPrincipal(ctx, db, authz.Principal{TenantID: matrixTenant, ObjectID: uuid.NewString(), UPN: name + "@contoso.com",
			DisplayName: name, UserType: "Member", AccountEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range grants {
			role, scope, _ := strings.Cut(g, "@")
			if _, err := db.Exec(ctx, `INSERT INTO grants (principal_id, role, scope_selector) VALUES ($1,$2,$3)`, p.ID, role, scope); err != nil {
				t.Fatal(err)
			}
		}
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Get(ts.URL + "/auth/dev-login?oid=" + p.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return c
	}
	csrf := func(c *http.Client) string {
		u, _ := url.Parse(ts.URL)
		for _, ck := range c.Jar.Cookies(u) {
			if ck.Name == "olympos_csrf" {
				return ck.Value
			}
		}
		return ""
	}
	nobody := principal("nobody")
	outside := principal("outside", "viewer@env=other")
	inside := principal("inside", "viewer@env=prod")

	type route struct{ method, pattern string }
	var routes []route
	if err := chi.Walk(h.(chi.Routes), func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(pattern, "/api/v1/") {
			routes = append(routes, route{method, pattern})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(routes) < 60 {
		t.Fatalf("only %d routes walked", len(routes))
	}
	call := func(c *http.Client, method, path string) (int, string) {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf(c))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	leaks := []string{ids["cluster"], ids["target"], ids["job"], ids["vault"], ids["cr"], "prod-secret-cluster"}
	// Readable by every signed-in reader by design: global configuration
	// that cluster-scoped operators pick from (destinations, notification
	// channels; no secret material in the views; docs/security-review-v0.1.md).
	openToAll := regexp.MustCompile(`^/api/v1/(me|principals/search|notifications/catalog|destinations/\{id\}|notifications/channels/\{id\})$`)
	for _, r := range routes {
		path := fill(r.pattern, ids)
		write := r.method != http.MethodGet
		hasParam := strings.Contains(r.pattern, "{") || strings.HasSuffix(r.pattern, "*")

		if code, _ := call(nobody, r.method, path); code < 300 {
			t.Errorf("no grants: %s %s → %d", r.method, r.pattern, code)
		}
		code, body := call(outside, r.method, path)
		switch {
		case write && code < 300:
			t.Errorf("out of scope write: %s %s → %d", r.method, r.pattern, code)
		case !write && hasParam && code < 300 && !openToAll.MatchString(r.pattern):
			t.Errorf("out of scope read of a prod object: %s %s → %d", r.method, r.pattern, code)
		case !write && code < 300:
			for _, l := range leaks {
				if l != "" && strings.Contains(body, l) {
					t.Errorf("out of scope list leaks %q: %s %s", l, r.method, r.pattern)
				}
			}
		}
		if write {
			if code, _ := call(inside, r.method, path); code < 300 {
				t.Errorf("viewer (missing role) write: %s %s → %d", r.method, r.pattern, code)
			}
		}
	}
	t.Logf("%d routes × 3 principals", len(routes))
}

// fill substitutes route parameters with the seeded prod objects.
func fill(pattern string, ids map[string]string) string {
	prefixes := []struct{ prefix, key string }{
		{"/api/v1/clusters/", "cluster"}, {"/api/v1/targets/", "target"}, {"/api/v1/backup/jobs/", "job"},
		{"/api/v1/backup/runs/", "run"}, {"/api/v1/vaults/", "vault"}, {"/api/v1/change-requests/", "cr"},
		{"/api/v1/audit/schedules/", "schedule"}, {"/api/v1/audit/runs/", "audit_run"}, {"/api/v1/images/", "digest"},
		{"/api/v1/destinations/", "destination"}, {"/api/v1/notifications/channels/", "channel"},
		{"/api/v1/registries/", "registry"}, {"/api/v1/grants/", "grant"},
	}
	id := uuid.NewString()
	for _, p := range prefixes {
		if strings.HasPrefix(pattern, p.prefix) && ids[p.key] != "" {
			id = ids[p.key]
			break
		}
	}
	out := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllStringFunc(pattern, func(string) string { return url.PathEscape(id) })
	return strings.ReplaceAll(out, "/*", "/app/db")
}

func seedProd(t *testing.T, db *store.DB) map[string]string {
	t.Helper()
	ctx := context.Background()
	ids := map[string]string{}
	q := func(key, sql string, args ...any) {
		t.Helper()
		var id string
		if err := db.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		ids[key] = id
	}
	q("cluster", `INSERT INTO clusters (name, labels, status, last_seen_at) VALUES ('prod-secret-cluster', '{"env":"prod"}', 'online', now()) RETURNING id::text`)
	ids["target"] = targetid.Compute(ids["cluster"], "shop", "orders-pg", 5432)
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ($1,$2,'shop','orders-pg',5432,'postgresql')`,
		ids["target"], ids["cluster"]); err != nil {
		t.Fatal(err)
	}
	vt := targetid.Compute(ids["cluster"], "vault", "vault", 8200)
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine, vault_provider) VALUES ($1,$2,'vault','vault',8200,'vault','hashicorp')`,
		vt, ids["cluster"]); err != nil {
		t.Fatal(err)
	}
	q("destination", `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('prod-dest', 'acct', 'backups', 'p', 'managed_identity') RETURNING id::text`)
	q("job", `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone) VALUES ($1, $2, '0 2 * * *', 'UTC') RETURNING id::text`, ids["target"], ids["destination"])
	q("run", `INSERT INTO backup_runs (job_id, trigger, status, blob_path, sha256) VALUES ($1, 'manual', 'succeeded', 'p/x.zip', 'abc') RETURNING id::text`, ids["job"])
	q("vault", `INSERT INTO vaults (target_id, provider, status) VALUES ($1, 'hashicorp', 'discovered') RETURNING id::text`, vt)
	var maker uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO principals (tenant_id, object_id, upn_snapshot, display_name_snapshot, user_type, account_enabled)
		VALUES ($1, $2, 'maker@contoso.com', 'maker', 'Member', true) RETURNING id`, matrixTenant, uuid.NewString()).Scan(&maker); err != nil {
		t.Fatal(err)
	}
	q("cr", `INSERT INTO change_requests (vault_id, maker_principal_id, justification, expires_at) VALUES ($1, $2, 'rotate', now() + interval '1 day') RETURNING id::text`, ids["vault"], maker)
	q("schedule", `INSERT INTO audit_schedules (tool, cron, scope_selector) VALUES ('polaris', '0 3 * * *', 'env=prod') RETURNING id::text`)
	q("audit_run", `INSERT INTO audit_runs (schedule_id, tool, cluster_id, status) VALUES ($1, 'polaris', $2, 'succeeded') RETURNING id::text`, ids["schedule"], ids["cluster"])
	ids["digest"] = "sha256:" + strings.Repeat("ab", 32)
	if _, err := db.Exec(ctx, `INSERT INTO images (digest, repo) VALUES ($1, 'registry.prod/app')`, ids["digest"]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO image_usage (digest, cluster_id, namespace, workload_kind, workload_name, container) VALUES ($1, $2, 'shop', 'Deployment', 'api', 'api')`,
		ids["digest"], ids["cluster"]); err != nil {
		t.Fatal(err)
	}
	q("channel", `INSERT INTO notification_channels (name, slack_channel_id) VALUES ('#prod-alerts', 'C0PROD') RETURNING id::text`)
	q("registry", `INSERT INTO registries (host_pattern) VALUES ('registry.prod') RETURNING id::text`)
	q("grant", `INSERT INTO grants (principal_id, role, scope_selector) VALUES ($1, 'operator', 'env=prod') RETURNING id::text`, maker)
	return ids
}
