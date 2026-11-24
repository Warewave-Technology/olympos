//go:build dev

package synthetic_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/synthetic"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// canary is a credential value: it must never appear in a response, a log
// line, an activity row or an event.
const canary = "CANARY-synthetic-secret-5d1e77-never-shown"

type env struct {
	*apitest.Env
	svc *synthetic.Service
	t   *testing.T
	// clusters by name: dev-1, dev-2 (env=dev), prod-1 (env=prod).
	clusters map[string]uuid.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	var svc *synthetic.Service
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		svc = &synthetic.Service{DB: e.DB, Log: e.Log, Probes: e.Gateway, Creds: &backup.Credentials{KV: e.KV, Envelope: e.Envelope}}
		svc.OnResult = svc.ApplyOutcome
		return []server.Module{&synthetic.API{Svc: svc, Log: e.Log, TestRunsPerMinute: 2}}
	}})
	x := &env{Env: e, svc: svc, t: t, clusters: map[string]uuid.UUID{}}
	for _, c := range []struct{ name, env, probe string }{{"dev-1", "dev", "online"}, {"dev-2", "dev", "online"}, {"prod-1", "prod", "online"}} {
		x.clusters[c.name] = x.cluster(c.name, c.env, c.probe)
	}
	return x
}

func (x *env) cluster(name, envLabel, probe string) uuid.UUID {
	x.t.Helper()
	var id uuid.UUID
	labels := fmt.Sprintf(`{"env":%q,"olympos.io/cluster":%q}`, envLabel, name)
	if err := x.DB.QueryRow(context.Background(), `INSERT INTO clusters (name, labels, status, last_seen_at, probe_status, probe_last_seen_at)
		VALUES ($1, $2, 'online', now(), $3, now()) RETURNING id`, name, labels, probe).Scan(&id); err != nil {
		x.t.Fatal(err)
	}
	return id
}

func (x *env) exec(sql string, args ...any) {
	x.t.Helper()
	if _, err := x.DB.Exec(context.Background(), sql, args...); err != nil {
		x.t.Fatalf("%s: %v", sql, err)
	}
}

func (x *env) login(name string, grants ...string) *apitest.Client {
	x.t.Helper()
	return x.Login(x.Principal(name, "Member", grants...))
}

// errBody is an error response.
type errBody struct {
	Error       string            `json:"error"`
	Fields      map[string]string `json:"fields"`
	Scenarios   []string          `json:"scenarios"`
	Credentials []string          `json:"credentials"`
}

func httpStep(url string) map[string]any {
	return map[string]any{"kind": "http", "http": map[string]any{"method": "GET", "url": url},
		"assertions": []map[string]any{{"subject": "status_code", "operator": "equals", "value": "200"}}}
}

func scenarioBody(name string, steps ...map[string]any) map[string]any {
	typ := "http"
	if len(steps) > 1 {
		typ = "http_flow"
	}
	return map[string]any{"name": name, "type": typ, "interval_seconds": 60, "timeout_seconds": 10, "steps": steps}
}

func with(m map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

type scenarioResp struct {
	ID      uuid.UUID `json:"id"`
	CanEdit bool      `json:"can_edit"`
	Steps   []struct {
		Hidden bool `json:"hidden"`
		HTTP   *struct {
			Headers map[string]string `json:"headers"`
			Body    *string           `json:"body"`
		} `json:"http"`
		Credential *struct {
			Name string `json:"name"`
		} `json:"credential"`
	} `json:"steps"`
	Targets struct {
		RunsOn   int      `json:"runs_on"`
		Of       int      `json:"of"`
		Clusters []string `json:"clusters"`
		Excluded []string `json:"excluded"`
	} `json:"targets"`
}

func (x *env) createScenario(c *apitest.Client, body map[string]any) uuid.UUID {
	x.t.Helper()
	var out scenarioResp
	if code := c.Do("POST", "/api/v1/synthetic/scenarios", body, &out); code != http.StatusCreated {
		_, raw := c.Raw("POST", "/api/v1/synthetic/scenarios", body)
		x.t.Fatalf("create scenario: %d %s", code, raw)
	}
	return out.ID
}

func (x *env) addRule(c *apitest.Client, pattern, kind string) uuid.UUID {
	x.t.Helper()
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	if code := c.Do("POST", "/api/v1/synthetic/allowlist", map[string]any{"pattern": pattern, "kind": kind}, &out); code != http.StatusCreated {
		x.t.Fatalf("add rule %s: %d", pattern, code)
	}
	return out.ID
}

func (x *env) addCredential(c *apitest.Client, body map[string]any) uuid.UUID {
	x.t.Helper()
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	if code := c.Do("POST", "/api/v1/synthetic/credentials", body, &out); code != http.StatusCreated {
		_, raw := c.Raw("POST", "/api/v1/synthetic/credentials", body)
		x.t.Fatalf("add credential: %d %s", code, raw)
	}
	return out.ID
}

func bearer(name, password string, bound ...string) map[string]any {
	hosts := []map[string]any{}
	for _, b := range bound {
		kind, pattern, _ := strings.Cut(b, ":")
		hosts = append(hosts, map[string]any{"kind": kind, "pattern": pattern})
	}
	return map[string]any{"name": name, "kind": "bearer", "bound_hosts": hosts,
		"secret": map[string]any{"source": "stored", "password": password}}
}

// ---------------------------------------------------------------- hosts

func TestSaveRefusesHostsOutsideTheAllowlist(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	editor := x.login("editor", "synthetic-editor")
	x.addRule(admin, "wrw.com", "suffix")

	var e errBody
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios", scenarioBody("a", httpStep("https://api.other.io/healthz")), &e); code != 422 {
		t.Fatalf("admin, host not allowed: %d", code)
	}
	if got := e.Fields["steps.0.http.url"]; got != "Host api.other.io is not allowed. Add a rule in Settings › Synthetic monitoring." {
		t.Fatalf("admin message: %q", got)
	}
	e = errBody{}
	if code := editor.Do("POST", "/api/v1/synthetic/scenarios", scenarioBody("a", httpStep("https://API.Other.io./healthz")), &e); code != 422 {
		t.Fatalf("editor, host not allowed: %d", code)
	}
	if got := e.Fields["steps.0.http.url"]; got != "Host api.other.io is not allowed. Ask an admin to add it to the synthetic allowlist." {
		t.Fatalf("editor message: %q", got)
	}
	// DNS, TCP and TLS hosts (and SNI) are checked as well.
	for _, st := range []map[string]any{
		{"kind": "dns", "dns": map[string]any{"name": "db.other.io", "record_type": "A"}, "assertions": []any{}},
		{"kind": "tcp", "tcp": map[string]any{"host": "db.other.io", "port": 5432}, "assertions": []any{}},
		{"kind": "tls", "tls": map[string]any{"host": "api.wrw.com", "port": 443, "sni": "x.other.io"}, "assertions": []any{}},
	} {
		body := scenarioBody("a", st)
		body["type"] = st["kind"]
		e = errBody{}
		if code := admin.Do("POST", "/api/v1/synthetic/scenarios", body, &e); code != 422 || !strings.Contains(fmt.Sprint(e.Fields), "other.io is not allowed") {
			t.Fatalf("%s step: %d %v", st["kind"], code, e.Fields)
		}
	}

	// Always denied, whatever the rules: the Kubernetes API, the metadata
	// addresses, any IP literal, and a variable in the host.
	// Rules that would match the Kubernetes API names if they could match.
	x.addRule(admin, "default.svc", "suffix")
	x.addRule(admin, "cluster.local", "suffix")
	for url, want := range map[string]string{
		"https://kubernetes.default.svc/":               "always denied",
		"http://169.254.169.254/latest":                 "IP addresses are not allowed",
		"http://[fd00:ec2::254]/":                       "IP addresses are not allowed",
		"https://${host}/x":                             "variables are not allowed in the scheme, host or port",
		"https://api.wrw.com/${missing}/x":              "is not extracted by an earlier step",
		"https://api.wrw.com/a${b":                      "there is no escape",
		"https://kubernetes.default.svc.cluster.local/": "always denied",
	} {
		e = errBody{}
		if code := admin.Do("POST", "/api/v1/synthetic/scenarios", scenarioBody("a", httpStep(url)), &e); code != 422 {
			t.Fatalf("%s: %d", url, code)
		}
		if got := e.Fields["steps.0.http.url"]; !strings.Contains(got, want) {
			t.Fatalf("%s: %q, want %q", url, got, want)
		}
	}
	x.createScenario(admin, scenarioBody("ok", httpStep("https://api.wrw.com/healthz")))
}

// ---------------------------------------------------------------- scope

func TestEditorScope(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	dev := x.login("dev-editor", "synthetic-editor@env=dev")
	viewer := x.login("viewer", "viewer")
	base := scenarioBody("s", httpStep("https://api.wrw.com/"))

	expect := func(c *apitest.Client, method, path string, body any, want int) string {
		t.Helper()
		code, raw := c.Raw(method, path, body)
		if code != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, code, raw, want)
		}
		return raw
	}
	expect(viewer, "POST", "/api/v1/synthetic/scenarios", base, 403)
	// All clusters needs scope all.
	raw := expect(dev, "POST", "/api/v1/synthetic/scenarios", base, 403)
	if !strings.Contains(raw, "scope all") {
		t.Fatalf("run_on all refusal: %s", raw)
	}
	// A selector inside the scope is fine; one reaching prod is not, unless
	// prod is excluded; one matching nothing is refused.
	own := x.createScenario(dev, with(base, "run_on", "selector", "run_on_selector", "env=dev"))
	expect(dev, "POST", "/api/v1/synthetic/scenarios", with(base, "run_on", "selector", "run_on_selector", "env in (dev,prod)"), 403)
	x.createScenario(dev, with(base, "run_on", "selector", "run_on_selector", "env in (dev,prod)", "exclude_selectors", []string{"env=prod"}))
	raw = expect(dev, "POST", "/api/v1/synthetic/scenarios", with(base, "run_on", "selector", "run_on_selector", "env=nowhere"), 403)
	if !strings.Contains(raw, "matches no cluster") {
		t.Fatalf("empty selector: %s", raw)
	}
	// owner_selector is a label, not a scope.
	x.createScenario(dev, with(base, "run_on", "selector", "run_on_selector", "env=dev", "owner_selector", "env=prod"))
	expect(dev, "POST", "/api/v1/synthetic/scenarios", with(base, "run_on", "selector", "run_on_selector", "env=dev", "owner_selector", "nolabel"), 422)

	// The dev editor cannot change a scenario that runs everywhere, nor
	// move its own onto prod.
	global := x.createScenario(admin, base)
	path := "/api/v1/synthetic/scenarios/" + global.String()
	var sv scenarioResp
	if code := dev.Do("GET", path, nil, &sv); code != 200 || sv.CanEdit {
		t.Fatalf("dev editor reads the global scenario: %d can_edit=%v", code, sv.CanEdit)
	}
	expect(dev, "PUT", path, base, 403)
	expect(dev, "PATCH", path, map[string]any{"enabled": false}, 403)
	expect(dev, "DELETE", path, nil, 403)
	expect(dev, "POST", path+"/run", map[string]any{}, 403)
	ownPath := "/api/v1/synthetic/scenarios/" + own.String()
	expect(dev, "PUT", ownPath, with(base, "run_on", "selector", "run_on_selector", "env=prod"), 403)
	expect(dev, "PUT", ownPath, with(base, "name", "renamed", "run_on", "selector", "run_on_selector", "env=dev"), 200)
	expect(dev, "PATCH", ownPath, map[string]any{"enabled": false}, 200)

	// A prod-only scenario is not visible to someone who reads dev only.
	prod := x.createScenario(admin, with(base, "run_on", "selector", "run_on_selector", "env=prod"))
	devViewer := x.login("dev-viewer", "viewer@env=dev")
	expect(devViewer, "GET", "/api/v1/synthetic/scenarios/"+prod.String(), nil, 404)
	expect(dev, "DELETE", "/api/v1/synthetic/scenarios/"+prod.String(), nil, 404)
	var list struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	devViewer.Do("GET", "/api/v1/synthetic/scenarios", nil, &list)
	for _, it := range list.Items {
		if it.ID == prod {
			t.Fatal("prod scenario listed to a dev viewer")
		}
	}
	// Targets name the clusters the caller sees.
	devViewer.Do("GET", path, nil, &sv)
	if sv.Targets.RunsOn != 2 || sv.Targets.Of != 2 || slices.Contains(sv.Targets.Clusters, "prod-1") {
		t.Fatalf("targets of the global scenario for a dev viewer: %+v", sv.Targets)
	}
	expect(dev, "DELETE", ownPath, nil, 204)
}

// ---------------------------------------------------------------- credentials

func TestCredentialsAndHiddenHeaders(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	editor := x.login("editor", "synthetic-editor")
	viewer := x.login("viewer", "viewer")
	x.addRule(admin, "*.prod.wrw.com", "wildcard")
	x.addRule(admin, "login.acme.net", "exact")

	// Bound hosts must be inside the allowlist.
	var e errBody
	if code := admin.Do("POST", "/api/v1/synthetic/credentials", bearer("c", canary, "suffix:prod.wrw.com"), &e); code != 422 || e.Fields["bound_hosts.0"] == "" {
		t.Fatalf("suffix over a wildcard is not covered: %d %v", code, e.Fields)
	}
	e = errBody{}
	if code := admin.Do("POST", "/api/v1/synthetic/credentials", bearer("c", canary, "exact:api.other.io"), &e); code != 422 || e.Fields["bound_hosts.0"] == "" {
		t.Fatalf("host outside the allowlist: %d %v", code, e.Fields)
	}
	// OAuth2: the token URL is https, allowlisted and inside the bounds.
	oauth := func(tokenURL string) map[string]any {
		return map[string]any{"name": "o", "kind": "oauth2_client_credentials", "bound_hosts": []map[string]any{{"kind": "wildcard", "pattern": "*.prod.wrw.com"}},
			"oauth_token_url": tokenURL, "secret": map[string]any{"source": "stored", "username": "client", "password": canary}}
	}
	for _, u := range []string{"http://auth.prod.wrw.com/token", "https://login.acme.net/token", "https://evil.io/token"} {
		e = errBody{}
		if code := admin.Do("POST", "/api/v1/synthetic/credentials", oauth(u), &e); code != 422 || e.Fields["oauth_token_url"] == "" {
			t.Fatalf("token url %s: %d %v", u, code, e.Fields)
		}
	}
	x.addCredential(admin, oauth("https://auth.prod.wrw.com/token"))
	// A header credential that the probe would never send is refused when
	// saved: the server and the probe share spec.ReservedCredentialHeader.
	header := func(name string) map[string]any {
		return map[string]any{"name": "h-" + name, "kind": "header", "header_name": name,
			"bound_hosts": []map[string]any{{"kind": "wildcard", "pattern": "*.prod.wrw.com"}},
			"secret":      map[string]any{"source": "stored", "password": canary}}
	}
	for _, name := range spec.ReservedCredentialHeaders() {
		for _, spelled := range []string{name, strings.ToLower(name)} {
			e = errBody{}
			if code := admin.Do("POST", "/api/v1/synthetic/credentials", header(spelled), &e); code != 422 || !strings.Contains(e.Fields["header_name"], "cannot carry a credential") {
				t.Fatalf("header credential %s: %d %v", spelled, code, e.Fields)
			}
		}
	}
	x.addCredential(admin, header("X-Api-Key"))
	// Only admins write credentials.
	if code := editor.Do("POST", "/api/v1/synthetic/credentials", bearer("c", canary, "wildcard:*.prod.wrw.com"), nil); code != 403 {
		t.Fatalf("editor creates a credential: %d", code)
	}
	cred := x.addCredential(admin, bearer("catalog", canary, "wildcard:*.prod.wrw.com"))

	// A step's credential must be bound to its host.
	step := httpStep("https://api.prod.wrw.com/v1")
	step["credential_id"] = cred
	step["http"] = map[string]any{"method": "POST", "url": "https://api.prod.wrw.com/v1", "headers": map[string]string{"X-Trace": "abc"},
		"body": `{"q":1}`, "body_type": "json"}
	bad := httpStep("https://login.acme.net/")
	bad["credential_id"] = cred
	e = errBody{}
	if code := editor.Do("POST", "/api/v1/synthetic/scenarios", scenarioBody("s", bad), &e); code != 422 ||
		!strings.Contains(e.Fields["steps.0.credential_id"], "not bound to host login.acme.net") {
		t.Fatalf("credential on a host outside its bounds: %d %v", code, e.Fields)
	}
	id := x.createScenario(editor, scenarioBody("s", step))

	path := "/api/v1/synthetic/scenarios/" + id.String()
	var v scenarioResp
	viewer.Do("GET", path, nil, &v)
	if !v.Steps[0].Hidden || v.Steps[0].HTTP.Headers != nil || v.Steps[0].HTTP.Body != nil || v.Steps[0].Credential.Name != "catalog" {
		t.Fatalf("viewer sees a credentialed step: %+v", v.Steps[0])
	}
	_, raw := viewer.Raw("GET", path, nil)
	if !strings.Contains(raw, `"headers":null`) || !strings.Contains(raw, `"body":null`) || strings.Contains(raw, "X-Trace") {
		t.Fatalf("viewer body: %s", raw)
	}
	editor.Do("GET", path, nil, &v)
	if v.Steps[0].Hidden || v.Steps[0].HTTP.Headers["X-Trace"] != "abc" || v.Steps[0].HTTP.Body == nil {
		t.Fatalf("editor sees the step: %+v", v.Steps[0])
	}
	// A view sent back as it is saves (round trip).
	_, raw = editor.Raw("GET", path, nil)
	var round map[string]any
	_ = json.Unmarshal([]byte(raw), &round)
	in := scenarioBody("s", nil)
	in["steps"] = round["steps"]
	if code, raw := editor.Raw("PUT", path, in); code != 200 {
		t.Fatalf("round trip: %d %s", code, raw)
	}
	// The run detail hides the same request.
	runID := x.finishedRun(id, x.clusters["dev-1"], "passed", `{"ok":true}`)
	_, raw = viewer.Raw("GET", "/api/v1/synthetic/runs/"+runID.String(), nil)
	if strings.Contains(raw, "X-Trace") || !strings.Contains(raw, `"hidden":true`) {
		t.Fatalf("viewer run detail: %s", raw)
	}

	// Removing a credential in use: 409 naming the scenario.
	e = errBody{}
	if code := admin.Do("DELETE", "/api/v1/synthetic/credentials/"+cred.String(), nil, &e); code != 409 || !slices.Equal(e.Scenarios, []string{"s"}) {
		t.Fatalf("delete a credential in use: %d %+v", code, e)
	}
	// Narrowing its bounds off the step's host: 409 too.
	narrow := bearer("catalog", "", "exact:other.prod.wrw.com")
	delete(narrow, "secret")
	e = errBody{}
	if code := admin.Do("PUT", "/api/v1/synthetic/credentials/"+cred.String(), narrow, &e); code != 409 || !slices.Equal(e.Scenarios, []string{"s"}) {
		t.Fatalf("narrow a credential in use: %d %+v", code, e)
	}
	// Rotation keeps the metadata and replaces the secret.
	rot := bearer("catalog", canary+"-2", "wildcard:*.prod.wrw.com")
	var cv struct {
		RotatedAt *time.Time `json:"rotated_at"`
	}
	if code := admin.Do("PUT", "/api/v1/synthetic/credentials/"+cred.String(), rot, &cv); code != 200 || cv.RotatedAt == nil {
		t.Fatalf("rotate: %d %+v", code, cv)
	}
	// A past expiry is refused on update too.
	past := bearer("catalog", "", "wildcard:*.prod.wrw.com")
	delete(past, "secret")
	past["expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	e = errBody{}
	if code := admin.Do("PUT", "/api/v1/synthetic/credentials/"+cred.String(), past, &e); code != 422 || e.Fields["expires_at"] != "must be in the future" {
		t.Fatalf("update with a past expiry: %d %+v", code, e)
	}
	if code := admin.Do("DELETE", path, nil, nil); code != 204 {
		t.Fatalf("delete scenario: %d", code)
	}
	if code := admin.Do("DELETE", "/api/v1/synthetic/credentials/"+cred.String(), nil, nil); code != 204 {
		t.Fatalf("delete an unused credential: %d", code)
	}
}

// A scenario read with GET goes back with PUT as it is, and comes back the
// same; a PUT that omits enabled and store_responses keeps them.
func TestScenarioRoundTrip(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	var channel uuid.UUID
	if err := x.DB.QueryRow(context.Background(), `INSERT INTO notification_channels (name, slack_channel_id) VALUES ('#payments-alerts', 'C1')
		RETURNING id`).Scan(&channel); err != nil {
		t.Fatal(err)
	}
	cred := x.addCredential(admin, bearer("tok", canary, "suffix:wrw.com"))
	s0 := map[string]any{"kind": "dns", "dns": map[string]any{"name": "api.wrw.com", "record_type": "A"},
		"assertions": []map[string]any{{"subject": "record_count", "operator": "greater_than", "value": "0"}}}
	s1 := httpStep("https://api.wrw.com/v1")
	s1["credential_id"] = cred
	s1["http"] = map[string]any{"method": "POST", "url": "https://api.wrw.com/v1", "headers": map[string]string{"X-Trace": "1"},
		"body": `{"a":1}`, "body_type": "json", "follow_redirects": true}
	s1["extracts"] = []map[string]any{{"name": "item", "source": "json_path", "expr": "$.items[0].id"}}
	s2 := map[string]any{"kind": "tls", "tls": map[string]any{"host": "api.wrw.com", "port": 443, "sni": "www.wrw.com"},
		"assertions": []map[string]any{{"subject": "tls_days_left", "operator": "greater_than", "value": "14"}}}
	body := with(scenarioBody("flow", s0, s1, s2), "owner_selector", "team=payments", "step_retries", 1, "enabled", false,
		"store_responses", false, "exclude_selectors", []string{"env=prod"},
		"alerts", map[string]any{"cluster_fail_after": 4, "fleet_critical_clusters": 2, "recovery_after": 3, "send_recovery": false,
			"channel_id": channel, "critical_channel_id": channel})
	id := x.createScenario(admin, body)
	path := "/api/v1/synthetic/scenarios/" + id.String()
	read := func() map[string]any {
		t.Helper()
		var m map[string]any
		if code := admin.Do("GET", path, nil, &m); code != 200 {
			t.Fatalf("get: %d", code)
		}
		return m
	}
	before := read()
	if before["alerts"].(map[string]any)["channel_name"] != "#payments-alerts" {
		t.Fatalf("view: %v", before["alerts"])
	}
	// The whole GET body, read-only fields and all.
	if code, raw := admin.Raw("PUT", path, before); code != 200 {
		t.Fatalf("round trip: %d %s", code, raw)
	}
	after := read()
	delete(before, "updated_at")
	delete(after, "updated_at")
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if string(b1) != string(b2) {
		t.Fatalf("round trip changed the scenario:\n%s\n%s", b1, b2)
	}
	// enabled and store_responses omitted: kept (false), not reset to true.
	put := map[string]any{}
	for k, v := range after {
		put[k] = v
	}
	delete(put, "enabled")
	delete(put, "store_responses")
	if code, raw := admin.Raw("PUT", path, put); code != 200 {
		t.Fatalf("put without the switches: %d %s", code, raw)
	}
	if m := read(); m["enabled"] != false || m["store_responses"] != false {
		t.Fatalf("switches reset: enabled=%v store_responses=%v", m["enabled"], m["store_responses"])
	}
}

// finishedRun stores a finished run of the scenario on the cluster with
// one step result.
func (x *env) finishedRun(scenarioID, clusterID uuid.UUID, status, excerpt string) uuid.UUID {
	x.t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := x.DB.QueryRow(ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, status, started_at, finished_at, total_ms, probe_ip)
		VALUES ($1, $2, 'running', now(), NULL, NULL, '') RETURNING id`, scenarioID, clusterID).Scan(&id); err != nil {
		x.t.Fatal(err)
	}
	x.exec(`INSERT INTO synthetic_step_results (run_id, position, status, status_code, timings, assertions, excerpt)
		VALUES ($1, 0, $2, 200, '{"total_us":1000}', '[]', $3)`, id, status, []byte(excerpt))
	x.exec(`UPDATE synthetic_runs SET status = $2, finished_at = now(), total_ms = 12 WHERE id = $1`, id, status)
	return id
}

func TestCanaryNeverInAnyResponse(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	editor := x.login("editor", "synthetic-editor")
	viewer := x.login("viewer", "viewer")
	x.addRule(admin, "wrw.com", "suffix")

	var bodies []string
	keep := func(code int, raw string) {
		if code >= 500 {
			t.Fatalf("server error: %s", raw)
		}
		bodies = append(bodies, raw)
	}
	keep(admin.Raw("POST", "/api/v1/synthetic/credentials", bearer("b", canary, "suffix:wrw.com")))
	basic := map[string]any{"name": "u", "kind": "basic", "bound_hosts": []map[string]any{{"kind": "suffix", "pattern": "wrw.com"}},
		"secret": map[string]any{"source": "stored", "username": "monitor", "password": canary}}
	keep(admin.Raw("POST", "/api/v1/synthetic/credentials", basic))
	// A refused input echoes nothing of the secret either.
	keep(admin.Raw("POST", "/api/v1/synthetic/credentials", map[string]any{"name": "", "kind": "bearer", "bound_hosts": []any{},
		"secret": map[string]any{"source": "stored", "password": canary}}))
	var list struct {
		Items []struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		} `json:"items"`
	}
	admin.Do("GET", "/api/v1/synthetic/credentials", nil, &list)
	if len(list.Items) != 2 {
		t.Fatalf("credentials: %+v", list.Items)
	}
	keep(admin.Raw("PUT", "/api/v1/synthetic/credentials/"+list.Items[0].ID.String(), bearer("b", canary+"x", "suffix:wrw.com")))
	step := httpStep("https://api.wrw.com/")
	step["credential_id"] = list.Items[0].ID
	id := x.createScenario(editor, scenarioBody("s", step))
	run := x.finishedRun(id, x.clusters["dev-1"], "passed", "HTTP/1.1 200 OK")
	for _, c := range []*apitest.Client{admin, editor, viewer} {
		for _, p := range []string{"/api/v1/synthetic/credentials", "/api/v1/synthetic/allowlist", "/api/v1/synthetic/overview",
			"/api/v1/synthetic/scenarios", "/api/v1/synthetic/scenarios/" + id.String(), "/api/v1/synthetic/scenarios/" + id.String() + "/clusters",
			"/api/v1/synthetic/scenarios/" + id.String() + "/alerts", "/api/v1/synthetic/runs", "/api/v1/synthetic/runs/" + run.String(),
			"/api/v1/activity", "/api/v1/clusters"} {
			keep(c.Raw("GET", p, nil))
		}
	}
	for _, b := range bodies {
		if strings.Contains(b, canary) {
			t.Fatalf("canary in a response: %s", b)
		}
	}
	if strings.Contains(x.LogBuf.String(), canary) {
		t.Fatal("canary in the logs")
	}
	var leaks int
	if err := x.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM activity_log WHERE details::text LIKE '%' || $1 || '%')
		+ (SELECT count(*) FROM outbox WHERE payload::text LIKE '%' || $1 || '%')
		+ (SELECT count(*) FROM synthetic_credentials WHERE row_to_json(synthetic_credentials)::text LIKE '%' || $1 || '%')
		+ (SELECT count(*) FROM credentials WHERE row_to_json(credentials)::text LIKE '%' || $1 || '%')`, canary).Scan(&leaks); err != nil {
		t.Fatal(err)
	}
	if leaks > 0 {
		t.Fatalf("canary stored in plain text in %d rows", leaks)
	}
}

// ---------------------------------------------------------------- allowlist

func TestAllowlistChangesAreRecordedAndAnnounced(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	editor := x.login("editor", "synthetic-editor")
	if code := editor.Do("POST", "/api/v1/synthetic/allowlist", map[string]any{"pattern": "wrw.com", "kind": "suffix"}, nil); code != 403 {
		t.Fatalf("editor adds a rule: %d", code)
	}
	var e errBody
	for _, in := range []map[string]any{{"pattern": "169.254.169.254", "kind": "exact"}, {"pattern": "com", "kind": "suffix"},
		{"pattern": "a.*.com", "kind": "wildcard"}, {"pattern": "x.com", "kind": "regex"}} {
		if code := admin.Do("POST", "/api/v1/synthetic/allowlist", in, &e); code != 422 {
			t.Fatalf("invalid rule %v: %d", in, code)
		}
	}
	id := x.addRule(admin, "WRW.com.", "suffix")
	if code := admin.Do("POST", "/api/v1/synthetic/allowlist", map[string]any{"pattern": "wrw.com", "kind": "suffix"}, &e); code != 422 {
		t.Fatalf("duplicate rule: %d", code)
	}
	ctx := context.Background()
	var pattern string
	if err := x.DB.QueryRow(ctx, `SELECT pattern FROM synthetic_allowlist WHERE id = $1`, id).Scan(&pattern); err != nil || pattern != "wrw.com" {
		t.Fatalf("stored pattern %q %v", pattern, err)
	}
	if code := admin.Do("DELETE", "/api/v1/synthetic/allowlist/"+id.String(), nil, nil); code != 204 {
		t.Fatalf("remove an unused rule: %d", code)
	}
	var acts, events int
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE object_id = $1
		AND action IN ('synthetic.allowlist_rule_added','synthetic.allowlist_rule_removed') AND actor_principal_id IS NOT NULL`, id.String()).Scan(&acts); err != nil {
		t.Fatal(err)
	}
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type = 'synthetic.allowlist_changed'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if acts != 2 || events != 2 {
		t.Fatalf("activity %d, events %d; want 2 and 2", acts, events)
	}

	// Check a host.
	x.addRule(admin, "wrw.com", "suffix")
	x.addRule(admin, "*.prod.wrw.com", "wildcard")
	var chk struct {
		Host    string `json:"host"`
		Allowed bool   `json:"allowed"`
		Rule    *struct {
			Pattern string `json:"pattern"`
		} `json:"rule"`
		Also []struct {
			Pattern string `json:"pattern"`
		} `json:"also"`
		DeniedReason string `json:"denied_reason"`
	}
	editor.Do("POST", "/api/v1/synthetic/allowlist/check", map[string]any{"host": "API.prod.wrw.com"}, &chk)
	if !chk.Allowed || chk.Host != "api.prod.wrw.com" || chk.Rule == nil || len(chk.Also) != 1 {
		t.Fatalf("check allowed host: %+v", chk)
	}
	for host, reason := range map[string]string{"wrw.com.evil.io": "no_rule", "169.254.169.254": "ip_literal",
		"kubernetes.default.svc": "always_denied", "https://xwrw.com/path": "no_rule"} {
		chk.Rule, chk.Also = nil, nil
		editor.Do("POST", "/api/v1/synthetic/allowlist/check", map[string]any{"host": host}, &chk)
		if chk.Allowed || chk.DeniedReason != reason {
			t.Fatalf("check %s: %+v", host, chk)
		}
	}
}

func TestRemovingARuleInUse(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	suffix := x.addRule(admin, "wrw.com", "suffix")
	exact := x.addRule(admin, "api.wrw.com", "exact")
	x.createScenario(admin, scenarioBody("checkout", httpStep("https://checkout.wrw.com/")))
	x.createScenario(admin, scenarioBody("api", httpStep("https://api.wrw.com/")))

	// The exact rule is redundant: wrw.com still allows api.wrw.com.
	if code := admin.Do("DELETE", "/api/v1/synthetic/allowlist/"+exact.String(), nil, nil); code != 204 {
		t.Fatalf("remove a redundant rule: %d", code)
	}
	var e errBody
	if code := admin.Do("DELETE", "/api/v1/synthetic/allowlist/"+suffix.String(), nil, &e); code != 409 {
		t.Fatalf("remove a rule in use: %d", code)
	}
	if !slices.Equal(e.Scenarios, []string{"api", "checkout"}) || !strings.Contains(e.Error, "api, checkout") {
		t.Fatalf("409 names the scenarios: %+v", e)
	}
	// A credential bound inside the rule keeps it too.
	x2 := newEnv(t)
	admin2 := x2.login("admin", "admin")
	r := x2.addRule(admin2, "wrw.com", "suffix")
	x2.addCredential(admin2, bearer("tok", canary, "exact:api.wrw.com"))
	e = errBody{}
	if code := admin2.Do("DELETE", "/api/v1/synthetic/allowlist/"+r.String(), nil, &e); code != 409 || !slices.Equal(e.Credentials, []string{"tok"}) {
		t.Fatalf("remove a rule a credential needs: %d %+v", code, e)
	}
}

// ---------------------------------------------------------------- caps

func TestRateCapOnSave(t *testing.T) {
	x := newEnv(t)
	x.svc.Cfg.MaxRequestsPerMinutePerCluster = 20
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	// 1 step × (1 + 5 redirects) × 60 / 30 = 12 per minute.
	step := httpStep("https://api.wrw.com/")
	step["http"] = map[string]any{"method": "GET", "url": "https://api.wrw.com/", "follow_redirects": true}
	body := with(scenarioBody("first", step), "interval_seconds", 30)
	x.createScenario(admin, body)
	var e errBody
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios", with(body, "name", "second"), &e); code != 422 {
		t.Fatalf("second scenario over the cluster cap: %d", code)
	}
	if msg := e.Fields["interval_seconds"]; !strings.Contains(msg, "dev-1") || !strings.Contains(msg, "dev-2") || !strings.Contains(msg, "prod-1") {
		t.Fatalf("cap message names the clusters: %q", msg)
	}
	// Paused, it saves; resuming is refused the same way.
	var created scenarioResp
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios", with(body, "name", "second", "enabled", false), &created); code != 201 {
		t.Fatalf("paused scenario: %d", code)
	}
	if code := admin.Do("PATCH", "/api/v1/synthetic/scenarios/"+created.ID.String(), map[string]any{"enabled": true}, &e); code != 422 {
		t.Fatalf("resume over the cap: %d", code)
	}
	// Excluding the clusters makes room.
	x.createScenario(admin, with(body, "name", "third", "exclude_selectors", []string{"env=dev", "env=prod"}))
	// Over the per-scenario cap by itself: 10 × 3 × 6 × 2 = 360.
	steps := []map[string]any{}
	for range 10 {
		steps = append(steps, step)
	}
	big := with(scenarioBody("big", steps...), "interval_seconds", 30, "step_retries", 2)
	e = errBody{}
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios", big, &e); code != 422 || !strings.Contains(e.Fields["interval_seconds"], "the cap is 120") {
		t.Fatalf("per-scenario cap: %d %v", code, e.Fields)
	}
	var pv struct {
		RunsOn          int  `json:"runs_on"`
		OverScenarioCap bool `json:"over_scenario_cap"`
		OverLimit       []struct {
			Cluster string `json:"cluster"`
		} `json:"over_limit"`
	}
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios/preview", big, &pv); code != 200 || !pv.OverScenarioCap || pv.RunsOn != 3 {
		t.Fatalf("preview: %d %+v", code, pv)
	}
	admin.Do("POST", "/api/v1/synthetic/scenarios/preview", with(body, "name", "x"), &pv)
	if len(pv.OverLimit) != 3 {
		t.Fatalf("preview over the cluster cap: %+v", pv)
	}
}

// ---------------------------------------------------------------- taint

// The credentials ValidateTaint is given at save are those a run seals for
// the probe (CredentialIDs of the stored scenario).
func TestTaintBoundsAreTheRunCredentials(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	a := x.addCredential(admin, bearer("a", canary, "exact:a.wrw.com"))
	b := x.addCredential(admin, bearer("b", canary, "exact:b.wrw.com"))
	s0 := httpStep("https://a.wrw.com/login")
	s0["credential_id"] = a
	s0["extracts"] = []map[string]any{{"name": "tok", "source": "header", "expr": "X-Token"}}
	s1 := httpStep("https://b.wrw.com/x")
	s1["credential_id"] = b
	s2 := httpStep("https://a.wrw.com/again")
	s2["credential_id"] = a
	id := x.createScenario(admin, scenarioBody("flow", s0, s1, s2))
	sc, err := synthetic.LoadScenario(context.Background(), x.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	// What the API gave ValidateTaint: CredentialIDs of the input steps.
	input := &spec.Scenario{Steps: []spec.Step{{CredentialID: &a}, {CredentialID: &b}, {CredentialID: &a}}}
	if got, want := synthetic.CredentialIDs(sc), synthetic.CredentialIDs(input); !slices.Equal(got, want) || !slices.Equal(got, []uuid.UUID{a, b}) {
		t.Fatalf("run credentials %v, save-time credentials %v, want [a b]", got, want)
	}
	// ${tok} carries credential a: it may not go to b.wrw.com.
	s1["http"] = map[string]any{"method": "GET", "url": "https://b.wrw.com/${tok}"}
	var e errBody
	if code := admin.Do("PUT", "/api/v1/synthetic/scenarios/"+id.String(), scenarioBody("flow", s0, s1, s2), &e); code != 422 ||
		!strings.Contains(e.Fields["steps.1.http.url"], "credential a") {
		t.Fatalf("tainted variable to another host: %d %v", code, e.Fields)
	}
}

// ---------------------------------------------------------------- results

func TestOverviewCells(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	offline := x.cluster("off-1", "dev", "offline")
	none := x.cluster("none-1", "dev", "not_installed")
	excluded := x.cluster("lab-1", "lab", "online")
	id := x.createScenario(admin, with(scenarioBody("s", httpStep("https://api.wrw.com/")), "exclude_selectors", []string{"env=lab"}))
	paused := x.createScenario(admin, with(scenarioBody("p", httpStep("https://api.wrw.com/")), "enabled", false))
	ctx := context.Background()
	// dev-1 fails with an alert, dev-2 failed once, prod-1 passes.
	r1 := x.finishedRun(id, x.clusters["dev-1"], "failed", "")
	r2 := x.finishedRun(id, x.clusters["dev-2"], "failed", "")
	r3 := x.finishedRun(id, x.clusters["prod-1"], "passed", "")
	for c, r := range map[uuid.UUID]uuid.UUID{x.clusters["dev-1"]: r1, x.clusters["dev-2"]: r2, x.clusters["prod-1"]: r3} {
		var status string
		_ = x.DB.QueryRow(ctx, `SELECT status FROM synthetic_runs WHERE id = $1`, r).Scan(&status)
		x.exec(`INSERT INTO synthetic_state (scenario_id, cluster_id, consecutive_failures, last_run_id, last_status, last_finished_at)
			VALUES ($1, $2, $3, $4, $5, now())`, id, c, map[string]int{"failed": 1, "passed": 0}[status], r, status)
	}
	x.exec(`INSERT INTO synthetic_alerts (scenario_id, cluster_id, state, reason, last_run_id) VALUES ($1, $2, 'firing', 'timeout', $3)`, id, x.clusters["dev-1"], r1)

	var ov struct {
		KPIs struct {
			Scenarios         int      `json:"scenarios"`
			Active            int      `json:"active"`
			Paused            int      `json:"paused"`
			FailingScenarios  int      `json:"failing_scenarios"`
			FailingClusters   int      `json:"failing_clusters"`
			DegradedScenarios int      `json:"degraded_scenarios"`
			ProbesOnline      int      `json:"probes_online"`
			ProbesTotal       int      `json:"probes_total"`
			ProbesOffline     []string `json:"probes_offline"`
		} `json:"kpis"`
		Scenarios []struct {
			ID     uuid.UUID `json:"id"`
			Status string    `json:"status"`
			Cells  []struct {
				ClusterID uuid.UUID `json:"cluster_id"`
				State     string    `json:"state"`
			} `json:"cells"`
			Availability24h *float64 `json:"availability_24h"`
		} `json:"scenarios"`
	}
	raw := ""
	admin.Do("GET", "/api/v1/synthetic/overview", nil, &ov)
	_, raw = admin.Raw("GET", "/api/v1/synthetic/overview", nil)
	want := map[uuid.UUID]string{x.clusters["dev-1"]: "failing", x.clusters["dev-2"]: "degraded", x.clusters["prod-1"]: "passing",
		offline: "probe_offline", none: "not_installed", excluded: "excluded"}
	for _, s := range ov.Scenarios {
		for _, c := range s.Cells {
			switch s.ID {
			case id:
				if want[c.ClusterID] != c.State {
					t.Fatalf("cell %s: %s, want %s (%s)", c.ClusterID, c.State, want[c.ClusterID], raw)
				}
			case paused:
				if c.State != "paused" && c.State != "excluded" {
					t.Fatalf("paused scenario cell: %s", c.State)
				}
			}
		}
		if s.ID == id && (s.Status != "failing" || s.Availability24h == nil || *s.Availability24h != 33.33) {
			t.Fatalf("scenario status %s availability %v", s.Status, s.Availability24h)
		}
	}
	k := ov.KPIs
	if k.Scenarios != 2 || k.Active != 1 || k.Paused != 1 || k.FailingScenarios != 1 || k.FailingClusters != 1 ||
		k.ProbesOnline != 4 || k.ProbesTotal != 6 || !slices.Equal(k.ProbesOffline, []string{"off-1"}) {
		t.Fatalf("kpis: %+v", k)
	}

	var cl struct {
		Items []struct {
			ClusterName string `json:"cluster_name"`
			State       string `json:"state"`
			Timeline    []struct {
				State string `json:"state"`
			} `json:"timeline"`
			LastRun *struct {
				Status string `json:"status"`
			} `json:"last_run"`
		} `json:"items"`
	}
	if code := admin.Do("GET", "/api/v1/synthetic/scenarios/"+id.String()+"/clusters", nil, &cl); code != 200 || len(cl.Items) != 6 {
		t.Fatalf("clusters: %d %+v", code, cl)
	}
	for _, it := range cl.Items {
		if len(it.Timeline) != 48 {
			t.Fatalf("timeline of %s: %d buckets", it.ClusterName, len(it.Timeline))
		}
		if it.ClusterName == "dev-1" && (it.State != "failing" || it.LastRun == nil || it.Timeline[47].State != "failed") {
			t.Fatalf("dev-1 row: %+v", it)
		}
	}
	var al struct {
		Items []struct {
			ClusterName string `json:"cluster_name"`
			State       string `json:"state"`
		} `json:"items"`
	}
	admin.Do("GET", "/api/v1/synthetic/scenarios/"+id.String()+"/alerts", nil, &al)
	if len(al.Items) != 1 || al.Items[0].ClusterName != "dev-1" || al.Items[0].State != "firing" {
		t.Fatalf("alerts: %+v", al)
	}
	var runs struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	devViewer := x.login("dev-viewer", "viewer@env=dev")
	devViewer.Do("GET", "/api/v1/synthetic/runs?scenario_id="+id.String(), nil, &runs)
	if len(runs.Items) != 2 {
		t.Fatalf("a dev viewer sees the dev runs only: %+v", runs)
	}
	if code := devViewer.Do("GET", "/api/v1/synthetic/runs/"+r3.String(), nil, nil); code != 404 {
		t.Fatalf("a dev viewer reads a prod run: %d", code)
	}
	var rd struct {
		ConsecutiveFailures int `json:"consecutive_failures"`
		Alert               *struct {
			State string `json:"state"`
		} `json:"alert"`
		Definition string `json:"definition"`
		Steps      []struct {
			Status  string          `json:"status"`
			Request json.RawMessage `json:"request"`
		} `json:"steps"`
	}
	if code := devViewer.Do("GET", "/api/v1/synthetic/runs/"+r1.String(), nil, &rd); code != 200 || rd.ConsecutiveFailures != 1 ||
		rd.Alert == nil || rd.Definition != "saved" || len(rd.Steps) != 1 || rd.Steps[0].Status != "failed" {
		t.Fatalf("run detail: %d %+v", code, rd)
	}
}

// ---------------------------------------------------------------- run now, test runs

func TestRunNowAndTestRuns(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	body := scenarioBody("s", httpStep("https://api.wrw.com/"))
	id := x.createScenario(admin, body)
	var out struct {
		RunIDs []uuid.UUID `json:"run_ids"`
		RunID  uuid.UUID   `json:"run_id"`
	}
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios/"+id.String()+"/run", map[string]any{"cluster_id": x.clusters["dev-1"]}, &out); code != 202 || len(out.RunIDs) != 1 {
		t.Fatalf("run now on one cluster: %d %+v", code, out)
	}
	x.exec(`UPDATE clusters SET probe_status = 'offline'`)
	var e errBody
	if code := admin.Do("POST", "/api/v1/synthetic/scenarios/"+id.String()+"/run", nil, &e); code != 409 || !strings.Contains(e.Error, "no cluster") {
		t.Fatalf("run now with every probe offline: %d %+v", code, e)
	}
	devEditor := x.login("dev-editor", "synthetic-editor@env=dev")
	// A test run that makes no run uses up no slot (TestRunsPerMinute is
	// 2 in this env).
	for range 3 {
		if code := devEditor.Do("POST", "/api/v1/synthetic/test-runs", map[string]any{"scenario": body, "cluster_id": x.clusters["dev-1"]}, &e); code != 409 {
			t.Fatalf("test run on an offline probe: %d", code)
		}
	}
	x.exec(`UPDATE clusters SET probe_status = 'online'`)

	// A cluster the editor cannot read is unknown to it.
	if code := devEditor.Do("POST", "/api/v1/synthetic/test-runs", map[string]any{"scenario": body, "cluster_id": x.clusters["prod-1"]}, nil); code != 422 {
		t.Fatalf("test run outside the editor's scope: %d", code)
	}
	// One it reads but does not edit on is refused.
	devReader := x.login("dev-reader", "synthetic-editor@env=dev", "viewer@env=prod")
	if code := devReader.Do("POST", "/api/v1/synthetic/test-runs", map[string]any{"scenario": body, "cluster_id": x.clusters["prod-1"]}, nil); code != 403 {
		t.Fatalf("test run on a cluster read but not edited: %d", code)
	}
	bad := scenarioBody("s", httpStep("https://other.io/"))
	if code := devEditor.Do("POST", "/api/v1/synthetic/test-runs", map[string]any{"scenario": bad, "cluster_id": x.clusters["dev-1"]}, &e); code != 422 {
		t.Fatalf("test run of a host outside the allowlist: %d", code)
	}
	// TestRunsPerMinute is 2 in this env.
	for i := range 3 {
		code := devEditor.Do("POST", "/api/v1/synthetic/test-runs", map[string]any{"scenario": body, "cluster_id": x.clusters["dev-1"]}, &out)
		want := 202
		if i == 2 {
			want = 429
		}
		if code != want {
			t.Fatalf("test run %d: %d, want %d", i, code, want)
		}
	}
	var test bool
	if err := x.DB.QueryRow(context.Background(), `SELECT test FROM synthetic_runs WHERE id = $1`, out.RunID).Scan(&test); err != nil || !test {
		t.Fatalf("test run stored: %v %v", test, err)
	}
}

// Run now is limited per user (6 a minute by default), like test runs: a
// request that makes no run uses up no slot, and one user's limit does not
// hold another back.
func TestRunNowRateLimit(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	x.addRule(admin, "wrw.com", "suffix")
	id := x.createScenario(admin, scenarioBody("s", httpStep("https://api.wrw.com/")))
	path := "/api/v1/synthetic/scenarios/" + id.String() + "/run"
	one := map[string]any{"cluster_id": x.clusters["dev-1"]}

	x.exec(`UPDATE clusters SET probe_status = 'offline'`)
	for range 7 {
		if code := admin.Do("POST", path, one, nil); code != 409 {
			t.Fatalf("run now on an offline probe: %d", code)
		}
	}
	x.exec(`UPDATE clusters SET probe_status = 'online'`)
	for i := range 6 {
		if code := admin.Do("POST", path, one, nil); code != 202 {
			t.Fatalf("run now %d: %d", i, code)
		}
	}
	var e errBody
	if code := admin.Do("POST", path, nil, &e); code != 429 || !strings.Contains(e.Error, "At most 6 Run now requests a minute") {
		t.Fatalf("seventh run now: %d %+v", code, e)
	}
	other := x.login("admin-2", "admin")
	if code := other.Do("POST", path, one, nil); code != 202 {
		t.Fatalf("another user's run now: %d", code)
	}
}

// ---------------------------------------------------------------- inventory

// A reissued add cluster command (POST /clusters/{id}/token) enrolls the
// probe only on a cluster that has none: once a probe is enrolled (pending,
// online or offline) its token is for the agent alone, so the command
// cannot enroll a second, rogue probe. A probe is replaced with Install
// probe.
func TestReissuedTokenEnrollsNoSecondProbe(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	ctx := context.Background()
	var added struct {
		Cluster struct {
			ID uuid.UUID `json:"id"`
		} `json:"cluster"`
	}
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "re-1"}, &added); code != 201 {
		t.Fatalf("add cluster: %d", code)
	}
	id := added.Cluster.ID
	x.exec(`UPDATE clusters SET status = 'online' WHERE id = $1`, id)
	tokenRe := regexp.MustCompile(`--set bootstrapToken=(\S+)`)
	for _, c := range []struct {
		probe string
		want  []string
	}{
		{"not_installed", []string{"agent", "probe"}},
		{"pending", []string{"agent"}},
		{"online", []string{"agent"}},
		{"offline", []string{"agent"}},
		{"revoked", []string{"agent", "probe"}},
	} {
		x.exec(`UPDATE clusters SET probe_status = $2 WHERE id = $1`, id, c.probe)
		var inst struct {
			Command string `json:"command"`
		}
		if code := admin.Do("POST", "/api/v1/clusters/"+id.String()+"/token", nil, &inst); code != 200 {
			t.Fatalf("token with probe %s: %d", c.probe, code)
		}
		m := tokenRe.FindStringSubmatch(inst.Command)
		if m == nil {
			t.Fatalf("no token in %q", inst.Command)
		}
		var roles []string
		if err := x.DB.QueryRow(ctx, `SELECT roles FROM enroll_tokens WHERE token_hash = $1`, gateway.HashToken(m[1])).Scan(&roles); err != nil || !slices.Equal(roles, c.want) {
			t.Fatalf("probe %s: token roles %v (%v), want %v", c.probe, roles, err, c.want)
		}
		// Only the new token is live.
		var live int
		if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM enroll_tokens WHERE cluster_id = $1 AND expires_at > now()`, id).Scan(&live); err != nil || live != 1 {
			t.Fatalf("probe %s: %d live tokens, %v", c.probe, live, err)
		}
	}
}

func TestProbeTokenAndRevoke(t *testing.T) {
	x := newEnv(t)
	admin := x.login("admin", "admin")
	ctx := context.Background()
	var added struct {
		Cluster struct {
			ID          uuid.UUID `json:"id"`
			ProbeStatus string    `json:"probe_status"`
		} `json:"cluster"`
	}
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "new-1"}, &added); code != 201 || added.Cluster.ProbeStatus != "not_installed" {
		t.Fatalf("add cluster: %d %+v", code, added)
	}
	id := added.Cluster.ID
	var roles []string
	if err := x.DB.QueryRow(ctx, `SELECT roles FROM enroll_tokens WHERE cluster_id = $1`, id).Scan(&roles); err != nil || !slices.Equal(roles, []string{"agent", "probe"}) {
		t.Fatalf("add cluster token roles %v %v", roles, err)
	}
	// Ruling P24: no probe token while the cluster waits for its first agent;
	// the add cluster token keeps both roles.
	var pe errBody
	if code := admin.Do("POST", "/api/v1/clusters/"+id.String()+"/probe-token", nil, &pe); code != 409 || !strings.Contains(pe.Error, "already installs the probe") {
		t.Fatalf("probe token for a pending cluster: %d %+v", code, pe)
	}
	if err := x.DB.QueryRow(ctx, `SELECT roles FROM enroll_tokens WHERE cluster_id = $1`, id).Scan(&roles); err != nil || !slices.Equal(roles, []string{"agent", "probe"}) {
		t.Fatalf("add cluster token roles after a refused probe token %v %v", roles, err)
	}
	// From here the cluster is enrolled (its install token left unused, so
	// the withdrawal below still has an agent role to keep).
	x.exec(`UPDATE clusters SET status = 'online' WHERE id = $1`, id)
	var inst struct {
		Command string `json:"command"`
	}
	if code := admin.Do("POST", "/api/v1/clusters/"+id.String()+"/probe-token", nil, &inst); code != 200 {
		t.Fatalf("probe token: %d", code)
	}
	const prefix = "helm upgrade olympos-agent oci://ghcr.io/warewave-technology/charts/olympos-agent -n olympos-system --reuse-values --set probe.enabled=true --set probe.bootstrapToken="
	if !strings.HasPrefix(inst.Command, prefix) {
		t.Fatalf("command: %q", inst.Command)
	}
	token := strings.TrimPrefix(inst.Command, prefix)
	if err := x.DB.QueryRow(ctx, `SELECT roles FROM enroll_tokens WHERE token_hash = $1`, gateway.HashToken(token)).Scan(&roles); err != nil || !slices.Equal(roles, []string{"probe"}) {
		t.Fatalf("probe token roles %v %v", roles, err)
	}
	// The install token keeps its agent role and loses the probe's.
	var live int
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM enroll_tokens WHERE cluster_id = $1 AND expires_at > now() AND 'probe' = ANY(roles)`, id).Scan(&live); err != nil || live != 1 {
		t.Fatalf("probe-capable live tokens: %d %v", live, err)
	}
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM enroll_tokens WHERE cluster_id = $1 AND expires_at > now() AND roles = '{agent}'`, id).Scan(&live); err != nil || live != 1 {
		t.Fatalf("agent token kept: %d %v", live, err)
	}
	editor := x.login("editor", "synthetic-editor")
	if code := editor.Do("POST", "/api/v1/clusters/"+id.String()+"/probe-token", nil, nil); code != 403 {
		t.Fatalf("editor issues a probe token: %d", code)
	}

	// No probe yet: nothing to revoke, nothing changes (ruling P17).
	var e errBody
	if code := admin.Do("DELETE", "/api/v1/clusters/"+id.String()+"/probe", nil, &e); code != 409 || e.Error != "no probe installed" {
		t.Fatalf("revoke a probe never installed: %d %+v", code, e)
	}
	var probeStatus string
	if err := x.DB.QueryRow(ctx, `SELECT probe_status FROM clusters WHERE id = $1`, id).Scan(&probeStatus); err != nil || probeStatus != "not_installed" {
		t.Fatalf("probe status after a refused revoke: %q %v", probeStatus, err)
	}
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM enroll_tokens WHERE cluster_id = $1 AND expires_at > now() AND 'probe' = ANY(roles)`, id).Scan(&live); err != nil || live != 1 {
		t.Fatalf("probe token kept after a refused revoke: %d %v", live, err)
	}
	x.exec(`UPDATE clusters SET probe_status = 'online', probe_cert_serial = 'abc123' WHERE id = $1`, id)
	if code := admin.Do("DELETE", "/api/v1/clusters/"+id.String()+"/probe", nil, nil); code != 204 {
		t.Fatalf("revoke probe: %d", code)
	}
	var c struct {
		Status      string `json:"status"`
		ProbeStatus string `json:"probe_status"`
	}
	admin.Do("GET", "/api/v1/clusters/"+id.String(), nil, &c)
	if c.ProbeStatus != "revoked" || c.Status == "revoked" {
		t.Fatalf("after probe revoke: %+v", c)
	}
	var revoked, acts int
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM revoked_certs WHERE serial = 'abc123'`).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatalf("probe serial revoked: %d %v", revoked, err)
	}
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM enroll_tokens WHERE cluster_id = $1 AND expires_at > now() AND 'probe' = ANY(roles)`, id).Scan(&live); err != nil || live != 0 {
		t.Fatalf("probe tokens after revoke: %d %v", live, err)
	}
	if err := x.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE object_id = $1 AND action IN ('cluster.probe_token_issued','cluster.probe_revoked')`,
		id.String()).Scan(&acts); err != nil || acts != 2 {
		t.Fatalf("activity: %d %v", acts, err)
	}
	// /me tells the SPA who edits scenarios.
	var me struct {
		Permissions map[string]bool `json:"permissions"`
	}
	editor.Do("GET", "/api/v1/me", nil, &me)
	if !me.Permissions["synthetic_edit"] || !me.Permissions["synthetic_edit_global"] {
		t.Fatalf("me: %+v", me.Permissions)
	}
}
