//go:build dev

package audit

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/findings"
	"github.com/Warewave-Technology/olympos/internal/server"
)

type apiEnv struct {
	e         *apitest.Env
	prod, dev uuid.UUID
	devBench  uuid.UUID
}

func newAPIEnv(t *testing.T) apiEnv {
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&API{DB: e.DB, Log: e.Log}}
	}})
	return apiEnv{e: e,
		prod:     addCluster(t, e.DB, "prod-1", map[string]string{"env": "prod"}, "azure", "online", false),
		dev:      addCluster(t, e.DB, "dev-1", map[string]string{"env": "dev"}, "onprem", "online", false),
		devBench: addCluster(t, e.DB, "dev-bench", map[string]string{"env": "dev"}, "onprem", "online", true),
	}
}

func TestScheduleCRUDPermissions(t *testing.T) {
	a := newAPIEnv(t)
	admin := a.e.Login(a.e.Principal("ada", "Member", "admin"))
	op := a.e.Login(a.e.Principal("otto", "Member", "operator"))
	scopedOp := a.e.Login(a.e.Principal("sam", "Member", "operator@env=prod"))
	viewer := a.e.Login(a.e.Principal("vic", "Member", "viewer@env=prod"))
	nobody := a.e.Login(a.e.Principal("nob", "Member"))

	in := map[string]any{"tool": "kubescape", "frameworks": []string{"nsa", "cis"}, "scope_selector": "env=prod", "cron": "0 3 * * *", "timezone": "Europe/Istanbul"}
	if code, body := scopedOp.Raw("POST", "/api/v1/audit/schedules", in); code != http.StatusForbidden {
		t.Fatalf("scoped operator create: %d %s", code, body)
	}
	if code, _ := viewer.Raw("POST", "/api/v1/audit/schedules", in); code != http.StatusForbidden {
		t.Fatalf("viewer create: %d", code)
	}
	var s Schedule
	if code := op.Do("POST", "/api/v1/audit/schedules", in, &s); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	if s.ID == uuid.Nil || s.Tool != "kubescape" || len(s.Frameworks) != 2 || s.ScopeSelector != "env=prod" || !s.Enabled || s.NextRunAt == nil || s.Clusters != 1 {
		t.Fatalf("schedule %+v", s)
	}

	// Validation.
	bad := []map[string]any{
		{"tool": "trivy", "cron": "0 3 * * *"},
		{"tool": "polaris", "cron": "0 3 * * *", "frameworks": []string{"nsa"}},
		{"tool": "kubescape", "cron": "0 3 * * *", "frameworks": []string{"soc2"}},
		{"tool": "kubescape", "cron": "61 3 * * *"},
		{"tool": "kubescape", "cron": "0 3 * * *", "timezone": "Mars/Base"},
		{"tool": "kubescape", "cron": "0 3 * * *", "scope_selector": "env in ("},
		{"tool": "kubescape", "cron": "0 3 * * *", "notify_channel_id": uuid.NewString()},
		{"tool": "kubescape"},
	}
	for _, b := range bad {
		if code, body := admin.Raw("POST", "/api/v1/audit/schedules", b); code != http.StatusUnprocessableEntity {
			t.Errorf("%v: %d %s", b, code, body)
		}
	}

	// List: readable by viewers; cluster count limited to their scope.
	var list struct{ Items []Schedule }
	if code := viewer.Do("GET", "/api/v1/audit/schedules", nil, &list); code != 200 || len(list.Items) != 1 {
		t.Fatalf("viewer list: %d %+v", code, list)
	}
	if code, _ := nobody.Raw("GET", "/api/v1/audit/schedules", nil); code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("no grants list: %d", code)
	}

	// Patch.
	if code, _ := scopedOp.Raw("PATCH", "/api/v1/audit/schedules/"+s.ID.String(), map[string]any{"enabled": false}); code != http.StatusForbidden {
		t.Fatalf("scoped patch: %d", code)
	}
	var p Schedule
	if code := op.Do("PATCH", "/api/v1/audit/schedules/"+s.ID.String(), map[string]any{"enabled": false, "scope_selector": "all"}, &p); code != 200 {
		t.Fatalf("patch: %d", code)
	}
	if p.Enabled || p.ScopeSelector != "all" || p.NextRunAt != nil || p.Cron != "0 3 * * *" || len(p.Frameworks) != 2 {
		t.Fatalf("patched %+v", p)
	}
	if code, _ := op.Raw("PATCH", "/api/v1/audit/schedules/"+s.ID.String(), map[string]any{"tool": "polaris"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("tool change: %d", code)
	}
	if code, _ := op.Raw("PATCH", "/api/v1/audit/schedules/"+uuid.NewString(), map[string]any{"enabled": true}); code != http.StatusNotFound {
		t.Fatalf("patch unknown: %d", code)
	}

	// Activity recorded.
	var n int
	_ = a.e.DB.QueryRow(context.Background(), `SELECT count(*) FROM activity_log WHERE action LIKE 'audit.schedule_%'`).Scan(&n)
	if n != 2 {
		t.Fatalf("activity rows %d", n)
	}

	// Delete keeps run history.
	run := addRunningRun(t, a.e.DB, s.ID, ToolKubescape, a.prod)
	if code, _ := scopedOp.Raw("DELETE", "/api/v1/audit/schedules/"+s.ID.String(), nil); code != http.StatusForbidden {
		t.Fatalf("scoped delete: %d", code)
	}
	if code, body := admin.Raw("DELETE", "/api/v1/audit/schedules/"+s.ID.String(), nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, body)
	}
	if r, err := GetRun(context.Background(), a.e.DB, run); err != nil || r.ScheduleID != nil {
		t.Fatalf("run after delete: %+v %v", r, err)
	}
	if code, _ := admin.Raw("DELETE", "/api/v1/audit/schedules/"+s.ID.String(), nil); code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", code)
	}
}

func TestRunNowScopes(t *testing.T) {
	a := newAPIEnv(t)
	ks := addSchedule(t, a.e.DB, ToolKubescape, "all", "0 3 * * *", nil)
	kb := addSchedule(t, a.e.DB, ToolKubeBench, "all", "0 3 * * *", nil)
	scopedOp := a.e.Login(a.e.Principal("sam", "Member", "operator@env=prod"))
	viewer := a.e.Login(a.e.Principal("vic", "Member", "viewer"))
	devOp := a.e.Login(a.e.Principal("dora", "Member", "operator@env=dev"))
	path := "/api/v1/audit/schedules/" + ks.String() + "/run"

	var res struct{ Items []Run }
	if code := scopedOp.Do("POST", path, map[string]any{"cluster_id": a.prod.String()}, &res); code != http.StatusAccepted {
		t.Fatalf("run prod: %d", code)
	}
	if len(res.Items) != 1 || res.Items[0].Status != "queued" || res.Items[0].ClusterName != "prod-1" || res.Items[0].Tool != "kubescape" {
		t.Fatalf("items %+v", res.Items)
	}
	first := res.Items[0].ID
	// Same request again returns the pending run instead of a duplicate.
	scopedOp.Do("POST", path, map[string]any{"cluster_id": a.prod.String()}, &res)
	if len(res.Items) != 1 || res.Items[0].ID != first {
		t.Fatalf("duplicate manual run: %+v", res.Items)
	}
	// Out of scope → 404, not 403.
	if code, _ := scopedOp.Raw("POST", path, map[string]any{"cluster_id": a.dev.String()}); code != http.StatusNotFound {
		t.Fatalf("out of scope: %d", code)
	}
	if code, _ := scopedOp.Raw("POST", path, map[string]any{"cluster_id": uuid.NewString()}); code != http.StatusNotFound {
		t.Fatalf("unknown cluster: %d", code)
	}
	// Visible but not operable → 403.
	if code, _ := viewer.Raw("POST", path, map[string]any{"cluster_id": a.prod.String()}); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	if code, _ := viewer.Raw("POST", path, nil); code != http.StatusForbidden {
		t.Fatalf("viewer all: %d", code)
	}
	// All clusters in scope ∩ operable.
	if code := devOp.Do("POST", path, nil, &res); code != http.StatusAccepted || len(res.Items) != 2 {
		t.Fatalf("dev all: %d %+v", code, res.Items)
	}
	for _, r := range res.Items {
		if r.ClusterID == a.prod {
			t.Fatal("queued a run outside the caller's scope")
		}
	}

	// kube-bench needs the agent capability.
	kbPath := "/api/v1/audit/schedules/" + kb.String() + "/run"
	code, body := devOp.Raw("POST", kbPath, map[string]any{"cluster_id": a.dev.String()})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("bench without capability: %d %s", code, body)
	}
	if code := devOp.Do("POST", kbPath, nil, &res); code != http.StatusAccepted || len(res.Items) != 1 || res.Items[0].ClusterID != a.devBench {
		t.Fatalf("bench all: %d %+v", code, res.Items)
	}
	if code, _ := scopedOp.Raw("POST", kbPath, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("bench no eligible cluster: %d", code)
	}
	if code, _ := scopedOp.Raw("POST", "/api/v1/audit/schedules/"+uuid.NewString()+"/run", nil); code != http.StatusNotFound {
		t.Fatalf("unknown schedule: %d", code)
	}
}

func TestRunsAndFindingsScoped(t *testing.T) {
	a := newAPIEnv(t)
	ctx := context.Background()
	sched := addSchedule(t, a.e.DB, ToolKubeBench, "all", "0 3 * * *", nil)
	rProd := addRunningRun(t, a.e.DB, sched, ToolKubeBench, a.prod)
	rDev := addRunningRun(t, a.e.DB, sched, ToolKubeBench, a.dev)
	if _, err := a.e.DB.Exec(ctx, `INSERT INTO bench_node_results (run_id, node_name, benchmark, state, pass, fail, control_plane_na)
		VALUES ($1, 'aks-n1', 'aks-1.8', 'succeeded', 3, 1, true)`, rProd); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		c   uuid.UUID
		run uuid.UUID
		id  string
	}{{a.prod, rProd, "aks-1.8:3.1.3"}, {a.dev, rDev, "cis-1.12:4.2.6"}} {
		run := f.run
		if _, err := findings.Open(ctx, a.e.DB, findings.Finding{Source: "kube-bench", ClusterID: f.c, ControlID: f.id, Severity: "high",
			ResourceRef: "node/x", Title: "t"}, &run); err != nil {
			t.Fatal(err)
		}
	}
	prodViewer := a.e.Login(a.e.Principal("pv", "Member", "viewer@env=prod"))
	admin := a.e.Login(a.e.Principal("ada", "Member", "admin"))

	var runs struct{ Items []Run }
	if code := prodViewer.Do("GET", "/api/v1/audit/runs", nil, &runs); code != 200 || len(runs.Items) != 1 || runs.Items[0].ID != rProd {
		t.Fatalf("scoped runs: %d %+v", code, runs.Items)
	}
	admin.Do("GET", "/api/v1/audit/runs?tool=kube-bench&cluster_id="+a.dev.String(), nil, &runs)
	if len(runs.Items) != 1 || runs.Items[0].ID != rDev {
		t.Fatalf("filtered runs %+v", runs.Items)
	}
	admin.Do("GET", "/api/v1/audit/runs?tool=polaris", nil, &runs)
	if len(runs.Items) != 0 {
		t.Fatalf("tool filter %+v", runs.Items)
	}

	var run Run
	if code := prodViewer.Do("GET", "/api/v1/audit/runs/"+rProd.String(), nil, &run); code != 200 {
		t.Fatalf("get run: %d", code)
	}
	if len(run.BenchNodes) != 1 || !run.BenchNodes[0].ControlPlaneNA || run.BenchNodes[0].Fail != 1 {
		t.Fatalf("bench nodes %+v", run.BenchNodes)
	}
	if code, _ := prodViewer.Raw("GET", "/api/v1/audit/runs/"+rDev.String(), nil); code != http.StatusNotFound {
		t.Fatalf("out-of-scope run: %d", code)
	}
	if code, _ := prodViewer.Raw("GET", "/api/v1/audit/runs/"+uuid.NewString(), nil); code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", code)
	}

	var fs struct{ Items []findings.Finding }
	if code := prodViewer.Do("GET", "/api/v1/findings", nil, &fs); code != 200 || len(fs.Items) != 1 || fs.Items[0].ClusterID != a.prod {
		t.Fatalf("scoped findings: %d %+v", code, fs.Items)
	}
	prodViewer.Do("GET", "/api/v1/findings?cluster="+a.dev.String(), nil, &fs)
	if len(fs.Items) != 0 {
		t.Fatal("out-of-scope cluster filter leaked findings")
	}
	admin.Do("GET", "/api/v1/findings?cluster=dev-1&source=kube-bench&status=open", nil, &fs)
	if len(fs.Items) != 1 || fs.Items[0].ControlID != "cis-1.12:4.2.6" {
		t.Fatalf("by name %+v", fs.Items)
	}
	admin.Do("GET", "/api/v1/findings?run_id="+rProd.String(), nil, &fs)
	if len(fs.Items) != 1 || fs.Items[0].ClusterID != a.prod {
		t.Fatalf("by run %+v", fs.Items)
	}
	admin.Do("GET", "/api/v1/findings?status=resolved", nil, &fs)
	if len(fs.Items) != 0 {
		t.Fatalf("status filter %+v", fs.Items)
	}
}

// The raw reports destination is set in the UI (Audit › Raw reports), not by
// SQL: readable by every reader, changed only by a global admin, recorded.
func TestRawReportsDestinationSetting(t *testing.T) {
	a := newAPIEnv(t)
	ctx := context.Background()
	admin := a.e.Login(a.e.Principal("ada", "Member", "admin"))
	scopedAdmin := a.e.Login(a.e.Principal("sia", "Member", "admin@env=prod"))
	viewer := a.e.Login(a.e.Principal("vic", "Member", "viewer@env=prod"))
	var dest uuid.UUID
	if err := a.e.DB.QueryRow(ctx, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('audit-raw', 'acct', 'raw', 'olympos', 'managed_identity') RETURNING id`).Scan(&dest); err != nil {
		t.Fatal(err)
	}

	var s Settings
	if code := viewer.Do("GET", "/api/v1/audit/settings", nil, &s); code != 200 || s.RawDestination != nil {
		t.Fatalf("unset: %d %+v", code, s)
	}
	set := map[string]any{"raw_destination_id": dest}
	if code, _ := viewer.Raw("PUT", "/api/v1/audit/settings", set); code != http.StatusForbidden {
		t.Fatalf("viewer put: %d", code)
	}
	if code, _ := scopedAdmin.Raw("PUT", "/api/v1/audit/settings", set); code != http.StatusForbidden {
		t.Fatalf("scoped admin put: %d", code)
	}
	if code, body := admin.Raw("PUT", "/api/v1/audit/settings", map[string]any{"raw_destination_id": uuid.New()}); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown destination: %d %s", code, body)
	}
	if code := admin.Do("PUT", "/api/v1/audit/settings", set, &s); code != 200 || s.RawDestination == nil || s.RawDestination.ID != dest || s.RawDestination.Name != "audit-raw" || s.RawDestination.Kind != "azure_blob" {
		t.Fatalf("set: %d %+v", code, s)
	}
	// The service reads the same key.
	var v string
	if err := a.e.DB.QueryRow(ctx, `SELECT value #>> '{}' FROM settings WHERE key = $1`, RawDestinationSetting).Scan(&v); err != nil || v != dest.String() {
		t.Fatalf("stored %q %v", v, err)
	}
	if code := admin.Do("PUT", "/api/v1/audit/settings", map[string]any{"raw_destination_id": nil}, &s); code != 200 || s.RawDestination != nil {
		t.Fatalf("clear: %d %+v", code, s)
	}
	var n int
	if err := a.e.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE action = 'audit.settings_changed'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("activity rows %d %v", n, err)
	}
}
