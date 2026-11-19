//go:build dev

package inventory_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

func TestProviderAndVersions(t *testing.T) {
	for in, want := range map[string]string{"azure:///sub/x": "azure", "aws:///eu-west-1a/i-1": "aws", "gce://p/z/n": "gcp",
		"oci://ocid1": "oracle", "huaweicloud://x": "huawei", "": "onprem", "kind://docker/x": "onprem"} {
		if got := inventory.DetectProvider(in); got != want {
			t.Errorf("%q: %s", in, got)
		}
	}
	if inventory.Minor("v1.31.4-gke.100") != 31 || inventory.Minor("garbage") != 0 {
		t.Fatal("minor parsing")
	}
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	if !inventory.IsEOL(29, now) || inventory.IsEOL(36, now) || !inventory.IsEOL(20, now) || inventory.IsEOL(40, now) {
		t.Fatal("eol table")
	}
}

func TestIngestAndDashboardScope(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	ctx := context.Background()
	admin := e.Login(e.Principal("admin", "Member", "admin"))

	var created inventory.InstallResponse
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "prod-aks-weu-01", "labels": map[string]string{"env": "prod"}}, &created); code != 201 {
		t.Fatal(code)
	}
	if !strings.Contains(created.Command, "--set bootstrapToken=olyb_") || !strings.Contains(created.Command, "--set serverCA=") {
		t.Fatalf("install command: %s", created.Command)
	}
	var dev inventory.InstallResponse
	admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "dev-onprem", "labels": map[string]string{"env": "dev"}}, &dev)

	svc := &inventory.Service{DB: e.DB, Log: e.Log}
	var hooks gateway.Hooks
	svc.Hooks(&hooks)
	id := created.Cluster.ID
	if err := hooks.Connected(ctx, id, &pb.Hello{AgentVersion: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	tid := targetid.Compute(id.String(), "db", "orders-pg", 5432)
	err := hooks.Inventory(ctx, id, &pb.InventorySnapshot{ApiVersion: "v1.29.3", Namespaces: []string{"default", "db"},
		Nodes: []*pb.Node{
			{Name: "n1", ProviderId: "azure:///subscriptions/x/n1", KubeletVersion: "v1.28.9", Region: "westeurope", CpuCapacityMilli: 4000, MemCapacityBytes: 16 << 30, Ready: true},
			{Name: "n2", ProviderId: "azure:///subscriptions/x/n2", KubeletVersion: "v1.29.3", Region: "westeurope", CpuCapacityMilli: 4000, MemCapacityBytes: 16 << 30, Ready: true},
		},
		Targets: []*pb.Target{
			{TargetId: tid, Namespace: "db", Service: "orders-pg", Port: 5432, Engine: "postgresql"},
			{TargetId: "forged", Namespace: "db", Service: "other", Port: 5432, Engine: "postgresql"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	var d inventory.Dashboard
	admin.Do("GET", "/api/v1/dashboard", nil, &d)
	if d.Totals.Clusters != 2 || d.Totals.Nodes != 2 || d.Totals.SkewClusters != 1 || d.Totals.AgentsOnline != 1 {
		t.Fatalf("totals: %+v", d.Totals)
	}
	foundEOL := false
	for _, a := range d.Attention {
		if a.Kind == "eol" {
			foundEOL = true
		}
	}
	if !foundEOL {
		t.Fatalf("expected EOL attention item: %+v", d.Attention)
	}
	var c inventory.Cluster
	admin.Do("GET", "/api/v1/clusters/"+id.String(), nil, &c)
	if c.Provider != "azure" || c.Region != "westeurope" || c.APIVersion != "v1.29.3" {
		t.Fatalf("cluster: %+v", c)
	}
	var targets struct{ Items []inventory.Target }
	admin.Do("GET", "/api/v1/targets?status=candidate", nil, &targets)
	if len(targets.Items) != 1 || targets.Items[0].ID != tid {
		t.Fatalf("forged target id accepted or target missing: %+v", targets.Items)
	}

	// Scoped viewer sees only dev; prod cluster is a 404, not 403.
	viewer := e.Login(e.Principal("devviewer", "Member", "viewer@env=dev"))
	var vd inventory.Dashboard
	viewer.Do("GET", "/api/v1/dashboard", nil, &vd)
	if vd.Totals.Clusters != 1 {
		t.Fatalf("scoped dashboard: %+v", vd.Totals)
	}
	if code := viewer.Do("GET", "/api/v1/clusters/"+id.String(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("out of scope cluster: %d", code)
	}
	if code := viewer.Do("GET", "/api/v1/clusters/"+uuid.NewString(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("missing cluster: %d", code)
	}

	// Compressed mode always produces a finding.
	if code := admin.Do("PATCH", "/api/v1/clusters/"+id.String(), map[string]any{"transfer_mode": "compressed"}, nil); code != 200 {
		t.Fatal(code)
	}
	var n int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE cluster_id = $1 AND control_id = 'transfer.compressed_mode' AND status = 'open'`, id).Scan(&n)
	if n != 1 {
		t.Fatal("compressed mode finding missing")
	}
	admin.Do("PATCH", "/api/v1/clusters/"+id.String(), map[string]any{"transfer_mode": "e2e-tls"}, nil)
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE cluster_id = $1 AND status = 'open'`, id).Scan(&n)
	if n != 0 {
		t.Fatal("finding not resolved")
	}

	// Target disappears -> gone.
	if err := hooks.TargetDelete(ctx, id, tid); err != nil {
		t.Fatal(err)
	}
	var st string
	_ = e.DB.QueryRow(ctx, `SELECT status FROM targets WHERE id = $1`, tid).Scan(&st)
	if st != "gone" {
		t.Fatalf("target status %s", st)
	}

	// Offline transition emits exactly one event.
	_, _ = e.DB.Exec(ctx, `UPDATE clusters SET last_seen_at = now() - interval '10 minutes' WHERE id = $1`, id)
	mctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	go svc.RunOfflineMonitor(mctx)
	deadline := time.Now().Add(16 * time.Second)
	for time.Now().Before(deadline) {
		_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type = 'agent.offline'`).Scan(&n)
		if n > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n != 1 {
		t.Fatalf("agent.offline events: %d", n)
	}
}

func TestReservedClusterLabel(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	var created inventory.InstallResponse
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "edge-1",
		"labels": map[string]string{"env": "dev", inventory.ClusterNameLabel: "spoofed"}}, &created); code != 201 {
		t.Fatal(code)
	}
	if l := created.Cluster.Labels; l[inventory.ClusterNameLabel] != "edge-1" || l["env"] != "dev" {
		t.Fatalf("labels on create: %v", l)
	}
	id := created.Cluster.ID.String()
	// Other olympos.io/ keys are refused.
	if code := admin.Do("PATCH", "/api/v1/clusters/"+id, map[string]any{"labels": map[string]string{"olympos.io/tier": "x"}}, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("reserved prefix accepted: %d", code)
	}
	// Removing or changing the cluster label is ignored.
	if code := admin.Do("PATCH", "/api/v1/clusters/"+id, map[string]any{"labels": map[string]string{"team": "a"}}, nil); code != 200 {
		t.Fatal(code)
	}
	var got struct {
		Labels map[string]string `json:"labels"`
	}
	admin.Do("GET", "/api/v1/clusters/"+id, nil, &got)
	if got.Labels[inventory.ClusterNameLabel] != "edge-1" || got.Labels["team"] != "a" || got.Labels["env"] != "" {
		t.Fatalf("labels after patch: %v", got.Labels)
	}
}

// Security review #1: the TLS name is pinned at first sight; a changed
// annotation is held (and shown) until an admin of the cluster accepts the
// exact name, and the pinned name stays the one verified meanwhile.
func TestTargetTLSNamePinned(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	ctx := context.Background()
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	var created inventory.InstallResponse
	admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "prod", "labels": map[string]string{"env": "prod"}}, &created)
	id := created.Cluster.ID
	svc := &inventory.Service{DB: e.DB, Log: e.Log}
	var hooks gateway.Hooks
	svc.Hooks(&hooks)
	_ = hooks.Connected(ctx, id, &pb.Hello{AgentVersion: "1.0.0"})
	tid := targetid.Compute(id.String(), "db", "orders-pg", 5432)
	up := func(name string) {
		t.Helper()
		if err := hooks.TargetUpsert(ctx, id, &pb.Target{TargetId: tid, Namespace: "db", Service: "orders-pg", Port: 5432, Engine: "postgresql", TlsServerName: name}); err != nil {
			t.Fatal(err)
		}
	}
	get := func() inventory.Target {
		t.Helper()
		var ts struct{ Items []inventory.Target }
		admin.Do("GET", "/api/v1/targets", nil, &ts)
		if len(ts.Items) != 1 {
			t.Fatalf("targets: %+v", ts.Items)
		}
		return ts.Items[0]
	}
	attention := func() []inventory.AttentionItem {
		var d inventory.Dashboard
		admin.Do("GET", "/api/v1/dashboard", nil, &d)
		var out []inventory.AttentionItem
		for _, a := range d.Attention {
			if a.Kind == "target_tls_changed" {
				out = append(out, a)
			}
		}
		return out
	}

	up("orders-pg.db.svc")
	up("db.attacker.example")
	if tg := get(); tg.TLSServerName != "orders-pg.db.svc" || tg.TLSServerNamePending == nil || *tg.TLSServerNamePending != "db.attacker.example" {
		t.Fatalf("changed name must be held: %+v", tg)
	}
	if a := attention(); len(a) != 1 || !strings.Contains(a[0].Detail, "db.attacker.example") || a[0].Severity != "crit" {
		t.Fatalf("attention: %+v", a)
	}
	// Reverting the annotation clears it.
	up("orders-pg.db.svc")
	if tg := get(); tg.TLSServerNamePending != nil || len(attention()) != 0 {
		t.Fatalf("revert: %+v", tg)
	}

	up("pg.prod.internal")
	scoped := e.Login(e.Principal("devadmin", "Member", "admin@env=dev"))
	if code := scoped.Do("POST", "/api/v1/targets/"+tid+"/accept-tls-name", map[string]any{"name": "pg.prod.internal"}, nil); code != http.StatusNotFound {
		t.Fatalf("out-of-scope admin: %d", code)
	}
	op := e.Login(e.Principal("op", "Member", "operator"))
	if code := op.Do("POST", "/api/v1/targets/"+tid+"/accept-tls-name", map[string]any{"name": "pg.prod.internal"}, nil); code != http.StatusForbidden {
		t.Fatalf("operator: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/targets/"+tid+"/accept-tls-name", map[string]any{"name": "other.example"}, nil); code != http.StatusConflict {
		t.Fatalf("stale name: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/targets/"+tid+"/accept-tls-name", map[string]any{"name": "pg.prod.internal"}, nil); code != http.StatusNoContent {
		t.Fatalf("accept: %d", code)
	}
	if tg := get(); tg.TLSServerName != "pg.prod.internal" || tg.TLSServerNamePending != nil {
		t.Fatalf("accepted: %+v", tg)
	}
	var n int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE action IN ('target.tls_name_changed','target.tls_name_accepted')`).Scan(&n)
	if n != 3 {
		t.Fatalf("activity rows: %d", n)
	}
}
