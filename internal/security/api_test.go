package security

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/server"
)

const canaryAPI = "api-canary-registry-pw-77aa"

type apiEnv struct {
	*apitest.Env
	prod, dev uuid.UUID
}

func newAPIEnv(t *testing.T) *apiEnv {
	t.Helper()
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&API{DB: e.DB, Log: e.Log, Envelope: e.Envelope}}
	}})
	a := &apiEnv{Env: e, prod: mkCluster(t, e.DB, "prod-weu", map[string]string{"env": "prod"}),
		dev: mkCluster(t, e.DB, "dev-weu", map[string]string{"env": "dev"})}
	ctx := context.Background()
	in := &Ingester{DB: e.DB, Log: e.Log, SystemNamespaces: []string{"kube-system"}}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(in.Report(ctx, a.prod, imageReport(
		use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"),
		use("harbor.factory.local/mes/line-agent:3.2", dg3, "mes", "Deployment", "line", "agent"),
	)))
	must(in.Report(ctx, a.dev, imageReport(
		use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"),
		use("acr.contoso.io/erp/api:2.14.1", dg2, "erp", "Deployment", "api", "api"),
	)))
	_, err := e.DB.Exec(ctx, `UPDATE images SET scan_status = 'missing_credential' WHERE digest = $1`, dg3)
	must(err)
	_, err = e.DB.Exec(ctx, `UPDATE images SET scan_status = 'scanned', critical = 1, high = 0 WHERE digest = $1`, dg1)
	must(err)
	_, err = e.DB.Exec(ctx, `INSERT INTO image_vulns (digest, cve_id, severity, package, installed, fixed_in, title)
		VALUES ($1, 'CVE-2024-5535', 'critical', 'libcrypto3', '3.1.3-r0', '3.1.6-r0', 'openssl'),
		       ($1, 'CVE-2023-42366', 'low', 'busybox', '1.36.1-r2', '', 'busybox')`, dg1)
	must(err)
	must(in.Report(ctx, a.prod, kyvernoReport(true, []*pb.KyvernoPolicy{{Name: "disallow-latest-tag", Mode: "Enforce", Rules: []string{"a", "b"}, Ready: true}},
		&pb.KyvernoResult{Policy: "disallow-latest-tag", Rule: "a", Result: "fail", ResourceKind: "Pod", ResourceNamespace: "web", ResourceName: "x"})))
	must(in.Report(ctx, a.dev, kyvernoReport(false, nil)))
	must(in.Report(ctx, a.prod, netpolReport([]string{"web", "kube-system"})))
	must(in.Report(ctx, a.dev, netpolReport([]string{"erp"})))
	return a
}

func TestAPIImagesScope(t *testing.T) {
	a := newAPIEnv(t)
	viewer := a.Login(a.Principal("vic", "Member", "viewer@env=prod"))

	var list struct{ Items []Image }
	if code := viewer.Do("GET", "/api/v1/images", nil, &list); code != 200 {
		t.Fatalf("list = %d", code)
	}
	got := map[string]Image{}
	for _, im := range list.Items {
		got[im.Digest] = im
	}
	if len(got) != 2 || got[dg2].Digest != "" {
		t.Fatalf("viewer sees %v", list.Items)
	}
	if im := got[dg1]; im.Clusters != 1 || im.Workloads != 1 || im.Critical != 1 || im.Fixable != 1 || im.Registry != "public" ||
		im.Repo != "docker.io/library/nginx" {
		t.Errorf("nginx = %+v", im)
	}
	if im := got[dg3]; im.ScanStatus != "missing_credential" || im.Registry != "" {
		t.Errorf("harbor = %+v", im)
	}
	// Filters.
	viewer.Do("GET", "/api/v1/images?severity=critical", nil, &list)
	if len(list.Items) != 1 || list.Items[0].Digest != dg1 {
		t.Errorf("severity filter = %v", list.Items)
	}
	viewer.Do("GET", "/api/v1/images?q=harbor", nil, &list)
	if len(list.Items) != 1 || list.Items[0].Digest != dg3 {
		t.Errorf("q filter = %v", list.Items)
	}
	viewer.Do("GET", "/api/v1/images?q=%25", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("q=%% must be literal, got %v", list.Items)
	}
	viewer.Do("GET", "/api/v1/images?cluster=dev-weu", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("out-of-scope cluster filter = %v", list.Items)
	}
	viewer.Do("GET", "/api/v1/images?status=missing_credential&cluster="+a.prod.String(), nil, &list)
	if len(list.Items) != 1 {
		t.Errorf("status filter = %v", list.Items)
	}
	if code, _ := viewer.Raw("GET", "/api/v1/images?severity=bogus", nil); code != 422 {
		t.Errorf("bad severity = %d", code)
	}

	// Detail: usage limited to visible clusters; out-of-scope digest is 404.
	var d ImageDetail
	if code := viewer.Do("GET", "/api/v1/images/"+dg1, nil, &d); code != 200 {
		t.Fatalf("detail = %d", code)
	}
	if len(d.Usage) != 1 || d.Usage[0].ClusterName != "prod-weu" || len(d.Vulns) != 2 || d.Vulns[0].CVEID != "CVE-2024-5535" {
		t.Errorf("detail = %+v", d)
	}
	for _, p := range []string{"/api/v1/images/" + dg2, "/api/v1/images/sha256:bad", "/api/v1/images/" + strings.Replace(dg1, "1", "9", -1)} {
		if code, _ := viewer.Raw("GET", p, nil); code != 404 {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
	// Escaped colon works too.
	if code, _ := viewer.Raw("GET", "/api/v1/images/"+strings.Replace(dg1, ":", "%3A", 1), nil); code != 200 {
		t.Errorf("escaped digest = %d", code)
	}

	// Manual scan: viewer 403, out of scope 404, operator 202 + activity.
	if code, _ := viewer.Raw("POST", "/api/v1/images/"+dg1+"/scan", nil); code != 403 {
		t.Errorf("viewer scan = %d", code)
	}
	op := a.Login(a.Principal("otto", "Member", "operator@env=prod"))
	if code, _ := op.Raw("POST", "/api/v1/images/"+dg2+"/scan", nil); code != 404 {
		t.Errorf("out-of-scope scan = %d", code)
	}
	if code, _ := op.Raw("POST", "/api/v1/images/"+dg1+"/scan", nil); code != 202 {
		t.Errorf("operator scan = %d", code)
	}
	var st string
	_ = a.DB.QueryRow(context.Background(), `SELECT scan_status FROM images WHERE digest = $1`, dg1).Scan(&st)
	var acts int
	_ = a.DB.QueryRow(context.Background(), `SELECT count(*) FROM activity_log WHERE action = 'image.scan_requested' AND object_id = $1`, dg1).Scan(&acts)
	if st != "pending" || acts != 1 {
		t.Errorf("after scan request: %s, %d activity rows", st, acts)
	}
}

func TestAPIKyvernoNetpolScope(t *testing.T) {
	a := newAPIEnv(t)
	viewer := a.Login(a.Principal("vic", "Member", "viewer@env=prod"))
	var k struct {
		Items    []KyvernoPolicy
		Clusters []KyvernoCluster
	}
	if code := viewer.Do("GET", "/api/v1/security/kyverno", nil, &k); code != 200 {
		t.Fatalf("kyverno = %d", code)
	}
	if len(k.Items) != 1 || k.Items[0].Rules != 2 || k.Items[0].FailCount != 1 || k.Items[0].Mode != "Enforce" ||
		len(k.Clusters) != 1 || !k.Clusters[0].Installed {
		t.Errorf("kyverno = %+v", k)
	}
	admin := a.Login(a.Principal("ada", "Member", "admin"))
	admin.Do("GET", "/api/v1/security/kyverno?cluster=dev-weu", nil, &k)
	if len(k.Items) != 0 || len(k.Clusters) != 1 || k.Clusters[0].Installed {
		t.Errorf("dev kyverno = %+v", k)
	}
	var n struct{ Items []NetpolNamespace }
	viewer.Do("GET", "/api/v1/security/netpol", nil, &n)
	if len(n.Items) != 2 {
		t.Fatalf("netpol = %+v", n)
	}
	for _, x := range n.Items {
		if x.ClusterName != "prod-weu" || (x.Namespace == "kube-system") != x.Excluded {
			t.Errorf("netpol row = %+v", x)
		}
	}
	viewer.Do("GET", "/api/v1/security/netpol?cluster=dev-weu", nil, &n)
	if len(n.Items) != 0 {
		t.Errorf("out of scope netpol = %+v", n)
	}
}

func TestAPIRegistries(t *testing.T) {
	a := newAPIEnv(t)
	ctx := context.Background()
	admin := a.Login(a.Principal("ada", "Member", "admin"))
	scopedAdmin := a.Login(a.Principal("sam", "Member", "admin@env=dev"))
	viewer := a.Login(a.Principal("vic", "Member", "viewer@env=dev"))

	body := map[string]any{"host_pattern": "harbor.factory.local", "username": "robot$scan",
		"password": map[string]any{"source": "stored", "value": canaryAPI}}
	for _, c := range []*apitest.Client{viewer, scopedAdmin} {
		if code, _ := c.Raw("POST", "/api/v1/registries", body); code != 403 {
			t.Errorf("non-global admin create = %d", code)
		}
	}
	// Validation.
	for _, bad := range []map[string]any{
		{"host_pattern": "*"},
		{"host_pattern": "*.io"},
		{"host_pattern": "acr.contoso.io", "username": "u"},
		{"host_pattern": "acr.contoso.io", "username": "u", "password": map[string]any{"source": "keyvault_ref", "ref": "https://x"}},
		{"host_pattern": "acr.contoso.io", "password": map[string]any{"source": "stored", "value": "x"}},
	} {
		if code, raw := admin.Raw("POST", "/api/v1/registries", bad); code != 422 {
			t.Errorf("create %v = %d %s", bad, code, raw)
		}
	}
	var reg Registry
	code, raw := admin.Raw("POST", "/api/v1/registries", body)
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	if strings.Contains(raw, canaryAPI) || strings.Contains(raw, `"value"`) {
		t.Errorf("secret in create response: %s", raw)
	}
	admin.Do("GET", "/api/v1/registries", nil, nil)
	if code := admin.Do("POST", "/api/v1/registries", map[string]any{"host_pattern": "*.azurecr.io"}, &reg); code != 201 {
		t.Fatalf("anonymous create = %d", code)
	}
	if code, _ := admin.Raw("POST", "/api/v1/registries", map[string]any{"host_pattern": "HARBOR.factory.local/"}); code != 422 {
		t.Errorf("duplicate = %d", code)
	}
	// The missing_credential image was requeued.
	var st string
	_ = a.DB.QueryRow(ctx, `SELECT scan_status FROM images WHERE digest = $1`, dg3).Scan(&st)
	if st != "pending" {
		t.Errorf("harbor image after registry create = %s", st)
	}
	_, _ = a.DB.Exec(ctx, `UPDATE images SET scan_status = 'missing_credential' WHERE digest = $1`, dg3)

	var list struct {
		Items     []Registry
		Unmatched []UnmatchedRegistry
	}
	code, raw = admin.Raw("GET", "/api/v1/registries", nil)
	if code != 200 || strings.Contains(raw, canaryAPI) {
		t.Fatalf("list = %d (secret leaked: %v)", code, strings.Contains(raw, canaryAPI))
	}
	admin.Do("GET", "/api/v1/registries", nil, &list)
	var harbor Registry
	for _, r := range list.Items {
		if r.HostPattern == "harbor.factory.local" {
			harbor = r
		}
	}
	if harbor.CredentialSource != "stored" || harbor.Username != "robot$scan" || harbor.Images != 1 || harbor.CredentialRef != "" {
		t.Errorf("harbor = %+v", harbor)
	}
	if len(list.Unmatched) != 1 || list.Unmatched[0].Host != "harbor.factory.local" || list.Unmatched[0].Images != 1 ||
		list.Unmatched[0].ExampleRepo != "harbor.factory.local/mes/line-agent" {
		t.Errorf("unmatched = %+v", list.Unmatched)
	}
	// A dev-scoped viewer may list registries but sees no prod images.
	viewer.Do("GET", "/api/v1/registries", nil, &list)
	if len(list.Items) != 2 || len(list.Unmatched) != 0 {
		t.Errorf("scoped list = %+v", list)
	}
	for _, r := range list.Items {
		if r.HostPattern == "harbor.factory.local" && r.Images != 0 {
			t.Errorf("scoped viewer sees prod image count: %+v", r)
		}
	}

	// PATCH: switch to a Key Vault reference; the old stored credential is deleted.
	var credsBefore int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM credentials`).Scan(&credsBefore)
	code = admin.Do("PATCH", "/api/v1/registries/"+harbor.ID.String(),
		map[string]any{"password": map[string]any{"source": "keyvault_ref", "ref": "kv://kv-platform/harbor-pull"}}, &reg)
	if code != 200 || reg.CredentialSource != "keyvault_ref" || reg.CredentialRef != "kv://kv-platform/harbor-pull" || reg.Username != "robot$scan" {
		t.Errorf("patch = %d %+v", code, reg)
	}
	var credsAfter int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM credentials`).Scan(&credsAfter)
	if credsAfter != credsBefore {
		t.Errorf("credentials %d → %d", credsBefore, credsAfter)
	}
	code = admin.Do("PATCH", "/api/v1/registries/"+harbor.ID.String(), map[string]any{"username": "robot2"}, &reg)
	if code != 200 || reg.Username != "robot2" {
		t.Errorf("patch username = %d %+v", code, reg)
	}
	code = admin.Do("PATCH", "/api/v1/registries/"+harbor.ID.String(), map[string]any{"password": map[string]any{"source": "none"}}, &reg)
	if code != 200 || reg.CredentialSource != "" || reg.Username != "" {
		t.Errorf("patch none = %d %+v", code, reg)
	}
	if code, _ := admin.Raw("PATCH", "/api/v1/registries/"+harbor.ID.String(), map[string]any{"host_pattern": "*.azurecr.io"}); code != 422 {
		t.Errorf("patch to duplicate = %d", code)
	}
	if code, _ := viewer.Raw("PATCH", "/api/v1/registries/"+harbor.ID.String(), map[string]any{"username": "x"}); code != 403 {
		t.Errorf("viewer patch = %d", code)
	}
	if code, _ := admin.Raw("DELETE", "/api/v1/registries/"+harbor.ID.String(), nil); code != 204 {
		t.Errorf("delete = %d", code)
	}
	if code, _ := admin.Raw("DELETE", "/api/v1/registries/"+harbor.ID.String(), nil); code != 404 {
		t.Errorf("second delete = %d", code)
	}
	if code, _ := admin.Raw("PATCH", "/api/v1/registries/"+uuid.NewString(), map[string]any{}); code != http.StatusNotFound {
		t.Errorf("patch unknown = %d", code)
	}

	// No secret in logs, activity or anywhere but the sealed ciphertext.
	if strings.Contains(a.LogBuf.String(), canaryAPI) {
		t.Error("canary in logs")
	}
	var n int
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE details::text LIKE '%' || $1 || '%'`, canaryAPI).Scan(&n)
	if n != 0 {
		t.Error("canary in activity log")
	}
	_ = a.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE action LIKE 'registry.%'`).Scan(&n)
	if n != 6 {
		t.Errorf("registry activity rows = %d", n)
	}
}
