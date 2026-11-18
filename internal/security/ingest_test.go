package security

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/findings"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func mkCluster(t *testing.T, db *store.DB, name string, labels map[string]string) uuid.UUID {
	t.Helper()
	if labels == nil {
		labels = map[string]string{}
	}
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO clusters (name, labels, status) VALUES ($1, $2, 'online') RETURNING id`, name, labels).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func openFindings(t *testing.T, db *store.DB, source string, cluster uuid.UUID) []string {
	t.Helper()
	fs, err := findings.List(context.Background(), db, findings.Filter{Source: source, Status: "open", ClusterID: &cluster, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.ControlID+"@"+f.ResourceRef+"#"+f.Severity)
	}
	sort.Strings(out)
	return out
}

func netpolReport(nss []string, pols ...*pb.NetworkPolicy) *pb.ResourceReport {
	return &pb.ResourceReport{Report: &pb.ResourceReport_NetworkPolicies{NetworkPolicies: &pb.NetworkPolicyReport{Namespaces: nss, Policies: pols}}}
}

func TestIngestNetpol(t *testing.T) {
	ctx := context.Background()
	db := testutil.DB(t)
	c := mkCluster(t, db, "prod-1", nil)
	in := &Ingester{DB: db, Log: quiet, SystemNamespaces: []string{"kube-system", "kube-public", "olympos-*"}}

	rep := netpolReport([]string{"kube-system", "olympos-system", "shop", "billing", "analytics", "edge", "mixed"},
		// shop: proper default-deny.
		&pb.NetworkPolicy{Namespace: "shop", Name: "default-deny", SelectsAllPods: true, PolicyTypes: []string{"Ingress"}},
		// billing: selects all pods with Ingress but HAS rules → allow policy, not deny.
		&pb.NetworkPolicy{Namespace: "billing", Name: "allow-all", SelectsAllPods: true, PolicyTypes: []string{"Ingress"}, IngressRules: 1},
		// analytics: Egress-only deny → not an ingress default-deny.
		&pb.NetworkPolicy{Namespace: "analytics", Name: "deny-egress", SelectsAllPods: true, PolicyTypes: []string{"Egress"}},
		// edge: deny for a subset of pods only.
		&pb.NetworkPolicy{Namespace: "edge", Name: "deny-web", SelectsAllPods: false, PolicyTypes: []string{"Ingress"}},
		// mixed: one allow + one deny → deny.
		&pb.NetworkPolicy{Namespace: "mixed", Name: "allow", SelectsAllPods: false, PolicyTypes: []string{"Ingress"}, IngressRules: 2},
		&pb.NetworkPolicy{Namespace: "mixed", Name: "deny", SelectsAllPods: true, PolicyTypes: []string{"Ingress", "Egress"}, EgressRules: 1},
	)
	if err := in.Report(ctx, c, rep); err != nil {
		t.Fatal(err)
	}
	type row struct {
		count          int
		deny, excluded bool
	}
	got := map[string]row{}
	rows, _ := db.Query(ctx, `SELECT namespace, policy_count, default_deny, excluded FROM network_policy_status WHERE cluster_id = $1`, c)
	for rows.Next() {
		var ns string
		var r row
		if err := rows.Scan(&ns, &r.count, &r.deny, &r.excluded); err != nil {
			t.Fatal(err)
		}
		got[ns] = r
	}
	rows.Close()
	want := map[string]row{
		"kube-system": {0, false, true}, "olympos-system": {0, false, true}, "shop": {1, true, false},
		"billing": {1, false, false}, "analytics": {1, false, false}, "edge": {1, false, false}, "mixed": {2, true, false},
	}
	for ns, w := range want {
		if got[ns] != w {
			t.Errorf("%s = %+v, want %+v", ns, got[ns], w)
		}
	}
	f := openFindings(t, db, findings.SourceNetpol, c)
	wantF := []string{
		"netpol.no_default_deny@analytics#medium", "netpol.no_default_deny@billing#medium", "netpol.no_default_deny@edge#medium",
	}
	if strings.Join(f, ",") != strings.Join(wantF, ",") {
		t.Errorf("findings = %v, want %v", f, wantF)
	}

	// billing adds a deny → its finding resolves; the namespace "edge" goes away.
	rep2 := netpolReport([]string{"kube-system", "shop", "billing", "analytics"},
		&pb.NetworkPolicy{Namespace: "shop", Name: "default-deny", SelectsAllPods: true, PolicyTypes: []string{"Ingress"}},
		&pb.NetworkPolicy{Namespace: "billing", Name: "default-deny", SelectsAllPods: true, PolicyTypes: []string{"Ingress"}},
	)
	if err := in.Report(ctx, c, rep2); err != nil {
		t.Fatal(err)
	}
	if f := openFindings(t, db, findings.SourceNetpol, c); strings.Join(f, ",") != "netpol.no_default_deny@analytics#medium" {
		t.Errorf("after fix: %v", f)
	}
	var n int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM network_policy_status WHERE cluster_id = $1`, c).Scan(&n)
	if n != 4 {
		t.Errorf("rows after replace = %d", n)
	}
}

func kyvernoReport(installed bool, pols []*pb.KyvernoPolicy, res ...*pb.KyvernoResult) *pb.ResourceReport {
	return &pb.ResourceReport{Report: &pb.ResourceReport_Kyverno{Kyverno: &pb.KyvernoReport{Installed: installed, Policies: pols, Results: res}}}
}

func TestIngestKyverno(t *testing.T) {
	ctx := context.Background()
	db := testutil.DB(t)
	c := mkCluster(t, db, "prod-1", nil)
	other := mkCluster(t, db, "prod-2", nil)
	in := &Ingester{DB: db, Log: quiet}
	pols := []*pb.KyvernoPolicy{
		{Name: "require-run-as-nonroot", Mode: "Audit", Rules: []string{"run-as-non-root"}, Ready: true},
		{Name: "disallow-latest-tag", Mode: "Enforce", Rules: []string{"require-tag", "no-latest"}, Ready: true},
		{Namespace: "shop", Name: "require-labels", Mode: "bogus", Rules: []string{"labels"}, Ready: false},
	}
	res := []*pb.KyvernoResult{
		{Policy: "require-run-as-nonroot", Rule: "run-as-non-root", Result: "fail", Severity: "medium", Message: "must run as non-root",
			ResourceKind: "Pod", ResourceNamespace: "shop", ResourceName: "api-1"},
		{Policy: "require-run-as-nonroot", Rule: "run-as-non-root", Result: "fail", Severity: "medium", Message: "must run as non-root",
			ResourceKind: "Pod", ResourceNamespace: "shop", ResourceName: "api-1"}, // duplicate
		{Policy: "disallow-latest-tag", Rule: "no-latest", Result: "fail", Severity: "high", Message: "latest",
			ResourceKind: "Deployment", ResourceNamespace: "a", ResourceName: "web"},
		{Policy: "disallow-latest-tag", Rule: "no-latest", Result: "warn", ResourceKind: "Deployment", ResourceNamespace: "b", ResourceName: "web"},
		{Policy: "shop/require-labels", Rule: "labels", Result: "fail", Severity: "weird",
			ResourceKind: "Service", ResourceNamespace: "shop", ResourceName: "api"},
		{Policy: "require-labels", Rule: "labels", Result: "fail", ResourceKind: "Service", ResourceNamespace: "shop", ResourceName: "db"},
	}
	if err := in.Report(ctx, c, kyvernoReport(true, pols, res...)); err != nil {
		t.Fatal(err)
	}
	if err := in.Report(ctx, other, kyvernoReport(true, pols[:1], res[0])); err != nil {
		t.Fatal(err)
	}
	type row struct {
		mode  string
		rules int
		fails int
		ready bool
	}
	got := map[string]row{}
	rows, _ := db.Query(ctx, `SELECT namespace, name, mode, cardinality(rules), fail_count, ready FROM kyverno_policies WHERE cluster_id = $1`, c)
	for rows.Next() {
		var ns, name string
		var r row
		if err := rows.Scan(&ns, &name, &r.mode, &r.rules, &r.fails, &r.ready); err != nil {
			t.Fatal(err)
		}
		got[ns+"/"+name] = r
	}
	rows.Close()
	want := map[string]row{
		"/require-run-as-nonroot": {"Audit", 1, 1, true},
		"/disallow-latest-tag":    {"Enforce", 2, 1, true},
		"shop/require-labels":     {"Audit", 1, 2, false},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %+v, want %+v", k, got[k], w)
		}
	}
	f := openFindings(t, db, findings.SourceKyverno, c)
	wantF := []string{
		"disallow-latest-tag/no-latest@Deployment/a/web#high",
		"require-labels/labels@Service/shop/db#medium",
		"require-run-as-nonroot/run-as-non-root@Pod/shop/api-1#medium",
		"shop/require-labels/labels@Service/shop/api#medium",
	}
	if strings.Join(f, ",") != strings.Join(wantF, ",") {
		t.Errorf("findings =\n%v\nwant\n%v", f, wantF)
	}
	var installed bool
	var fails int
	_ = db.QueryRow(ctx, `SELECT installed, fail_count FROM kyverno_status WHERE cluster_id = $1`, c).Scan(&installed, &fails)
	if !installed || fails != 4 {
		t.Errorf("status = %v %d", installed, fails)
	}

	// Kyverno uninstalled: policies cleared, findings resolved, other cluster untouched.
	if err := in.Report(ctx, c, kyvernoReport(false, nil)); err != nil {
		t.Fatal(err)
	}
	if f := openFindings(t, db, findings.SourceKyverno, c); len(f) != 0 {
		t.Errorf("findings after uninstall: %v", f)
	}
	var n int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM kyverno_policies WHERE cluster_id = $1`, c).Scan(&n)
	_ = db.QueryRow(ctx, `SELECT installed FROM kyverno_status WHERE cluster_id = $1`, c).Scan(&installed)
	if n != 0 || installed {
		t.Errorf("after uninstall: %d policies, installed=%v", n, installed)
	}
	if f := openFindings(t, db, findings.SourceKyverno, other); len(f) != 1 {
		t.Errorf("other cluster findings: %v", f)
	}
}

const (
	dg1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dg2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dg3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func imageReport(uses ...*pb.ImageUse) *pb.ResourceReport {
	return &pb.ResourceReport{Report: &pb.ResourceReport_Images{Images: &pb.ImageReport{Uses: uses}}}
}

func use(image, digest, ns, kind, name, container string) *pb.ImageUse {
	return &pb.ImageUse{Image: image, Digest: digest, Namespace: ns, WorkloadKind: kind, WorkloadName: name, Container: container}
}

func TestIngestImages(t *testing.T) {
	ctx := context.Background()
	db := testutil.DB(t)
	c1 := mkCluster(t, db, "prod-1", nil)
	c2 := mkCluster(t, db, "prod-2", nil)
	pokes := 0
	in := &Ingester{DB: db, Log: quiet, OnNewImages: func() { pokes++ }}

	if err := in.Report(ctx, c1, imageReport(
		use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"),
		use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"), // dup
		use("docker.io/library/nginx:stable", dg1, "web", "Deployment", "other", "nginx"),
		use("acr.contoso.io/erp/api:2.14.1", dg2, "erp", "StatefulSet", "api", "api"),
		use("bad image!!", dg3, "x", "Pod", "p", "c"),          // invalid repo → dropped
		use("nginx", "sha256:nope", "x", "Pod", "p", "c"),      // invalid digest → dropped
		use("--config=/etc/passwd", dg3, "x", "Pod", "p", "c"), // flag injection → dropped
	)); err != nil {
		t.Fatal(err)
	}
	if pokes != 1 {
		t.Errorf("pokes = %d", pokes)
	}
	var repo string
	var tags []string
	var status string
	if err := db.QueryRow(ctx, `SELECT repo, tags, scan_status FROM images WHERE digest = $1`, dg1).Scan(&repo, &tags, &status); err != nil {
		t.Fatal(err)
	}
	if repo != "docker.io/library/nginx" || strings.Join(tags, ",") != "1.25,stable" || status != "pending" {
		t.Errorf("image = %s %v %s", repo, tags, status)
	}
	var n int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM images`).Scan(&n)
	if n != 2 {
		t.Errorf("images = %d", n)
	}
	_ = db.QueryRow(ctx, `SELECT count(*) FROM image_usage WHERE cluster_id = $1`, c1).Scan(&n)
	if n != 3 {
		t.Errorf("usage = %d", n)
	}

	// Same digest in another cluster with a new tag: deduped, tags merged, no new-image poke.
	_, _ = db.Exec(ctx, `UPDATE images SET scan_status = 'scanned' WHERE digest = $1`, dg1)
	if err := in.Report(ctx, c2, imageReport(use("nginx:latest", dg1, "default", "DaemonSet", "edge", "nginx"))); err != nil {
		t.Fatal(err)
	}
	if pokes != 1 {
		t.Errorf("pokes after known digest = %d", pokes)
	}
	_ = db.QueryRow(ctx, `SELECT tags, scan_status FROM images WHERE digest = $1`, dg1).Scan(&tags, &status)
	if strings.Join(tags, ",") != "1.25,latest,stable" || status != "scanned" {
		t.Errorf("after c2: %v %s", tags, status)
	}

	// c1 replaces its usage: the erp workload is gone.
	if err := in.Report(ctx, c1, imageReport(use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"))); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(ctx, `SELECT count(*) FROM image_usage WHERE cluster_id = $1`, c1).Scan(&n)
	if n != 1 {
		t.Errorf("usage after replace = %d", n)
	}
	_ = db.QueryRow(ctx, `SELECT count(*) FROM image_usage WHERE cluster_id = $1`, c2).Scan(&n)
	if n != 1 {
		t.Errorf("c2 usage = %d", n)
	}
}

func TestIngestKyvernoKinds(t *testing.T) {
	ctx := context.Background()
	db := testutil.DB(t)
	c := mkCluster(t, db, "k20", nil)
	in := &Ingester{DB: db, Log: quiet}
	pols := []*pb.KyvernoPolicy{
		{Kind: "ClusterPolicy", Name: "require-team", Mode: "Audit", Ready: true},
		{Kind: "ValidatingPolicy", Name: "require-team", Mode: "Enforce", Rules: []string{"label team is required"}, Ready: true},
		{Kind: "NamespacedValidatingPolicy", Namespace: "shop", Name: "limits", Mode: "Audit", Ready: true},
		{Kind: "MutatingPolicy", Name: "not-reported", Mode: "Audit"},
	}
	res := []*pb.KyvernoResult{{Policy: "require-team", Result: "fail", ResourceKind: "Pod", ResourceNamespace: "lab", ResourceName: "web-1"}}
	if err := in.Report(ctx, c, kyvernoReport(true, pols, res...)); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, `SELECT kind, namespace, name, mode, fail_count FROM kyverno_policies WHERE cluster_id = $1 ORDER BY kind, name`, c)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var kind, ns, name, mode string
		var n int
		_ = rows.Scan(&kind, &ns, &name, &mode, &n)
		got = append(got, fmt.Sprintf("%s %s/%s %s %d", kind, ns, name, mode, n))
	}
	want := []string{
		"ClusterPolicy /require-team Audit 1",
		"NamespacedValidatingPolicy shop/limits Audit 0",
		"ValidatingPolicy /require-team Enforce 1",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("policies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
