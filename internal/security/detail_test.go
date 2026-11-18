//go:build dev

package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/server"
)

type detailEnv struct {
	*apitest.Env
	prod, dev, empty uuid.UUID
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newDetailEnv(t *testing.T) *detailEnv {
	t.Helper()
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&API{DB: e.DB, Log: e.Log, Envelope: e.Envelope}}
	}})
	d := &detailEnv{Env: e,
		prod:  mkCluster(t, e.DB, "prod-weu", map[string]string{"env": "prod"}),
		dev:   mkCluster(t, e.DB, "dev-weu", map[string]string{"env": "dev"}),
		empty: mkCluster(t, e.DB, "prod-empty", map[string]string{"env": "prod"}),
	}
	ctx := context.Background()
	in := &Ingester{DB: e.DB, Log: e.Log, SystemNamespaces: []string{"kube-system"}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	cpObj := mustJSON(t, map[string]any{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
		"metadata": map[string]any{"name": "disallow-latest-tag", "annotations": map[string]any{
			"policies.kyverno.io/title": "Disallow Latest Tag",
			"example.com/foreign":       "dropped-by-server", // an agent should not send it; the server drops it anyway
		}},
		"spec": map[string]any{"validationFailureAction": "Enforce", "background": true, "rules": []any{
			map[string]any{"name": "require-image-tag", "match": map[string]any{"any": []any{map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}}}}},
				"validate": map[string]any{"message": "An image tag is required.\u0000", "pattern": map[string]any{
					"spec": map[string]any{"containers": []any{map[string]any{"image": "*:*"}}}}}},
		}}})
	nsObj := mustJSON(t, map[string]any{"apiVersion": "kyverno.io/v1", "kind": "Policy",
		"metadata": map[string]any{"name": "require-labels", "namespace": "shop"},
		"spec":     map[string]any{"rules": []any{map[string]any{"name": "team"}}}})
	pols := []*pb.KyvernoPolicy{
		{Kind: "ClusterPolicy", Name: "disallow-latest-tag", Mode: "Enforce", Rules: []string{"require-image-tag"}, Ready: true, ObjectJson: cpObj},
		{Kind: "Policy", Namespace: "shop", Name: "require-labels", Mode: "Audit", Rules: []string{"team"}, Ready: true, ObjectJson: nsObj},
		{Kind: "ClusterPolicy", Name: "huge", Mode: "Audit", Ready: true, SpecOmitted: true},
		{Kind: "ValidatingPolicy", Name: "old-agent", Mode: "Audit", Ready: true}, // agent without specs
	}
	res := []*pb.KyvernoResult{
		{Policy: "disallow-latest-tag", Rule: "require-image-tag", Result: "fail", Severity: "medium", Message: "An image tag is required.",
			ResourceKind: "Pod", ResourceNamespace: "web", ResourceName: "front-1"},
		{Policy: "disallow-latest-tag", Rule: "require-image-tag", Result: "fail", Severity: "medium", Message: "An image tag is required.",
			ResourceKind: "Pod", ResourceNamespace: "web", ResourceName: "front-1"}, // duplicate
		{Policy: "disallow-latest-tag", Rule: "require-image-tag", Result: "warn", Message: "latest is discouraged",
			ResourceKind: "Deployment", ResourceNamespace: "web", ResourceName: "front"},
		{Policy: "disallow-latest-tag", Rule: "require-image-tag", Result: "pass", ResourceKind: "Pod", ResourceNamespace: "web", ResourceName: "ok"},
		{Policy: "require-labels", Rule: "team", Result: "fail", ResourceKind: "Pod", ResourceNamespace: "shop", ResourceName: "cart-1"},
		{Policy: "shop/require-labels", Rule: "team", Result: "error", ResourceKind: "Pod", ResourceNamespace: "shop", ResourceName: "cart-2"},
		{Policy: "require-labels", Rule: "team", Result: "fail", ResourceKind: "Pod", ResourceNamespace: "other", ResourceName: "x"}, // other namespace
	}
	must(in.Report(ctx, d.prod, kyvernoReport(true, pols, res...)))
	must(in.Report(ctx, d.dev, kyvernoReport(true, []*pb.KyvernoPolicy{{Kind: "ClusterPolicy", Name: "dev-only", Mode: "Audit", ObjectJson: cpObj}})))

	denySpec := mustJSON(t, map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}})
	allowSpec := mustJSON(t, map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "cart"}},
		"ingress": []any{map[string]any{"from": []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"team": "web"}}}},
			"ports": []any{map[string]any{"port": 8080, "protocol": "TCP"}}}}})
	var wls []*pb.Workload
	for i := 0; i < 55; i++ {
		wls = append(wls, &pb.Workload{Namespace: "shop", Kind: "Deployment", Name: fmt.Sprintf("svc-%02d", i), Labels: map[string]string{"app": "svc"}, Ports: []int32{8080}})
	}
	wls = append(wls,
		&pb.Workload{Namespace: "shop", Kind: "StatefulSet", Name: "cart-db", Labels: map[string]string{"app": "cart-db"}, Ports: []int32{5432, 0, 70000}},
		&pb.Workload{Namespace: "ghost", Kind: "Deployment", Name: "unknown-ns"},
		&pb.Workload{Namespace: "shop", Kind: "CronJob", Name: "not-a-workload-kind"},
	)
	must(in.Report(ctx, d.prod, &pb.ResourceReport{Report: &pb.ResourceReport_NetworkPolicies{NetworkPolicies: &pb.NetworkPolicyReport{
		Namespaces: []string{"shop", "web", "kube-system"},
		NamespaceLabels: []*pb.NamespaceLabels{
			{Name: "shop", Labels: map[string]string{"team": "shop", "kubernetes.io/metadata.name": "shop"}},
			{Name: "web", Labels: map[string]string{"team": "web"}},
		},
		Policies: []*pb.NetworkPolicy{
			{Namespace: "shop", Name: "default-deny", SelectsAllPods: true, PolicyTypes: []string{"Ingress"}, SpecJson: denySpec},
			{Namespace: "shop", Name: "allow-web", PolicyTypes: []string{"Ingress"}, IngressRules: 1, SpecJson: allowSpec},
			{Namespace: "shop", Name: "old-agent", PolicyTypes: []string{"Ingress"}},
			{Namespace: "web", Name: "bad-json", PolicyTypes: []string{"Ingress"}, SpecJson: []byte("{not json")},
		},
		Workloads: wls,
	}}}))
	must(in.Report(ctx, d.dev, netpolReport([]string{"erp"})))

	// Images on prod: two digests sharing one critical CVE.
	must(in.Report(ctx, d.prod, imageReport(
		use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"),
		use("harbor.local/shop/cart:3", dg3, "shop", "Deployment", "cart", "cart"),
		use("harbor.local/shop/cart:3", dg3, "shop", "Deployment", "cart-worker", "cart"),
	)))
	must(in.Report(ctx, d.dev, imageReport(use("acr.contoso.io/erp/api:2", dg2, "erp", "Deployment", "api", "api"))))
	for _, q := range []string{
		`UPDATE images SET scan_status = 'scanned', critical = 1, high = 1 WHERE digest = '` + dg1 + `'`,
		`UPDATE images SET scan_status = 'pending', critical = 1 WHERE digest = '` + dg3 + `'`,
		`INSERT INTO image_vulns (digest, cve_id, severity, package) VALUES
		   ('` + dg1 + `', 'CVE-1', 'critical', 'openssl'), ('` + dg1 + `', 'CVE-2', 'high', 'zlib'), ('` + dg1 + `', 'CVE-3', 'low', 'x'),
		   ('` + dg3 + `', 'CVE-1', 'critical', 'openssl'), ('` + dg2 + `', 'CVE-9', 'critical', 'glibc')`,
	} {
		_, err := e.DB.Exec(ctx, q)
		must(err)
	}
	return d
}

func TestKyvernoPolicyDetail(t *testing.T) {
	d := newDetailEnv(t)
	viewer := d.Login(d.Principal("vic", "Member", "viewer@env=prod"))
	var p KyvernoPolicyDetail
	if code := viewer.Do("GET", "/api/v1/security/kyverno/policy?cluster=prod-weu&kind=ClusterPolicy&name=disallow-latest-tag", nil, &p); code != 200 {
		t.Fatalf("policy = %d", code)
	}
	if p.ClusterID != d.prod || p.ClusterName != "prod-weu" || p.Mode != "Enforce" || p.FailCount != 1 || p.Rules != 1 || p.SpecOmitted {
		t.Errorf("policy = %+v", p.KyvernoPolicy)
	}
	var spec map[string]any
	if err := json.Unmarshal(p.Spec, &spec); err != nil || spec["validationFailureAction"] != "Enforce" {
		t.Fatalf("spec = %s (%v)", p.Spec, err)
	}
	wantYAML := []string{"apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  annotations:\n    policies.kyverno.io/title: Disallow Latest Tag\n  name: disallow-latest-tag\nspec:\n",
		"  validationFailureAction: Enforce\n", "  name: require-image-tag\n", "image: '*:*'"}
	for _, w := range wantYAML {
		if !strings.Contains(p.YAML, w) {
			t.Errorf("yaml lacks %q:\n%s", w, p.YAML)
		}
	}
	if strings.Contains(p.YAML, "dropped-by-server") || strings.Contains(string(p.Spec), "\\u0000") {
		t.Errorf("foreign annotation or NUL kept:\n%s", p.YAML)
	}
	// Non-passing results of the current report, deduplicated, fails first.
	if len(p.Violations) != 2 || p.Violations[0].Result != "fail" || p.Violations[0].ResourceName != "front-1" ||
		p.Violations[0].Severity != "medium" || p.Violations[1].Result != "warn" || p.Violations[1].ResourceKind != "Deployment" {
		t.Errorf("violations = %+v", p.Violations)
	}

	// Namespaced policy: both result forms ("ns/name" and the bare name in
	// the namespace) belong to it; the same bare name elsewhere does not.
	if code := viewer.Do("GET", "/api/v1/security/kyverno/policy?cluster="+d.prod.String()+"&kind=Policy&namespace=shop&name=require-labels", nil, &p); code != 200 {
		t.Fatalf("namespaced = %d", code)
	}
	if len(p.Violations) != 2 || p.FailCount != 1 || !strings.Contains(p.YAML, "namespace: shop") {
		t.Errorf("namespaced = %+v\n%s", p.Violations, p.YAML)
	}
	// Omitted or not sent: no spec, no YAML.
	for _, q := range []string{"kind=ClusterPolicy&name=huge", "kind=ValidatingPolicy&name=old-agent"} {
		code, body := viewer.Raw("GET", "/api/v1/security/kyverno/policy?cluster=prod-weu&"+q, nil)
		var raw map[string]any
		_ = json.Unmarshal([]byte(body), &raw)
		if code != 200 || raw["spec"] != nil || raw["yaml"] != "" || raw["spec_omitted"] != strings.Contains(q, "huge") {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
	// 404: out of scope, unknown cluster/kind/name, missing namespace.
	for _, q := range []string{
		"cluster=dev-weu&kind=ClusterPolicy&name=dev-only",
		"cluster=" + d.dev.String() + "&kind=ClusterPolicy&name=dev-only",
		"cluster=nope&kind=ClusterPolicy&name=disallow-latest-tag",
		"cluster=prod-weu&kind=Secret&name=disallow-latest-tag",
		"cluster=prod-weu&kind=ClusterPolicy&name=missing",
		"cluster=prod-weu&kind=Policy&name=require-labels",
		"kind=ClusterPolicy&name=disallow-latest-tag",
	} {
		if code, _ := viewer.Raw("GET", "/api/v1/security/kyverno/policy?"+q, nil); code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", q, code)
		}
	}
	devViewer := d.Login(d.Principal("dee", "Member", "viewer@env=dev"))
	if code, _ := devViewer.Raw("GET", "/api/v1/security/kyverno/policy?cluster=dev-weu&kind=ClusterPolicy&name=dev-only", nil); code != 200 {
		t.Errorf("dev viewer on dev = %d", code)
	}
}

func TestNetpolNamespaceDetail(t *testing.T) {
	d := newDetailEnv(t)
	viewer := d.Login(d.Principal("vic", "Member", "viewer@env=prod"))
	var n NetpolNamespaceDetail
	if code := viewer.Do("GET", "/api/v1/security/netpol/namespace?cluster=prod-weu&namespace=shop", nil, &n); code != 200 {
		t.Fatalf("namespace = %d", code)
	}
	if n.ClusterID != d.prod || n.Namespace != "shop" || !n.DefaultDeny || n.Excluded || n.NamespaceLabels["team"] != "shop" {
		t.Errorf("namespace = %+v", n)
	}
	var names []string
	for _, p := range n.Policies {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "allow-web,default-deny,old-agent" {
		t.Fatalf("policies = %v", names)
	}
	allow := n.Policies[0]
	var spec map[string]any
	if err := json.Unmarshal(allow.Spec, &spec); err != nil || spec["podSelector"] == nil {
		t.Errorf("spec = %s", allow.Spec)
	}
	for _, w := range []string{"apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: allow-web\n  namespace: shop\nspec:\n",
		"    - namespaceSelector:\n        matchLabels:\n          team: web\n", "port: 8080"} {
		if !strings.Contains(allow.YAML, w) {
			t.Errorf("yaml lacks %q:\n%s", w, allow.YAML)
		}
	}
	if old := n.Policies[2]; string(old.Spec) != "null" || old.YAML != "" {
		t.Errorf("old agent policy = %+v", old)
	}
	// Up to 50 workloads per namespace; unknown kinds and namespaces dropped.
	if len(n.Workloads) != 50 || n.Workloads[0].Kind != "Deployment" || n.Workloads[0].Name != "svc-00" ||
		n.Workloads[0].Labels["app"] != "svc" || len(n.Workloads[0].Ports) != 1 {
		t.Errorf("workloads = %d %+v", len(n.Workloads), n.Workloads[:1])
	}
	var others []string
	for _, o := range n.OtherNamespaces {
		others = append(others, o.Name+"="+o.Labels["team"])
	}
	if strings.Join(others, ",") != "kube-system=,web=web" {
		t.Errorf("other namespaces = %v", others)
	}
	// The StatefulSet was cut by the per-namespace cap (Deployments first);
	// check its port filtering through the store directly.
	var ports []int32
	if err := d.DB.QueryRow(context.Background(), `SELECT ports FROM namespace_workloads WHERE cluster_id = $1 AND name = 'cart-db'`, d.prod).Scan(&ports); err == nil {
		t.Errorf("cart-db stored despite the cap: %v", ports)
	}
	// web: invalid spec JSON is stored as no spec.
	n = NetpolNamespaceDetail{}
	if code := viewer.Do("GET", "/api/v1/security/netpol/namespace?cluster=prod-weu&namespace=web", nil, &n); code != 200 ||
		len(n.Policies) != 1 || string(n.Policies[0].Spec) != "null" || len(n.Workloads) != 0 || n.DefaultDeny {
		t.Errorf("web = %d %+v", code, n)
	}
	for _, q := range []string{"cluster=dev-weu&namespace=erp", "cluster=prod-weu&namespace=ghost", "cluster=prod-weu", "namespace=shop"} {
		if code, _ := viewer.Raw("GET", "/api/v1/security/netpol/namespace?"+q, nil); code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", q, code)
		}
	}
	// A new report replaces policies and workloads.
	in := &Ingester{DB: d.DB, Log: d.Log}
	if err := in.Report(context.Background(), d.prod, netpolReport([]string{"shop"})); err != nil {
		t.Fatal(err)
	}
	n = NetpolNamespaceDetail{}
	if code := viewer.Do("GET", "/api/v1/security/netpol/namespace?cluster=prod-weu&namespace=shop", nil, &n); code != 200 ||
		len(n.Policies) != 0 || len(n.Workloads) != 0 || len(n.OtherNamespaces) != 0 || len(n.NamespaceLabels) != 0 {
		t.Errorf("after replace = %d %+v", code, n)
	}
}

func TestSecurityClusterSummaries(t *testing.T) {
	d := newDetailEnv(t)
	all := d.Login(d.Principal("ada", "Member", "viewer"))
	var resp struct{ Items []ClusterSummary }
	if code := all.Do("GET", "/api/v1/security/clusters", nil, &resp); code != 200 {
		t.Fatalf("summary = %d", code)
	}
	rows := map[string]ClusterSummary{}
	for _, s := range resp.Items {
		rows[s.ClusterName] = s
	}
	if len(resp.Items) != 3 || resp.Items[0].ClusterName != "dev-weu" {
		t.Fatalf("items = %+v", resp.Items)
	}
	p := rows["prod-weu"]
	want := ClusterSummary{ClusterID: d.prod, ClusterName: "prod-weu", Status: "online",
		Images: 2, Workloads: 3, Critical: 1, High: 1, ImagesWithCritical: 2, NotScanned: 1,
		KyvernoInstalled: true, KyvernoPolicies: 4, KyvernoFailures: 2, Namespaces: 3, NamespacesWithoutDefaultDeny: 1}
	if p != want {
		t.Errorf("prod =\n%+v\nwant\n%+v", p, want)
	}
	if e := rows["prod-empty"]; e != (ClusterSummary{ClusterID: d.empty, ClusterName: "prod-empty", Status: "online"}) {
		t.Errorf("empty = %+v", e)
	}
	if dv := rows["dev-weu"]; dv.Critical != 1 || dv.Images != 1 || dv.Namespaces != 1 || dv.NamespacesWithoutDefaultDeny != 1 {
		t.Errorf("dev = %+v", dv)
	}
	viewer := d.Login(d.Principal("vic", "Member", "viewer@env=prod"))
	if code := viewer.Do("GET", "/api/v1/security/clusters", nil, &resp); code != 200 {
		t.Fatalf("viewer = %d", code)
	}
	if len(resp.Items) != 2 || resp.Items[0].ClusterName != "prod-empty" || resp.Items[1].ClusterName != "prod-weu" {
		t.Errorf("viewer items = %+v", resp.Items)
	}
}
