package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kdiscovery "k8s.io/client-go/discovery"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

const (
	dgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseImageID(t *testing.T) {
	cases := []struct {
		in, repo, digest string
		ok               bool
	}{
		{"docker-pullable://nginx@" + dgA, "nginx", dgA, true},
		{"docker.io/library/nginx@" + dgA, "docker.io/library/nginx", dgA, true},
		{"containerd://ghcr.io/org/app@" + dgB, "ghcr.io/org/app", dgB, true},
		{"cri-o://quay.io/x/y@" + strings.ToUpper(dgA[:7]) + dgA[7:], "quay.io/x/y", dgA, true},
		{"docker://" + dgA, "", dgA, true},
		{dgB, "", dgB, true},
		{"registry.local:5000/team/app@" + dgA, "registry.local:5000/team/app", dgA, true},
		{"", "", "", false},
		{"nginx:1.25", "", "", false},
		{"docker-pullable://nginx@sha256:short", "", "", false},
		{"nginx@sha512:" + strings.Repeat("a", 128), "", "", false},
	}
	for _, c := range cases {
		repo, dg, ok := ParseImageID(c.in)
		if ok != c.ok || repo != c.repo || dg != c.digest {
			t.Errorf("ParseImageID(%q) = %q, %q, %v; want %q, %q, %v", c.in, repo, dg, ok, c.repo, c.digest, c.ok)
		}
	}
}

func ctrl(kind, name string) []metav1.OwnerReference {
	t := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &t, APIVersion: "v1"}}
}

func TestResolveOwner(t *testing.T) {
	rs := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	_ = rs.Add(&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-7d9f", OwnerReferences: ctrl("Deployment", "api")}})
	_ = rs.Add(&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "bare-rs"}})
	pod := func(owner []metav1.OwnerReference, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p-1", OwnerReferences: owner, Labels: labels}}
	}
	cases := []struct {
		name       string
		p          *corev1.Pod
		kind, wl   string
		indexerNil bool
	}{
		{"deployment via rs", pod(ctrl("ReplicaSet", "api-7d9f"), nil), "Deployment", "api", false},
		{"rs without owner", pod(ctrl("ReplicaSet", "bare-rs"), nil), "ReplicaSet", "bare-rs", false},
		{"rs not cached, hash label", pod(ctrl("ReplicaSet", "web-5c6b8"), map[string]string{"pod-template-hash": "5c6b8"}), "Deployment", "web", false},
		{"rs not cached, no label", pod(ctrl("ReplicaSet", "web-5c6b8"), nil), "ReplicaSet", "web-5c6b8", true},
		{"statefulset", pod(ctrl("StatefulSet", "db"), nil), "StatefulSet", "db", false},
		{"daemonset", pod(ctrl("DaemonSet", "agent"), nil), "DaemonSet", "agent", false},
		{"cronjob job", pod(ctrl("Job", "nightly-report-29001234"), nil), "CronJob", "nightly-report", false},
		{"plain job", pod(ctrl("Job", "migrate-v2"), nil), "Job", "migrate-v2", false},
		{"bare pod", pod(nil, nil), "Pod", "p-1", false},
		{"custom controller", pod(ctrl("Rollout", "canary"), nil), "Rollout", "canary", false},
	}
	for _, c := range cases {
		idx := cache.Indexer(rs)
		if c.indexerNil {
			idx = nil
		}
		k, n := ResolveOwner(c.p, idx)
		if k != c.kind || n != c.wl {
			t.Errorf("%s: got %s/%s, want %s/%s", c.name, k, n, c.kind, c.wl)
		}
	}
}

func testInformers(t *testing.T, objs ...runtime.Object) *kubeInformers {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	k := newKubeInformers(fake.NewClientset(objs...))
	k.base = ctx
	return k
}

// firstReport runs a reporter until it sends one report.
func firstReport(t *testing.T, r Reporter) *pb.ResourceReport {
	t.Helper()
	ch := make(chan *pb.ResourceReport, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, func(rep *pb.ResourceReport) { ch <- rep }) }()
	select {
	case rep := <-ch:
		return rep
	case <-time.After(10 * time.Second):
		t.Fatal("no report")
	}
	return nil
}

func TestImageReporter(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-7d9f", OwnerReferences: ctrl("Deployment", "api")}}
	mk := func(name string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, OwnerReferences: ctrl("ReplicaSet", "api-7d9f")},
			Spec: corev1.PodSpec{
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
				InitContainers:   []corev1.Container{{Name: "migrate", Image: "ghcr.io/org/migrate:1.0"}},
				Containers: []corev1.Container{{Name: "api", Image: "acr.contoso.io/erp/api:2.14.1",
					Env: []corev1.EnvVar{{Name: "DB_PASSWORD", Value: "canary-secret"}}}},
			},
			Status: corev1.PodStatus{
				InitContainerStatuses: []corev1.ContainerStatus{{Name: "migrate", ImageID: "containerd://ghcr.io/org/migrate@" + dgB}},
				ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Image: "acr.contoso.io/erp/api:2.14.1",
					ImageID: "docker-pullable://acr.contoso.io/erp/api@" + dgA}},
			},
		}
	}
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "starting"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "x", Image: "nginx"}}},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "x", ImageID: ""}}},
	}
	inf := testInformers(t, rs, mk("api-7d9f-a"), mk("api-7d9f-b"), pending)
	r := newImageReporter(inf, quietLog)
	rep := firstReport(t, r).GetImages()
	if rep == nil {
		t.Fatal("expected image report")
	}
	want := []string{
		"shop/Deployment/api/api " + dgA + " acr.contoso.io/erp/api:2.14.1",
		"shop/Deployment/api/migrate " + dgB + " ghcr.io/org/migrate:1.0",
	}
	if len(rep.Uses) != len(want) {
		t.Fatalf("uses = %v", rep.Uses)
	}
	for i, u := range rep.Uses {
		got := u.Namespace + "/" + u.WorkloadKind + "/" + u.WorkloadName + "/" + u.Container + " " + u.Digest + " " + u.Image
		if got != want[i] {
			t.Errorf("use %d = %q, want %q", i, got, want[i])
		}
	}
	// The cache holds stripped pods only: no env, no imagePullSecrets.
	for _, o := range inf.pods.GetStore().List() {
		p := o.(*corev1.Pod)
		if len(p.Spec.ImagePullSecrets) > 0 {
			t.Error("imagePullSecrets cached")
		}
		for _, c := range p.Spec.Containers {
			if len(c.Env) > 0 {
				t.Error("env cached")
			}
		}
	}
}

func TestNetpolReporter(t *testing.T) {
	ns := func(n string) *corev1.Namespace { return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}} }
	deny := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "default-deny"},
		Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}}
	allow := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "allow-web"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
		}}
	inf := testInformers(t, ns("shop"), ns("default"), deny, allow)
	rep := firstReport(t, newNetpolReporter(inf, quietLog)).GetNetworkPolicies()
	if rep == nil || strings.Join(rep.Namespaces, ",") != "default,shop" {
		t.Fatalf("namespaces = %v", rep.GetNamespaces())
	}
	if len(rep.Policies) != 2 {
		t.Fatalf("policies = %v", rep.Policies)
	}
	a, d := rep.Policies[0], rep.Policies[1] // sorted: allow-web, default-deny
	if a.Name != "allow-web" || a.SelectsAllPods || a.IngressRules != 1 || strings.Join(a.PolicyTypes, ",") != "Ingress" {
		t.Errorf("allow-web = %v", a)
	}
	if d.Name != "default-deny" || !d.SelectsAllPods || d.IngressRules != 0 || strings.Join(d.PolicyTypes, ",") != "Ingress" {
		t.Errorf("default-deny = %v", d)
	}
}

func TestNetworkPolicyTypesDefaulting(t *testing.T) {
	np := &networkingv1.NetworkPolicy{Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "a", Operator: "Exists"}}},
		Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
	}}
	p := NetworkPolicyToPB(np)
	if p.SelectsAllPods || strings.Join(p.PolicyTypes, ",") != "Egress,Ingress" || p.EgressRules != 1 {
		t.Errorf("got %v", p)
	}
}

// lockedDiscovery lets a test flip which Kyverno resources are served.
type lockedDiscovery struct {
	kdiscovery.DiscoveryInterface
	mu        sync.Mutex
	resources []*metav1.APIResourceList
	fail      bool
}

func (d *lockedDiscovery) set(r []*metav1.APIResourceList) {
	d.mu.Lock()
	d.resources = r
	d.mu.Unlock()
}

func (d *lockedDiscovery) setFail(f bool) {
	d.mu.Lock()
	d.fail = f
	d.mu.Unlock()
}

func (d *lockedDiscovery) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return nil, errors.New("apiserver unavailable")
	}
	for _, l := range d.resources {
		if l.GroupVersion == gv {
			return l, nil
		}
	}
	return d.DiscoveryInterface.ServerResourcesForGroupVersion("not.found/v0")
}

var kyvernoAPIs = []*metav1.APIResourceList{
	{GroupVersion: "kyverno.io/v1", APIResources: []metav1.APIResource{{Name: "clusterpolicies"}, {Name: "policies", Namespaced: true}}},
	{GroupVersion: "wgpolicyk8s.io/v1alpha2", APIResources: []metav1.APIResource{{Name: "policyreports", Namespaced: true}, {Name: "clusterpolicyreports"}}},
}

func u(obj map[string]any) *unstructured.Unstructured { return &unstructured.Unstructured{Object: obj} }

func kyvernoObjects() []runtime.Object {
	return []runtime.Object{
		u(map[string]any{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
			"metadata": map[string]any{"name": "require-run-as-nonroot"},
			"spec": map[string]any{"validationFailureAction": "Audit", "rules": []any{
				map[string]any{"name": "run-as-non-root", "validate": map[string]any{"message": "x"}},
			}},
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}),
		u(map[string]any{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
			"metadata": map[string]any{"name": "disallow-latest-tag"},
			"spec": map[string]any{"validationFailureAction": "audit", "rules": []any{
				map[string]any{"name": "require-tag", "validate": map[string]any{}},
				map[string]any{"name": "no-latest", "validate": map[string]any{"failureAction": "Enforce"}},
			}},
			"status": map[string]any{"ready": false}}),
		u(map[string]any{"apiVersion": "kyverno.io/v1", "kind": "Policy",
			"metadata": map[string]any{"name": "add-labels", "namespace": "shop"},
			"spec":     map[string]any{"rules": []any{map[string]any{"name": "add", "mutate": map[string]any{}}}}}),
		u(map[string]any{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
			"metadata": map[string]any{"name": "r1", "namespace": "shop"},
			"scope":    map[string]any{"kind": "Pod", "name": "api-1", "namespace": "shop"},
			"results": []any{
				map[string]any{"policy": "require-run-as-nonroot", "rule": "run-as-non-root", "result": "fail", "severity": "Medium", "message": "must run as non-root"},
				map[string]any{"policy": "disallow-latest-tag", "rule": "require-tag", "result": "pass"},
			}}),
		u(map[string]any{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "ClusterPolicyReport",
			"metadata": map[string]any{"name": "cr1"},
			"results": []any{
				map[string]any{"policy": "disallow-latest-tag", "rule": "no-latest", "result": "fail", "severity": "high",
					"message": "latest tag \u00e9t\u00e9", "resources": []any{
						map[string]any{"kind": "Deployment", "namespace": "a", "name": "web"},
						map[string]any{"kind": "Deployment", "namespace": "b", "name": "web"},
					}},
				map[string]any{"policy": "x", "rule": "y", "result": "skip"},
			}}),
	}
}

func newTestKyverno(t *testing.T, apis []*metav1.APIResourceList, objs ...runtime.Object) (*kyvernoReporter, *lockedDiscovery) {
	t.Helper()
	disc := &lockedDiscovery{DiscoveryInterface: fake.NewClientset().Discovery(), resources: apis}
	listKinds := map[schema.GroupVersionResource]string{
		gvrClusterPolicy: "ClusterPolicyList", gvrPolicy: "PolicyList",
		gvrPolicyReport: "PolicyReportList", gvrClusterPolicyReport: "ClusterPolicyReportList",
		gvrValidatingPolicy: "ValidatingPolicyList", gvrNSValidatingPolicy: "NamespacedValidatingPolicyList",
		gvrImageVPolicy: "ImageValidatingPolicyList", gvrNSImageVPolicy: "NamespacedImageValidatingPolicyList",
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)
	r := newKyvernoReporter(disc, dyn, quietLog)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r.base = ctx
	return r, disc
}

func TestKyvernoAbsent(t *testing.T) {
	r, _ := newTestKyverno(t, nil)
	rep := firstReport(t, r).GetKyverno()
	if rep == nil || rep.Installed || len(rep.Policies) > 0 {
		t.Fatalf("want installed=false, got %v", rep)
	}
}

func TestKyvernoPresent(t *testing.T) {
	r, _ := newTestKyverno(t, kyvernoAPIs, kyvernoObjects()...)
	rep := firstReport(t, r).GetKyverno()
	if rep == nil || !rep.Installed {
		t.Fatalf("want installed, got %v", rep)
	}
	modes := map[string]string{}
	ready := map[string]bool{}
	for _, p := range rep.Policies {
		modes[p.Namespace+"/"+p.Name] = p.Mode
		ready[p.Namespace+"/"+p.Name] = p.Ready
	}
	wantModes := map[string]string{"/require-run-as-nonroot": "Audit", "/disallow-latest-tag": "Enforce", "shop/add-labels": "Audit"}
	for k, v := range wantModes {
		if modes[k] != v {
			t.Errorf("mode %s = %q, want %q", k, modes[k], v)
		}
	}
	if ready["/disallow-latest-tag"] || !ready["/require-run-as-nonroot"] || !ready["shop/add-labels"] {
		t.Errorf("ready = %v", ready)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("results = %v", rep.Results)
	}
	got := map[string]bool{}
	for _, x := range rep.Results {
		got[x.Policy+"|"+x.Rule+"|"+x.ResourceKind+"/"+x.ResourceNamespace+"/"+x.ResourceName+"|"+x.Result+"|"+x.Severity] = true
	}
	for _, k := range []string{
		"require-run-as-nonroot|run-as-non-root|Pod/shop/api-1|fail|medium",
		"disallow-latest-tag|no-latest|Deployment/a/web|fail|high",
		"disallow-latest-tag|no-latest|Deployment/b/web|fail|high",
	} {
		if !got[k] {
			t.Errorf("missing result %s in %v", k, got)
		}
	}
}

func TestKyvernoInstalledLater(t *testing.T) {
	r, disc := newTestKyverno(t, nil, kyvernoObjects()...)
	r.recheck = 50 * time.Millisecond
	ch := make(chan *pb.ResourceReport, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, func(rep *pb.ResourceReport) { ch <- rep }) }()
	first := <-ch
	if first.GetKyverno().GetInstalled() {
		t.Fatal("first report should be installed=false")
	}
	disc.set(kyvernoAPIs)
	deadline := time.After(15 * time.Second)
	for {
		select {
		case rep := <-ch:
			if rep.GetKyverno().GetInstalled() && len(rep.GetKyverno().Policies) == 3 {
				return
			}
		case <-deadline:
			t.Fatal("never reported installed=true")
		}
	}
}

// A discovery error must not be reported as "Kyverno not installed".
func TestKyvernoDiscoveryErrorSendsNothing(t *testing.T) {
	r, disc := newTestKyverno(t, kyvernoAPIs, kyvernoObjects()...)
	disc.setFail(true)
	r.recheck = 50 * time.Millisecond
	ch := make(chan *pb.ResourceReport, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx, func(rep *pb.ResourceReport) { ch <- rep }) }()
	select {
	case rep := <-ch:
		t.Fatalf("report sent while discovery fails: %v", rep)
	case <-time.After(300 * time.Millisecond):
	}
	disc.setFail(false)
	select {
	case rep := <-ch:
		if !rep.GetKyverno().GetInstalled() {
			t.Fatalf("want installed after recovery, got %v", rep)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no report after discovery recovered")
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := truncate("aé", 2)
	if s != "a" {
		t.Errorf("truncate = %q", s)
	}
}

// Kyverno 1.20: only the CEL policy API (plus reports) is served.
var celKyvernoAPIs = []*metav1.APIResourceList{
	{GroupVersion: "policies.kyverno.io/v1", APIResources: []metav1.APIResource{
		{Name: "validatingpolicies"}, {Name: "namespacedvalidatingpolicies", Namespaced: true},
		{Name: "imagevalidatingpolicies"}, {Name: "namespacedimagevalidatingpolicies", Namespaced: true},
		{Name: "mutatingpolicies"}}},
	{GroupVersion: "wgpolicyk8s.io/v1alpha2", APIResources: []metav1.APIResource{{Name: "policyreports", Namespaced: true}, {Name: "clusterpolicyreports"}}},
}

func TestKyvernoCELPolicies(t *testing.T) {
	objs := []runtime.Object{
		u(map[string]any{"apiVersion": "policies.kyverno.io/v1", "kind": "ValidatingPolicy",
			"metadata": map[string]any{"name": "require-team-label"},
			"spec": map[string]any{"validationActions": []any{"Deny"}, "validations": []any{
				map[string]any{"expression": "has(object.metadata.labels.team)", "message": "label team is required"},
				map[string]any{"expression": "true"},
			}},
			"status": map[string]any{"conditionStatus": map[string]any{"ready": true}}}),
		u(map[string]any{"apiVersion": "policies.kyverno.io/v1", "kind": "NamespacedValidatingPolicy",
			"metadata": map[string]any{"name": "limits", "namespace": "shop"},
			"spec":     map[string]any{"validationActions": []any{"Audit", "Warn"}},
			"status":   map[string]any{"conditionStatus": map[string]any{"ready": false}}}),
		u(map[string]any{"apiVersion": "policies.kyverno.io/v1", "kind": "ImageValidatingPolicy",
			"metadata": map[string]any{"name": "signed-images"},
			"spec":     map[string]any{"validationActions": []any{"Audit"}}}),
		u(map[string]any{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
			"metadata": map[string]any{"name": "r1", "namespace": "lab"},
			"scope":    map[string]any{"kind": "Pod", "name": "web-1", "namespace": "lab"},
			"results": []any{map[string]any{"policy": "require-team-label", "result": "fail", "message": "label team is required"}}}),
	}
	r, _ := newTestKyverno(t, celKyvernoAPIs, objs...)
	rep := firstReport(t, r).GetKyverno()
	if rep == nil || !rep.Installed {
		t.Fatalf("Kyverno 1.20 (CEL policies only) must count as installed: %v", rep)
	}
	got := map[string]*pb.KyvernoPolicy{}
	for _, p := range rep.Policies {
		got[p.Kind+"/"+p.Namespace+"/"+p.Name] = p
	}
	vp := got["ValidatingPolicy//require-team-label"]
	if vp == nil || vp.Mode != "Enforce" || !vp.Ready || len(vp.Rules) != 2 || vp.Rules[0] != "label team is required" || vp.Rules[1] != "validation-2" {
		t.Fatalf("ValidatingPolicy: %+v", vp)
	}
	if np := got["NamespacedValidatingPolicy/shop/limits"]; np == nil || np.Mode != "Audit" || np.Ready {
		t.Fatalf("NamespacedValidatingPolicy: %+v", np)
	}
	if ip := got["ImageValidatingPolicy//signed-images"]; ip == nil || ip.Mode != "Audit" {
		t.Fatalf("ImageValidatingPolicy: %+v", ip)
	}
	if len(rep.Results) != 1 || rep.Results[0].ResourceName != "web-1" {
		t.Fatalf("results: %v", rep.Results)
	}
}
