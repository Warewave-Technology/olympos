package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

func TestKyvernoPolicyObjectsSent(t *testing.T) {
	objs := kyvernoObjects()
	// Status, managedFields, labels and foreign annotations must not leave
	// the agent; policies.kyverno.io/* annotations do.
	cp := objs[0].(*unstructured.Unstructured)
	cp.SetAnnotations(map[string]string{
		"policies.kyverno.io/title":                        "Require runAsNonRoot",
		"policies.kyverno.io/severity":                     "medium",
		"kubectl.kubernetes.io/last-applied-configuration": `{"canary":"last-applied-canary"}`,
	})
	cp.SetLabels(map[string]string{"team": "label-canary"})
	cp.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "managed-canary"}})
	// A policy over the per-policy cap is reported without its object.
	big := u(map[string]any{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
		"metadata": map[string]any{"name": "huge"},
		"spec": map[string]any{"rules": []any{map[string]any{"name": "r", "validate": map[string]any{
			"message": strings.Repeat("x", 70<<10)}}}}})
	r, _ := newTestKyverno(t, kyvernoAPIs, append(objs, big)...)
	rep := firstReport(t, r).GetKyverno()
	got := map[string]*pb.KyvernoPolicy{}
	for _, p := range rep.GetPolicies() {
		got[p.Namespace+"/"+p.Name] = p
	}
	p := got["/require-run-as-nonroot"]
	if p == nil || len(p.ObjectJson) == 0 || p.SpecOmitted {
		t.Fatalf("policy object missing: %+v", p)
	}
	for _, canary := range []string{"last-applied-canary", "label-canary", "managed-canary", "conditions", "status"} {
		if strings.Contains(string(p.ObjectJson), canary) {
			t.Errorf("%q sent in policy object: %s", canary, p.ObjectJson)
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(p.ObjectJson, &obj); err != nil {
		t.Fatal(err)
	}
	meta, _ := obj["metadata"].(map[string]any)
	ann, _ := meta["annotations"].(map[string]any)
	if obj["apiVersion"] != "kyverno.io/v1" || obj["kind"] != "ClusterPolicy" || meta["name"] != "require-run-as-nonroot" ||
		ann["policies.kyverno.io/title"] != "Require runAsNonRoot" || len(ann) != 2 {
		t.Errorf("object = %s", p.ObjectJson)
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec["validationFailureAction"] != "Audit" {
		t.Errorf("spec = %v", spec)
	}
	if ns := got["shop/add-labels"]; ns == nil || !strings.Contains(string(ns.ObjectJson), `"namespace":"shop"`) {
		t.Errorf("namespaced policy object = %v", ns)
	}
	if h := got["/huge"]; h == nil || !h.SpecOmitted || len(h.ObjectJson) != 0 || h.Mode == "" {
		t.Errorf("huge policy = %+v", h)
	}
}

func TestKyvernoPolicyObjectsTotalBudget(t *testing.T) {
	old := maxPolicyObjectTotal
	maxPolicyObjectTotal = 250 // room for one or two of the three objects
	t.Cleanup(func() { maxPolicyObjectTotal = old })
	r, _ := newTestKyverno(t, kyvernoAPIs, kyvernoObjects()...)
	rep := firstReport(t, r).GetKyverno()
	sent, omitted := 0, 0
	for _, p := range rep.GetPolicies() {
		if p.SpecOmitted {
			omitted++
		} else if len(p.ObjectJson) > 0 {
			sent++
		}
	}
	if sent == 0 || omitted == 0 || sent+omitted != 3 {
		t.Fatalf("sent=%d omitted=%d", sent, omitted)
	}
}

const (
	canaryEnv     = "env-canary"
	canarySecRef  = "secret-ref-canary"
	canaryCMRef   = "cm-ref-canary"
	canaryVol     = "vol-canary"
	canaryImage   = "registry.local"
	canarySecret  = "secret-canary"
	canaryCM      = "configmap-canary"
	canaryNSAnn   = "ns-annotation-canary"
	canaryNPAnnot = "np-annotation-canary"
)

func netpolTestObjects() []runtime.Object {
	ns := func(n string, l map[string]string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n, Labels: l,
			Annotations: map[string]string{"note": canaryNSAnn}}}
	}
	tmpl := func(labels map[string]string, ports ...int32) corev1.PodTemplateSpec {
		c := corev1.Container{Name: "app", Image: canaryImage + "/app:1",
			Env: []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: canaryEnv},
				{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: canarySecRef}, Key: "k"}}},
			},
			EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: canaryCMRef}}}},
		}
		for _, p := range ports {
			c.Ports = append(c.Ports, corev1.ContainerPort{ContainerPort: p})
		}
		return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{c},
			Volumes: []corev1.Volume{{Name: "s", VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: canaryVol}}}},
		}}
	}
	allow := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "allow-web",
		Annotations: map[string]string{"kubectl.kubernetes.io/last-applied-configuration": canaryNPAnnot}},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "edge"}}}}}},
		}}
	return []runtime.Object{
		ns("shop", map[string]string{"team": "shop", "kubernetes.io/metadata.name": "shop"}),
		ns("edge", map[string]string{"team": "edge"}),
		allow,
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"},
			Spec: appsv1.DeploymentSpec{Template: tmpl(map[string]string{"app": "web"}, 8080, 8443, 8080)}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "db"},
			Spec: appsv1.StatefulSetSpec{Template: tmpl(map[string]string{"app": "db"}, 5432)}},
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "proxy"},
			Spec: appsv1.DaemonSetSpec{Template: tmpl(map[string]string{"app": "proxy"})}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "db"}, Data: map[string][]byte{"pw": []byte(canarySecret)}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "cfg"}, Data: map[string]string{"k": canaryCM}},
	}
}

func TestNetpolReporterSpecsLabelsWorkloads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client := fake.NewClientset(netpolTestObjects()...)
	inf := newKubeInformers(client)
	inf.base = ctx
	rep := firstReport(t, newNetpolReporter(inf, quietLog)).GetNetworkPolicies()
	if rep == nil || len(rep.Policies) != 1 {
		t.Fatalf("report = %v", rep)
	}
	var spec networkingv1.NetworkPolicySpec
	if err := json.Unmarshal(rep.Policies[0].SpecJson, &spec); err != nil {
		t.Fatalf("spec json: %v (%s)", err, rep.Policies[0].SpecJson)
	}
	if spec.PodSelector.MatchLabels["app"] != "web" || spec.Ingress[0].From[0].NamespaceSelector.MatchLabels["team"] != "edge" {
		t.Errorf("spec = %+v", spec)
	}
	labels := map[string]map[string]string{}
	for _, n := range rep.NamespaceLabels {
		labels[n.Name] = n.Labels
	}
	if labels["shop"]["team"] != "shop" || labels["edge"]["team"] != "edge" || len(labels) != 2 {
		t.Errorf("namespace labels = %v", labels)
	}
	var wls []string
	for _, w := range rep.Workloads {
		wls = append(wls, fmt.Sprintf("%s/%s/%s %v %v", w.Namespace, w.Kind, w.Name, w.Labels["app"], w.Ports))
	}
	want := []string{"edge/DaemonSet/proxy proxy []", "shop/Deployment/web web [8080 8443]", "shop/StatefulSet/db db [5432]"}
	if strings.Join(wls, "|") != strings.Join(want, "|") {
		t.Errorf("workloads = %v, want %v", wls, want)
	}
	b, _ := proto.Marshal(rep)
	for _, canary := range []string{canaryEnv, canarySecRef, canaryCMRef, canaryVol, canarySecret, canaryCM, canaryImage, canaryNSAnn, canaryNPAnnot} {
		if strings.Contains(string(b), canary) {
			t.Errorf("%q in report", canary)
		}
	}
	// Workloads are stripped before they enter the cache.
	for _, i := range []cache.SharedIndexInformer{inf.deploys, inf.sts, inf.ds} {
		for _, o := range i.GetStore().List() {
			b, _ := json.Marshal(o)
			for _, canary := range []string{canaryEnv, canarySecRef, canaryCMRef, canaryVol, canaryImage} {
				if strings.Contains(string(b), canary) {
					t.Errorf("%q cached: %s", canary, b)
				}
			}
		}
	}
	// Secrets and ConfigMaps are never requested.
	if len(client.Actions()) == 0 {
		t.Fatal("no API actions recorded")
	}
	for _, a := range client.Actions() {
		if r := a.GetResource().Resource; r == "secrets" || r == "configmaps" {
			t.Errorf("agent touched %s: %v", r, a)
		}
	}
}

func TestNetpolSpecCap(t *testing.T) {
	np := &networkingv1.NetworkPolicy{Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": strings.Repeat("x", 40<<10)}}}}
	if p := NetworkPolicyToPB(np); len(p.SpecJson) != 0 || p.SelectsAllPods {
		t.Errorf("oversized spec sent: %d bytes", len(p.SpecJson))
	}
}

func TestSelectWorkloadsCaps(t *testing.T) {
	var wls []*pb.Workload
	for i := 0; i < 60; i++ {
		wls = append(wls, &pb.Workload{Namespace: "big", Kind: "Deployment", Name: fmt.Sprintf("d-%02d", i)})
	}
	wls = append(wls, &pb.Workload{Namespace: "a", Kind: "DaemonSet", Name: "z"}, &pb.Workload{Namespace: "a", Kind: "Deployment", Name: "y"})
	out := SelectWorkloads(wls, 50, 1000)
	if len(out) != 52 || out[0].Name != "y" || out[1].Name != "z" || out[51].Name != "d-49" {
		t.Fatalf("per-namespace cap: %d %v", len(out), out[:3])
	}
	if out := SelectWorkloads(wls, 50, 10); len(out) != 10 {
		t.Fatalf("total cap: %d", len(out))
	}
	l := map[string]string{}
	for i := 0; i < 100; i++ {
		l[fmt.Sprintf("k%03d", i)] = "v"
	}
	if c := capLabels(l); len(c) != maxLabelsPerObject || c["k000"] != "v" {
		t.Errorf("capLabels = %d", len(c))
	}
}
