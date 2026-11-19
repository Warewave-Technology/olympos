package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// F3: Secrets are reached only through the metadata client. A typed client
// call on Secrets is allowed only in identity.go (the agent's own identity
// Secret, Role restricted to its name); a dynamic client must never name
// the secrets resource.
func TestNoSecretValueClients(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	typed := regexp.MustCompile(`\.Secrets\(`)
	dyn := regexp.MustCompile(`Resource:\s*"secrets"`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if typed.MatchString(src) && f != "identity.go" {
			t.Errorf("%s uses a typed Secrets client (only identity.go may, for its own Secret)", f)
		}
		if dyn.MatchString(src) && f != "reporter_secrets.go" {
			t.Errorf("%s names the secrets resource", f)
		}
		if f == "reporter_secrets.go" && (strings.Contains(src, `"k8s.io/client-go/dynamic"`) || typed.MatchString(src)) {
			t.Errorf("reporter_secrets.go must use the metadata client only")
		}
	}
}

func secretMeta(ns, name string, fields string, ann map[string]string) *metav1.PartialObjectMetadata {
	m := &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("u-" + name), Annotations: ann, CreationTimestamp: metav1.Now()}}
	if fields != "" {
		m.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubectl-create", Operation: metav1.ManagedFieldsOperationUpdate,
			FieldsType: "FieldsV1", FieldsV1: &metav1.FieldsV1{Raw: []byte(fields)}}}
	}
	return m
}

// client-go may apply a transform again to an already stripped object.
func TestSecretTransformsIdempotent(t *testing.T) {
	keepSecretRefs.Store(true)
	defer keepSecretRefs.Store(false)
	m := secretMeta("shop", "db", `{"f:data":{"f:password":{}}}`, map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "x"})
	once, _ := stripSecret(m)
	twice, _ := stripSecret(once)
	if twice.(*metav1.PartialObjectMetadata).Annotations[annKeys] != `["password"]` {
		t.Fatalf("keys lost on a second transform: %v", twice)
	}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}}}}
	p1, _ := stripPod(p)
	p2, _ := stripPod(p1)
	if p2.(*corev1.Pod).Annotations[annSecretRefs] != "regcred" {
		t.Fatalf("refs lost on a second transform: %v", p2)
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "sa"}, Secrets: []corev1.ObjectReference{{Name: "tok"}}}
	s1, _ := stripServiceAccount(sa)
	s2, _ := stripServiceAccount(s1)
	if s2.(*corev1.ServiceAccount).Annotations[annSecretRefs] != "tok" {
		t.Fatalf("SA refs lost on a second transform: %v", s2)
	}
}

func TestSecretInventoryReporter(t *testing.T) {
	const canary = "CANARY-secret-value-in-annotation"
	scheme := metafake.NewTestScheme()
	_ = metav1.AddMetaToScheme(scheme)
	mc := metafake.NewSimpleMetadataClient(scheme,
		secretMeta("shop", "db-creds", `{"f:data":{".":{},"f:password":{},"f:username":{}},"f:type":{}}`,
			map[string]string{"kubectl.kubernetes.io/last-applied-configuration": `{"data":{"password":"` + canary + `"}}`}),
		secretMeta("shop", "web-tls", `{"f:data":{".":{},"f:tls.crt":{},"f:tls.key":{}},"f:type":{}}`, nil),
		secretMeta("shop", "old-token", `{"f:data":{"f:token":{}}}`, map[string]string{annSAName: "deployer"}),
		secretMeta("shop", "mystery", "", nil),
		secretMeta("kube-system", "bootstrap", `{"f:data":{"f:x":{}}}`, nil),
	)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web-1", UID: "p1"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Env: []corev1.EnvVar{{Name: "PW", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}, Key: "password"}}}}}},
			Volumes: []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "web-tls"}}}}}}
	kube := fake.NewClientset(pod)
	shared := newKubeInformers(kube)
	r := newSecretReporter(mc, kube, shared, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer keepSecretRefs.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := make(chan *pb.SecretInventoryReport, 4)
	go func() { _ = r.Run(ctx, func(rep *pb.ResourceReport) { reports <- rep.GetSecretInventory() }) }()
	var rep *pb.SecretInventoryReport
	select {
	case rep = <-reports:
	case <-time.After(15 * time.Second):
		t.Fatal("no report")
	}
	by := map[string]*pb.K8SSecret{}
	for _, s := range rep.Secrets {
		by[s.Name] = s
	}
	if len(by) != 4 || by["bootstrap"] != nil {
		t.Fatalf("secrets: %v", rep.Secrets)
	}
	if s := by["db-creds"]; strings.Join(s.Keys, ",") != "password,username" || strings.Join(s.ReferencedBy, ",") != "Pod/web-1" || s.Type != "" {
		t.Fatalf("db-creds: %+v", s)
	}
	if s := by["web-tls"]; s.Type != "kubernetes.io/tls" || len(s.ReferencedBy) != 1 {
		t.Fatalf("web-tls: %+v", s)
	}
	if s := by["old-token"]; s.Type != "kubernetes.io/service-account-token" || strings.Join(s.ReferencedBy, ",") != "ServiceAccount/deployer" {
		t.Fatalf("old-token: %+v", s)
	}
	if s := by["mystery"]; !s.KeysUnknown || len(s.Keys) != 0 {
		t.Fatalf("mystery: %+v", s)
	}
	b, _ := proto.Marshal(rep)
	if strings.Contains(string(b), canary) {
		t.Fatal("report carries the last-applied annotation value")
	}
	for _, o := range r.secrets.GetStore().List() {
		if m := o.(*metav1.PartialObjectMetadata); m.Annotations["kubectl.kubernetes.io/last-applied-configuration"] != "" || m.ManagedFields != nil {
			t.Fatalf("cached secret %s keeps annotations or managedFields", m.Name)
		}
	}
	// Only metadata requests were made for secrets.
	for _, a := range mc.Actions() {
		if a.GetResource() == (schema.GroupVersionResource{Version: "v1", Resource: "secrets"}) && a.GetVerb() != "list" && a.GetVerb() != "watch" {
			t.Fatalf("unexpected %s on secrets", a.GetVerb())
		}
	}
	for _, a := range kube.Actions() {
		if a.GetResource().Resource == "secrets" {
			t.Fatalf("typed client touched secrets: %s", a.GetVerb())
		}
	}
}

// Security review #10: annotations a cluster user sets never make the
// transforms skip stripping or report spoofed names; the agent's own
// output is still stripped idempotently.
func TestStripIgnoresSpoofedMarkers(t *testing.T) {
	spoofed := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "x", Annotations: map[string]string{
		annKeys: `["fake"]`, annStripped: "guess",
		"kubectl.kubernetes.io/last-applied-configuration": `{"data":{"password":"CANARY"}}`}}}
	out, _ := stripSecret(spoofed)
	m := out.(*metav1.PartialObjectMetadata)
	if _, ok := m.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok || m.Annotations[annKeys] != "" || m.Annotations[annKeysUnknown] != "true" {
		t.Fatalf("spoofed secret kept: %+v", m.Annotations)
	}
	again, _ := stripSecret(m)
	if again.(*metav1.PartialObjectMetadata).Annotations[annKeysUnknown] != "true" {
		t.Fatal("not idempotent")
	}

	keepSecretRefs.Store(true)
	defer keepSecretRefs.Store(false)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "x", Annotations: map[string]string{annSecretRefs: "prod-db", annStripped: "guess"}}}
	po, _ := stripPod(pod)
	if v := po.(*corev1.Pod).Annotations[annSecretRefs]; v != "" {
		t.Fatalf("spoofed pod refs: %q", v)
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "x", Annotations: map[string]string{annSecretRefs: "prod-db"}}}
	so, _ := stripServiceAccount(sa)
	if v := so.(*corev1.ServiceAccount).Annotations[annSecretRefs]; v != "" {
		t.Fatalf("spoofed SA refs: %q", v)
	}
	real := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "x"}, Secrets: []corev1.ObjectReference{{Name: "tok"}}}
	r1, _ := stripServiceAccount(real)
	r2, _ := stripServiceAccount(r1)
	if v := r2.(*corev1.ServiceAccount).Annotations[annSecretRefs]; v != "tok" {
		t.Fatalf("own output not idempotent: %q", v)
	}
}
