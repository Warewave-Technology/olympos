package agent

// Opt-in Secret inventory (F3). Secrets are listed and watched ONLY through
// the metadata client (PartialObjectMetadata): no request for Secrets ever
// returns data. Key names come from managedFields (f:data / f:stringData);
// without managedFields the keys are unknown, never read instead. Every
// annotation is dropped in the transform (kubectl's last-applied-
// configuration holds the data) except the service account name used to
// recognise legacy tokens. secrets_test.go fails the build if any other
// client touches Secrets (only identity.go, the agent's own identity Secret).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

const (
	annSecretRefs   = "olympos.io/secret-refs"  // stripped pods/SAs: referenced Secret names
	annKeys         = "olympos.io/keys"         // stripped Secrets: key names (JSON)
	annKeysUnknown  = "olympos.io/keys-unknown" // no managedFields
	annTypeSet      = "olympos.io/type-set"     // managedFields has f:type (value not readable)
	annSAName       = "kubernetes.io/service-account.name"
	maxSecrets      = 20000
	maxReferencedBy = 10
)

var secretsGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

// PodSecretRefs are the Secret names a pod spec refers to: env and envFrom,
// secret and projected volumes, imagePullSecrets. Names only.
func PodSecretRefs(p *corev1.Pod) []string {
	set := map[string]bool{}
	for _, r := range p.Spec.ImagePullSecrets {
		set[r.Name] = true
	}
	for _, v := range p.Spec.Volumes {
		if v.Secret != nil {
			set[v.Secret.SecretName] = true
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil {
					set[src.Secret.Name] = true
				}
			}
		}
	}
	containers := append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...)
	for _, c := range containers {
		for _, e := range c.EnvFrom {
			if e.SecretRef != nil {
				set[e.SecretRef.Name] = true
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				set[e.ValueFrom.SecretKeyRef.Name] = true
			}
		}
	}
	delete(set, "")
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// SecretKeysFromManagedFields returns the key names written to data or
// stringData by any field manager, and whether the type field was set.
func SecretKeysFromManagedFields(mf []metav1.ManagedFieldsEntry) (keys []string, known, typeSet bool) {
	set := map[string]bool{}
	for _, e := range mf {
		if e.FieldsV1 == nil {
			continue
		}
		var f map[string]json.RawMessage
		if json.Unmarshal(e.FieldsV1.Raw, &f) != nil {
			continue
		}
		if _, ok := f["f:type"]; ok {
			typeSet = true
		}
		for _, field := range []string{"f:data", "f:stringData"} {
			raw, ok := f[field]
			if !ok {
				continue
			}
			known = true
			var sub map[string]json.RawMessage
			if json.Unmarshal(raw, &sub) != nil {
				continue
			}
			for k := range sub {
				if name, ok := strings.CutPrefix(k, "f:"); ok {
					set[name] = true
				}
			}
		}
	}
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, known, typeSet
}

// annStripped marks objects the agent's transforms produced. Its value is a
// random nonce per agent process, so a cluster user cannot make the
// transforms skip an object by setting annotations (security review #10).
const annStripped = "olympos.io/stripped"

var stripNonce = func() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}()

func strippedByAgent(ann map[string]string) bool { return ann[annStripped] == stripNonce }

// stripSecret keeps names, labels, owners and creation time; key names move
// to an annotation; managedFields and every other annotation go.
// Transforms may run more than once on the same (already stripped) object:
// they must be idempotent.
func stripSecret(obj any) (any, error) {
	m, ok := obj.(*metav1.PartialObjectMetadata)
	if !ok {
		return obj, nil
	}
	if strippedByAgent(m.Annotations) {
		return m, nil // already stripped
	}
	keys, known, typeSet := SecretKeysFromManagedFields(m.ManagedFields)
	ann := map[string]string{annStripped: stripNonce}
	if sa := m.Annotations[annSAName]; sa != "" {
		ann[annSAName] = sa
	}
	if known {
		b, _ := json.Marshal(keys)
		ann[annKeys] = string(b)
	} else {
		ann[annKeysUnknown] = "true"
	}
	if typeSet {
		ann[annTypeSet] = "true"
	}
	return &metav1.PartialObjectMetadata{TypeMeta: m.TypeMeta, ObjectMeta: metav1.ObjectMeta{
		Name: m.Name, Namespace: m.Namespace, UID: m.UID, ResourceVersion: m.ResourceVersion,
		Labels: m.Labels, OwnerReferences: m.OwnerReferences, CreationTimestamp: m.CreationTimestamp, Annotations: ann,
	}}, nil
}

// stripServiceAccount keeps the names of the Secrets a ServiceAccount lists.
func stripServiceAccount(obj any) (any, error) {
	sa, ok := obj.(*corev1.ServiceAccount)
	if !ok {
		return obj, nil
	}
	set := map[string]bool{}
	for _, r := range sa.Secrets {
		set[r.Name] = true
	}
	for _, r := range sa.ImagePullSecrets {
		set[r.Name] = true
	}
	var refs []string
	for n := range set {
		if n != "" {
			refs = append(refs, n)
		}
	}
	sort.Strings(refs)
	out := &corev1.ServiceAccount{TypeMeta: sa.TypeMeta, ObjectMeta: metav1.ObjectMeta{Name: sa.Name, Namespace: sa.Namespace, UID: sa.UID, ResourceVersion: sa.ResourceVersion,
		Annotations: map[string]string{annStripped: stripNonce}}}
	if len(refs) > 0 {
		out.Annotations[annSecretRefs] = strings.Join(refs, ",")
	} else if v := sa.Annotations[annSecretRefs]; v != "" && strippedByAgent(sa.Annotations) {
		out.Annotations[annSecretRefs] = v // already stripped
	}
	return out, nil
}

// InferSecretType guesses the type without reading it: the SA annotation,
// well-known key names, the Helm release label. "" when unknown; Opaque
// when the type field was never set (the API default).
func InferSecretType(m *metav1.PartialObjectMetadata, keys []string) string {
	has := map[string]bool{}
	for _, k := range keys {
		has[k] = true
	}
	switch {
	case m.Annotations[annSAName] != "":
		return string(corev1.SecretTypeServiceAccountToken)
	case m.Labels["owner"] == "helm" && strings.HasPrefix(m.Name, "sh.helm.release.v1."):
		return "helm.sh/release.v1"
	case has[corev1.TLSCertKey] && has[corev1.TLSPrivateKeyKey]:
		return string(corev1.SecretTypeTLS)
	case has[corev1.DockerConfigJsonKey]:
		return string(corev1.SecretTypeDockerConfigJson)
	case has[corev1.DockerConfigKey]:
		return string(corev1.SecretTypeDockercfg)
	case m.Annotations[annTypeSet] == "":
		return string(corev1.SecretTypeOpaque)
	}
	return ""
}

type secretReporter struct {
	log     *slog.Logger
	shared  *kubeInformers
	secrets cache.SharedIndexInformer
	sas     cache.SharedIndexInformer
	changed signal
	exclude []string
	once    sync.Once
}

func newSecretReporter(mc metadata.Interface, kube kubernetes.Interface, shared *kubeInformers, exclude []string, log *slog.Logger) *secretReporter {
	keepSecretRefs.Store(true)
	if exclude == nil {
		exclude = DefaultSensitiveExclude
	}
	mf := metadatainformer.NewSharedInformerFactory(mc, 0)
	r := &secretReporter{log: log, shared: shared, changed: newSignal(), exclude: exclude,
		secrets: mf.ForResource(secretsGVR).Informer(),
		sas:     informers.NewSharedInformerFactory(kube, 0).Core().V1().ServiceAccounts().Informer()}
	_ = r.secrets.SetTransform(stripSecret)
	_ = r.sas.SetTransform(stripServiceAccount)
	_, _ = r.secrets.AddEventHandler(r.changed.handler())
	_, _ = r.sas.AddEventHandler(r.changed.handler())
	_, _ = shared.pods.AddEventHandler(r.changed.handler())
	return r
}

func (r *secretReporter) Name() string { return "secret-inventory" }

func (r *secretReporter) excluded(ns string) bool {
	return (&sensitiveReporter{exclude: r.exclude}).skipped(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns}})
}

func (r *secretReporter) build(context.Context) (*pb.ResourceReport, error) {
	// referenced: namespace → secret name → referrers.
	refs := map[string]map[string][]string{}
	add := func(ns, secret, by string) {
		if refs[ns] == nil {
			refs[ns] = map[string][]string{}
		}
		for _, x := range refs[ns][secret] {
			if x == by {
				return
			}
		}
		refs[ns][secret] = append(refs[ns][secret], by)
	}
	for _, o := range r.shared.pods.GetStore().List() {
		p, ok := o.(*corev1.Pod)
		if !ok || p.Annotations[annSecretRefs] == "" {
			continue
		}
		kind, name := ResolveOwner(p, r.shared.rs.GetIndexer())
		for _, s := range strings.Split(p.Annotations[annSecretRefs], ",") {
			add(p.Namespace, s, kind+"/"+name)
		}
	}
	for _, o := range r.sas.GetStore().List() {
		sa, ok := o.(*corev1.ServiceAccount)
		if !ok || sa.Annotations[annSecretRefs] == "" {
			continue
		}
		for _, s := range strings.Split(sa.Annotations[annSecretRefs], ",") {
			add(sa.Namespace, s, "ServiceAccount/"+sa.Name)
		}
	}
	rep := &pb.SecretInventoryReport{}
	for _, o := range r.secrets.GetStore().List() {
		m, ok := o.(*metav1.PartialObjectMetadata)
		if !ok || r.excluded(m.Namespace) {
			continue
		}
		if len(rep.Secrets) >= maxSecrets {
			rep.Truncated = true
			break
		}
		s := &pb.K8SSecret{Namespace: m.Namespace, Name: m.Name, Labels: m.Labels, CreatedUnix: m.CreationTimestamp.Unix(),
			KeysUnknown: m.Annotations[annKeysUnknown] == "true"}
		if v := m.Annotations[annKeys]; v != "" {
			_ = json.Unmarshal([]byte(v), &s.Keys)
		}
		s.Type = InferSecretType(m, s.Keys)
		for _, or := range m.OwnerReferences {
			s.Owners = append(s.Owners, &pb.ObjectOwner{ApiVersion: or.APIVersion, Kind: or.Kind, Name: or.Name})
		}
		by := refs[m.Namespace][m.Name]
		if sa := m.Annotations[annSAName]; sa != "" {
			by = append(by, "ServiceAccount/"+sa)
		}
		sort.Strings(by)
		if len(by) > maxReferencedBy {
			by = append(by[:maxReferencedBy], "+"+strconv.Itoa(len(by)-maxReferencedBy)+" more")
		}
		s.ReferencedBy = by
		rep.Secrets = append(rep.Secrets, s)
	}
	sort.Slice(rep.Secrets, func(i, j int) bool {
		a, b := rep.Secrets[i], rep.Secrets[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return &pb.ResourceReport{Report: &pb.ResourceReport_SecretInventory{SecretInventory: rep}}, nil
}

func (r *secretReporter) Run(ctx context.Context, send func(*pb.ResourceReport)) error {
	r.once.Do(func() {
		go r.secrets.Run(context.Background().Done())
		go r.sas.Run(context.Background().Done())
	})
	if err := r.shared.start(ctx); err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, cacheSyncTimeout)
	defer cancel()
	if !cache.WaitForCacheSync(wctx.Done(), r.secrets.HasSynced, r.sas.HasSynced) {
		return context.DeadlineExceeded
	}
	l := &reportLoop{name: r.Name(), log: r.log, changed: r.changed, debounce: 5 * time.Second, build: r.build}
	return l.run(ctx, send)
}
