package agent

// Security reporters (SPEC §13, M5): Kyverno policies + PolicyReports,
// NetworkPolicies and workload images. Each reporter sends a full
// ResourceReport when a control session starts, whenever its state changes
// (debounced) and every resendInterval as a safety net.
//
// RBAC: only get/list/watch on resources from SPEC §4.2 (pods, replicasets,
// deployments, statefulsets, daemonsets, namespaces, networkpolicies,
// kyverno.io, policies.kyverno.io, wgpolicyk8s.io, read-only configmaps).
// Secrets are never read; imagePullSecrets and env never enter the cache:
// pods and workloads are stripped to the fields we need first. ConfigMap
// values are scanned for credentials in the informer transform and dropped
// (reporter_sensitive.go); only match metadata is reported.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// keepSecretRefs: stripped pods keep the names of the Secrets they use
// (only when the Secret inventory is on).
var keepSecretRefs atomic.Bool

const (
	resendInterval    = 10 * time.Minute
	informerResync    = 10 * time.Minute
	cacheSyncTimeout  = 2 * time.Minute
	maxKyvernoResults = 10000
)

func init() {
	registerExtender(func(a *Agent, cfg Config, rc *rest.Config) {
		shared := newKubeInformers(a.kube)
		a.Reporters = append(a.Reporters,
			newNetpolReporter(shared, a.log),
			newImageReporter(shared, a.log),
		)
		if cfg.SecretsInventory {
			mc, err := metadata.NewForConfig(rc)
			if err != nil {
				a.log.Error("secret inventory disabled: metadata client", "err", err)
			} else {
				a.Reporters = append(a.Reporters, newSecretReporter(mc, a.kube, shared, cfg.SensitiveDataExclude, a.log))
			}
		}
		if cfg.SensitiveData {
			if r, err := newSensitiveReporter(a.kube, cfg.SensitiveDataExclude, a.log); err != nil {
				a.log.Error("sensitive data reporter disabled", "err", err)
			} else {
				a.Reporters = append(a.Reporters, r)
			}
		}
		dyn, err := dynamic.NewForConfig(rc)
		if err != nil {
			a.log.Error("kyverno reporter disabled: dynamic client", "err", err)
			return
		}
		a.Reporters = append(a.Reporters, newKyvernoReporter(a.kube.Discovery(), dyn, a.log))
	})
}

// kubeInformers are the typed informers shared by the netpol and image
// reporters. They are started once, for the lifetime of the process (base),
// so a reconnect does not re-list every pod in the cluster.
type kubeInformers struct {
	base    context.Context
	factory informers.SharedInformerFactory
	pods    cache.SharedIndexInformer
	rs      cache.SharedIndexInformer
	nss     cache.SharedIndexInformer
	netpols cache.SharedIndexInformer
	// Workloads for the NetworkPolicy simulator (pod template labels and
	// container ports only, see stripWorkload).
	deploys cache.SharedIndexInformer
	sts     cache.SharedIndexInformer
	ds      cache.SharedIndexInformer

	once   sync.Once
	synced chan struct{}
	err    error
}

func newKubeInformers(kube kubernetes.Interface) *kubeInformers {
	f := informers.NewSharedInformerFactory(kube, informerResync)
	k := &kubeInformers{
		base:    context.Background(),
		factory: f,
		pods:    f.Core().V1().Pods().Informer(),
		rs:      f.Apps().V1().ReplicaSets().Informer(),
		nss:     f.Core().V1().Namespaces().Informer(),
		netpols: f.Networking().V1().NetworkPolicies().Informer(),
		deploys: f.Apps().V1().Deployments().Informer(),
		sts:     f.Apps().V1().StatefulSets().Informer(),
		ds:      f.Apps().V1().DaemonSets().Informer(),
		synced:  make(chan struct{}),
	}
	// Keep only what the reporters need: no env, volumes, or
	// imagePullSecrets ever sit in agent memory.
	_ = k.pods.SetTransform(stripPod)
	_ = k.rs.SetTransform(stripMeta)
	_ = k.nss.SetTransform(stripMeta)
	_ = k.netpols.SetTransform(stripMeta)
	for _, inf := range []cache.SharedIndexInformer{k.deploys, k.sts, k.ds} {
		_ = inf.SetTransform(stripWorkload)
	}
	return k
}

// stripWorkload reduces a Deployment, StatefulSet or DaemonSet to its name,
// pod template labels and container names/ports. Env, volumes, secret and
// ConfigMap references, images and everything else are dropped before the
// object enters the cache.
func stripWorkload(obj any) (any, error) {
	meta := func(m metav1.ObjectMeta) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: m.Name, Namespace: m.Namespace, UID: m.UID, ResourceVersion: m.ResourceVersion}
	}
	tmpl := func(t corev1.PodTemplateSpec) corev1.PodTemplateSpec {
		out := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: t.Labels}}
		for _, c := range t.Spec.Containers {
			cc := corev1.Container{Name: c.Name}
			for _, p := range c.Ports {
				cc.Ports = append(cc.Ports, corev1.ContainerPort{Name: p.Name, ContainerPort: p.ContainerPort, Protocol: p.Protocol})
			}
			out.Spec.Containers = append(out.Spec.Containers, cc)
		}
		return out
	}
	switch w := obj.(type) {
	case *appsv1.Deployment:
		return &appsv1.Deployment{TypeMeta: w.TypeMeta, ObjectMeta: meta(w.ObjectMeta), Spec: appsv1.DeploymentSpec{Template: tmpl(w.Spec.Template)}}, nil
	case *appsv1.StatefulSet:
		return &appsv1.StatefulSet{TypeMeta: w.TypeMeta, ObjectMeta: meta(w.ObjectMeta), Spec: appsv1.StatefulSetSpec{Template: tmpl(w.Spec.Template)}}, nil
	case *appsv1.DaemonSet:
		return &appsv1.DaemonSet{TypeMeta: w.TypeMeta, ObjectMeta: meta(w.ObjectMeta), Spec: appsv1.DaemonSetSpec{Template: tmpl(w.Spec.Template)}}, nil
	}
	return obj, nil
}

// start starts the informers once and waits (bounded by ctx) for the caches.
func (k *kubeInformers) start(ctx context.Context) error {
	k.once.Do(func() {
		k.factory.Start(k.base.Done())
		go func() {
			defer close(k.synced)
			wctx, cancel := context.WithTimeout(k.base, cacheSyncTimeout)
			defer cancel()
			for typ, ok := range k.factory.WaitForCacheSync(wctx.Done()) {
				if !ok {
					k.err = fmt.Errorf("informer cache sync failed for %v", typ)
				}
			}
		}()
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-k.synced:
		return k.err
	}
}

// stripPod reduces a Pod to metadata, container names/images and container
// statuses. Everything else (env, volumes, imagePullSecrets, ...) is dropped.
func stripPod(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	out := &corev1.Pod{
		TypeMeta: p.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name, Namespace: p.Namespace, UID: p.UID, ResourceVersion: p.ResourceVersion,
			Labels: p.Labels, OwnerReferences: p.OwnerReferences,
		},
	}
	if keepSecretRefs.Load() {
		// Opt-in Secret inventory (F3): the NAMES of referenced Secrets only.
		// Transforms may run again on the stripped pod: keep what it has.
		if refs := PodSecretRefs(p); len(refs) > 0 {
			out.Annotations = map[string]string{annSecretRefs: strings.Join(refs, ",")}
		} else if v := p.Annotations[annSecretRefs]; v != "" {
			out.Annotations = map[string]string{annSecretRefs: v}
		}
	}
	for _, c := range p.Spec.Containers {
		out.Spec.Containers = append(out.Spec.Containers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range p.Spec.InitContainers {
		out.Spec.InitContainers = append(out.Spec.InitContainers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	out.Status.Phase = p.Status.Phase
	for _, s := range p.Status.ContainerStatuses {
		out.Status.ContainerStatuses = append(out.Status.ContainerStatuses, corev1.ContainerStatus{Name: s.Name, Image: s.Image, ImageID: s.ImageID})
	}
	for _, s := range p.Status.InitContainerStatuses {
		out.Status.InitContainerStatuses = append(out.Status.InitContainerStatuses, corev1.ContainerStatus{Name: s.Name, Image: s.Image, ImageID: s.ImageID})
	}
	return out, nil
}

// stripMeta drops managedFields and annotations from cached objects.
func stripMeta(obj any) (any, error) {
	if m, ok := obj.(metav1.Object); ok {
		m.SetManagedFields(nil)
		m.SetAnnotations(nil)
	}
	return obj, nil
}

// signal is a coalescing change notification.
type signal chan struct{}

func newSignal() signal { return make(signal, 1) }

func (s signal) poke() {
	select {
	case s <- struct{}{}:
	default:
	}
}

func (s signal) handler() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { s.poke() },
		UpdateFunc: func(any, any) { s.poke() },
		DeleteFunc: func(any) { s.poke() },
	}
}

// reportLoop drives one reporter for one control session: full report on
// start, debounced re-send on change (only when the content changed), and an
// unconditional resend every resend interval.
type reportLoop struct {
	name     string
	log      *slog.Logger
	changed  signal
	debounce time.Duration
	resend   time.Duration
	// extra triggers a rebuild on a timer (e.g. Kyverno CRD recheck); may be nil.
	extra <-chan time.Time
	build func(ctx context.Context) (*pb.ResourceReport, error)
}

func (l *reportLoop) run(ctx context.Context, send func(*pb.ResourceReport)) error {
	var last *pb.ResourceReport
	emit := func(force bool) {
		rep, err := l.build(ctx)
		if err != nil {
			if ctx.Err() == nil {
				l.log.Warn("build report", "reporter", l.name, "err", err)
			}
			return
		}
		if !force && last != nil && proto.Equal(last, rep) {
			return
		}
		send(rep)
		last = rep
	}
	emit(true)
	resend := l.resend
	if resend <= 0 {
		resend = resendInterval
	}
	t := time.NewTicker(resend)
	defer t.Stop()
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-l.changed:
			if debounce == nil {
				debounce = time.After(l.debounce)
			}
		case <-debounce:
			debounce = nil
			emit(false)
		case <-l.extra:
			emit(false)
		case <-t.C:
			emit(true)
		}
	}
}
