package agent

import (
	"context"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// imageReporter reports running images by digest (SPEC §13.3) from Pod
// container statuses, attributed to their top-level workload. It never reads
// imagePullSecrets: the server pulls with its own registry credentials.
type imageReporter struct {
	inf     *kubeInformers
	log     *slog.Logger
	changed signal
}

func newImageReporter(inf *kubeInformers, log *slog.Logger) *imageReporter {
	r := &imageReporter{inf: inf, log: log, changed: newSignal()}
	_, _ = inf.pods.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { r.changed.poke() },
		UpdateFunc: func(o, n any) {
			// Pods update constantly (status, probes); only image or owner
			// changes matter here.
			op, ok1 := o.(*corev1.Pod)
			np, ok2 := n.(*corev1.Pod)
			if !ok1 || !ok2 || podImageSignature(op) != podImageSignature(np) {
				r.changed.poke()
			}
		},
		DeleteFunc: func(any) { r.changed.poke() },
	})
	_, _ = inf.rs.AddEventHandler(r.changed.handler())
	return r
}

func (r *imageReporter) Name() string { return "images" }

func (r *imageReporter) Run(ctx context.Context, send func(*pb.ResourceReport)) error {
	if err := r.inf.start(ctx); err != nil {
		return err
	}
	l := &reportLoop{name: r.Name(), log: r.log, changed: r.changed, debounce: 10 * time.Second, build: r.build}
	return l.run(ctx, send)
}

func (r *imageReporter) build(context.Context) (*pb.ResourceReport, error) {
	var pods []*corev1.Pod
	for _, o := range r.inf.pods.GetStore().List() {
		if p, ok := o.(*corev1.Pod); ok {
			pods = append(pods, p)
		}
	}
	return &pb.ResourceReport{Report: &pb.ResourceReport_Images{Images: &pb.ImageReport{
		Uses: ImageUses(pods, r.inf.rs.GetIndexer()),
	}}}, nil
}

// ImageUses converts pods into deduplicated, sorted image uses. rs is an
// indexer of ReplicaSets (namespace/name keys) used to resolve Deployments.
func ImageUses(pods []*corev1.Pod, rs cache.Indexer) []*pb.ImageUse {
	type key struct{ digest, ns, kind, name, container string }
	seen := map[key]*pb.ImageUse{}
	for _, p := range pods {
		kind, name := ResolveOwner(p, rs)
		specImages := map[string]string{}
		for _, c := range p.Spec.InitContainers {
			specImages[c.Name] = c.Image
		}
		for _, c := range p.Spec.Containers {
			specImages[c.Name] = c.Image
		}
		statuses := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		for _, st := range statuses {
			repo, digest, ok := ParseImageID(st.ImageID)
			if !ok {
				continue
			}
			img := specImages[st.Name]
			if img == "" {
				img = st.Image
			}
			if img == "" || strings.HasPrefix(img, "sha256:") {
				img = repo
			}
			if img == "" {
				continue
			}
			k := key{digest, p.Namespace, kind, name, st.Name}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = &pb.ImageUse{Image: img, Digest: digest, Namespace: p.Namespace, WorkloadKind: kind, WorkloadName: name, Container: st.Name}
		}
	}
	out := make([]*pb.ImageUse, 0, len(seen))
	for _, u := range seen {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.WorkloadKind != b.WorkloadKind {
			return a.WorkloadKind < b.WorkloadKind
		}
		if a.WorkloadName != b.WorkloadName {
			return a.WorkloadName < b.WorkloadName
		}
		if a.Container != b.Container {
			return a.Container < b.Container
		}
		return a.Digest < b.Digest
	})
	return out
}

var digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ParseImageID extracts the digest (sha256:...) and, when present, the
// repository from a containerStatus imageID. Runtime prefixes such as
// docker-pullable:// are stripped. ok is false when there is no digest
// (container not started yet, or an unknown format).
func ParseImageID(id string) (repo, digest string, ok bool) {
	id = strings.TrimSpace(id)
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if at := strings.LastIndex(id, "@"); at >= 0 {
		repo, id = id[:at], id[at+1:]
	}
	id = strings.ToLower(id)
	if !digestRe.MatchString(id) {
		return "", "", false
	}
	return repo, id, true
}

// cronJobSuffix matches Job names created by the CronJob controller:
// <cronjob>-<scheduled time in minutes since the epoch>.
var cronJobSuffix = regexp.MustCompile(`^(.+)-([0-9]{8,10})$`)

// ResolveOwner returns the top-level workload of a pod: Deployment (via its
// ReplicaSet), StatefulSet, DaemonSet, CronJob (best effort, from the Job
// name: the agent has no RBAC on batch/jobs), Job, other controllers, or the
// Pod itself.
func ResolveOwner(p *corev1.Pod, rs cache.Indexer) (kind, name string) {
	ref := metav1.GetControllerOf(p)
	if ref == nil {
		return "Pod", p.Name
	}
	switch ref.Kind {
	case "ReplicaSet":
		if rs != nil {
			if o, exists, err := rs.GetByKey(p.Namespace + "/" + ref.Name); err == nil && exists {
				if r, ok := o.(*appsv1.ReplicaSet); ok {
					if owner := metav1.GetControllerOf(r); owner != nil {
						return owner.Kind, owner.Name
					}
					return "ReplicaSet", r.Name
				}
			}
		}
		// ReplicaSet not cached (yet): Deployment-owned ReplicaSets are named
		// <deployment>-<pod-template-hash>.
		if h := p.Labels[appsv1.DefaultDeploymentUniqueLabelKey]; h != "" {
			if d, ok := strings.CutSuffix(ref.Name, "-"+h); ok && d != "" {
				return "Deployment", d
			}
		}
		return "ReplicaSet", ref.Name
	case "Job":
		if m := cronJobSuffix.FindStringSubmatch(ref.Name); m != nil {
			return "CronJob", m[1]
		}
		return "Job", ref.Name
	default:
		return ref.Kind, ref.Name
	}
}

// podImageSignature changes when anything ImageUses depends on changes.
func podImageSignature(p *corev1.Pod) string {
	var b strings.Builder
	for _, r := range p.OwnerReferences {
		b.WriteString(r.Kind + "/" + r.Name + ";")
	}
	for _, s := range p.Status.InitContainerStatuses {
		b.WriteString(s.Name + "=" + s.ImageID + ";")
	}
	for _, s := range p.Status.ContainerStatuses {
		b.WriteString(s.Name + "=" + s.ImageID + ";")
	}
	for _, c := range p.Spec.Containers {
		b.WriteString(c.Name + ":" + c.Image + ";")
	}
	return b.String()
}
