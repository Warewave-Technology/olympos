package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// KubeBenchImage is the kube-bench image, pinned by digest (SPEC §12.3.2).
// The digest is the multi-arch index of docker.io/aquasec/kube-bench:v0.16.0
// (Docker Hub, pushed 2026-08-05). To update: pick a release tag, read its
// index digest (`crane digest docker.io/aquasec/kube-bench:<tag>` or
// `docker buildx imagetools inspect`), verify it (optionally with cosign),
// update both the tag and the digest here and in the Kyverno PolicyException
// of the agent chart, and re-check BenchProfiles against the release's cfg/.
const KubeBenchImage = "docker.io/aquasec/kube-bench:v0.16.0@sha256:75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679"

// Bench limits.
const (
	benchActiveDeadline = 600 // seconds (SPEC §12.3.3)
	benchTTL            = 300 // seconds after finish
	benchChunkSize      = 256 << 10
	benchMaxLog         = 16 << 20
	benchContainer      = "kube-bench"
	benchJobLabel       = "olympos.io/bench-job"
)

// benchProfile is a compiled-in kube-bench invocation. The server only ever
// names a profile; it cannot influence the command line, image or mounts.
type benchProfile struct {
	Benchmark    string // kube-bench --benchmark
	Targets      string // kube-bench --targets
	ControlPlane bool   // mount /var/lib/etcd and run control plane targets
}

// benchProfiles is the allowlist advertised in Hello (SPEC §12.3.1). IDs are
// "<benchmark>/<role>"; managed providers only have node profiles.
var benchProfiles = map[string]benchProfile{
	"cis-1.9/master":  {Benchmark: "cis-1.9", Targets: "master,controlplane,node,policies", ControlPlane: true},
	"cis-1.9/node":    {Benchmark: "cis-1.9", Targets: "node"},
	"cis-1.10/master": {Benchmark: "cis-1.10", Targets: "master,controlplane,node,policies", ControlPlane: true},
	"cis-1.10/node":   {Benchmark: "cis-1.10", Targets: "node"},
	"cis-1.11/master": {Benchmark: "cis-1.11", Targets: "master,controlplane,node,policies", ControlPlane: true},
	"cis-1.11/node":   {Benchmark: "cis-1.11", Targets: "node"},
	"cis-1.12/master": {Benchmark: "cis-1.12", Targets: "master,controlplane,node,policies", ControlPlane: true},
	"cis-1.12/node":   {Benchmark: "cis-1.12", Targets: "node"},
	"aks-1.8/node":    {Benchmark: "aks-1.8", Targets: "node"},
	"eks-1.8.0/node":  {Benchmark: "eks-1.8.0", Targets: "node"},
	"gke-1.9.0/node":  {Benchmark: "gke-1.9.0", Targets: "node"},
}

// BenchProfiles returns the sorted allowlist of benchmark profile IDs.
func BenchProfiles() []string {
	out := make([]string, 0, len(benchProfiles))
	for k := range benchProfiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func init() {
	registerExtender(func(a *Agent, cfg Config, _ *rest.Config) {
		if !cfg.BenchEnabled {
			return
		}
		a.Bench = newBenchRunner(a.kube, cfg, a.log)
	})
}

// benchRunner implements BenchRunner with one Job per node.
type benchRunner struct {
	kube  kubernetes.Interface
	ns    string
	image string
	log   *slog.Logger
	sem   chan struct{}
	poll  time.Duration
	// readLogs streams the kube-bench container log (stubbed in tests).
	readLogs func(ctx context.Context, pod string) (io.ReadCloser, error)
}

func newBenchRunner(kube kubernetes.Interface, cfg Config, log *slog.Logger) *benchRunner {
	n := cfg.BenchMaxParallel
	if n < 1 {
		n = 1
	}
	ns := cfg.BenchNamespace
	if ns == "" {
		ns = "olympos-bench"
	}
	b := &benchRunner{kube: kube, ns: ns, image: KubeBenchImage, log: log, sem: make(chan struct{}, n), poll: 3 * time.Second}
	b.readLogs = func(ctx context.Context, pod string) (io.ReadCloser, error) {
		limit := int64(benchMaxLog)
		return b.kube.CoreV1().Pods(b.ns).GetLogs(pod, &corev1.PodLogOptions{Container: benchContainer, LimitBytes: &limit}).Stream(ctx)
	}
	return b
}

func (b *benchRunner) Allowlist() []string { return BenchProfiles() }

// Run validates the request, runs the Job and streams the JSON result.
func (b *benchRunner) Run(ctx context.Context, req *pb.RunBench, status func(*pb.BenchStatus), chunk func(*pb.BenchResultChunk)) {
	st := func(state, msg string) {
		status(&pb.BenchStatus{RunId: req.RunId, NodeName: req.NodeName, State: state, Message: msg})
	}
	prof, ok := benchProfiles[req.Benchmark]
	if !ok {
		st("rejected", fmt.Sprintf("benchmark %q is not in the agent allowlist", req.Benchmark))
		return
	}
	if _, err := uuid.Parse(req.RunId); err != nil {
		st("rejected", "invalid run id")
		return
	}
	if errs := validation.IsDNS1123Subdomain(req.NodeName); len(errs) > 0 {
		st("rejected", "invalid node name")
		return
	}
	if _, err := b.kube.CoreV1().Nodes().Get(ctx, req.NodeName, metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			st("rejected", "unknown node")
		} else {
			st("rejected", "node lookup failed")
		}
		return
	}
	st("accepted", "")

	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		st("failed", "agent shutting down")
		return
	}
	defer func() { <-b.sem }()
	st("running", "")

	job := BenchJob(b.ns, b.image, req.RunId, req.NodeName, req.Benchmark, prof)
	if _, err := b.kube.BatchV1().Jobs(b.ns).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			st("failed", "a kube-bench job for this run and node already exists")
		} else {
			b.log.Error("create kube-bench job", "node", req.NodeName, "err", err)
			st("failed", "could not create kube-bench job")
		}
		return
	}
	defer b.deleteJob(job.Name)

	data, err := b.wait(ctx, job.Name)
	if err != nil {
		st("failed", err.Error())
		return
	}
	for off := 0; ; off += benchChunkSize {
		end := min(off+benchChunkSize, len(data))
		last := end == len(data)
		chunk(&pb.BenchResultChunk{RunId: req.RunId, NodeName: req.NodeName, Data: data[off:end], Last: last})
		if last {
			break
		}
	}
	st("succeeded", "")
}

func (b *benchRunner) deleteJob(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bg := metav1.DeletePropagationBackground
	if err := b.kube.BatchV1().Jobs(b.ns).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil && !apierrors.IsNotFound(err) {
		// ttlSecondsAfterFinished cleans up anyway.
		b.log.Warn("delete kube-bench job", "job", name, "err", err)
	}
}

// wait polls the Job until it finishes, then reads the pod log.
func (b *benchRunner) wait(ctx context.Context, name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, (benchActiveDeadline+120)*time.Second)
	defer cancel()
	t := time.NewTicker(b.poll)
	defer t.Stop()
	for {
		j, err := b.kube.BatchV1().Jobs(b.ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			if done, failed := jobFinished(j); done {
				if failed {
					return nil, fmt.Errorf("kube-bench job failed: %s", jobFailureReason(j))
				}
				return b.result(ctx, name)
			}
		} else if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("kube-bench job disappeared")
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("kube-bench job did not finish in time")
		case <-t.C:
		}
	}
}

func (b *benchRunner) result(ctx context.Context, job string) ([]byte, error) {
	pods, err := b.kube.CoreV1().Pods(b.ns).List(ctx, metav1.ListOptions{LabelSelector: benchJobLabel + "=" + job})
	if err != nil || len(pods.Items) == 0 {
		return nil, fmt.Errorf("kube-bench pod not found")
	}
	rc, err := b.readLogs(ctx, pods.Items[0].Name)
	if err != nil {
		return nil, fmt.Errorf("read kube-bench log failed")
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, benchMaxLog+1))
	if err != nil {
		return nil, fmt.Errorf("read kube-bench log failed")
	}
	if len(data) > benchMaxLog {
		return nil, fmt.Errorf("kube-bench output too large")
	}
	data = extractJSON(data)
	if data == nil {
		return nil, fmt.Errorf("kube-bench output is not JSON")
	}
	return data, nil
}

// extractJSON returns the kube-bench JSON document from a pod log. The log
// mixes stdout and stderr, so warnings may surround the document; the first
// line that parses as a JSON object wins.
func extractJSON(log []byte) []byte {
	if t := bytes.TrimSpace(log); json.Valid(t) {
		return t
	}
	for _, line := range bytes.Split(log, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] == '{' && json.Valid(line) {
			return line
		}
	}
	return nil
}

func jobFinished(j *batchv1.Job) (done, failed bool) {
	for _, c := range j.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return true, false
		case batchv1.JobFailed:
			return true, true
		}
	}
	return false, false
}

func jobFailureReason(j *batchv1.Job) string {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			if c.Reason != "" {
				return c.Reason
			}
		}
	}
	return "unknown"
}

// BenchJobName is deterministic per (run, node) and DNS-safe.
func BenchJobName(runID, node string) string {
	h := sha256.Sum256([]byte(runID + "/" + node))
	return "olympos-bench-" + hex.EncodeToString(h[:8])
}

// BenchJob is the compiled-in Job spec (SPEC §12.3.3). Only the node name,
// run id and a profile from benchProfiles vary.
func BenchJob(ns, image, runID, node, profileID string, p benchProfile) *batchv1.Job {
	name := BenchJobName(runID, node)
	labels := map[string]string{
		"app.kubernetes.io/name":       "olympos-bench",
		"app.kubernetes.io/managed-by": "olympos-agent",
		benchJobLabel:                  name,
		"olympos.io/run-id":            runID,
	}
	annotations := map[string]string{"olympos.io/node": node, "olympos.io/benchmark": profileID}
	hostPath := func(volName, path string) corev1.Volume {
		t := corev1.HostPathUnset // no checks: absent paths (e.g. etcd) don't block the pod
		return corev1.Volume{Name: volName, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path, Type: &t}}}
	}
	volumes := []corev1.Volume{
		hostPath("etc-kubernetes", "/etc/kubernetes"),
		hostPath("var-lib-kubelet", "/var/lib/kubelet"),
		hostPath("etc-systemd", "/etc/systemd"),
		hostPath("usr-bin", "/usr/bin"),
	}
	mounts := []corev1.VolumeMount{
		{Name: "etc-kubernetes", MountPath: "/etc/kubernetes", ReadOnly: true},
		{Name: "var-lib-kubelet", MountPath: "/var/lib/kubelet", ReadOnly: true},
		{Name: "etc-systemd", MountPath: "/etc/systemd", ReadOnly: true},
		// Host binaries are mounted aside (kube-bench's convention), never
		// over the container's own /usr/bin.
		{Name: "usr-bin", MountPath: "/usr/local/mount-from-host/bin", ReadOnly: true},
	}
	if p.ControlPlane {
		volumes = append(volumes, hostPath("var-lib-etcd", "/var/lib/etcd"))
		mounts = append(mounts, corev1.VolumeMount{Name: "var-lib-etcd", MountPath: "/var/lib/etcd", ReadOnly: true})
	}
	f, t := false, true
	root := int64(0)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels, Annotations: annotations},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr(int32(0)),
			Parallelism:             ptr(int32(1)),
			Completions:             ptr(int32(1)),
			ActiveDeadlineSeconds:   ptr(int64(benchActiveDeadline)),
			TTLSecondsAfterFinished: ptr(int32(benchTTL)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations},
				Spec: corev1.PodSpec{
					NodeName:                     node,
					HostPID:                      true,
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: &f,
					EnableServiceLinks:           &f,
					Tolerations: []corev1.Toleration{
						{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
						{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
					},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:      &root, // node files are root-owned
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            benchContainer,
						Image:           image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"kube-bench", "run", "--targets", p.Targets, "--benchmark", p.Benchmark, "--json"},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               &f,
							AllowPrivilegeEscalation: &f,
							ReadOnlyRootFilesystem:   &t,
							// No added capabilities; the runtime default set is
							// kept so root can traverse restrictive host dirs.
							Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
						},
						VolumeMounts: mounts,
					}},
					Volumes: volumes,
				},
			},
		},
	}
}

func ptr[T any](v T) *T { return &v }
