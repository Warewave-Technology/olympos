package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

func TestBenchImagePinnedByDigest(t *testing.T) {
	if !strings.HasPrefix(KubeBenchImage, "docker.io/aquasec/kube-bench:") || !strings.Contains(KubeBenchImage, "@sha256:") {
		t.Fatalf("image not pinned by digest: %s", KubeBenchImage)
	}
	d := KubeBenchImage[strings.Index(KubeBenchImage, "@sha256:")+8:]
	if len(d) != 64 {
		t.Fatalf("digest length %d", len(d))
	}
}

// Golden assertions on the compiled-in Job spec (SPEC §12.3.3).
func TestBenchJobSpec(t *testing.T) {
	runID := "7d1c2a64-1d7b-4c43-9a59-3f1c8f1b0c2e"
	j := BenchJob("olympos-bench", KubeBenchImage, runID, "node-a", "cis-1.12/node", benchProfiles["cis-1.12/node"])
	if j.Namespace != "olympos-bench" || j.Name != BenchJobName(runID, "node-a") || len(j.Name) > 63 {
		t.Fatalf("meta %s/%s", j.Namespace, j.Name)
	}
	s := j.Spec
	if *s.ActiveDeadlineSeconds != 600 || *s.TTLSecondsAfterFinished != 300 || *s.BackoffLimit != 0 || *s.Parallelism != 1 {
		t.Fatalf("job spec %+v", s)
	}
	p := s.Template.Spec
	if p.NodeName != "node-a" || !p.HostPID || p.HostNetwork || p.HostIPC || p.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("pod %+v", p)
	}
	if p.AutomountServiceAccountToken == nil || *p.AutomountServiceAccountToken {
		t.Fatal("service account token must not be mounted")
	}
	wantTol := []corev1.Toleration{
		{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		{Key: "node-role.kubernetes.io/master", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
	}
	if !reflect.DeepEqual(p.Tolerations, wantTol) {
		t.Fatalf("tolerations %+v", p.Tolerations)
	}
	if len(p.Containers) != 1 || len(p.InitContainers) != 0 {
		t.Fatal("exactly one container")
	}
	c := p.Containers[0]
	if c.Image != KubeBenchImage {
		t.Fatalf("image %s", c.Image)
	}
	if want := []string{"kube-bench", "run", "--targets", "node", "--benchmark", "cis-1.12", "--json"}; !reflect.DeepEqual(c.Command, want) || len(c.Args) != 0 {
		t.Fatalf("command %v args %v", c.Command, c.Args)
	}
	sc := c.SecurityContext
	if sc == nil || sc.Privileged == nil || *sc.Privileged || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem {
		t.Fatalf("security context %+v", sc)
	}
	if sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
		t.Fatalf("added capabilities %v", sc.Capabilities.Add)
	}
	if len(c.Env) != 0 || len(c.EnvFrom) != 0 || len(c.Ports) != 0 {
		t.Fatal("no env, envFrom or ports")
	}
	wantMounts := map[string]string{
		"/etc/kubernetes":                "/etc/kubernetes",
		"/var/lib/kubelet":               "/var/lib/kubelet",
		"/etc/systemd":                   "/etc/systemd",
		"/usr/local/mount-from-host/bin": "/usr/bin",
	}
	checkMounts(t, p, c, wantMounts)

	// Control plane profile additionally mounts /var/lib/etcd read-only.
	j = BenchJob("olympos-bench", KubeBenchImage, runID, "cp-1", "cis-1.12/master", benchProfiles["cis-1.12/master"])
	p = j.Spec.Template.Spec
	if p.Containers[0].Command[3] != "master,controlplane,node,policies" {
		t.Fatalf("targets %v", p.Containers[0].Command)
	}
	wantMounts["/var/lib/etcd"] = "/var/lib/etcd"
	checkMounts(t, p, p.Containers[0], wantMounts)
}

func checkMounts(t *testing.T, p corev1.PodSpec, c corev1.Container, want map[string]string) {
	t.Helper()
	vols := map[string]corev1.Volume{}
	for _, v := range p.Volumes {
		vols[v.Name] = v
	}
	if len(c.VolumeMounts) != len(want) || len(p.Volumes) != len(want) {
		t.Fatalf("mounts %d volumes %d want %d", len(c.VolumeMounts), len(p.Volumes), len(want))
	}
	for _, m := range c.VolumeMounts {
		if !m.ReadOnly {
			t.Errorf("mount %s is writable", m.MountPath)
		}
		v, ok := vols[m.Name]
		if !ok || v.HostPath == nil {
			t.Fatalf("mount %s has no hostPath volume", m.MountPath)
		}
		if want[m.MountPath] != v.HostPath.Path {
			t.Errorf("mount %s ← %s, want %s", m.MountPath, v.HostPath.Path, want[m.MountPath])
		}
	}
}

func TestBenchAllowlist(t *testing.T) {
	al := BenchProfiles()
	for _, want := range []string{"aks-1.8/node", "eks-1.8.0/node", "gke-1.9.0/node", "cis-1.12/master", "cis-1.12/node"} {
		found := false
		for _, a := range al {
			found = found || a == want
		}
		if !found {
			t.Errorf("%s missing from %v", want, al)
		}
	}
	for id, p := range benchProfiles {
		if strings.ContainsAny(p.Benchmark+p.Targets, " ;&|$`") {
			t.Errorf("profile %s has unsafe characters", id)
		}
	}
}

// ---------------------------------------------------------------- Run

type recorder struct {
	mu     sync.Mutex
	states []string
	msgs   []string
	data   bytes.Buffer
	chunks int
	last   bool
}

func (r *recorder) status(s *pb.BenchStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, s.State)
	r.msgs = append(r.msgs, s.Message)
}

func (r *recorder) chunk(c *pb.BenchResultChunk) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(c.Data) > benchChunkSize {
		panic("chunk too large")
	}
	r.data.Write(c.Data)
	r.chunks++
	r.last = c.Last
}

func (r *recorder) final() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.states) == 0 {
		return ""
	}
	return r.states[len(r.states)-1]
}

func newTestRunner(t *testing.T, maxParallel int, nodes ...string) (*benchRunner, *fake.Clientset) {
	t.Helper()
	kube := fake.NewClientset()
	for _, n := range nodes {
		if _, err := kube.CoreV1().Nodes().Create(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	b := newBenchRunner(kube, Config{BenchMaxParallel: maxParallel, BenchNamespace: "olympos-bench"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.poll = 10 * time.Millisecond
	return b, kube
}

// completeJobs plays the Job controller: marks jobs complete and creates
// their pod, until ctx ends.
func completeJobs(ctx context.Context, kube *fake.Clientset, ns string, fail bool) {
	done := map[string]bool{}
	for ctx.Err() == nil {
		jobs, _ := kube.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		for _, j := range jobs.Items {
			if done[j.Name] {
				continue
			}
			done[j.Name] = true
			_, _ = kube.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: j.Name + "-abcde", Namespace: ns,
				Labels: j.Spec.Template.Labels}}, metav1.CreateOptions{})
			cond := batchv1.JobCondition{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}
			if fail {
				cond = batchv1.JobCondition{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"}
			}
			j.Status.Conditions = append(j.Status.Conditions, cond)
			_, _ = kube.BatchV1().Jobs(ns).UpdateStatus(ctx, &j, metav1.UpdateOptions{})
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBenchRunSuccessStreamsChunksAndDeletesJob(t *testing.T) {
	b, kube := newTestRunner(t, 2, "node-a")
	big := `{"Controls":[{"id":"4","node_type":"node","tests":[]}],"pad":"` + strings.Repeat("x", 600<<10) + `"}`
	b.readLogs = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(big + "\n")), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go completeJobs(ctx, kube, "olympos-bench", false)

	rec := &recorder{}
	b.Run(ctx, &pb.RunBench{RunId: uuid.NewString(), NodeName: "node-a", Benchmark: "cis-1.12/node"}, rec.status, rec.chunk)
	if got := strings.Join(rec.states, ","); got != "accepted,running,succeeded" {
		t.Fatalf("states %s (%v)", got, rec.msgs)
	}
	if rec.data.String() != big || !rec.last || rec.chunks != 3 {
		t.Fatalf("chunks=%d last=%v len=%d", rec.chunks, rec.last, rec.data.Len())
	}
	jobs, _ := kube.BatchV1().Jobs("olympos-bench").List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatalf("job not deleted: %d", len(jobs.Items))
	}
}

func TestBenchRunJobFailureAndNonJSON(t *testing.T) {
	b, kube := newTestRunner(t, 1, "node-a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go completeJobs(ctx, kube, "olympos-bench", true)
	rec := &recorder{}
	b.Run(ctx, &pb.RunBench{RunId: uuid.NewString(), NodeName: "node-a", Benchmark: "aks-1.8/node"}, rec.status, rec.chunk)
	if rec.final() != "failed" || !strings.Contains(rec.msgs[len(rec.msgs)-1], "DeadlineExceeded") || rec.chunks != 0 {
		t.Fatalf("states %v %v", rec.states, rec.msgs)
	}

	b2, kube2 := newTestRunner(t, 1, "node-a")
	go completeJobs(ctx, kube2, "olympos-bench", false)
	b2.readLogs = func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("level=error something")), nil
	}
	rec = &recorder{}
	b2.Run(ctx, &pb.RunBench{RunId: uuid.NewString(), NodeName: "node-a", Benchmark: "aks-1.8/node"}, rec.status, rec.chunk)
	if rec.final() != "failed" || rec.chunks != 0 {
		t.Fatalf("non-JSON: %v %v", rec.states, rec.msgs)
	}
}

func TestBenchRejectsUnknownNodeAndBenchmark(t *testing.T) {
	b, kube := newTestRunner(t, 1, "node-a")
	ctx := context.Background()
	cases := []struct {
		req  *pb.RunBench
		want string
	}{
		{&pb.RunBench{RunId: uuid.NewString(), NodeName: "node-zzz", Benchmark: "cis-1.12/node"}, "unknown node"},
		{&pb.RunBench{RunId: uuid.NewString(), NodeName: "node-a", Benchmark: "cis-1.12"}, "allowlist"},
		{&pb.RunBench{RunId: uuid.NewString(), NodeName: "node-a", Benchmark: "cis-1.12/node --config /etc/x"}, "allowlist"},
		{&pb.RunBench{RunId: "../../x", NodeName: "node-a", Benchmark: "cis-1.12/node"}, "invalid run id"},
		{&pb.RunBench{RunId: uuid.NewString(), NodeName: "Node_A;rm", Benchmark: "cis-1.12/node"}, "invalid node name"},
	}
	for _, c := range cases {
		rec := &recorder{}
		b.Run(ctx, c.req, rec.status, rec.chunk)
		if len(rec.states) != 1 || rec.states[0] != "rejected" || !strings.Contains(rec.msgs[0], c.want) {
			t.Errorf("%+v: %v %v", c.req, rec.states, rec.msgs)
		}
	}
	jobs, _ := kube.BatchV1().Jobs("olympos-bench").List(ctx, metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatal("job created for a rejected request")
	}
}

func TestBenchParallelismCap(t *testing.T) {
	nodes := []string{"n1", "n2", "n3", "n4", "n5"}
	b, kube := newTestRunner(t, 2, nodes...)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	recs := make([]*recorder, len(nodes))
	for i, n := range nodes {
		recs[i] = &recorder{}
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			b.Run(ctx, &pb.RunBench{RunId: uuid.NewString(), NodeName: n, Benchmark: "cis-1.12/node"}, recs[i].status, recs[i].chunk)
		}(i, n)
	}
	// No job ever completes: only maxParallel jobs may exist.
	deadline := time.Now().Add(2 * time.Second)
	maxSeen := 0
	for time.Now().Before(deadline) {
		jobs, _ := kube.BatchV1().Jobs("olympos-bench").List(context.Background(), metav1.ListOptions{})
		maxSeen = max(maxSeen, len(jobs.Items))
		if maxSeen > 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if maxSeen != 2 {
		t.Fatalf("concurrent jobs = %d, want 2", maxSeen)
	}
	running := 0
	for _, r := range recs {
		r.mu.Lock()
		for _, s := range r.states {
			if s == "running" {
				running++
			}
		}
		r.mu.Unlock()
	}
	if running != 2 {
		t.Fatalf("running = %d", running)
	}
	cancel()
	wg.Wait()
	jobs, _ := kube.BatchV1().Jobs("olympos-bench").List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Fatalf("jobs left behind: %d", len(jobs.Items))
	}
}

func TestBenchExtenderOnlyWhenEnabled(t *testing.T) {
	a := &Agent{kube: fake.NewClientset(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	Extend(a, Config{BenchEnabled: false}, &rest.Config{})
	if a.Bench != nil {
		t.Fatal("bench runner installed while disabled")
	}
	Extend(a, Config{BenchEnabled: true, BenchMaxParallel: 3, BenchNamespace: "olympos-bench"}, &rest.Config{})
	if a.Bench == nil || len(a.Bench.Allowlist()) == 0 {
		t.Fatal("bench runner not installed")
	}
}
