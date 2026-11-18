package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// ---------------------------------------------------------------- fakes

type fakeGW struct {
	mu        sync.Mutex
	connected map[uuid.UUID]bool
	caps      map[uuid.UUID]*pb.Capabilities
	sent      []*pb.RunBench
	onSend    func(cluster uuid.UUID, rb *pb.RunBench)
}

func newFakeGW() *fakeGW {
	return &fakeGW{connected: map[uuid.UUID]bool{}, caps: map[uuid.UUID]*pb.Capabilities{}}
}

func (g *fakeGW) Connected(id uuid.UUID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.connected[id]
}

func (g *fakeGW) Capabilities(id uuid.UUID) (*pb.Capabilities, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.connected[id] {
		return nil, false
	}
	c := g.caps[id]
	if c == nil {
		c = &pb.Capabilities{}
	}
	return c, true
}

func (g *fakeGW) Send(id uuid.UUID, m *pb.ServerMessage) error {
	g.mu.Lock()
	if !g.connected[id] {
		g.mu.Unlock()
		return gateway.ErrAgentOffline
	}
	rb := m.GetRunBench()
	g.sent = append(g.sent, rb)
	f := g.onSend
	g.mu.Unlock()
	if f != nil && rb != nil {
		go f(id, rb)
	}
	return nil
}

func (g *fakeGW) DialAPIProxy(context.Context, uuid.UUID) (gateway.Conn, error) {
	return nil, errors.New("no tunnel in unit tests")
}

type fakeWriter struct {
	mu      sync.Mutex
	prefix  string
	uploads map[string][]byte
	tags    map[string]map[string]string
}

func (w *fakeWriter) Upload(_ context.Context, path string, r io.Reader, _ string, tags map[string]string) (blob.UploadResult, error) {
	b, _ := io.ReadAll(r)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.uploads[path] = b
	w.tags[path] = tags
	return blob.UploadResult{Bytes: int64(len(b))}, nil
}
func (w *fakeWriter) Prefix() string { return w.prefix }

type fakeResolver struct {
	id uuid.UUID
	w  *fakeWriter
}

func (f *fakeResolver) ForDestination(_ context.Context, id uuid.UUID) (blob.Writer, error) {
	if id != f.id {
		return nil, errors.New("unknown destination")
	}
	return f.w, nil
}

// ---------------------------------------------------------------- helpers

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func addCluster(t *testing.T, db *store.DB, name string, labels map[string]string, provider, status string, bench bool) uuid.UUID {
	t.Helper()
	l, _ := json.Marshal(labels)
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO clusters (name, labels, provider, status, bench_enabled, api_version)
		VALUES ($1, $2, $3, $4, $5, 'v1.33.1') RETURNING id`, name, l, provider, status, bench).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func addNode(t *testing.T, db *store.DB, cluster uuid.UUID, name string, roles ...string) {
	t.Helper()
	if roles == nil {
		roles = []string{}
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO nodes (cluster_id, name, roles) VALUES ($1,$2,$3)`, cluster, name, roles); err != nil {
		t.Fatal(err)
	}
}

func addSchedule(t *testing.T, db *store.DB, tool, scope, cron string, channel *uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	fw := []string{}
	if tool == ToolKubescape {
		fw = []string{"nsa", "mitre"}
	}
	if err := db.QueryRow(context.Background(), `INSERT INTO audit_schedules (tool, frameworks, scope_selector, cron, notify_channel_id)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`, tool, fw, scope, cron, channel).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func addRunningRun(t *testing.T, db *store.DB, sched uuid.UUID, tool string, cluster uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO audit_runs (schedule_id, tool, cluster_id, status, started_at)
		VALUES ($1,$2,$3,'running', now()) RETURNING id`, sched, tool, cluster).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func outboxEvents(t *testing.T, db *store.DB) []map[string]any {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT event_type, payload, channel_id FROM outbox ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var typ string
		var p []byte
		var ch *uuid.UUID
		if err := rows.Scan(&typ, &p, &ch); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		_ = json.Unmarshal(p, &m)
		m["_type"] = typ
		m["_channel"] = ch
		out = append(out, m)
	}
	return out
}

func openCount(t *testing.T, db *store.DB, source string, cluster uuid.UUID) int {
	t.Helper()
	var n int
	_ = db.QueryRow(context.Background(), `SELECT count(*) FROM findings WHERE source=$1 AND cluster_id=$2 AND status='open'`, source, cluster).Scan(&n)
	return n
}

// ---------------------------------------------------------------- tests

func TestKubescapeRunsDiffAndNotify(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	gw := newFakeGW()
	c := addCluster(t, db, "prod-aks", map[string]string{"env": "prod"}, "azure", "online", false)
	gw.connected[c] = true
	var channel uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO notification_channels (slack_channel_id, name) VALUES ('C123', 'sec') RETURNING id`).Scan(&channel); err != nil {
		t.Fatal(err)
	}
	sched := addSchedule(t, db, ToolKubescape, "env=prod", "0 3 * * *", &channel)

	destID := uuid.New()
	w := &fakeWriter{prefix: "olympos/", uploads: map[string][]byte{}, tags: map[string]map[string]string{}}
	if _, err := db.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, to_jsonb($2::text))`, RawDestinationSetting, destID.String()); err != nil {
		t.Fatal(err)
	}

	var fixtureName atomic.Value
	var gotInv Invocation
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw, Blob: &fakeResolver{id: destID, w: w}, KubescapeBin: "/usr/local/bin/kubescape",
		Exec: func(_ context.Context, inv Invocation, workDir string) ([]byte, error) {
			gotInv = inv
			if !strings.HasPrefix(inv.OutputFile, workDir) {
				t.Errorf("output outside the private dir: %s", inv.OutputFile)
			}
			return fixture(t, fixtureName.Load().(string)), nil
		}}

	// Run 1: four findings, all new → event with the schedule's channel.
	fixtureName.Store("kubescape-run1.json")
	r1 := addRunningRun(t, db, sched, ToolKubescape, c)
	if err := svc.Execute(ctx, r1); err != nil {
		t.Fatal(err)
	}
	run, err := GetRun(ctx, db, r1)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "succeeded" || run.NewFindings != 4 || run.ResolvedFindings != 0 || run.Score == nil || *run.Score != 77.1 {
		t.Fatalf("run1 %+v", run)
	}
	if gotInv.Args[2] != "nsa,mitre" {
		t.Errorf("frameworks from schedule: %v", gotInv.Args)
	}
	wantPath := "olympos/audit/prod-aks/kubescape/" + r1.String() + ".json"
	if run.RawBlobPath != wantPath || w.uploads[wantPath] == nil || w.tags[wantPath]["olympos-tier"] != "audit" {
		t.Fatalf("raw path %q uploads %v", run.RawBlobPath, w.uploads)
	}
	ev := outboxEvents(t, db)
	if len(ev) != 1 || ev[0]["_type"] != "audit.new_findings" || ev[0]["link"] != "/audit?run="+r1.String() {
		t.Fatalf("events %v", ev)
	}
	if ch, _ := ev[0]["_channel"].(*uuid.UUID); ch == nil || *ch != channel {
		t.Fatalf("channel override missing: %v", ev[0]["_channel"])
	}
	if !strings.Contains(ev[0]["title"].(string), "4 new kubescape findings on prod-aks") {
		t.Errorf("title %v", ev[0]["title"])
	}

	// Run 2: one new (db StatefulSet), two resolved (C-0057, C-0262).
	fixtureName.Store("kubescape-run2.json")
	r2 := addRunningRun(t, db, sched, ToolKubescape, c)
	if err := svc.Execute(ctx, r2); err != nil {
		t.Fatal(err)
	}
	run, _ = GetRun(ctx, db, r2)
	if run.NewFindings != 1 || run.ResolvedFindings != 2 {
		t.Fatalf("run2 new=%d resolved=%d", run.NewFindings, run.ResolvedFindings)
	}
	if n := openCount(t, db, "kubescape", c); n != 3 {
		t.Fatalf("open = %d", n)
	}
	var resolvedRun uuid.UUID
	_ = db.QueryRow(ctx, `SELECT resolved_run_id FROM findings WHERE control_id='C-0057' AND status='resolved'`).Scan(&resolvedRun)
	if resolvedRun != r2 {
		t.Errorf("resolved_run_id %v", resolvedRun)
	}
	if ev := outboxEvents(t, db); len(ev) != 2 {
		t.Fatalf("events after run2: %d", len(ev))
	}

	// Run 3: same as run 2 → nothing new → no event.
	r3 := addRunningRun(t, db, sched, ToolKubescape, c)
	if err := svc.Execute(ctx, r3); err != nil {
		t.Fatal(err)
	}
	run, _ = GetRun(ctx, db, r3)
	if run.NewFindings != 0 || run.ResolvedFindings != 0 || run.Status != "succeeded" {
		t.Fatalf("run3 %+v", run)
	}
	if ev := outboxEvents(t, db); len(ev) != 2 {
		t.Fatalf("event emitted with new=0: %d events", len(ev))
	}

	// A failing run never resolves findings.
	svc.Exec = func(context.Context, Invocation, string) ([]byte, error) {
		return nil, errors.New("kubescape failed: boom")
	}
	r4 := addRunningRun(t, db, sched, ToolKubescape, c)
	if err := svc.Execute(ctx, r4); err != nil {
		t.Fatal(err)
	}
	run, _ = GetRun(ctx, db, r4)
	if run.Status != "failed" || !strings.Contains(run.Error, "boom") || openCount(t, db, "kubescape", c) != 3 {
		t.Fatalf("failed run %+v open=%d", run, openCount(t, db, "kubescape", c))
	}
}

func TestPolarisRunWithoutDestination(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	gw := newFakeGW()
	c := addCluster(t, db, "dev", nil, "onprem", "online", false)
	gw.connected[c] = true
	sched := addSchedule(t, db, ToolPolaris, "all", "0 3 * * *", nil)
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw, PolarisBin: "polaris",
		Exec: func(context.Context, Invocation, string) ([]byte, error) { return fixture(t, "polaris.json"), nil }}
	r := addRunningRun(t, db, sched, ToolPolaris, c)
	if err := svc.Execute(ctx, r); err != nil {
		t.Fatal(err)
	}
	run, _ := GetRun(ctx, db, r)
	if run.Status != "succeeded" || run.NewFindings != 3 || run.RawBlobPath != "" {
		t.Fatalf("run %+v", run)
	}
	if !strings.Contains(run.Details["raw_report"].(string), RawDestinationSetting) {
		t.Fatalf("details %v", run.Details)
	}
	ev := outboxEvents(t, db)
	if len(ev) != 1 || ev[0]["_channel"].(*uuid.UUID) != nil {
		t.Fatalf("events %v", ev)
	}
}

func TestToolRunAgentOffline(t *testing.T) {
	db := testutil.DB(t)
	gw := newFakeGW()
	c := addCluster(t, db, "c1", nil, "onprem", "online", false)
	sched := addSchedule(t, db, ToolPolaris, "all", "0 3 * * *", nil)
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw}
	r := addRunningRun(t, db, sched, ToolPolaris, c)
	if err := svc.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	run, _ := GetRun(context.Background(), db, r)
	if run.Status != "failed" || run.Error != "agent_offline" {
		t.Fatalf("run %+v", run)
	}
}

func TestKubeBenchManagedRun(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	gw := newFakeGW()
	c := addCluster(t, db, "prod-aks", nil, "azure", "online", true)
	other := addCluster(t, db, "other", nil, "azure", "online", true)
	addNode(t, db, c, "aks-n1", "agent")
	addNode(t, db, c, "aks-n2", "agent")
	gw.connected[c] = true
	gw.caps[c] = &pb.Capabilities{BenchEnabled: true, BenchMaxParallel: 2, BenchAllowlist: []string{"aks-1.8/node", "cis-1.12/node"}}
	sched := addSchedule(t, db, ToolKubeBench, "all", "0 4 * * 0", nil)

	var hooks gateway.Hooks
	var prevCalls atomic.Int32
	hooks.BenchStatus = func(context.Context, uuid.UUID, *pb.BenchStatus) { prevCalls.Add(1) }
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw}
	svc.InstallHooks(&hooks)

	raw := fixture(t, "kube-bench-aks.json")
	gw.onSend = func(cluster uuid.UUID, rb *pb.RunBench) {
		st := func(s, m string) {
			hooks.BenchStatus(ctx, cluster, &pb.BenchStatus{RunId: rb.RunId, NodeName: rb.NodeName, State: s, Message: m})
		}
		if rb.Benchmark != "aks-1.8/node" {
			st("rejected", "unexpected benchmark "+rb.Benchmark)
			return
		}
		// A spoofed message from another cluster must be ignored.
		hooks.BenchStatus(ctx, other, &pb.BenchStatus{RunId: rb.RunId, NodeName: rb.NodeName, State: "failed", Message: "spoof"})
		if rb.NodeName == "aks-n2" {
			st("rejected", "unknown node")
			return
		}
		st("accepted", "")
		st("running", "")
		half := len(raw) / 2
		hooks.BenchResult(ctx, cluster, &pb.BenchResultChunk{RunId: rb.RunId, NodeName: rb.NodeName, Data: raw[:half]})
		hooks.BenchResult(ctx, cluster, &pb.BenchResultChunk{RunId: rb.RunId, NodeName: rb.NodeName, Data: raw[half:], Last: true})
		st("succeeded", "")
	}

	r := addRunningRun(t, db, sched, ToolKubeBench, c)
	done := make(chan error, 1)
	go func() { done <- svc.Execute(ctx, r) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("bench run did not finish")
	}
	run, _ := GetRun(ctx, db, r)
	if run.Status != "succeeded" || run.NewFindings != 1 || run.Details["partial"] != true {
		t.Fatalf("run %+v", run)
	}
	if len(run.BenchNodes) != 2 {
		t.Fatalf("nodes %+v", run.BenchNodes)
	}
	n1, n2 := run.BenchNodes[0], run.BenchNodes[1]
	if n1.State != "succeeded" || n1.Pass != 3 || n1.Fail != 1 || n1.Warn != 1 || !n1.ControlPlaneNA || n1.Benchmark != "aks-1.8" {
		t.Fatalf("n1 %+v", n1)
	}
	if n2.State != "rejected" || n2.Message != "unknown node" || !n2.ControlPlaneNA {
		t.Fatalf("n2 %+v", n2)
	}
	if run.Details["control_plane"] != "Control plane N/A · managed" {
		t.Errorf("details %v", run.Details)
	}
	if prevCalls.Load() == 0 {
		t.Error("previous BenchStatus hook not chained")
	}
	// The managed control plane FAIL (2.1.1) is never a finding.
	var cp int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM findings WHERE source='kube-bench' AND control_id LIKE '%:2.1.1'`).Scan(&cp)
	if cp != 0 {
		t.Fatal("control plane check reported as a finding on a managed cluster")
	}

	// Second run: n1 fails, n2 succeeds. n1's finding must stay open (a
	// failed node is not evidence of a fix); n2's is new.
	gw.onSend = func(cluster uuid.UUID, rb *pb.RunBench) {
		if rb.NodeName == "aks-n1" {
			hooks.BenchStatus(ctx, cluster, &pb.BenchStatus{RunId: rb.RunId, NodeName: rb.NodeName, State: "failed", Message: "kube-bench job failed: DeadlineExceeded"})
			return
		}
		hooks.BenchResult(ctx, cluster, &pb.BenchResultChunk{RunId: rb.RunId, NodeName: rb.NodeName, Data: raw, Last: true})
		hooks.BenchStatus(ctx, cluster, &pb.BenchStatus{RunId: rb.RunId, NodeName: rb.NodeName, State: "succeeded"})
	}
	r2 := addRunningRun(t, db, sched, ToolKubeBench, c)
	if err := svc.Execute(ctx, r2); err != nil {
		t.Fatal(err)
	}
	run, _ = GetRun(ctx, db, r2)
	if run.Status != "succeeded" || run.NewFindings != 1 || run.ResolvedFindings != 0 || openCount(t, db, "kube-bench", c) != 2 {
		t.Fatalf("run2 %+v open=%d", run, openCount(t, db, "kube-bench", c))
	}
	if run.BenchNodes[0].State != "failed" || !strings.Contains(run.BenchNodes[0].Message, "DeadlineExceeded") {
		t.Fatalf("n1 %+v", run.BenchNodes[0])
	}

	// Third run: every node fails → run failed, nothing resolved.
	gw.onSend = func(cluster uuid.UUID, rb *pb.RunBench) {
		hooks.BenchStatus(ctx, cluster, &pb.BenchStatus{RunId: rb.RunId, NodeName: rb.NodeName, State: "failed", Message: "x"})
	}
	r3 := addRunningRun(t, db, sched, ToolKubeBench, c)
	if err := svc.Execute(ctx, r3); err != nil {
		t.Fatal(err)
	}
	run, _ = GetRun(ctx, db, r3)
	if run.Status != "failed" || openCount(t, db, "kube-bench", c) != 2 {
		t.Fatalf("run3 %+v open=%d", run, openCount(t, db, "kube-bench", c))
	}
}

func TestKubeBenchRequiresCapability(t *testing.T) {
	db := testutil.DB(t)
	gw := newFakeGW()
	c := addCluster(t, db, "c1", nil, "onprem", "online", false)
	addNode(t, db, c, "n1")
	gw.connected[c] = true
	gw.caps[c] = &pb.Capabilities{BenchEnabled: false}
	sched := addSchedule(t, db, ToolKubeBench, "all", "0 4 * * 0", nil)
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw}
	r := addRunningRun(t, db, sched, ToolKubeBench, c)
	if err := svc.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	run, _ := GetRun(context.Background(), db, r)
	if run.Status != "failed" || !strings.Contains(run.Error, "bench.enabled=true") || len(gw.sent) != 0 {
		t.Fatalf("run %+v sent=%d", run, len(gw.sent))
	}
}

func TestKubeBenchOnPremSelectsPerNode(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	gw := newFakeGW()
	c := addCluster(t, db, "lab", nil, "onprem", "online", true)
	addNode(t, db, c, "cp1", "control-plane")
	addNode(t, db, c, "w1")
	gw.connected[c] = true
	gw.caps[c] = &pb.Capabilities{BenchEnabled: true, BenchMaxParallel: 1, BenchAllowlist: []string{"cis-1.12/master", "cis-1.12/node"}}
	var hooks gateway.Hooks
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw}
	svc.InstallHooks(&hooks)
	master := fixture(t, "kube-bench-master.json")
	gw.onSend = func(cluster uuid.UUID, rb *pb.RunBench) {
		hooks.BenchResult(ctx, cluster, &pb.BenchResultChunk{RunId: rb.RunId, NodeName: rb.NodeName, Data: master, Last: true})
		hooks.BenchStatus(ctx, cluster, &pb.BenchStatus{RunId: rb.RunId, NodeName: rb.NodeName, State: "succeeded"})
	}
	sched := addSchedule(t, db, ToolKubeBench, "all", "0 4 * * 0", nil)
	r := addRunningRun(t, db, sched, ToolKubeBench, c)
	if err := svc.Execute(ctx, r); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range gw.sent {
		got[s.NodeName] = s.Benchmark
	}
	if got["cp1"] != "cis-1.12/master" || got["w1"] != "cis-1.12/node" {
		t.Fatalf("benchmarks %v", got)
	}
	run, _ := GetRun(ctx, db, r)
	for _, n := range run.BenchNodes {
		if n.ControlPlaneNA || n.State != "succeeded" || n.Fail != 2 {
			t.Fatalf("node %+v", n)
		}
	}
	if run.Score == nil || *run.Score != 50 {
		t.Fatalf("score %v", run.Score)
	}
}

func TestSchedulerTickQueuesIdempotently(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	prod := addCluster(t, db, "prod", map[string]string{"env": "prod"}, "azure", "online", true)
	addCluster(t, db, "dev", map[string]string{"env": "dev"}, "azure", "online", true)
	prodNoBench := addCluster(t, db, "prod2", map[string]string{"env": "prod"}, "azure", "offline", false)
	addCluster(t, db, "pending", map[string]string{"env": "prod"}, "", "pending", true)
	ks := addSchedule(t, db, ToolKubescape, "env=prod", "*/5 * * * *", nil)
	kb := addSchedule(t, db, ToolKubeBench, "env=prod", "*/5 * * * *", nil)
	disabled := addSchedule(t, db, ToolPolaris, "all", "*/5 * * * *", nil)
	if _, err := db.Exec(ctx, `UPDATE audit_schedules SET created_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE audit_schedules SET enabled = false WHERE id = $1`, disabled); err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db, Log: quietLog(), Gateway: newFakeGW()}
	for i := 0; i < 2; i++ {
		if err := svc.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sched uuid.UUID) (n int, clusters []uuid.UUID) {
		rows, _ := db.Query(ctx, `SELECT cluster_id FROM audit_runs WHERE schedule_id = $1 AND status = 'queued'`, sched)
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			_ = rows.Scan(&id)
			clusters = append(clusters, id)
		}
		return len(clusters), clusters
	}
	if n, cl := count(ks); n != 2 || !containsID(cl, prod) || !containsID(cl, prodNoBench) {
		t.Fatalf("kubescape runs %d %v", n, cl)
	}
	if n, cl := count(kb); n != 1 || cl[0] != prod {
		t.Fatalf("kube-bench runs %d %v (bench capability required)", n, cl)
	}
	if n, _ := count(disabled); n != 0 {
		t.Fatal("disabled schedule queued")
	}
	// Idempotent even if last_scheduled_for is rolled back.
	if _, err := db.Exec(ctx, `UPDATE audit_schedules SET last_scheduled_for = last_scheduled_for - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := count(ks); n != 2 {
		t.Fatalf("duplicate runs: %d", n)
	}
}

func containsID(xs []uuid.UUID, id uuid.UUID) bool {
	for _, x := range xs {
		if x == id {
			return true
		}
	}
	return false
}

func TestDispatch(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	gw := newFakeGW()
	here := addCluster(t, db, "here", nil, "onprem", "online", false)
	elsewhere := addCluster(t, db, "elsewhere", nil, "onprem", "online", false)
	offline := addCluster(t, db, "offline", nil, "onprem", "offline", false)
	gw.connected[here] = true
	sched := addSchedule(t, db, ToolPolaris, "all", "0 3 * * *", nil)
	queue := func(c uuid.UUID) uuid.UUID {
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO audit_runs (schedule_id, tool, cluster_id, status) VALUES ($1,'polaris',$2,'queued') RETURNING id`, sched, c).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	rHere, rElse, rOff := queue(here), queue(elsewhere), queue(offline)
	var execs atomic.Int32
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw, Exec: func(context.Context, Invocation, string) ([]byte, error) {
		execs.Add(1)
		return fixture(t, "polaris.json"), nil
	}}
	if err := svc.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	svc.Wait()
	status := func(id uuid.UUID) (string, string) {
		r, _ := GetRun(ctx, db, id)
		return r.Status, r.Error
	}
	if s, _ := status(rHere); s != "succeeded" || execs.Load() != 1 {
		t.Fatalf("here: %s execs=%d", s, execs.Load())
	}
	if s, _ := status(rElse); s != "queued" {
		t.Fatalf("elsewhere (connected to another replica) should stay queued: %s", s)
	}
	if s, e := status(rOff); s != "failed" || e != "agent_offline" {
		t.Fatalf("offline: %s %s", s, e)
	}
	// Waited too long → agent_offline.
	svc.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := svc.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	if s, e := status(rElse); s != "failed" || e != "agent_offline" {
		t.Fatalf("stale: %s %s", s, e)
	}
}

func TestEventOnlyWhenNew(t *testing.T) {
	r := Run{ID: uuid.New(), ClusterName: "c", Tool: "polaris"}
	e := NewFindingsEvent(r, nil, 1, 0, nil)
	if e.Type != "audit.new_findings" || e.Title != "1 new polaris finding on c" || !bytes.Contains([]byte(e.Link), []byte(r.ID.String())) {
		t.Fatalf("event %+v", e)
	}
}
