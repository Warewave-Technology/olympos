// Package audit runs kubescape and polaris on the server against a cluster's
// read-only API proxy, orchestrates the opt-in kube-bench Jobs on agents,
// normalizes results into findings and diffs them run over run (SPEC §12).
//
// Raw reports go to Blob at {prefix}/audit/{cluster}/{tool}/{run_id}.json on
// the destination named by settings key "audit.raw_destination_id" (a JSON
// string holding a destination id). The server never deletes them: the
// 400-day retention is a Blob lifecycle rule (prefix "{prefix}/audit/",
// delete base blob 400 days after creation; blobs also carry the index tag
// olympos-tier=audit for tag-filtered rules).
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/findings"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// RawDestinationSetting is the settings key naming the Blob destination for
// raw reports.
const RawDestinationSetting = "audit.raw_destination_id"

// ErrAgentOffline is the failure reason when the agent is not connected.
const reasonAgentOffline = "agent_offline"

// Gateway is the part of *gateway.Gateway the audit module uses.
type Gateway interface {
	Connected(clusterID uuid.UUID) bool
	Capabilities(clusterID uuid.UUID) (*pb.Capabilities, bool)
	Send(clusterID uuid.UUID, m *pb.ServerMessage) error
	DialAPIProxy(ctx context.Context, clusterID uuid.UUID) (gateway.Conn, error)
}

// Service executes audit runs.
type Service struct {
	DB           *store.DB
	Log          *slog.Logger
	Gateway      Gateway
	Blob         blob.Resolver // nil: raw reports are not stored
	KubescapeBin string

	ksMu       sync.Mutex
	ksFws      []string // cached `kubescape list frameworks`
	PolarisBin string
	// Exec runs a tool (default ExecTool).
	Exec        Exec
	ToolTimeout time.Duration
	// MaxConcurrent bounds runs executing on this replica (default 2).
	MaxConcurrent int
	// Poll is the worker's queue poll interval (default 5 s).
	Poll time.Duration
	// QueueTimeout fails runs queued longer than this whose agent is not
	// connected to this replica (default 15 min).
	QueueTimeout time.Duration
	Now          func() time.Time

	once     sync.Once
	mu       sync.Mutex
	bench    map[uuid.UUID]*benchCollector
	clusters map[uuid.UUID]bool // clusters with a run executing here
	sem      chan struct{}
	wg       sync.WaitGroup
}

func (s *Service) init() {
	s.once.Do(func() {
		s.bench = map[uuid.UUID]*benchCollector{}
		s.clusters = map[uuid.UUID]bool{}
		if s.MaxConcurrent <= 0 {
			s.MaxConcurrent = 2
		}
		s.sem = make(chan struct{}, s.MaxConcurrent)
		if s.Exec == nil {
			s.Exec = ExecTool
		}
		if s.ToolTimeout <= 0 {
			s.ToolTimeout = DefaultToolTimeout
		}
		if s.Poll <= 0 {
			s.Poll = 5 * time.Second
		}
		if s.QueueTimeout <= 0 {
			s.QueueTimeout = 15 * time.Minute
		}
		if s.Log == nil {
			s.Log = slog.Default()
		}
	})
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// InstallHooks routes agent bench messages to running collectors, chaining
// any hooks already installed.
func (s *Service) InstallHooks(h *gateway.Hooks) {
	s.init()
	prevStatus, prevResult := h.BenchStatus, h.BenchResult
	h.BenchStatus = func(ctx context.Context, clusterID uuid.UUID, st *pb.BenchStatus) {
		if c := s.collector(clusterID, st.GetRunId()); c != nil {
			c.status(st)
		}
		if prevStatus != nil {
			prevStatus(ctx, clusterID, st)
		}
	}
	h.BenchResult = func(ctx context.Context, clusterID uuid.UUID, ch *pb.BenchResultChunk) {
		if c := s.collector(clusterID, ch.GetRunId()); c != nil {
			c.chunk(ch)
		}
		if prevResult != nil {
			prevResult(ctx, clusterID, ch)
		}
	}
}

// collector returns the run's collector only if the message comes from the
// cluster the run belongs to.
func (s *Service) collector(clusterID uuid.UUID, runID string) *benchCollector {
	id, err := uuid.Parse(runID)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.bench[id]
	if c == nil || c.cluster != clusterID {
		return nil
	}
	return c
}

// ---------------------------------------------------------------- run model

// BenchNodeResult is one kube-bench node row.
type BenchNodeResult struct {
	NodeName       string `json:"node_name"`
	Benchmark      string `json:"benchmark"`
	State          string `json:"state"`
	Pass           int    `json:"pass"`
	Fail           int    `json:"fail"`
	Warn           int    `json:"warn"`
	Info           int    `json:"info"`
	ControlPlaneNA bool   `json:"control_plane_na"`
	Message        string `json:"message"`
	// Checks is every kube-bench check of the node (run detail only).
	Checks []BenchCheck `json:"checks"`
}

// Run is an audit run.
type Run struct {
	ID               uuid.UUID  `json:"id"`
	ScheduleID       *uuid.UUID `json:"schedule_id"`
	Tool             string     `json:"tool"`
	ClusterID        uuid.UUID  `json:"cluster_id"`
	ClusterName      string     `json:"cluster_name"`
	Status           string     `json:"status"`
	ScheduledFor     *time.Time `json:"scheduled_for,omitempty"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	Score            *float64   `json:"score"`
	NewFindings      int        `json:"new_findings"`
	ResolvedFindings int        `json:"resolved_findings"`
	RawBlobPath      string     `json:"raw_blob_path,omitempty"`
	Error            string     `json:"error"`
	// Log is the captured console output of a failed kubescape/polaris run
	// (redacted, last MaxLogBytes). Set by GetRun only (run detail).
	Log        *string           `json:"log,omitempty"`
	Details    map[string]any    `json:"details,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	BenchNodes []BenchNodeResult `json:"bench_nodes,omitempty"`
}

const runSelect = `
	SELECT r.id, r.schedule_id, r.tool, r.cluster_id, c.name, r.status, r.scheduled_for, r.started_at, r.finished_at,
	       r.score::float8, r.new_findings, r.resolved_findings, r.raw_blob_path, r.error, r.details, r.created_at
	FROM audit_runs r JOIN clusters c ON c.id = r.cluster_id`

func scanRuns(rows pgx.Rows) ([]Run, error) {
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		var d []byte
		if err := rows.Scan(&r.ID, &r.ScheduleID, &r.Tool, &r.ClusterID, &r.ClusterName, &r.Status, &r.ScheduledFor,
			&r.StartedAt, &r.FinishedAt, &r.Score, &r.NewFindings, &r.ResolvedFindings, &r.RawBlobPath, &r.Error, &d, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(d, &r.Details)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRun loads a run with its bench node results.
func GetRun(ctx context.Context, q store.Querier, id uuid.UUID) (Run, error) {
	rows, err := q.Query(ctx, runSelect+` WHERE r.id = $1`, id)
	if err != nil {
		return Run{}, err
	}
	runs, err := scanRuns(rows)
	if err != nil {
		return Run{}, err
	}
	if len(runs) == 0 {
		return Run{}, store.ErrNotFound
	}
	r := runs[0]
	var log string
	if err := q.QueryRow(ctx, `SELECT log FROM audit_runs WHERE id = $1`, id).Scan(&log); err != nil {
		return Run{}, store.NotFound(err)
	}
	r.Log = &log
	if r.Tool == ToolKubeBench {
		if r.BenchNodes, err = benchNodes(ctx, q, id); err != nil {
			return Run{}, err
		}
	}
	return r, nil
}

func benchNodes(ctx context.Context, q store.Querier, runID uuid.UUID) ([]BenchNodeResult, error) {
	rows, err := q.Query(ctx, `SELECT node_name, benchmark, state, pass, fail, warn, info, control_plane_na, message, checks
		FROM bench_node_results WHERE run_id = $1 ORDER BY node_name`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BenchNodeResult{}
	for rows.Next() {
		var b BenchNodeResult
		var cj []byte
		if err := rows.Scan(&b.NodeName, &b.Benchmark, &b.State, &b.Pass, &b.Fail, &b.Warn, &b.Info, &b.ControlPlaneNA, &b.Message, &cj); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cj, &b.Checks); err != nil || b.Checks == nil {
			b.Checks = []BenchCheck{}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// runContext is everything Execute needs about a run.
type runContext struct {
	Run
	Provider   string
	APIVersion string
	Frameworks []string
	NotifyID   *uuid.UUID
}

func (s *Service) loadRunContext(ctx context.Context, id uuid.UUID) (runContext, error) {
	var rc runContext
	var d []byte
	err := s.DB.QueryRow(ctx, `
		SELECT r.id, r.schedule_id, r.tool, r.cluster_id, c.name, r.status, r.details,
		       COALESCE(NULLIF(c.provider_override, ''), c.provider), c.api_version,
		       COALESCE(sch.frameworks, '{}'), sch.notify_channel_id
		FROM audit_runs r JOIN clusters c ON c.id = r.cluster_id
		LEFT JOIN audit_schedules sch ON sch.id = r.schedule_id
		WHERE r.id = $1`, id).Scan(&rc.ID, &rc.ScheduleID, &rc.Tool, &rc.ClusterID, &rc.ClusterName, &rc.Status, &d,
		&rc.Provider, &rc.APIVersion, &rc.Frameworks, &rc.NotifyID)
	if err != nil {
		return rc, store.NotFound(err)
	}
	_ = json.Unmarshal(d, &rc.Details)
	if rc.Details == nil {
		rc.Details = map[string]any{}
	}
	if fw, ok := rc.Details["frameworks"].([]any); ok && len(fw) > 0 {
		rc.Frameworks = rc.Frameworks[:0]
		for _, f := range fw {
			if s, ok := f.(string); ok {
				rc.Frameworks = append(rc.Frameworks, s)
			}
		}
	}
	return rc, nil
}

// ---------------------------------------------------------------- execute

// outcome is a finished tool run, ready to be persisted.
type outcome struct {
	status   string // succeeded | failed
	err      string // short reason
	log      string // captured tool output (failed kubescape/polaris runs)
	score    *float64
	current  []findings.Finding
	keepRefs []string // resource_refs whose open findings must not be resolved (partial runs)
	details  map[string]any
	rawPath  string
	nodes    []BenchNodeResult
}

// Execute runs a claimed (status=running) run to completion.
func (s *Service) Execute(ctx context.Context, runID uuid.UUID) error {
	s.init()
	rc, err := s.loadRunContext(ctx, runID)
	if err != nil {
		return err
	}
	var out outcome
	switch rc.Tool {
	case ToolKubescape, ToolPolaris:
		out = s.execTool(ctx, rc)
	case ToolKubeBench:
		out = s.execBench(ctx, rc)
	default:
		out = outcome{status: "failed", err: "unknown tool " + rc.Tool}
	}
	return s.finish(ctx, rc, out)
}

func failed(msg string) outcome { return outcome{status: "failed", err: msg} }

func (s *Service) execTool(ctx context.Context, rc runContext) outcome {
	if !s.Gateway.Connected(rc.ClusterID) {
		return failed(reasonAgentOffline)
	}
	proxy, err := StartAPIProxy(ctx, func(dctx context.Context) (net.Conn, error) {
		return s.Gateway.DialAPIProxy(dctx, rc.ClusterID)
	}, s.Log.With("component", "audit-proxy", "cluster", rc.ClusterName))
	if err != nil {
		return failed("could not start API proxy: " + err.Error())
	}
	defer proxy.Close()

	var inv Invocation
	switch rc.Tool {
	case ToolKubescape:
		inv, err = KubescapeInvocation(s.KubescapeBin, rc.Frameworks, rc.Provider, proxy.Kubeconfig, proxy.Dir(), s.kubescapeFrameworks(ctx)...)
		if err != nil {
			return failed(err.Error())
		}
	case ToolPolaris:
		inv = PolarisInvocation(s.PolarisBin, proxy.Kubeconfig, proxy.Dir())
	}
	tctx, cancel := context.WithTimeout(ctx, s.ToolTimeout)
	defer cancel()
	raw, err := s.Exec(tctx, inv, proxy.Dir())
	proxy.Close()
	if err != nil {
		var te *ToolError
		if errors.As(err, &te) {
			out := failed(Redact(te.Reason))
			out.log = RedactLog(te.Log)
			return out
		}
		return failed(Redact(err.Error()))
	}
	var n Normalized
	if rc.Tool == ToolKubescape {
		n, err = NormalizeKubescape(raw)
	} else {
		n, err = NormalizePolaris(raw)
	}
	if err != nil {
		return failed(err.Error())
	}
	details := map[string]any{"summary": n.Summary, "findings_total": len(n.Findings)}
	if rc.Tool == ToolKubescape {
		details["frameworks"] = rc.Frameworks
	}
	out := outcome{status: "succeeded", score: n.Score, current: n.Findings, details: details}
	out.rawPath = s.uploadRaw(ctx, rc, raw, details)
	return out
}

// ---------------------------------------------------------------- kube-bench

type nodeRow struct {
	name  string
	roles []string
}

func (s *Service) execBench(ctx context.Context, rc runContext) outcome {
	caps, ok := s.Gateway.Capabilities(rc.ClusterID)
	if !ok {
		return failed(reasonAgentOffline)
	}
	if !caps.GetBenchEnabled() {
		return failed("kube-bench is not enabled on this cluster's agent (set bench.enabled=true in the olympos-agent Helm values)")
	}
	allowed := map[string]bool{}
	for _, b := range caps.GetBenchAllowlist() {
		allowed[b] = true
	}
	rows, err := s.DB.Query(ctx, `SELECT name, roles FROM nodes WHERE cluster_id = $1 ORDER BY name`, rc.ClusterID)
	if err != nil {
		return failed("load nodes: " + err.Error())
	}
	var nodes []nodeRow
	for rows.Next() {
		var n nodeRow
		if err := rows.Scan(&n.name, &n.roles); err != nil {
			rows.Close()
			return failed("load nodes: " + err.Error())
		}
		nodes = append(nodes, n)
	}
	rows.Close()
	if len(nodes) == 0 {
		return failed("no nodes in the cluster inventory yet")
	}
	managed := inventory.ManagedControlPlane(rc.Provider)

	profiles := map[string]string{}
	var eligible []string
	for _, n := range nodes {
		p := SelectBenchmark(rc.Provider, rc.APIVersion, n.roles)
		profiles[n.name] = p
		state, msg := "pending", ""
		if !allowed[p] {
			state, msg = "rejected", fmt.Sprintf("benchmark %s is not in the agent allowlist (upgrade the agent)", p)
		} else {
			eligible = append(eligible, n.name)
		}
		if _, err := s.DB.Exec(ctx, `INSERT INTO bench_node_results (run_id, node_name, benchmark, state, control_plane_na, message)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (run_id, node_name) DO UPDATE SET benchmark = EXCLUDED.benchmark,
			state = EXCLUDED.state, control_plane_na = EXCLUDED.control_plane_na, message = EXCLUDED.message, updated_at = now()`,
			rc.ID, n.name, benchmarkName(p), state, managed, msg); err != nil {
			return failed("record bench nodes: " + err.Error())
		}
	}

	col := newBenchCollector(rc.ClusterID, eligible)
	s.mu.Lock()
	s.bench[rc.ID] = col
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.bench, rc.ID)
		s.mu.Unlock()
	}()
	for _, n := range eligible {
		err := s.Gateway.Send(rc.ClusterID, &pb.ServerMessage{Msg: &pb.ServerMessage_RunBench{RunBench: &pb.RunBench{
			RunId: rc.ID.String(), NodeName: n, Benchmark: profiles[n]}}})
		if err != nil {
			col.fail(n, reasonAgentOffline)
		}
	}
	persist := func() {
		for name, st := range col.snapshot() {
			_, _ = s.DB.Exec(ctx, `UPDATE bench_node_results SET state = $3, message = $4, updated_at = now()
				WHERE run_id = $1 AND node_name = $2 AND state <> $3`, rc.ID, name, st.State, st.Message)
		}
	}
	complete := col.wait(ctx, benchDeadline(len(eligible), int(caps.GetBenchMaxParallel())), persist)

	states := col.snapshot()
	out := outcome{details: map[string]any{}}
	var pass, fail, nOK, nFailed int
	raw := map[string]json.RawMessage{}
	for _, n := range nodes {
		res := BenchNodeResult{NodeName: n.name, Benchmark: benchmarkName(profiles[n.name]), ControlPlaneNA: managed}
		st, ok := states[n.name]
		switch {
		case !ok:
			res.State, res.Message = "rejected", fmt.Sprintf("benchmark %s is not in the agent allowlist (upgrade the agent)", profiles[n.name])
		case st.State == "succeeded" && st.Last:
			bn, err := NormalizeKubeBench(st.Data.Bytes(), n.name, profiles[n.name], managed)
			if err != nil {
				res.State, res.Message = "failed", err.Error()
				break
			}
			res.State = "succeeded"
			res.Pass, res.Fail, res.Warn, res.Info = bn.Pass, bn.Fail, bn.Warn, bn.Info
			res.Checks = bn.Checks
			pass += bn.Pass
			fail += bn.Fail
			out.current = append(out.current, bn.Findings...)
			raw[n.name] = json.RawMessage(bytes.Clone(st.Data.Bytes()))
		default:
			res.State, res.Message = st.State, st.Message
			if !st.done() {
				res.State = "failed"
				if ctx.Err() != nil {
					res.Message = "server shutting down"
				} else if !complete {
					res.Message = "timed out waiting for kube-bench result"
				}
			}
		}
		if res.State == "succeeded" {
			nOK++
		} else {
			nFailed++
			out.keepRefs = append(out.keepRefs, "node/"+n.name)
		}
		out.nodes = append(out.nodes, res)
	}
	out.details["nodes_succeeded"] = nOK
	out.details["nodes_failed"] = nFailed
	if managed {
		out.details["control_plane"] = "Control plane N/A · managed"
	}
	if pass+fail > 0 {
		out.score = round1(float64(pass) / float64(pass+fail) * 100)
	}
	if nOK == 0 {
		out.status, out.err = "failed", "kube-bench did not succeed on any node"
		return out
	}
	out.status = "succeeded"
	if nFailed > 0 {
		out.details["partial"] = true
	}
	b, _ := json.Marshal(map[string]any{"benchmark_by_node": profiles, "control_plane_na": managed, "nodes": raw})
	out.rawPath = s.uploadRaw(ctx, rc, b, out.details)
	return out
}

// ---------------------------------------------------------------- persist

func (s *Service) uploadRaw(ctx context.Context, rc runContext, raw []byte, details map[string]any) string {
	var v []byte
	err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, RawDestinationSetting).Scan(&v)
	var destID uuid.UUID
	if err == nil {
		var str string
		if json.Unmarshal(v, &str) == nil {
			destID, _ = uuid.Parse(str)
		}
	}
	if destID == uuid.Nil || s.Blob == nil {
		details["raw_report"] = "not stored: set settings key " + RawDestinationSetting + " to a destination id"
		return ""
	}
	w, err := s.Blob.ForDestination(ctx, destID)
	if err != nil {
		s.Log.Warn("audit raw report destination", "err", err)
		details["raw_report"] = "not stored: destination unavailable"
		return ""
	}
	p := path.Join(strings.Trim(w.Prefix(), "/"), "audit", rc.ClusterName, rc.Tool, rc.ID.String()+".json")
	p = strings.TrimPrefix(p, "/")
	if _, err := w.Upload(ctx, p, bytes.NewReader(raw), "application/json", map[string]string{"olympos-tier": "audit"}); err != nil {
		s.Log.Warn("audit raw report upload", "run_id", rc.ID, "err", err)
		details["raw_report"] = "not stored: upload failed"
		return ""
	}
	return p
}

// finish persists the outcome, diffs findings and emits audit.new_findings
// in one transaction.
func (s *Service) finish(ctx context.Context, rc runContext, out outcome) error {
	// Persist even when the run's context was cancelled (shutdown).
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if out.details == nil {
		out.details = map[string]any{}
	}
	for k, v := range rc.Details {
		if _, ok := out.details[k]; !ok {
			out.details[k] = v
		}
	}
	var newCount, resolvedCount int
	err := store.Tx(pctx, s.DB, func(tx pgx.Tx) error {
		for _, n := range out.nodes {
			checks := n.Checks
			if checks == nil {
				checks = []BenchCheck{}
			}
			cj, _ := json.Marshal(checks)
			if _, err := tx.Exec(pctx, `UPDATE bench_node_results SET state = $3, pass = $4, fail = $5, warn = $6, info = $7,
				control_plane_na = $8, message = $9, checks = $10, updated_at = now() WHERE run_id = $1 AND node_name = $2`,
				rc.ID, n.NodeName, n.State, n.Pass, n.Fail, n.Warn, n.Info, n.ControlPlaneNA, truncate(n.Message, 500), cj); err != nil {
				return err
			}
		}
		if out.status == "succeeded" {
			current := out.current
			if len(out.keepRefs) > 0 {
				kept, err := openFindings(pctx, tx, rc.Tool, rc.ClusterID, out.keepRefs)
				if err != nil {
					return err
				}
				current = append(current, kept...)
			}
			var err error
			newCount, resolvedCount, err = findings.Reconcile(pctx, tx, rc.Tool, rc.ClusterID, current, &rc.ID)
			if err != nil {
				return err
			}
		}
		d, _ := json.Marshal(out.details)
		if _, err := tx.Exec(pctx, `UPDATE audit_runs SET status = $2, finished_at = now(), started_at = COALESCE(started_at, now()),
			score = $3, new_findings = $4, resolved_findings = $5, raw_blob_path = $6, error = $7, details = $8, log = $9 WHERE id = $1`,
			rc.ID, out.status, out.score, newCount, resolvedCount, out.rawPath, truncate(out.err, 2000), d, out.log); err != nil {
			return err
		}
		if newCount > 0 {
			return notify.Emit(pctx, tx, NewFindingsEvent(rc.Run, rc.NotifyID, newCount, resolvedCount, out.score))
		}
		return nil
	})
	if err != nil {
		return err
	}
	metrics.AuditRuns.WithLabelValues(rc.Tool, out.status).Inc()
	s.Log.Info("audit run finished", "run_id", rc.ID, "tool", rc.Tool, "cluster", rc.ClusterName, "status", out.status,
		"new", newCount, "resolved", resolvedCount, "error", out.err)
	return nil
}

// NewFindingsEvent builds the audit.new_findings notification (link only, no
// finding details beyond counts).
func NewFindingsEvent(r Run, channel *uuid.UUID, newCount, resolved int, score *float64) notify.Event {
	fields := map[string]string{"cluster": r.ClusterName, "tool": r.Tool,
		"new": fmt.Sprint(newCount), "resolved": fmt.Sprint(resolved)}
	if score != nil {
		fields["score"] = fmt.Sprintf("%.1f", *score)
	}
	plural := "s"
	if newCount == 1 {
		plural = ""
	}
	return notify.Event{
		Type: notify.AuditNewFindings, Key: notify.AuditNewFindings + ":" + r.ID.String(), ChannelID: channel,
		Title:  fmt.Sprintf("%d new %s finding%s on %s", newCount, r.Tool, plural, r.ClusterName),
		Link:   "/audit?run=" + r.ID.String(),
		Fields: fields,
		Payload: map[string]any{"run_id": r.ID.String(), "cluster_id": r.ClusterID.String(), "new_findings": newCount,
			"resolved_findings": resolved},
	}
}

// openFindings returns the open findings for refs (kept open on partial runs).
func openFindings(ctx context.Context, q store.Querier, source string, clusterID uuid.UUID, refs []string) ([]findings.Finding, error) {
	rows, err := q.Query(ctx, `SELECT control_id, resource_ref, severity, title, details FROM findings
		WHERE status = 'open' AND source = $1 AND cluster_id = $2 AND resource_ref = ANY($3)`, source, clusterID, refs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findings.Finding
	for rows.Next() {
		var f findings.Finding
		var d []byte
		if err := rows.Scan(&f.ControlID, &f.ResourceRef, &f.Severity, &f.Title, &d); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(d, &f.Details)
		out = append(out, f)
	}
	return out, rows.Err()
}

// failQueued fails a queued run without executing it.
func (s *Service) failQueued(ctx context.Context, id uuid.UUID, tool, reason string) error {
	tag, err := s.DB.Exec(ctx, `UPDATE audit_runs SET status = 'failed', error = $2, finished_at = now()
		WHERE id = $1 AND status = 'queued'`, id, reason)
	if err == nil && tag.RowsAffected() > 0 {
		metrics.AuditRuns.WithLabelValues(tool, "failed").Inc()
	}
	return err
}

// kubescapeFrameworks returns (and caches) the installed kubescape's
// framework names; nil if the binary cannot list them (fallback table).
func (s *Service) kubescapeFrameworks(ctx context.Context) []string {
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if s.ksFws == nil {
		fws, err := ListKubescapeFrameworks(ctx, s.KubescapeBin)
		if err != nil {
			s.Log.Warn("kubescape frameworks unknown; using built-in names", "err", err)
			return nil
		}
		s.ksFws = fws
	}
	return s.ksFws
}
