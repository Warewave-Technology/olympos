package synthetic

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Cell states of the overview matrix and the per-cluster table
// (decisions after review, 4). Probe states come from clusters.probe_status:
// a skipped run never touches synthetic_state.
const (
	// CellFailing: the cluster alert fires.
	CellFailing = "failing"
	// CellDegraded: the last run failed or errored; the alert does not fire
	// (yet).
	CellDegraded = "degraded"
	// CellPassing: the last run passed.
	CellPassing = "passing"
	// CellProbeOffline: the probe is offline, or enrolled and not
	// connected yet. Never shown as failed (§2.3).
	CellProbeOffline = "probe_offline"
	// CellNotInstalled: the cluster has no probe (never installed, or
	// revoked).
	CellNotInstalled = "not_installed"
	// CellExcluded: the scenario's targeting leaves the cluster out.
	CellExcluded = "excluded"
	// CellPaused: the scenario is disabled.
	CellPaused = "paused"
	// CellNoData: no run has counted yet.
	CellNoData = "no_data"
)

// Window of the availability, the percentiles and the timeline.
const (
	statsWindow    = 24 * time.Hour
	bucketWidth    = 30 * time.Minute
	timelineBucket = 48
)

// cellState is where a scenario stands on a cluster. Excluded wins, then
// paused, then the probe, then the alert, then the last counted run.
func cellState(enabled bool, target string, firing bool, lastStatus *string) string {
	switch {
	case target == TargetExcluded:
		return CellExcluded
	case !enabled:
		return CellPaused
	case target == TargetProbeNotInstalled:
		return CellNotInstalled
	case target == TargetProbeOffline:
		return CellProbeOffline
	case firing:
		return CellFailing
	case lastStatus == nil:
		return CellNoData
	case *lastStatus == StatusFailed || *lastStatus == StatusError:
		return CellDegraded
	case *lastStatus == StatusPassed:
		return CellPassing
	}
	return CellNoData
}

// pairState is a synthetic_state row with its last run's failure.
type pairState struct {
	failures, passes int
	lastRun          *uuid.UUID
	lastStatus       *string
	lastFinished     *time.Time
	blocked          string
	failedStep       *int
	reason           string
}

func loadPairStates(ctx context.Context, q store.Querier, scenarios []uuid.UUID) (map[pair]pairState, error) {
	rows, err := q.Query(ctx, `SELECT st.scenario_id, st.cluster_id, st.consecutive_failures, st.consecutive_passes, st.last_run_id,
			st.last_status, st.last_finished_at, st.blocked_reason, r.failed_step, COALESCE(r.failure_reason, '')
		FROM synthetic_state st LEFT JOIN synthetic_runs r ON r.id = st.last_run_id WHERE st.scenario_id = ANY($1)`, scenarios)
	if err != nil {
		return nil, err
	}
	out := map[pair]pairState{}
	_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
		var p pair
		var s pairState
		err := r.Scan(&p.scenario, &p.cluster, &s.failures, &s.passes, &s.lastRun, &s.lastStatus, &s.lastFinished, &s.blocked,
			&s.failedStep, &s.reason)
		out[p] = s
		return struct{}{}, err
	})
	return out, err
}

func loadFiring(ctx context.Context, q store.Querier, scenarios []uuid.UUID) (map[pair]bool, error) {
	rows, err := q.Query(ctx, `SELECT scenario_id, cluster_id FROM synthetic_alerts
		WHERE state = 'firing' AND cluster_id IS NOT NULL AND scenario_id = ANY($1)`, scenarios)
	if err != nil {
		return nil, err
	}
	out := map[pair]bool{}
	_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
		var p pair
		err := r.Scan(&p.scenario, &p.cluster)
		out[p] = true
		return struct{}{}, err
	})
	return out, err
}

// stats are the counted runs (passed, failed, error; no test runs) of a
// window.
type stats struct {
	runs, passed int
	p50, p95     *float64
}

// availability is the share of passed runs in percent, two decimals; nil
// without runs.
func (s stats) availability() *float64 {
	if s.runs == 0 {
		return nil
	}
	v := math.Round(float64(s.passed)*10000/float64(s.runs)) / 100
	return &v
}

func ms(v *float64) *int {
	if v == nil {
		return nil
	}
	n := int(math.Round(*v))
	return &n
}

// loadStats reads the stats since since per scenario, or per scenario and
// cluster (byCluster), over the given clusters.
func loadStats(ctx context.Context, q store.Querier, scenarios, clusters []uuid.UUID, since time.Time, byCluster bool) (map[pair]stats, error) {
	cols, group := `scenario_id, NULL::uuid`, `scenario_id`
	if byCluster {
		cols, group = `scenario_id, cluster_id`, `scenario_id, cluster_id`
	}
	rows, err := q.Query(ctx, `SELECT `+cols+`, count(*), count(*) FILTER (WHERE status = 'passed'),
			percentile_cont(0.5) WITHIN GROUP (ORDER BY total_ms), percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms)
		FROM synthetic_runs WHERE scenario_id = ANY($1) AND cluster_id = ANY($2) AND NOT test
		  AND `+countedRunSQL+` AND finished_at > $3
		GROUP BY `+group, scenarios, clusters, since)
	if err != nil {
		return nil, err
	}
	out := map[pair]stats{}
	_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
		var p pair
		var c *uuid.UUID
		var s stats
		err := r.Scan(&p.scenario, &c, &s.runs, &s.passed, &s.p50, &s.p95)
		if c != nil {
			p.cluster = *c
		}
		out[p] = s
		return struct{}{}, err
	})
	return out, err
}

// ---------------------------------------------------------------- overview

type overviewCluster struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	ProbeStatus     string     `json:"probe_status"`
	ProbeVersion    string     `json:"probe_version"`
	ProbeLastSeenAt *time.Time `json:"probe_last_seen_at"`
}

// cellView is one scenario on one cluster: its state and its last counted
// run.
type cellView struct {
	ClusterID           uuid.UUID  `json:"cluster_id"`
	State               string     `json:"state"`
	LastRunID           *uuid.UUID `json:"last_run_id"`
	LastStatus          *string    `json:"last_status"`
	LastFinishedAt      *time.Time `json:"last_finished_at"`
	FailedStep          *int       `json:"failed_step"`
	FailureReason       string     `json:"failure_reason"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	// BlockedReason: rate_limit when a cap of §6.3 keeps the scheduler from
	// running the scenario there.
	BlockedReason string `json:"blocked_reason"`
}

type overviewRow struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	OwnerSelector    string     `json:"owner_selector"`
	IntervalSeconds  int        `json:"interval_seconds"`
	Enabled          bool       `json:"enabled"`
	Steps            int        `json:"steps"`
	Status           string     `json:"status"`
	FailingClusters  int        `json:"failing_clusters"`
	DegradedClusters int        `json:"degraded_clusters"`
	Cells            []cellView `json:"cells"`
	Runs24h          int        `json:"runs_24h"`
	Availability24h  *float64   `json:"availability_24h"`
	P95Ms24h         *int       `json:"p95_ms_24h"`
	CanEdit          bool       `json:"can_edit"`
}

type overviewKPIs struct {
	Scenarios          int      `json:"scenarios"`
	Active             int      `json:"active"`
	Paused             int      `json:"paused"`
	FailingScenarios   int      `json:"failing_scenarios"`
	FailingClusters    int      `json:"failing_clusters"`
	DegradedScenarios  int      `json:"degraded_scenarios"`
	DegradedClusters   int      `json:"degraded_clusters"`
	ProbesOnline       int      `json:"probes_online"`
	ProbesTotal        int      `json:"probes_total"`
	ProbesOffline      []string `json:"probes_offline"`
	ProbesNotInstalled []string `json:"probes_not_installed"`
}

type overviewView struct {
	KPIs      overviewKPIs      `json:"kpis"`
	Clusters  []overviewCluster `json:"clusters"`
	Scenarios []overviewRow     `json:"scenarios"`
}

// scenarioStatus is a scenario's status from its cells: paused, failing
// (a cluster alert fires), degraded, passing or no_data.
func scenarioStatus(enabled bool, cells []cellView) (status string, failing, degraded int) {
	passing := 0
	for _, c := range cells {
		switch c.State {
		case CellFailing:
			failing++
		case CellDegraded:
			degraded++
		case CellPassing:
			passing++
		}
	}
	switch {
	case !enabled:
		status = CellPaused
	case failing > 0:
		status = CellFailing
	case degraded > 0:
		status = CellDegraded
	case passing > 0:
		status = CellPassing
	default:
		status = CellNoData
	}
	return status, failing, degraded
}

// overview is Monitoring › Synthetic: KPIs, the scenario × cluster matrix
// over the clusters the caller sees, 24 h availability and p95.
func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	q := a.db()
	f, err := loadFleet(ctx, q, sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ss, err := visibleScenarios(ctx, q, sub, f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ids := make([]uuid.UUID, len(ss))
	for i, s := range ss {
		ids[i] = s.ID
	}
	states, err := loadPairStates(ctx, q, ids)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	firing, err := loadFiring(ctx, q, ids)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	visible := f.visible()
	st, err := loadStats(ctx, q, ids, f.readableIDs(), a.now().Add(-statsWindow), false)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	counts, err := stepCounts(ctx, q)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	out := overviewView{Clusters: []overviewCluster{}, Scenarios: []overviewRow{},
		KPIs: overviewKPIs{ProbesOffline: []string{}, ProbesNotInstalled: []string{}}}
	for _, c := range visible {
		out.Clusters = append(out.Clusters, overviewCluster{ID: c.ID, Name: c.Name, ProbeStatus: c.ProbeStatus,
			ProbeVersion: c.ProbeVersion, ProbeLastSeenAt: c.ProbeLastSeenAt})
		out.KPIs.ProbesTotal++
		switch probeState(c.ProbeStatus) {
		case TargetIncluded:
			out.KPIs.ProbesOnline++
		case TargetProbeOffline:
			out.KPIs.ProbesOffline = append(out.KPIs.ProbesOffline, c.Name)
		default:
			out.KPIs.ProbesNotInstalled = append(out.KPIs.ProbesNotInstalled, c.Name)
		}
	}
	failingClusters, degradedClusters := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	edit := sub.CanAny(authz.PermSyntheticEdit)
	for _, s := range ss {
		row := overviewRow{ID: s.ID, Name: s.Name, Type: s.Type, OwnerSelector: s.OwnerSelector, IntervalSeconds: s.IntervalSeconds,
			Enabled: s.Enabled, Steps: counts[s.ID], Cells: []cellView{}, CanEdit: edit && editRefusal(sub, s.Target, f) == ""}
		for _, tc := range f.targets(s.Target) {
			if !f.readable[tc.ID] {
				continue
			}
			p := pair{s.ID, tc.ID}
			ps := states[p]
			cell := cellView{ClusterID: tc.ID, State: cellState(s.Enabled, tc.State, firing[p], ps.lastStatus),
				LastRunID: ps.lastRun, LastStatus: ps.lastStatus, LastFinishedAt: ps.lastFinished, FailedStep: ps.failedStep,
				FailureReason: ps.reason, ConsecutiveFailures: ps.failures, BlockedReason: ps.blocked}
			switch cell.State {
			case CellFailing:
				failingClusters[tc.ID] = true
			case CellDegraded:
				degradedClusters[tc.ID] = true
			}
			row.Cells = append(row.Cells, cell)
		}
		row.Status, row.FailingClusters, row.DegradedClusters = scenarioStatus(s.Enabled, row.Cells)
		if x, ok := st[pair{scenario: s.ID}]; ok {
			row.Runs24h, row.Availability24h, row.P95Ms24h = x.runs, x.availability(), ms(x.p95)
		}
		out.KPIs.Scenarios++
		if s.Enabled {
			out.KPIs.Active++
		} else {
			out.KPIs.Paused++
		}
		switch row.Status {
		case CellFailing:
			out.KPIs.FailingScenarios++
		case CellDegraded:
			out.KPIs.DegradedScenarios++
		}
		out.Scenarios = append(out.Scenarios, row)
	}
	out.KPIs.FailingClusters, out.KPIs.DegradedClusters = len(failingClusters), len(degradedClusters)
	httpx.JSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- scenario detail

type lastRunView struct {
	ID            uuid.UUID  `json:"id"`
	Status        string     `json:"status"`
	FinishedAt    *time.Time `json:"finished_at"`
	FailedStep    *int       `json:"failed_step"`
	FailureReason string     `json:"failure_reason"`
}

type bucketView struct {
	Start  time.Time `json:"start"`
	Runs   int       `json:"runs"`
	Passed int       `json:"passed"`
	Failed int       `json:"failed"`
	// State: passed (every run passed), failed (one did not) or no_data.
	State string `json:"state"`
}

type clusterRowView struct {
	ClusterID           uuid.UUID    `json:"cluster_id"`
	ClusterName         string       `json:"cluster_name"`
	ProbeStatus         string       `json:"probe_status"`
	State               string       `json:"state"`
	LastRun             *lastRunView `json:"last_run"`
	ConsecutiveFailures int          `json:"consecutive_failures"`
	ConsecutivePasses   int          `json:"consecutive_passes"`
	BlockedReason       string       `json:"blocked_reason"`
	Runs24h             int          `json:"runs_24h"`
	Availability24h     *float64     `json:"availability_24h"`
	P50Ms               *int         `json:"p50_ms"`
	P95Ms               *int         `json:"p95_ms"`
	Timeline            []bucketView `json:"timeline"`
}

// scenarioClusters is the per-cluster table of the scenario page: every
// cluster the caller sees, its state and last result, p50/p95 and
// availability over 24 h, and a timeline of 48 buckets of 30 minutes (the
// last one holds now).
func (a *API) scenarioClusters(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	q := a.db()
	f, err := loadFleet(ctx, q, sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	s, err := seeScenario(ctx, q, sub, f, id, false)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ids := []uuid.UUID{id}
	states, err := loadPairStates(ctx, q, ids)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	firing, err := loadFiring(ctx, q, ids)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.now()
	readable := f.readableIDs()
	st, err := loadStats(ctx, q, ids, readable, now.Add(-statsWindow), true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	start := now.Truncate(bucketWidth).Add(bucketWidth - statsWindow)
	type key struct {
		cluster uuid.UUID
		bucket  int
	}
	buckets := map[key]bucketView{}
	rows, err := q.Query(ctx, `SELECT cluster_id, floor(extract(epoch FROM finished_at - $3::timestamptz)::float8 / $5::float8)::int, count(*),
			count(*) FILTER (WHERE status = 'passed')
		FROM synthetic_runs WHERE scenario_id = $1 AND cluster_id = ANY($2) AND NOT test AND `+countedRunSQL+`
		  AND finished_at >= $3 AND finished_at < $4
		GROUP BY 1, 2`, id, readable, start, start.Add(statsWindow), bucketWidth.Seconds())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	_, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (struct{}, error) {
		var k key
		var b bucketView
		err := row.Scan(&k.cluster, &k.bucket, &b.Runs, &b.Passed)
		b.Failed = b.Runs - b.Passed
		buckets[k] = b
		return struct{}{}, err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}

	out := []clusterRowView{}
	for _, tc := range f.targets(s.Target) {
		if !f.readable[tc.ID] {
			continue
		}
		p := pair{id, tc.ID}
		ps := states[p]
		row := clusterRowView{ClusterID: tc.ID, ClusterName: tc.Name, ProbeStatus: tc.ProbeStatus,
			State:               cellState(s.Enabled, tc.State, firing[p], ps.lastStatus),
			ConsecutiveFailures: ps.failures, ConsecutivePasses: ps.passes, BlockedReason: ps.blocked,
			Timeline: make([]bucketView, timelineBucket)}
		if ps.lastRun != nil && ps.lastStatus != nil {
			row.LastRun = &lastRunView{ID: *ps.lastRun, Status: *ps.lastStatus, FinishedAt: ps.lastFinished,
				FailedStep: ps.failedStep, FailureReason: ps.reason}
		}
		if x, ok := st[p]; ok {
			row.Runs24h, row.Availability24h, row.P50Ms, row.P95Ms = x.runs, x.availability(), ms(x.p50), ms(x.p95)
		}
		for i := range row.Timeline {
			b := buckets[key{tc.ID, i}]
			b.Start = start.Add(time.Duration(i) * bucketWidth)
			switch {
			case b.Runs == 0:
				b.State = CellNoData
			case b.Failed > 0:
				b.State = StatusFailed
			default:
				b.State = StatusPassed
			}
			row.Timeline[i] = b
		}
		out = append(out, row)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out, "window_start": start,
		"bucket_minutes": int(bucketWidth.Minutes()), "buckets": timelineBucket})
}

type alertItem struct {
	ID          uuid.UUID  `json:"id"`
	Fleet       bool       `json:"fleet"`
	ClusterID   *uuid.UUID `json:"cluster_id"`
	ClusterName string     `json:"cluster_name"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	OpenedAt    time.Time  `json:"opened_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	// DurationSeconds: how long a resolved alert fired.
	DurationSeconds *int       `json:"duration_seconds"`
	LastRunID       *uuid.UUID `json:"last_run_id"`
	FailedStep      *int       `json:"failed_step"`
	// Clusters: for a fleet alert, the failing clusters (the caller sees)
	// when it opened; ClustersTotal counts them all.
	Clusters      []string `json:"clusters"`
	ClustersTotal int      `json:"clusters_total"`
	StillFailing  *int     `json:"still_failing"`
	Notified      bool     `json:"notified"`
}

// scenarioAlerts is the alert history of a scenario, firing alerts first:
// cluster alerts of the clusters the caller sees, and fleet alerts.
func (a *API) scenarioAlerts(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	q := a.db()
	f, err := loadFleet(ctx, q, sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := seeScenario(ctx, q, sub, f, id, false); err != nil {
		a.fail(w, r, err)
		return
	}
	limit := min(max(httpx.IntQuery(r, "limit", 100), 1), 500)
	rows, err := q.Query(ctx, `SELECT a.id, a.cluster_id, a.state, a.reason, a.clusters, a.still_failing, a.opened_at, a.resolved_at,
			a.last_run_id, r.failed_step, a.notified_at IS NOT NULL
		FROM synthetic_alerts a LEFT JOIN synthetic_runs r ON r.id = a.last_run_id
		WHERE a.scenario_id = $1 AND (a.cluster_id IS NULL OR a.cluster_id = ANY($2))
		ORDER BY a.state = 'firing' DESC, a.opened_at DESC, a.id LIMIT $3`, id, f.readableIDs(), limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (alertItem, error) {
		var x alertItem
		var clusters []string
		if err := row.Scan(&x.ID, &x.ClusterID, &x.State, &x.Reason, &clusters, &x.StillFailing, &x.OpenedAt, &x.ResolvedAt,
			&x.LastRunID, &x.FailedStep, &x.Notified); err != nil {
			return x, err
		}
		x.Fleet = x.ClusterID == nil
		if x.ClusterID != nil {
			x.ClusterName = f.byID[*x.ClusterID].Name
		}
		if x.ResolvedAt != nil {
			d := int(x.ResolvedAt.Sub(x.OpenedAt).Seconds())
			x.DurationSeconds = &d
		}
		// The fleet alert's clusters column holds cluster ids (Task 10).
		x.Clusters, x.ClustersTotal = []string{}, len(clusters)
		for _, c := range clusters {
			if cid, err := uuid.Parse(c); err == nil && f.readable[cid] {
				x.Clusters = append(x.Clusters, f.byID[cid].Name)
			}
		}
		return x, nil
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// ---------------------------------------------------------------- runs

type runItem struct {
	ID            uuid.UUID  `json:"id"`
	ScenarioID    *uuid.UUID `json:"scenario_id"`
	ScenarioName  string     `json:"scenario_name"`
	ClusterID     uuid.UUID  `json:"cluster_id"`
	ClusterName   string     `json:"cluster_name"`
	ScheduledFor  time.Time  `json:"scheduled_for"`
	StartedAt     *time.Time `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	Status        string     `json:"status"`
	FailedStep    *int       `json:"failed_step"`
	FailureReason string     `json:"failure_reason"`
	TotalMs       *int       `json:"total_ms"`
	Test          bool       `json:"test"`
	Manual        bool       `json:"manual"`
	ProbeVersion  string     `json:"probe_version"`
}

const runSelect = `SELECT r.id, r.scenario_id, COALESCE(s.name, r.test_spec->>'name', ''), r.cluster_id, c.name, r.scheduled_for,
	r.started_at, r.finished_at, r.status, r.failed_step, r.failure_reason, r.total_ms, r.test, r.manual, r.probe_version
	FROM synthetic_runs r JOIN clusters c ON c.id = r.cluster_id LEFT JOIN scenarios s ON s.id = r.scenario_id`

func scanRun(row pgx.CollectableRow) (runItem, error) {
	var x runItem
	return x, row.Scan(&x.ID, &x.ScenarioID, &x.ScenarioName, &x.ClusterID, &x.ClusterName, &x.ScheduledFor, &x.StartedAt,
		&x.FinishedAt, &x.Status, &x.FailedStep, &x.FailureReason, &x.TotalMs, &x.Test, &x.Manual, &x.ProbeVersion)
}

// listRuns lists runs of the clusters the caller sees, newest first,
// filtered by scenario_id, cluster_id, status and test, before a
// scheduled_for (paging).
func (a *API) listRuns(w http.ResponseWriter, r *http.Request) {
	ctx, sub := r.Context(), httpx.Subject(r)
	qs := r.URL.Query()
	fields := map[string]string{}
	parseID := func(k string) *uuid.UUID {
		v := qs.Get(k)
		if v == "" {
			return nil
		}
		id, err := uuid.Parse(v)
		if err != nil {
			fields[k] = "must be a UUID"
			return nil
		}
		return &id
	}
	scenarioID, clusterID := parseID("scenario_id"), parseID("cluster_id")
	status := qs.Get("status")
	switch status {
	case "", StatusScheduled, StatusRunning, StatusPassed, StatusFailed, StatusError, StatusSkipped:
	default:
		fields["status"] = "unknown status"
	}
	var test *bool
	switch v := qs.Get("test"); v {
	case "":
	case "1", "true", "0", "false":
		b := v == "1" || v == "true"
		test = &b
	default:
		fields["test"] = "true or false"
	}
	var before *time.Time
	if v := qs.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			fields["before"] = "an RFC 3339 time"
		}
		before = &t
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid filter", fields)
		return
	}
	limit := min(max(httpx.IntQuery(r, "limit", 50), 1), 200)
	f, err := loadFleet(ctx, a.db(), sub)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	rows, err := a.db().Query(ctx, runSelect+`
		WHERE r.cluster_id = ANY($1) AND ($2::uuid IS NULL OR r.scenario_id = $2) AND ($3::uuid IS NULL OR r.cluster_id = $3)
		  AND ($4 = '' OR r.status = $4) AND ($5::boolean IS NULL OR r.test = $5) AND ($6::timestamptz IS NULL OR r.scheduled_for < $6)
		ORDER BY r.scheduled_for DESC, r.id DESC LIMIT $7`,
		f.readableIDs(), scenarioID, clusterID, status, test, before, limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, scanRun)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

type runAlertView struct {
	ID         uuid.UUID  `json:"id"`
	State      string     `json:"state"`
	OpenedAt   time.Time  `json:"opened_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// runStepView is one step of a run: the request as the scenario defines it
// (hidden as in stepView), and what the probe reported.
type runStepView struct {
	Position int `json:"position"`
	// Status is empty when the probe reported nothing for the step.
	Status         string          `json:"status"`
	StatusCode     *int            `json:"status_code"`
	Timings        json.RawMessage `json:"timings"`
	Assertions     json.RawMessage `json:"assertions"`
	Excerpt        *string         `json:"excerpt"`
	ExtractedNames []string        `json:"extracted_names"`
	Error          string          `json:"error"`
	Request        *stepView       `json:"request"`
}

type runDetail struct {
	runItem
	ScenarioType     string `json:"scenario_type"`
	RemoteIP         string `json:"remote_ip"`
	ProbeIP          string `json:"probe_ip"`
	AllowlistVersion int64  `json:"allowlist_version"`
	RequestedByName  string `json:"requested_by_name"`
	// ConsecutiveFailures: for a failed or errored run that counts, how
	// many in a row it ends ("3rd failed run in a row").
	ConsecutiveFailures int `json:"consecutive_failures"`
	// Alert is the cluster alert this run opened or resolved.
	Alert *runAlertView `json:"alert"`
	// Definition says where the requests come from: "test" (what the test
	// run was given), "saved" (the scenario as saved now, which may have
	// changed since the run) or "none" (the scenario is gone).
	Definition string        `json:"definition"`
	Steps      []runStepView `json:"steps"`
}

// getRun is the run detail: per-step timings, assertion results, redacted
// excerpts and the requests (for "Copy as curl"). Seen by whoever reads the
// run's cluster.
func (a *API) getRun(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, sub := r.Context(), httpx.Subject(r)
	q := a.db()
	rows, err := q.Query(ctx, runSelect+` WHERE r.id = $1 AND c.status <> 'revoked'`, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	item, err := pgx.CollectExactlyOneRow(rows, scanRun)
	if err != nil {
		a.fail(w, r, store.NotFound(err))
		return
	}
	labels, err := httpx.ClusterLabels(ctx, q, item.ClusterID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !sub.Can(authz.PermRead, labels) {
		httpx.NotFound(w)
		return
	}
	d := runDetail{runItem: item, Definition: "none", Steps: []runStepView{}}
	var testSpec []byte
	if err := q.QueryRow(ctx, `SELECT r.remote_ip, r.probe_ip, r.allowlist_version, COALESCE(p.display_name_snapshot, ''), r.test_spec
		FROM synthetic_runs r LEFT JOIN principals p ON p.id = r.requested_by WHERE r.id = $1`, id).
		Scan(&d.RemoteIP, &d.ProbeIP, &d.AllowlistVersion, &d.RequestedByName, &testSpec); err != nil {
		a.fail(w, r, err)
		return
	}

	var sc *spec.Scenario
	switch {
	case item.Test && testSpec != nil:
		var t spec.Scenario
		if json.Unmarshal(testSpec, &t) == nil {
			sc, d.Definition = &t, "test"
		}
	case item.ScenarioID != nil:
		sc, err = LoadScenario(ctx, q, *item.ScenarioID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			sc = nil
		case err != nil:
			a.fail(w, r, err)
			return
		default:
			d.Definition = "saved"
		}
	}
	requests := map[int]*stepView{}
	if sc != nil {
		d.ScenarioType = sc.Type
		creds, err := credentialRefs(ctx, q, CredentialIDs(sc))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		for _, v := range viewSteps(sc.Steps, creds, sub.CanAny(authz.PermSyntheticEdit)) {
			requests[v.Position] = &v
		}
	}

	rows, err = q.Query(ctx, `SELECT position, status, status_code, timings, assertions, excerpt, extracted_names, error
		FROM synthetic_step_results WHERE run_id = $1 ORDER BY position`, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	results, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (runStepView, error) {
		var s runStepView
		var excerpt []byte
		err := row.Scan(&s.Position, &s.Status, &s.StatusCode, &s.Timings, &s.Assertions, &excerpt, &s.ExtractedNames, &s.Error)
		if excerpt != nil {
			e := string(excerpt)
			s.Excerpt = &e
		}
		return s, err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	byPos := map[int]runStepView{}
	last := -1
	for _, s := range results {
		byPos[s.Position] = s
		last = max(last, s.Position)
	}
	for p := range requests {
		last = max(last, p)
	}
	for p := 0; p <= last; p++ {
		s, ok := byPos[p]
		if !ok {
			if requests[p] == nil {
				continue
			}
			s = runStepView{Position: p, Timings: json.RawMessage("null"), Assertions: json.RawMessage("[]"), ExtractedNames: []string{}}
		}
		s.Request = requests[p]
		d.Steps = append(d.Steps, s)
	}

	if item.ScenarioID != nil && !item.Test && item.FinishedAt != nil {
		if item.Status == StatusFailed || item.Status == StatusError {
			if err := q.QueryRow(ctx, `SELECT count(*) FROM synthetic_runs x
				WHERE x.scenario_id = $1 AND x.cluster_id = $2 AND NOT x.test AND x.status IN ('failed','error') AND x.finished_at <= $3
				  AND x.finished_at > COALESCE((SELECT max(p.finished_at) FROM synthetic_runs p WHERE p.scenario_id = $1
				    AND p.cluster_id = $2 AND NOT p.test AND p.status = 'passed' AND p.finished_at <= $3), '-infinity')`,
				*item.ScenarioID, item.ClusterID, *item.FinishedAt).Scan(&d.ConsecutiveFailures); err != nil {
				a.fail(w, r, err)
				return
			}
		}
		var al runAlertView
		err := q.QueryRow(ctx, `SELECT id, state, opened_at, resolved_at FROM synthetic_alerts
			WHERE scenario_id = $1 AND cluster_id = $2 AND last_run_id = $3 ORDER BY opened_at DESC LIMIT 1`,
			*item.ScenarioID, item.ClusterID, id).Scan(&al.ID, &al.State, &al.OpenedAt, &al.ResolvedAt)
		switch {
		case err == nil:
			d.Alert = &al
		case !errors.Is(err, pgx.ErrNoRows):
			a.fail(w, r, err)
			return
		}
	}
	httpx.JSON(w, http.StatusOK, d)
}
