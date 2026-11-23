package synthetic

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// labeledCluster adds a cluster with labels (the reserved name label
// included, as inventory stores it).
func (e *env) labeledCluster(name, probeStatus string, labels map[string]string) uuid.UUID {
	e.t.Helper()
	l := map[string]string{inventory.ClusterNameLabel: name}
	for k, v := range labels {
		l[k] = v
	}
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO clusters (name, labels, status, last_seen_at, probe_status, probe_last_seen_at)
		VALUES ($1, $2, 'online', now(), $3, $4) RETURNING id`, name, l, probeStatus, e.clock.now()).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// planned is a scenario as the rate tests need it.
type planned struct {
	interval, steps, retries int
	redirects                bool
	cred                     *uuid.UUID
	target                   Targeting
	enabled                  bool
}

// ratedScenario saves a scenario of steps HTTP steps; created orders it (the
// per-cluster cap is filled oldest first).
func (e *env) ratedScenario(name string, p planned, created time.Duration) uuid.UUID {
	e.t.Helper()
	if p.target.RunOn == "" {
		p.target.RunOn = RunOnAll
	}
	if p.target.Exclude == nil {
		p.target.Exclude = []string{}
	}
	if p.interval == 0 {
		p.interval = 60
	}
	steps := make([]spec.Step, p.steps)
	for i := range steps {
		steps[i] = httpStep("https://api.example.com/", p.cred)
		steps[i].HTTP.FollowRedirects = p.redirects
	}
	var id uuid.UUID
	err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(e.ctx, `INSERT INTO scenarios (name, type, interval_seconds, timeout_seconds, step_retries, enabled,
			run_on, run_on_selector, exclude_selectors, created_at)
			VALUES ($1, 'http_flow', $2, 10, $3, $4, $5, $6, $7, $8) RETURNING id`, name, p.interval, p.retries, p.enabled,
			p.target.RunOn, p.target.RunOnSelector, p.target.Exclude, e.clock.now().Add(-time.Hour+created)).Scan(&id); err != nil {
			return err
		}
		return WriteSteps(e.ctx, tx, id, steps)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) tick(svc *Service) {
	e.t.Helper()
	if err := svc.Tick(e.ctx); err != nil {
		e.t.Fatalf("Tick: %v", err)
	}
}

// replica is another server on the same database, with its own clock.
func (e *env) replica(c *clock) *Service {
	return &Service{DB: e.db, Log: e.svc.Log, Probes: e.probes, Creds: e.svc.Creds, Cfg: e.svc.Cfg, Now: c.now, OnResult: e.svc.OnResult}
}

type slotRow struct {
	id          uuid.UUID
	scenario    uuid.UUID
	cluster     uuid.UUID
	status      string
	scheduled   time.Time
	manual      bool
	test        bool
	requestedBy *uuid.UUID
}

func (e *env) runs() []slotRow {
	e.t.Helper()
	rows, err := e.db.Query(e.ctx, `SELECT id, COALESCE(scenario_id, '00000000-0000-0000-0000-000000000000'), cluster_id, status, scheduled_for, manual, test, requested_by
		FROM synthetic_runs ORDER BY scheduled_for, id`)
	if err != nil {
		e.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (slotRow, error) {
		var s slotRow
		err := r.Scan(&s.id, &s.scenario, &s.cluster, &s.status, &s.scheduled, &s.manual, &s.test, &s.requestedBy)
		return s, err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) openRuns() map[pair][]slotRow {
	out := map[pair][]slotRow{}
	for _, r := range e.runs() {
		if r.status == StatusScheduled || r.status == StatusRunning {
			out[pair{r.scenario, r.cluster}] = append(out[pair{r.scenario, r.cluster}], r)
		}
	}
	return out
}

func (e *env) blockedReason(scenario, cluster uuid.UUID) string {
	e.t.Helper()
	var r string
	err := e.db.QueryRow(e.ctx, `SELECT blocked_reason FROM synthetic_state WHERE scenario_id = $1 AND cluster_id = $2`, scenario, cluster).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return "(no row)"
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func states(ts []TargetCluster) map[string]string {
	out := map[string]string{}
	for _, t := range ts {
		out[t.Name] = t.State
	}
	return out
}

func wantStates(t *testing.T, got []TargetCluster, want map[string]string) {
	t.Helper()
	g := states(got)
	if len(g) != len(want) {
		t.Fatalf("states %v, want %v", g, want)
	}
	for k, v := range want {
		if g[k] != v {
			t.Fatalf("%s is %q, want %q (all: %v)", k, g[k], v, g)
		}
	}
}

func TestResolveTargets(t *testing.T) {
	cs := []ClusterInfo{
		// The name label is missing on purpose: Resolve sets it from Name,
		// and a stale value cannot hide the cluster.
		{ID: uuid.New(), Name: "ist-lab", Labels: map[string]string{"env": "prod", "region": "ist"}, ProbeStatus: ProbeOnlineState},
		{ID: uuid.New(), Name: "ams-prod", Labels: map[string]string{"env": "prod", inventory.ClusterNameLabel: "stale"}, ProbeStatus: ProbeOnlineState},
		{ID: uuid.New(), Name: "dev-1", Labels: map[string]string{"env": "dev"}, ProbeStatus: ProbeOnlineState},
		{ID: uuid.New(), Name: "dev-off", Labels: map[string]string{"env": "dev"}, ProbeStatus: ProbeOfflineState},
		{ID: uuid.New(), Name: "off", Labels: map[string]string{"env": "prod"}, ProbeStatus: ProbeOfflineState},
		{ID: uuid.New(), Name: "pending", ProbeStatus: ProbePending},
		{ID: uuid.New(), Name: "none", ProbeStatus: ProbeNotInstalled},
		{ID: uuid.New(), Name: "revoked", ProbeStatus: ProbeRevoked},
	}
	all := Targeting{RunOn: RunOnAll, Exclude: []string{"olympos.io/cluster=ist-lab", "env=dev", ""}}
	got := Resolve(all, cs)
	wantStates(t, got, map[string]string{
		"ist-lab": TargetExcluded, "ams-prod": TargetIncluded, "dev-1": TargetExcluded,
		// Excluded wins over the probe's state.
		"dev-off": TargetExcluded,
		"off":     TargetProbeOffline, "pending": TargetProbeOffline,
		"none": TargetProbeNotInstalled, "revoked": TargetProbeNotInstalled,
	})
	if got[1].Labels[inventory.ClusterNameLabel] != "ams-prod" || got[0].Labels[inventory.ClusterNameLabel] != "ist-lab" {
		t.Fatalf("labels %v %v", got[0].Labels, got[1].Labels)
	}
	if _, ok := cs[0].Labels[inventory.ClusterNameLabel]; ok {
		t.Fatal("Resolve changed the caller's labels")
	}

	// run_on all takes a cluster added later.
	later := append(cs, ClusterInfo{ID: uuid.New(), Name: "new", ProbeStatus: ProbeOnlineState})
	if st := states(Resolve(all, later))["new"]; st != TargetIncluded {
		t.Fatalf("a cluster added later is %q", st)
	}

	sel := Targeting{RunOn: RunOnSelector, RunOnSelector: "env in (prod),region!=ams", Exclude: []string{"olympos.io/cluster=off"}}
	wantStates(t, Resolve(sel, cs), map[string]string{
		"ist-lab": TargetIncluded, "ams-prod": TargetIncluded, "dev-1": TargetExcluded, "dev-off": TargetExcluded,
		"off": TargetExcluded, "pending": TargetExcluded, "none": TargetExcluded, "revoked": TargetExcluded,
	})

	// Targeting that does not parse runs nowhere, and Validate says why.
	for _, bad := range []Targeting{
		{RunOn: RunOnSelector},
		{RunOn: RunOnSelector, RunOnSelector: "env in ("},
		{RunOn: RunOnAll, Exclude: []string{"a b c"}},
		{RunOn: "some"},
	} {
		if bad.Validate() == nil {
			t.Fatalf("%+v validates", bad)
		}
		for _, tc := range Resolve(bad, cs) {
			if tc.State != TargetExcluded {
				t.Fatalf("%+v: %s is %s", bad, tc.Name, tc.State)
			}
		}
	}
	if err := all.Validate(); err != nil {
		t.Fatal(err)
	}

	// The scheduler follows: a cluster added later gets runs.
	e := newEnv(t)
	sc := e.ratedScenario("all", planned{steps: 1, enabled: true, target: Targeting{RunOn: RunOnAll, Exclude: []string{"env=dev"}}}, 0)
	prod := e.labeledCluster("prod-1", ProbeOnlineState, map[string]string{"env": "prod"})
	dev := e.labeledCluster("dev-1", ProbeOnlineState, map[string]string{"env": "dev"})
	e.tick(e.svc)
	added := e.labeledCluster("prod-2", ProbeOnlineState, nil)
	e.tick(e.svc)
	open := e.openRuns()
	if len(open[pair{sc, prod}]) != 1 || len(open[pair{sc, added}]) != 1 || len(open[pair{sc, dev}]) != 0 {
		t.Fatalf("open runs %v", open)
	}
}

func TestJitterSpread(t *testing.T) {
	const interval = 60 * time.Second
	scenario := uuid.NewSHA1(uuid.NameSpaceURL, []byte("scenario"))
	now := time.Date(2026, 11, 23, 10, 0, 30, 0, time.UTC)
	distinct := map[time.Time]bool{}
	seconds := map[int]bool{}
	for i := range 100 {
		cl := uuid.NewSHA1(uuid.NameSpaceURL, fmt.Appendf(nil, "cluster-%d", i))
		slot := SlotFor(scenario, cl, interval, now)
		if !slot.After(now) || slot.After(now.Add(interval)) {
			t.Fatalf("slot %s is not the next one after %s", slot, now)
		}
		off := slot.Sub(slot.Round(interval))
		if off < -6*time.Second || off > 6*time.Second {
			t.Fatalf("cluster %d: offset %s outside ±10%% of %s", i, off, interval)
		}
		distinct[slot.Truncate(100*time.Millisecond)] = true
		seconds[int((off+6*time.Second)/time.Second)] = true

		// Stable: the same phase from any now, on any replica.
		for _, n := range []time.Time{now.Add(-interval), now.Add(17 * time.Second), now.Add(10 * time.Minute), now.Add(36 * time.Hour)} {
			again := SlotFor(scenario, cl, interval, n)
			if again.Sub(slot)%interval != 0 || !again.After(n) || again.After(n.Add(interval)) {
				t.Fatalf("cluster %d: slot %s from %s does not keep the phase of %s", i, again, n, slot)
			}
		}
	}
	// 100 pairs over a 12 s window: at least 50 different times (to
	// 100 ms), and every second of the window used.
	if len(distinct) < 50 {
		t.Fatalf("%d distinct slots", len(distinct))
	}
	if len(seconds) < 12 {
		t.Fatalf("only %d of the window's seconds used: %v", len(seconds), seconds)
	}
}

// Review Focus 5: a scheduler that was stopped for 10 minutes does not make
// up for the slots it missed, and a new one keeps the pairs' offsets.
func TestRestartNoStormNoBackfill(t *testing.T) {
	e := newEnv(t)
	for i := range 2 {
		e.ratedScenario(fmt.Sprintf("s%d", i), planned{steps: 1, enabled: true}, time.Duration(i)*time.Second)
	}
	for i := range 3 {
		e.cluster(fmt.Sprintf("c%d", i), ProbeOnlineState)
	}
	t0 := e.clock.now()
	e.tick(e.svc)
	first := map[pair]time.Time{}
	for p, rs := range e.openRuns() {
		if len(rs) != 1 {
			t.Fatalf("%v: %d open runs", p, len(rs))
		}
		first[p] = rs[0].scheduled
	}
	if len(first) != 6 {
		t.Fatalf("%d pairs scheduled, want 6", len(first))
	}
	// One pair ran and passed; the others were never sent.
	var done pair
	for p := range first {
		done = p
		break
	}
	e.exec(`UPDATE synthetic_runs SET status = 'passed', finished_at = scheduled_for WHERE scenario_id = $1 AND cluster_id = $2`, done.scenario, done.cluster)

	// The scheduler stops for 10 minutes; a new server comes up.
	c2 := &clock{t: t0.Add(10 * time.Minute)}
	next := e.replica(c2)
	// The stale runs still block their pairs until the dispatcher ends them:
	// no second run for a pair.
	e.tick(next)
	if n := e.count(`SELECT count(*) FROM synthetic_runs`); n != 7 {
		t.Fatalf("%d runs before the dispatcher ran, want 7", n)
	}
	if _, err := next.Dispatch(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE status = 'skipped' AND failure_reason = $1`, ReasonNotDispatched); n != 5 {
		t.Fatalf("%d runs skipped as not dispatched, want 5", n)
	}
	for range 3 {
		e.tick(next)
	}
	now := c2.now()
	open := e.openRuns()
	if len(open) != 6 {
		t.Fatalf("%d pairs open after the restart, want 6", len(open))
	}
	for p, rs := range open {
		if len(rs) != 1 {
			t.Fatalf("%v: %d open runs", p, len(rs))
		}
		s := rs[0].scheduled
		if !s.After(now) || s.After(now.Add(time.Minute)) {
			t.Fatalf("%v: slot %s is not the next one after %s", p, s, now)
		}
		if d := s.Sub(first[p]); d%time.Minute != 0 {
			t.Fatalf("%v: offset moved: %s then %s", p, first[p], s)
		}
	}
	// Nothing for the 10 minutes in between: 6 runs then 6 runs.
	if n := e.count(`SELECT count(*) FROM synthetic_runs`); n != 12 {
		t.Fatalf("%d runs, want 12", n)
	}
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE scheduled_for > $1 AND scheduled_for <= $2`, t0.Add(time.Minute), now); n != 0 {
		t.Fatalf("%d runs backfilled", n)
	}
}

// Review Focus 5: ticks at once, on several servers and clocks, plan each
// pair once.
func TestConcurrentTicksNoDuplicates(t *testing.T) {
	e := newEnv(t)
	for i := range 4 {
		e.ratedScenario(fmt.Sprintf("s%d", i), planned{steps: 1, enabled: true}, time.Duration(i)*time.Second)
	}
	for i := range 5 {
		e.cluster(fmt.Sprintf("c%d", i), ProbeOnlineState)
	}
	run := func(svcs []*Service) {
		var wg sync.WaitGroup
		errs := make(chan error, len(svcs)*4)
		for _, svc := range svcs {
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := svc.Tick(e.ctx); err != nil {
						errs <- err
					}
				}()
			}
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("Tick: %v", err)
		}
		open := e.openRuns()
		if len(open) != 20 {
			t.Fatalf("%d pairs open, want 20", len(open))
		}
		for p, rs := range open {
			if len(rs) != 1 {
				t.Fatalf("%v: %d open runs", p, len(rs))
			}
		}
	}
	// The same clock: the same slot.
	run([]*Service{e.svc, e.replica(e.clock), e.replica(e.clock), e.replica(e.clock)})
	n := e.count(`SELECT count(*) FROM synthetic_runs`)

	// The runs ended after their slots; two servers whose clocks are 59 s
	// apart (a slot apart for nearly every pair) tick at once: still one
	// open run per pair.
	e.exec(`UPDATE synthetic_runs SET status = 'skipped', finished_at = now()`)
	early := &clock{t: e.clock.now().Add(67 * time.Second)}
	late := &clock{t: early.now().Add(59 * time.Second)}
	run([]*Service{e.replica(early), e.replica(late), e.replica(early), e.replica(late)})
	if m := e.count(`SELECT count(*) FROM synthetic_runs`); m != n+20 {
		t.Fatalf("%d runs, want %d", m, n+20)
	}
}

func TestOfflineProbeNoRun(t *testing.T) {
	e := newEnv(t)
	sc := e.ratedScenario("s", planned{steps: 1, enabled: true}, 0)
	online := e.cluster("online", ProbeOnlineState)
	var others []uuid.UUID
	for _, st := range []string{ProbeOfflineState, ProbeNotInstalled, ProbePending, ProbeRevoked} {
		others = append(others, e.cluster(st, st))
	}
	e.tick(e.svc)
	open := e.openRuns()
	if len(open) != 1 || len(open[pair{sc, online}]) != 1 {
		t.Fatalf("open runs %v", open)
	}

	// The probe comes back: its runs start at the next slot.
	e.exec(`UPDATE clusters SET probe_status = 'online' WHERE id = $1`, others[0])
	e.tick(e.svc)
	if len(e.openRuns()[pair{sc, others[0]}]) != 1 {
		t.Fatal("no run once the probe is online")
	}

	// A disabled scenario gets no new run.
	e.exec(`UPDATE synthetic_runs SET status = 'skipped'`)
	e.exec(`UPDATE scenarios SET enabled = false`)
	e.tick(e.svc)
	if open := e.openRuns(); len(open) != 0 {
		t.Fatalf("runs of a disabled scenario: %v", open)
	}
}

// 120 requests per minute: 10 HTTP steps that follow redirects (6
// requests each), every 30 s.
var at120 = planned{interval: 30, steps: 10, redirects: true, enabled: true}

func TestRateCapPerCluster(t *testing.T) {
	e := newEnv(t)
	cl := e.cluster("c1", ProbeOnlineState)
	other := e.cluster("c2", ProbeOnlineState)
	var big []uuid.UUID
	for i := range 5 {
		// Only c1 carries the 600: c2 has room.
		p := at120
		p.target = Targeting{RunOn: RunOnSelector, RunOnSelector: "olympos.io/cluster=c1"}
		big = append(big, e.ratedScenario(fmt.Sprintf("big%d", i), p, time.Duration(i)*time.Second))
	}
	// One more request per minute: 601.
	small := e.ratedScenario("small", planned{steps: 1, enabled: true, target: Targeting{RunOn: RunOnAll}}, time.Minute)
	e.tick(e.svc)
	open := e.openRuns()
	for _, b := range big {
		if len(open[pair{b, cl}]) != 1 {
			t.Fatalf("an older scenario under the cap has no run: %v", open)
		}
		if r := e.blockedReason(b, cl); r != "(no row)" {
			t.Fatalf("older scenario blocked: %q", r)
		}
	}
	if len(open[pair{small, cl}]) != 0 {
		t.Fatal("the scenario over the cap was scheduled")
	}
	if r := e.blockedReason(small, cl); r != BlockedRateLimit {
		t.Fatalf("blocked_reason %q", r)
	}
	if len(open[pair{small, other}]) != 1 || e.blockedReason(small, other) != "(no row)" {
		t.Fatal("the cap of one cluster reached another")
	}

	// The API's check on save says the same.
	sc, err := LoadScenario(e.ctx, e.db, small)
	if err != nil {
		t.Fatal(err)
	}
	over, err := e.svc.CheckRate(e.ctx, e.db, sc, []uuid.UUID{cl, other}, &small)
	if err != nil {
		t.Fatal(err)
	}
	if len(over) != 1 || over["c1"] != 601 {
		t.Fatalf("CheckRate %v", over)
	}
	// RunNow refuses where the cap blocks, and runs elsewhere.
	if _, err := e.svc.RunNow(e.ctx, small, []uuid.UUID{cl}, uuid.Nil); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("RunNow on a blocked cluster: %v", err)
	}
	ids, err := e.svc.RunNow(e.ctx, small, nil, uuid.Nil)
	if err != nil || len(ids) != 1 {
		t.Fatalf("RunNow on every cluster: %v %v", ids, err)
	}

	// The oldest is disabled: the newest fits, and is no longer blocked.
	e.exec(`UPDATE scenarios SET enabled = false WHERE id = $1`, big[0])
	if over, err := e.svc.CheckRate(e.ctx, e.db, sc, []uuid.UUID{cl}, &small); err != nil || len(over) != 0 {
		t.Fatalf("CheckRate after the oldest was disabled: %v %v", over, err)
	}
	e.tick(e.svc)
	if len(e.openRuns()[pair{small, cl}]) != 1 {
		t.Fatal("no run once the scenario fits")
	}
	if r := e.blockedReason(small, cl); r != "" {
		t.Fatalf("blocked_reason %q once it fits", r)
	}

	// Another reason is not overwritten, nor cleared.
	e.exec(`UPDATE scenarios SET enabled = true WHERE id = $1`, big[0])
	e.exec(`INSERT INTO synthetic_state (scenario_id, cluster_id, blocked_reason) VALUES ($1, $2, 'allowlist')`, big[4], cl)
	e.exec(`UPDATE synthetic_runs SET status = 'skipped' WHERE status IN ('scheduled','running')`)
	e.tick(e.svc)
	if r := e.blockedReason(big[4], cl); r != "allowlist" {
		t.Fatalf("other reason %q", r)
	}
}

func TestRateCapPerScenario(t *testing.T) {
	e := newEnv(t)
	cl := e.cluster("c1", ProbeOnlineState)
	cred := e.credential("tok", spec.CredBearer, "", "s3cret", "suffix:example.com")
	// 10 steps × 2 attempts × 6 requests + 1 token request, every 60 s: 121.
	p := planned{interval: 60, steps: 10, retries: 1, redirects: true, cred: &cred, enabled: true}
	over := e.ratedScenario("over", p, 0)
	fits := e.ratedScenario("fits", at120, time.Second)

	// The scheduler's rate is the spec's, from the stored scenario.
	plans, err := loadPlans(e.ctx, e.db, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pl := range plans {
		sc, err := LoadScenario(e.ctx, e.db, pl.id)
		if err != nil {
			t.Fatal(err)
		}
		if want := spec.RequestsPerMinute(sc); pl.rpm != want {
			t.Fatalf("scenario %s: rate %v, spec says %v", pl.id, pl.rpm, want)
		}
	}

	e.tick(e.svc)
	open := e.openRuns()
	if len(open[pair{over, cl}]) != 0 || e.blockedReason(over, cl) != BlockedRateLimit {
		t.Fatalf("a scenario over its cap: runs %v, reason %q", open, e.blockedReason(over, cl))
	}
	// It does not use up the cluster's room either.
	if len(open[pair{fits, cl}]) != 1 {
		t.Fatal("a scenario at the cap has no run")
	}
	sc, err := LoadScenario(e.ctx, e.db, over)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CheckRate(e.ctx, e.db, sc, []uuid.UUID{cl}, &over); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("CheckRate: %v", err)
	}
	if _, err := e.svc.RunNow(e.ctx, over, nil, uuid.Nil); !errors.Is(err, ErrRateLimit) {
		t.Fatalf("RunNow: %v", err)
	}
}

func TestRunNow(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	var who uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO principals (tenant_id, object_id) VALUES ('t', 'p') RETURNING id`).Scan(&who); err != nil {
		t.Fatal(err)
	}
	sc := e.ratedScenario("s", planned{steps: 1, enabled: true, target: Targeting{RunOn: RunOnAll, Exclude: []string{"olympos.io/cluster=skip"}}}, 0)
	cl := e.labeledCluster("c1", ProbeOnlineState, nil)
	skip := e.labeledCluster("skip", ProbeOnlineState, nil)
	off := e.labeledCluster("off", ProbeOfflineState, nil)

	// A scheduled run waits at its slot; Run now at that very time is a run
	// of its own.
	e.tick(e.svc)
	slot := e.openRuns()[pair{sc, cl}]
	if len(slot) != 1 {
		t.Fatalf("scheduled %v", slot)
	}
	e.clock.t = slot[0].scheduled
	ids, err := e.svc.RunNow(e.ctx, sc, nil, who)
	if err != nil || len(ids) != 1 {
		t.Fatalf("RunNow: %v %v", ids, err)
	}
	again, err := e.svc.RunNow(e.ctx, sc, []uuid.UUID{cl}, who)
	if err != nil || len(again) != 1 || again[0] != ids[0] {
		t.Fatalf("RunNow while one waits: %v %v, want %v", again, err, ids)
	}
	var manual *slotRow
	for _, r := range e.runs() {
		if r.id == ids[0] {
			manual = &r
		}
	}
	if manual == nil || !manual.manual || manual.test || manual.requestedBy == nil || *manual.requestedBy != who ||
		!manual.scheduled.Equal(slot[0].scheduled) || manual.cluster != cl {
		t.Fatalf("manual run %+v", manual)
	}

	for _, c := range []struct {
		clusters []uuid.UUID
		want     error
	}{
		{[]uuid.UUID{skip}, ErrNotTarget},
		{[]uuid.UUID{uuid.New()}, ErrNotTarget},
		{[]uuid.UUID{off}, ErrProbeNotOnline},
		{[]uuid.UUID{cl, off}, ErrProbeNotOnline},
	} {
		if _, err := e.svc.RunNow(e.ctx, sc, c.clusters, who); !errors.Is(err, c.want) {
			t.Fatalf("RunNow %v: %v, want %v", c.clusters, err, c.want)
		}
	}
	if _, err := e.svc.RunNow(e.ctx, uuid.New(), nil, who); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RunNow of no scenario: %v", err)
	}

	// Both runs go out, once each; the manual one counts toward alerting.
	e.probes.connect(t, cl, 4)
	if n := e.dispatch(); n != 2 {
		t.Fatalf("sent %d, want 2", n)
	}
	if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: ids[0].String(), Status: StatusFailed, FailedStep: 0,
		Steps: []*pb.StepResult{{Position: 0, Status: StatusFailed}}}); err != nil {
		t.Fatal(err)
	}
	var got *RunOutcome
	for _, o := range e.results() {
		if o.RunID == ids[0] {
			got = &o
		}
	}
	if got == nil || got.Test || got.ScenarioID != sc || got.Status != StatusFailed {
		t.Fatalf("outcome %+v", got)
	}
	// A new manual run once the last one ended.
	next, err := e.svc.RunNow(e.ctx, sc, []uuid.UUID{cl}, uuid.Nil)
	if err != nil || len(next) != 1 || next[0] == ids[0] {
		t.Fatalf("RunNow after the run ended: %v %v", next, err)
	}

	e.exec(`UPDATE scenarios SET enabled = false WHERE id = $1`, sc)
	if _, err := e.svc.RunNow(e.ctx, sc, nil, who); !errors.Is(err, ErrScenarioDisabled) {
		t.Fatalf("RunNow of a disabled scenario: %v", err)
	}
}

// An open manual run holds the pair: the scheduler plans the next slot
// once it ended.
func TestManualRunHoldsSchedule(t *testing.T) {
	e := newEnv(t)
	sc := e.ratedScenario("s", planned{steps: 1, enabled: true}, 0)
	cl := e.cluster("c1", ProbeOnlineState)
	ids, err := e.svc.RunNow(e.ctx, sc, nil, uuid.Nil)
	if err != nil || len(ids) != 1 {
		t.Fatalf("RunNow: %v %v", ids, err)
	}
	e.tick(e.svc)
	if n := len(e.openRuns()[pair{sc, cl}]); n != 1 {
		t.Fatalf("%d open runs while the manual one waits", n)
	}
	e.exec(`UPDATE synthetic_runs SET status = 'passed', finished_at = now() WHERE id = $1`, ids[0])
	e.tick(e.svc)
	open := e.openRuns()[pair{sc, cl}]
	if len(open) != 1 || open[0].manual || !open[0].scheduled.After(e.clock.now()) {
		t.Fatalf("next run %+v", open)
	}
}

func TestTestRun(t *testing.T) {
	e := newEnv(t)
	cl := e.cluster("c1", ProbeOnlineState)
	off := e.cluster("off", ProbeOfflineState)
	saved := e.ratedScenario("saved", planned{steps: 1, enabled: true}, 0)
	sc := spec.Scenario{Name: "try", Type: spec.TypeHTTPFlow, IntervalSeconds: 60, TimeoutSeconds: 10,
		Steps: []spec.Step{httpStep("https://api.example.com/", nil)}}

	unsaved, err := e.svc.TestRun(e.ctx, sc, cl, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	sc.ID = saved.String()
	linked, err := e.svc.TestRun(e.ctx, sc, cl, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	// Another test run at the same time: test runs take no slot.
	if _, err := e.svc.TestRun(e.ctx, sc, cl, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	var scenario *uuid.UUID
	var test, manual bool
	var body []byte
	if err := e.db.QueryRow(e.ctx, `SELECT scenario_id, test, manual, test_spec FROM synthetic_runs WHERE id = $1`, unsaved).
		Scan(&scenario, &test, &manual, &body); err != nil {
		t.Fatal(err)
	}
	if scenario != nil || !test || manual || len(body) == 0 {
		t.Fatalf("unsaved test run: %v %v %v %s", scenario, test, manual, body)
	}
	if err := e.db.QueryRow(e.ctx, `SELECT scenario_id FROM synthetic_runs WHERE id = $1`, linked).Scan(&scenario); err != nil || scenario == nil || *scenario != saved {
		t.Fatalf("linked test run: %v %v", scenario, err)
	}
	got, err := runScenario(e.ctx, e.db, nil, body)
	if err != nil || got.Name != "try" || len(got.Steps) != 1 {
		t.Fatalf("test_spec: %+v %v", got, err)
	}

	// Test runs do not hold the schedule.
	e.tick(e.svc)
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE scenario_id = $1 AND NOT test AND status = 'scheduled'`, saved); n != 1 {
		t.Fatalf("%d scheduled runs next to test runs", n)
	}

	if _, err := e.svc.TestRun(e.ctx, sc, off, uuid.Nil); !errors.Is(err, ErrProbeNotOnline) {
		t.Fatalf("TestRun on an offline probe: %v", err)
	}
	if _, err := e.svc.TestRun(e.ctx, sc, uuid.New(), uuid.Nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("TestRun on no cluster: %v", err)
	}
	bad := sc
	bad.IntervalSeconds = 5
	if _, err := e.svc.TestRun(e.ctx, bad, cl, uuid.Nil); !errors.Is(err, ErrInvalidScenario) {
		t.Fatalf("TestRun of an invalid scenario: %v", err)
	}
}
