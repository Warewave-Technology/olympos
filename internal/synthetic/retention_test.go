package synthetic

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

const hour = time.Hour

// retentionEnv has its clock at half past an hour, so that "the previous
// hour" and "this hour" are clear.
func retentionEnv(t *testing.T) (*env, time.Time) {
	t.Helper()
	e := newEnv(t)
	cur := time.Now().UTC().Truncate(hour)
	e.clock.t = cur.Add(30 * time.Minute)
	return e, cur
}

// finished inserts a finished run, as ingestion leaves it. totalMS < 0 is
// NULL. A scenario of uuid.Nil is a test run of an unsaved scenario.
func (e *env) finished(sc, cl uuid.UUID, status string, at time.Time, totalMS int, test bool) uuid.UUID {
	e.t.Helper()
	e.slots++
	var ms *int
	if totalMS >= 0 {
		ms = &totalMS
	}
	var scn any = sc
	if sc == uuid.Nil {
		scn = nil
	}
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, started_at, finished_at, status, total_ms, test)
		VALUES ($1, $2, $7, $3, $3, $4, $5, $6) RETURNING id`,
		scn, cl, at, status, ms, test, at.Add(-time.Duration(e.slots)*time.Millisecond)).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) maintain() {
	e.t.Helper()
	if err := e.svc.Maintain(e.ctx); err != nil {
		e.t.Fatalf("Maintain: %v", err)
	}
}

type hourlyRow struct {
	Runs, Passed, Failed, P50, P95 int
}

func (e *env) hourly(sc, cl uuid.UUID, h time.Time) (hourlyRow, bool) {
	e.t.Helper()
	var r hourlyRow
	rows, err := e.db.Query(e.ctx, `SELECT runs, passed, failed, p50_ms, p95_ms FROM synthetic_hourly WHERE scenario_id = $1 AND cluster_id = $2 AND hour = $3`, sc, cl, h)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		return r, false
	}
	if err := rows.Scan(&r.Runs, &r.Passed, &r.Failed, &r.P50, &r.P95); err != nil {
		e.t.Fatal(err)
	}
	return r, true
}

func (e *env) wantHourly(sc, cl uuid.UUID, h time.Time, want hourlyRow) {
	e.t.Helper()
	got, ok := e.hourly(sc, cl, h)
	if !ok {
		e.t.Fatalf("no hourly row for %s", h)
	}
	if got != want {
		e.t.Fatalf("hourly %s = %+v, want %+v", h, got, want)
	}
}

func (e *env) runExists(id uuid.UUID) bool {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM synthetic_runs WHERE id = $1`, id) == 1
}

func TestRollupValues(t *testing.T) {
	e, cur := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	c1, c2 := e.cluster("c1", ProbeOnlineState), e.cluster("c2", ProbeOnlineState)
	prev := cur.Add(-hour)

	// c1, previous hour: 3 passed (10, 20, 30 ms), 1 failed (40), 1 error
	// (100). Never counted: a skipped run, a test run, a run of the current
	// hour (not finished yet), and the runs of a credential error.
	for i, ms := range []int{10, 20, 30} {
		e.finished(sc, c1, StatusPassed, prev.Add(time.Duration(i+1)*time.Minute), ms, false)
	}
	e.finished(sc, c1, StatusFailed, prev.Add(10*time.Minute), 40, false)
	e.finished(sc, c1, StatusError, prev.Add(59*time.Minute), 100, false)
	e.finished(sc, c1, StatusSkipped, prev.Add(20*time.Minute), 5000, false)
	e.finished(sc, c1, StatusFailed, prev.Add(21*time.Minute), 7000, true)
	e.finished(sc, c1, StatusPassed, cur.Add(5*time.Minute), 1, false)
	for i, reason := range []string{ReasonCredentialBroken, ReasonCredentialExpired} {
		at := prev.Add(time.Duration(30+i) * time.Minute)
		e.exec(`INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, started_at, finished_at, status, total_ms, failure_reason)
			VALUES ($1, $2, $3, $3, $3, 'error', 3, $4)`, sc, c1, at, reason)
	}
	// c2, two hours ago: a passed run and an error without a duration.
	e.finished(sc, c2, StatusPassed, prev.Add(-hour+time.Minute), 7, false)
	e.finished(sc, c2, StatusError, prev.Add(-hour+2*time.Minute), -1, false)
	// An hour on the hour mark belongs to the hour it starts.
	e.finished(sc, c2, StatusPassed, cur.Add(-3*hour), 50, false)

	e.maintain()

	// percentile_cont over 10,20,30,40,100: p50 = 30, p95 = 40 + 0.8*60 = 88.
	e.wantHourly(sc, c1, prev, hourlyRow{Runs: 5, Passed: 3, Failed: 2, P50: 30, P95: 88})
	e.wantHourly(sc, c2, prev.Add(-hour), hourlyRow{Runs: 2, Passed: 1, Failed: 1, P50: 7, P95: 7})
	e.wantHourly(sc, c2, cur.Add(-3*hour), hourlyRow{Runs: 1, Passed: 1, P50: 50, P95: 50})
	if _, ok := e.hourly(sc, c1, cur); ok {
		t.Fatal("the current hour is not finished and must not be rolled up")
	}
	if n := e.count(`SELECT count(*) FROM synthetic_hourly`); n != 3 {
		t.Fatalf("%d hourly rows, want 3", n)
	}
	// Availability is passed / (passed + failed + error): 3 of 5.
	var avail float64
	if err := e.db.QueryRow(e.ctx, `SELECT passed::float8 / runs FROM synthetic_hourly WHERE scenario_id = $1 AND cluster_id = $2 AND hour = $3`, sc, c1, prev).Scan(&avail); err != nil {
		t.Fatal(err)
	}
	if avail != 0.6 {
		t.Fatalf("availability %v, want 0.6", avail)
	}
}

func TestMaintainTwiceDoesNotDoubleCount(t *testing.T) {
	e, cur := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	cl := e.cluster("c1", ProbeOnlineState)
	prev := cur.Add(-hour)
	e.finished(sc, cl, StatusPassed, prev.Add(time.Minute), 10, false)
	e.finished(sc, cl, StatusFailed, prev.Add(2*time.Minute), 30, false)

	e.maintain()
	want := hourlyRow{Runs: 2, Passed: 1, Failed: 1, P50: 20, P95: 29}
	e.wantHourly(sc, cl, prev, want)
	e.maintain()
	e.maintain()
	e.wantHourly(sc, cl, prev, want)

	// A run that was still arriving in the newest rolled hour is picked up
	// by the next pass, once.
	e.finished(sc, cl, StatusPassed, prev.Add(50*time.Minute), 20, false)
	e.maintain()
	e.maintain()
	e.wantHourly(sc, cl, prev, hourlyRow{Runs: 3, Passed: 2, Failed: 1, P50: 20, P95: 29})

	// The hour that ends next is rolled; the earlier one stays as it was.
	e.finished(sc, cl, StatusPassed, cur.Add(10*time.Minute), 5, false)
	e.clock.add(hour)
	e.maintain()
	e.maintain()
	e.wantHourly(sc, cl, cur, hourlyRow{Runs: 1, Passed: 1, P50: 5, P95: 5})
	e.wantHourly(sc, cl, prev, hourlyRow{Runs: 3, Passed: 2, Failed: 1, P50: 20, P95: 29})
	if n := e.count(`SELECT count(*) FROM synthetic_hourly`); n != 2 {
		t.Fatalf("%d hourly rows, want 2", n)
	}
}

func TestExcerptsGoAfterSevenDays(t *testing.T) {
	e, _ := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	cl := e.cluster("c1", ProbeOnlineState)
	old := e.finished(sc, cl, StatusPassed, e.clock.now().Add(-8*24*hour), 10, false)
	fresh := e.finished(sc, cl, StatusPassed, e.clock.now().Add(-6*24*hour), 10, false)
	for _, id := range []uuid.UUID{old, fresh} {
		e.exec(`INSERT INTO synthetic_step_results (run_id, position, status, status_code, excerpt, extracted_names) VALUES ($1, 0, 'passed', 200, $2, '{token}')`,
			id, []byte(`{"ok":true}`))
	}

	e.maintain()

	excerpt := func(id uuid.UUID) (has bool, status string) {
		if err := e.db.QueryRow(e.ctx, `SELECT excerpt IS NOT NULL, status FROM synthetic_step_results WHERE run_id = $1`, id).Scan(&has, &status); err != nil {
			t.Fatal(err)
		}
		return
	}
	if has, st := excerpt(old); has || st != "passed" {
		t.Fatalf("8 day old step: excerpt kept=%v status=%s, want the excerpt gone and the step kept", has, st)
	}
	if has, _ := excerpt(fresh); !has {
		t.Fatal("6 day old excerpt was cleared")
	}
	if !e.runExists(old) {
		t.Fatal("an 8 day old run is kept for 30 days")
	}
	var names []string
	if err := e.db.QueryRow(e.ctx, `SELECT extracted_names FROM synthetic_step_results WHERE run_id = $1`, old).Scan(&names); err != nil || len(names) != 1 {
		t.Fatalf("extracted names changed: %v %v", names, err)
	}
}

func TestRunsGoAfterThirtyDaysOnceRolledUp(t *testing.T) {
	e, cur := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	c1, c2 := e.cluster("c1", ProbeOnlineState), e.cluster("c2", ProbeOnlineState)

	runCut := cur.Add(-30 * 24 * hour)
	// c1: two runs of an hour long past, never rolled up (the server was off
	// for a long time): Maintain rolls them up and then deletes them.
	oldHour := cur.Add(-40 * 24 * hour)
	a := e.finished(sc, c1, StatusPassed, oldHour.Add(time.Minute), 10, false)
	b := e.finished(sc, c1, StatusFailed, oldHour.Add(2*time.Minute), 30, false)
	skipped := e.finished(sc, c1, StatusSkipped, oldHour.Add(3*time.Minute), -1, false)
	// c2: an hour that is already rolled up is left as it is.
	rolled := cur.Add(-35 * 24 * hour)
	e.finished(sc, c2, StatusPassed, rolled.Add(time.Minute), 10, false)
	e.exec(`INSERT INTO synthetic_hourly (scenario_id, cluster_id, hour, runs, passed, failed, p50_ms, p95_ms) VALUES ($1, $2, $3, 99, 98, 1, 1, 2)`, sc, c2, rolled)
	// Younger runs stay: 29 days, and one of the hour that the cut falls in
	// (whole hours go at a time).
	young := e.finished(sc, c1, StatusPassed, cur.Add(-29*24*hour), 10, false)
	cutHour := e.finished(sc, c1, StatusPassed, runCut.Add(10*time.Minute), 10, false)
	e.exec(`INSERT INTO synthetic_step_results (run_id, position, status) VALUES ($1, 0, 'passed')`, a)

	e.maintain()

	e.wantHourly(sc, c1, oldHour, hourlyRow{Runs: 2, Passed: 1, Failed: 1, P50: 20, P95: 29})
	e.wantHourly(sc, c2, rolled, hourlyRow{Runs: 99, Passed: 98, Failed: 1, P50: 1, P95: 2})
	for name, id := range map[string]uuid.UUID{"passed": a, "failed": b, "skipped": skipped} {
		if e.runExists(id) {
			t.Fatalf("the %s run of 40 days ago is kept", name)
		}
	}
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE scheduled_for < $1`, runCut); n != 0 {
		t.Fatalf("%d runs older than the cut are kept", n)
	}
	if e.count(`SELECT count(*) FROM synthetic_step_results WHERE run_id = $1`, a) != 0 {
		t.Fatal("step results outlive their run")
	}
	if !e.runExists(young) || !e.runExists(cutHour) {
		t.Fatal("a run younger than the cut was deleted")
	}
	// Runs that stay are rolled up too: their hour is long finished.
	if _, ok := e.hourly(sc, c1, cur.Add(-29*24*hour)); !ok {
		t.Fatal("the hour of a kept run, long finished, is not rolled up")
	}
	e.maintain()
	e.wantHourly(sc, c1, oldHour, hourlyRow{Runs: 2, Passed: 1, Failed: 1, P50: 20, P95: 29})
}

func TestTestRunsGoAfterSevenDays(t *testing.T) {
	e, _ := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	cl := e.cluster("c1", ProbeOnlineState)
	now := e.clock.now()
	oldSaved := e.finished(sc, cl, StatusFailed, now.Add(-8*24*hour), 10, true)
	oldUnsaved := e.finished(uuid.Nil, cl, StatusPassed, now.Add(-9*24*hour), 10, true)
	freshTest := e.finished(sc, cl, StatusPassed, now.Add(-6*24*hour), 10, true)
	// A real run of the same age is kept: it has 30 days.
	real := e.finished(sc, cl, StatusPassed, now.Add(-8*24*hour), 10, false)

	e.maintain()

	if e.runExists(oldSaved) || e.runExists(oldUnsaved) {
		t.Fatal("a test run older than 7 days is kept")
	}
	if !e.runExists(freshTest) || !e.runExists(real) {
		t.Fatal("a test run of 6 days, or a real run of 8, was deleted")
	}
	if n := e.count(`SELECT count(*) FROM synthetic_hourly`); n != 1 {
		t.Fatalf("%d hourly rows: test runs must not be rolled up (only the real run is)", n)
	}
	e.wantHourly(sc, cl, now.Add(-8*24*hour).Truncate(hour), hourlyRow{Runs: 1, Passed: 1, P50: 10, P95: 10})
}

func TestAggregatesGoAfter400Days(t *testing.T) {
	e, cur := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	cl := e.cluster("c1", ProbeOnlineState)
	for _, d := range []int{401, 399} {
		e.exec(`INSERT INTO synthetic_hourly (scenario_id, cluster_id, hour, runs, passed, failed, p50_ms, p95_ms) VALUES ($1, $2, $3, 4, 4, 0, 5, 6)`,
			sc, cl, cur.Add(-time.Duration(d)*24*hour))
	}
	// A run of an hour past the aggregate retention (the retention of runs
	// is longer here) is not rolled up again.
	e.svc.Cfg.RunRetention = 500 * 24 * hour
	e.finished(sc, cl, StatusPassed, cur.Add(-450*24*hour+time.Minute), 10, false)

	e.maintain()

	if _, ok := e.hourly(sc, cl, cur.Add(-401*24*hour)); ok {
		t.Fatal("an aggregate of 401 days is kept")
	}
	if _, ok := e.hourly(sc, cl, cur.Add(-399*24*hour)); !ok {
		t.Fatal("an aggregate of 399 days was deleted")
	}
	if n := e.count(`SELECT count(*) FROM synthetic_hourly`); n != 1 {
		t.Fatalf("%d hourly rows, want 1", n)
	}
}

func TestAlertsAreKept(t *testing.T) {
	e, cur := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	cl := e.cluster("c1", ProbeOnlineState)
	runID := e.finished(sc, cl, StatusFailed, cur.Add(-40*24*hour), 10, false)
	opened := cur.Add(-500 * 24 * hour)
	e.exec(`INSERT INTO synthetic_alerts (scenario_id, cluster_id, state, reason, opened_at, resolved_at, last_run_id) VALUES ($1, $2, 'resolved', 'x', $3, $4, $5)`,
		sc, cl, opened, opened.Add(hour), runID)
	e.exec(`INSERT INTO synthetic_alerts (scenario_id, cluster_id, state, reason, opened_at) VALUES ($1, NULL, 'firing', 'fleet', $2)`, sc, opened)

	e.maintain()

	if e.runExists(runID) {
		t.Fatal("the old run is kept")
	}
	if n := e.count(`SELECT count(*) FROM synthetic_alerts`); n != 2 {
		t.Fatalf("%d alerts, want 2: alerts are kept forever", n)
	}
	if n := e.count(`SELECT count(*) FROM synthetic_alerts WHERE opened_at = $1`, opened); n != 2 {
		t.Fatal("an alert was changed")
	}
	if n := e.count(`SELECT count(*) FROM synthetic_alerts WHERE state = 'resolved' AND last_run_id IS NULL`); n != 1 {
		t.Fatalf("the alert of the deleted run must lose only the link, got %d", n)
	}
}

func TestStateLosesLinkToDeletedRun(t *testing.T) {
	e, cur := retentionEnv(t)
	sc := simpleScenario(e, "pay")
	cl := e.cluster("c1", ProbeOnlineState)
	old := e.finished(sc, cl, StatusFailed, cur.Add(-40*24*hour), 10, false)
	young := e.finished(sc, cl, StatusPassed, cur.Add(-hour), 10, false)
	c2 := e.cluster("c2", ProbeOnlineState)
	e.exec(`INSERT INTO synthetic_state (scenario_id, cluster_id, consecutive_failures, last_run_id, last_status, last_finished_at) VALUES ($1, $2, 1, $3, 'failed', $4)`,
		sc, cl, old, cur.Add(-40*24*hour))
	e.exec(`INSERT INTO synthetic_state (scenario_id, cluster_id, consecutive_passes, last_run_id, last_status, last_finished_at) VALUES ($1, $2, 1, $3, 'passed', $4)`,
		sc, c2, young, cur.Add(-hour))

	e.maintain()

	if e.runExists(old) {
		t.Fatal("the old run is kept")
	}
	var lastRun *uuid.UUID
	var failures int
	if err := e.db.QueryRow(e.ctx, `SELECT last_run_id, consecutive_failures FROM synthetic_state WHERE scenario_id = $1 AND cluster_id = $2`, sc, cl).Scan(&lastRun, &failures); err != nil {
		t.Fatalf("the state row of the deleted run is gone: %v", err)
	}
	if lastRun != nil || failures != 1 {
		t.Fatalf("state: last_run_id=%v failures=%d, want NULL and the rest unchanged", lastRun, failures)
	}
	if err := e.db.QueryRow(e.ctx, `SELECT last_run_id FROM synthetic_state WHERE cluster_id = $1`, c2).Scan(&lastRun); err != nil || lastRun == nil || *lastRun != young {
		t.Fatalf("the state of a kept run changed: %v %v", lastRun, err)
	}
}

func TestMaintenanceTickRunsExpiryDaily(t *testing.T) {
	e, _ := retentionEnv(t)
	t0 := e.clock.now()
	last, err := e.svc.maintenanceTick(e.ctx, time.Time{})
	if err != nil || !last.Equal(t0) {
		t.Fatalf("first tick: last=%v err=%v, want the expiry check done at %v", last, err, t0)
	}
	e.clock.add(MaintenanceInterval)
	again, err := e.svc.maintenanceTick(e.ctx, last)
	if err != nil || !again.Equal(last) {
		t.Fatalf("a tick 10 minutes later checked expiry again: %v %v", again, err)
	}
	e.clock.add(ExpiryInterval)
	next, err := e.svc.maintenanceTick(e.ctx, again)
	if err != nil || !next.Equal(e.clock.now()) {
		t.Fatalf("a tick a day later: last=%v err=%v, want the expiry check done again", next, err)
	}
}
