package synthetic

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func TestStep(t *testing.T) {
	r := AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2}
	cases := []struct {
		name   string
		st     StreakState
		status string
		rule   AlertRule
		want   StreakState
		tr     Transition
	}{
		{"first failure", StreakState{}, StatusFailed, r, StreakState{Failures: 1}, None},
		{"error counts as failure", StreakState{Failures: 1}, StatusError, r, StreakState{Failures: 2}, None},
		{"third failure opens", StreakState{Failures: 2}, StatusFailed, r, StreakState{Failures: 3, Firing: true}, Open},
		{"third error opens", StreakState{Failures: 2}, StatusError, r, StreakState{Failures: 3, Firing: true}, Open},
		{"failure while firing", StreakState{Failures: 3, Firing: true}, StatusFailed, r, StreakState{Failures: 4, Firing: true}, None},
		{"pass ends the failures", StreakState{Failures: 2}, StatusPassed, r, StreakState{Passes: 1}, None},
		{"first pass while firing", StreakState{Failures: 5, Firing: true}, StatusPassed, r, StreakState{Passes: 1, Firing: true}, None},
		{"second pass recovers", StreakState{Passes: 1, Firing: true}, StatusPassed, r, StreakState{Passes: 2}, Recover},
		{"failure ends the passes", StreakState{Passes: 1, Firing: true}, StatusFailed, r, StreakState{Failures: 1, Firing: true}, None},
		{"pass while not firing", StreakState{Passes: 7}, StatusPassed, r, StreakState{Passes: 8}, None},
		{"skipped changes nothing", StreakState{Failures: 2}, StatusSkipped, r, StreakState{Failures: 2}, None},
		{"skipped while firing", StreakState{Passes: 1, Firing: true}, StatusSkipped, r, StreakState{Passes: 1, Firing: true}, None},
		{"unknown status changes nothing", StreakState{Failures: 2}, "running", r, StreakState{Failures: 2}, None},
		{"fail after 1", StreakState{}, StatusFailed, AlertRule{ClusterFailAfter: 1, RecoveryAfter: 1}, StreakState{Failures: 1, Firing: true}, Open},
		{"recover after 1", StreakState{Failures: 1, Firing: true}, StatusPassed, AlertRule{ClusterFailAfter: 1, RecoveryAfter: 1}, StreakState{Passes: 1}, Recover},
		{"zero thresholds count as 1", StreakState{}, StatusFailed, AlertRule{}, StreakState{Failures: 1, Firing: true}, Open},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, tr := Step(c.st, c.status, c.rule)
			if got != c.want || tr != c.tr {
				t.Fatalf("Step(%+v, %s) = %+v, %v; want %+v, %v", c.st, c.status, got, tr, c.want, c.tr)
			}
		})
	}
}

// newAlertEnv is newEnv with the production OnResult.
func newAlertEnv(t *testing.T) *env {
	e := newEnv(t)
	e.svc.OnResult = e.svc.ApplyOutcome
	return e
}

const failReason = "assertion_failed: status_code 500, want 200"

// outcome records a finished run of sc on cl and applies it as the
// finishing transaction does. kind: F failed, E error, P passed, S skipped
// (probe_disconnected), T a failed test run, M a failed manual run.
func (e *env) outcome(sc, cl uuid.UUID, kind byte) uuid.UUID {
	e.t.Helper()
	e.clock.add(time.Minute)
	e.slots++
	status, reason, test, manual := StatusFailed, failReason, false, false
	var step *int
	switch kind {
	case 'F':
		step = ptr(0)
	case 'E':
		status, reason = StatusError, "timeout"
	case 'P':
		status, reason = StatusPassed, ""
	case 'S':
		status, reason = StatusSkipped, ReasonProbeDisconnected
	case 'T':
		test, step = true, ptr(0)
	case 'M':
		manual, step = true, ptr(0)
	default:
		e.t.Fatalf("outcome kind %c", kind)
	}
	now := e.clock.now()
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, started_at, finished_at, status,
		failed_step, failure_reason, test, manual) VALUES ($1, $2, $3, $3, $3, $4, $5, $6, $7, $8) RETURNING id`,
		sc, cl, now.Add(time.Duration(e.slots)*time.Millisecond), status, step, reason, test, manual).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	if err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error {
		return e.svc.OnResult(e.ctx, tx, RunOutcome{RunID: id, ScenarioID: sc, ClusterID: cl, Status: status, FailedStep: step,
			Reason: reason, Test: test, FinishedAt: now})
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// applySeq applies a sequence of outcome kinds, with a Notify pass after
// each when notifyEach.
func (e *env) applySeq(sc, cl uuid.UUID, seq string, notifyEach bool) {
	e.t.Helper()
	for i := range len(seq) {
		e.outcome(sc, cl, seq[i])
		if notifyEach {
			e.notify()
		}
	}
}

func (e *env) notify() {
	e.t.Helper()
	if err := e.svc.Notify(e.ctx); err != nil {
		e.t.Fatalf("Notify: %v", err)
	}
}

type outboxMsg struct {
	Type, Key string
	Channel   *uuid.UUID
	Title     string
	Link      string
	Fields    map[string]string
	Payload   map[string]any
	Raw       string
}

// alertMessages lists the outbox rows of the synthetic alert events.
func (e *env) alertMessages() []outboxMsg {
	e.t.Helper()
	rows, err := e.db.Query(e.ctx, `SELECT event_type, idempotency_key, channel_id, payload::text FROM outbox
		WHERE event_type LIKE 'synthetic.%' ORDER BY created_at, idempotency_key`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []outboxMsg
	for rows.Next() {
		var m outboxMsg
		if err := rows.Scan(&m.Type, &m.Key, &m.Channel, &m.Raw); err != nil {
			e.t.Fatal(err)
		}
		var body struct {
			Title  string            `json:"title"`
			Link   string            `json:"link"`
			Fields map[string]string `json:"fields"`
		}
		if err := json.Unmarshal([]byte(m.Raw), &body); err != nil {
			e.t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(m.Raw), &m.Payload); err != nil {
			e.t.Fatal(err)
		}
		m.Title, m.Link, m.Fields = body.Title, body.Link, body.Fields
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) wantMessages(want map[string]int) []outboxMsg {
	e.t.Helper()
	msgs := e.alertMessages()
	got := map[string]int{}
	for _, m := range msgs {
		got[m.Type]++
	}
	for _, k := range []string{notify.SyntheticFailing, notify.SyntheticCritical, notify.SyntheticRecovered} {
		if got[k] != want[k] {
			e.t.Fatalf("%s: %d messages, want %d (all: %v)", k, got[k], want[k], got)
		}
	}
	return msgs
}

func (e *env) channel(name string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO notification_channels (slack_channel_id, name) VALUES ($1, $1) RETURNING id`, name).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// alertRule stores a scenario's alert settings.
func (e *env) alertRule(sc uuid.UUID, r AlertRule) {
	e.t.Helper()
	e.exec(`INSERT INTO scenario_alerts (scenario_id, cluster_fail_after, fleet_critical_clusters, recovery_after, send_recovery, channel_id, critical_channel_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, sc, r.ClusterFailAfter, r.FleetCriticalClusters, r.RecoveryAfter, r.SendRecovery, r.ChannelID, r.CriticalChannelID)
}

func (e *env) firing(sc uuid.UUID) (clusters, fleet int) {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM synthetic_alerts WHERE scenario_id = $1 AND state = 'firing' AND cluster_id IS NOT NULL`, sc),
		e.count(`SELECT count(*) FROM synthetic_alerts WHERE scenario_id = $1 AND state = 'firing' AND cluster_id IS NULL`, sc)
}

type streak struct {
	failures, passes int
	lastStatus       *string
}

func (e *env) streak(sc, cl uuid.UUID) streak {
	e.t.Helper()
	var s streak
	err := e.db.QueryRow(e.ctx, `SELECT consecutive_failures, consecutive_passes, last_status FROM synthetic_state WHERE scenario_id = $1 AND cluster_id = $2`,
		sc, cl).Scan(&s.failures, &s.passes, &s.lastStatus)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		e.t.Fatal(err)
	}
	return s
}

func simpleScenario(e *env, name string) uuid.UUID {
	e.t.Helper()
	return e.scenario(name, true, httpStep("https://api.example.com/health", nil))
}

// Three failed runs in a row, through dispatch and ingestion: one
// synthetic.failing to the scenario's channel, with the cluster, the failed
// step, the reason and a link to the run; further failures send nothing.
func TestThreeFailuresOneMessage(t *testing.T) {
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	sc := simpleScenario(e, "checkout")
	ch := e.channel("ops")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2, SendRecovery: true, ChannelID: &ch})
	cl := e.cluster("ist-lab", ProbeOnlineState)
	e.probes.connect(t, cl, 4)

	fail := func() uuid.UUID {
		t.Helper()
		id := e.dispatched(sc, cl)
		if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: id.String(), Status: StatusFailed, FailedStep: 0, FailureReason: failReason,
			Steps: []*pb.StepResult{{Position: 0, Status: StatusFailed}}}); err != nil {
			t.Fatal(err)
		}
		e.wantRun(id, StatusFailed, failReason)
		e.notify()
		return id
	}
	fail()
	fail()
	e.wantMessages(map[string]int{})
	if s := e.streak(sc, cl); s.failures != 2 || s.lastStatus == nil || *s.lastStatus != StatusFailed {
		t.Fatalf("streak after two failures: %+v", s)
	}
	third := fail()
	msgs := e.wantMessages(map[string]int{notify.SyntheticFailing: 1})
	for range 4 {
		fail()
	}
	msgs = e.wantMessages(map[string]int{notify.SyntheticFailing: 1})

	m := msgs[0]
	var alertID uuid.UUID
	if err := e.db.QueryRow(e.ctx, `SELECT id FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id = $2 AND state = 'firing'`, sc, cl).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	if m.Key != "synthetic.failing:"+alertID.String() || m.Channel == nil || *m.Channel != ch {
		t.Fatalf("key %s channel %v", m.Key, m.Channel)
	}
	if m.Title != "Synthetic check failing: checkout on ist-lab" || m.Link != "/monitoring?scenario="+sc.String()+"&run="+third.String() {
		t.Fatalf("title %q link %q", m.Title, m.Link)
	}
	if m.Fields["scenario"] != "checkout" || m.Fields["clusters"] != "ist-lab" || m.Fields["failed step"] != "1 (http)" || m.Fields["reason"] != failReason {
		t.Fatalf("fields %v", m.Fields)
	}
	if c, f := e.firing(sc); c != 1 || f != 0 {
		t.Fatalf("firing %d cluster, %d fleet", c, f)
	}
}

// Review Focus 5: alternating results never send more than one message per
// open and resolve.
func TestFlappingDoesNotSpam(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "flappy")
	cl := e.cluster("c1", ProbeOnlineState)

	// F,F,P 30 times: the streak never reaches 3.
	e.applySeq(sc, cl, strings.Repeat("FFP", 30), true)
	e.wantMessages(map[string]int{})
	if e.count(`SELECT count(*) FROM synthetic_alerts`) != 0 {
		t.Fatal("an alert opened")
	}

	// F,F,F,P,F,P,F: opens once and never sees two passes in a row.
	sc2 := simpleScenario(e, "flappy-2")
	e.applySeq(sc2, cl, "FFFPFPF", true)
	e.wantMessages(map[string]int{notify.SyntheticFailing: 1})
	if c, _ := e.firing(sc2); c != 1 {
		t.Fatalf("%d firing alerts", c)
	}
	// The same with errors, and Notify only at the end.
	sc3 := simpleScenario(e, "flappy-3")
	e.applySeq(sc3, cl, "EEEPEPE", false)
	e.notify()
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticFailing: 2})
}

// Three clusters failing together: exactly one synthetic.critical, to the
// critical channel, naming them, and no separate synthetic.failing for them.
// Recovery mirrors it: the fleet's recovered message includes the cluster
// that recovered with it.
func TestFleetCritical(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "login")
	ch, crit := e.channel("ops"), e.channel("ops-critical")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2, SendRecovery: true, ChannelID: &ch, CriticalChannelID: &crit})
	cls := []uuid.UUID{e.cluster("c1", ProbeOnlineState), e.cluster("c2", ProbeOnlineState), e.cluster("c3", ProbeOnlineState)}
	for range 3 {
		for _, cl := range cls {
			e.outcome(sc, cl, 'F')
		}
	}
	if c, f := e.firing(sc); c != 3 || f != 1 {
		t.Fatalf("firing %d cluster, %d fleet", c, f)
	}
	e.notify()
	e.notify()
	msgs := e.wantMessages(map[string]int{notify.SyntheticCritical: 1})
	m := msgs[0]
	var fleetID uuid.UUID
	if err := e.db.QueryRow(e.ctx, `SELECT id FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id IS NULL`, sc).Scan(&fleetID); err != nil {
		t.Fatal(err)
	}
	if m.Key != "synthetic.critical:"+fleetID.String() || m.Channel == nil || *m.Channel != crit {
		t.Fatalf("key %s channel %v", m.Key, m.Channel)
	}
	if m.Title != "Synthetic check critical: login fails on 3 clusters" || m.Fields["clusters"] != "c1, c2, c3" || m.Fields["reason"] != failReason ||
		m.Fields["failed step"] != "1 (http)" {
		t.Fatalf("title %q fields %v", m.Title, m.Fields)
	}
	if n := e.count(`SELECT count(*) FROM synthetic_alerts WHERE scenario_id = $1 AND notified_at IS NULL`, sc); n != 0 {
		t.Fatalf("%d alerts not marked notified", n)
	}

	// c1 recovers: below the threshold, the fleet alert resolves with it.
	e.applySeq(sc, cls[0], "PP", false)
	if c, f := e.firing(sc); c != 2 || f != 0 {
		t.Fatalf("firing %d cluster, %d fleet", c, f)
	}
	e.notify()
	msgs = e.wantMessages(map[string]int{notify.SyntheticCritical: 1, notify.SyntheticRecovered: 1})
	rec := msgs[len(msgs)-1]
	if rec.Key != "synthetic.recovered:"+fleetID.String() || rec.Channel == nil || *rec.Channel != crit ||
		rec.Fields["clusters"] != "c1" || rec.Fields["still failing"] != "2 clusters" {
		t.Fatalf("recovered %s %v %v", rec.Key, rec.Channel, rec.Fields)
	}
	// The other two recover: one message, to the scenario's channel.
	e.applySeq(sc, cls[1], "PP", false)
	e.applySeq(sc, cls[2], "PP", false)
	e.notify()
	msgs = e.wantMessages(map[string]int{notify.SyntheticCritical: 1, notify.SyntheticRecovered: 2})
	rec = msgs[len(msgs)-1]
	if rec.Channel == nil || *rec.Channel != ch || rec.Title != "Synthetic check recovered: login on 2 clusters" || rec.Fields["clusters"] != "c2, c3" {
		t.Fatalf("recovered %v %q %v", rec.Channel, rec.Title, rec.Fields)
	}

	// A second incident opens a new series of alerts and keys; with no
	// critical channel, the critical message goes to the channel.
	e.exec(`UPDATE scenario_alerts SET critical_channel_id = NULL WHERE scenario_id = $1`, sc)
	for range 3 {
		for _, cl := range cls {
			e.outcome(sc, cl, 'E')
		}
	}
	e.notify()
	msgs = e.wantMessages(map[string]int{notify.SyntheticCritical: 2, notify.SyntheticRecovered: 2})
	for _, m := range msgs {
		if m.Type == notify.SyntheticCritical && m.Key != "synthetic.critical:"+fleetID.String() {
			if m.Channel == nil || *m.Channel != ch || m.Fields["reason"] != "timeout" {
				t.Fatalf("second critical %v %v", m.Channel, m.Fields)
			}
			if _, ok := m.Fields["failed step"]; ok {
				t.Fatalf("an error run with no failed step names one: %v", m.Fields)
			}
		}
	}
}

// Several clusters opening in one pass make one synthetic.failing that
// names the first five and counts the rest; with no channel set, it goes
// through the routes (no channel on the outbox row).
func TestFailingGroupedTopFive(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "dns")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 2, FleetCriticalClusters: 10, RecoveryAfter: 2, SendRecovery: true})
	var cls []uuid.UUID
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		cls = append(cls, e.cluster(n, ProbeOnlineState))
	}
	for range 2 {
		for _, cl := range cls {
			e.outcome(sc, cl, 'F')
		}
	}
	e.notify()
	msgs := e.wantMessages(map[string]int{notify.SyntheticFailing: 1})
	m := msgs[0]
	if m.Channel != nil || m.Title != "Synthetic check failing: dns on 7 clusters" || m.Fields["clusters"] != "a, b, c, d, e and 2 more" {
		t.Fatalf("channel %v title %q fields %v", m.Channel, m.Title, m.Fields)
	}
	if n, ok := m.Payload["cluster_count"].(float64); !ok || n != 7 {
		t.Fatalf("payload %v", m.Payload)
	}
	// A cluster opening later is a new message of its own.
	h := e.cluster("h", ProbeOnlineState)
	e.applySeq(sc, h, "FF", true)
	e.wantMessages(map[string]int{notify.SyntheticFailing: 2})
}

// Recovery after two passes, one message; none when send_recovery is off,
// and turning it on later does not send the old one.
func TestRecovery(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "api")
	cl := e.cluster("c1", ProbeOnlineState)
	e.applySeq(sc, cl, "FFF", true)
	e.outcome(sc, cl, 'P')
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticFailing: 1})
	e.outcome(sc, cl, 'P')
	e.notify()
	e.notify()
	msgs := e.wantMessages(map[string]int{notify.SyntheticFailing: 1, notify.SyntheticRecovered: 1})
	rec := msgs[len(msgs)-1]
	if rec.Title != "Synthetic check recovered: api on c1" || rec.Fields["reason"] != "" {
		t.Fatalf("recovered %q %v", rec.Title, rec.Fields)
	}
	if c, _ := e.firing(sc); c != 0 {
		t.Fatal("still firing")
	}

	quiet := simpleScenario(e, "quiet")
	e.alertRule(quiet, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2, SendRecovery: false})
	e.applySeq(quiet, cl, "FFFPP", true)
	e.wantMessages(map[string]int{notify.SyntheticFailing: 2, notify.SyntheticRecovered: 1})
	if n := e.count(`SELECT count(*) FROM synthetic_alerts WHERE scenario_id = $1 AND state = 'resolved' AND resolved_notified_at IS NOT NULL`, quiet); n != 1 {
		t.Fatalf("%d resolved alerts marked", n)
	}
	e.exec(`UPDATE scenario_alerts SET send_recovery = true WHERE scenario_id = $1`, quiet)
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticFailing: 2, notify.SyntheticRecovered: 1})

	// An alert that opens and resolves between two passes still gets its
	// pair of messages, in that order.
	blip := simpleScenario(e, "blip")
	e.alertRule(blip, AlertRule{ClusterFailAfter: 1, FleetCriticalClusters: 3, RecoveryAfter: 1, SendRecovery: true})
	e.applySeq(blip, cl, "FP", false)
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticFailing: 3, notify.SyntheticRecovered: 2})
}

// Test runs never alert, even of a saved scenario; Run now (manual) runs
// count like scheduled ones.
func TestTestRunsNeverAlert(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "editor")
	cl := e.cluster("c1", ProbeOnlineState)
	e.alertRule(sc, AlertRule{ClusterFailAfter: 1, FleetCriticalClusters: 1, RecoveryAfter: 1, SendRecovery: true})
	e.applySeq(sc, cl, "TTTTT", true)
	e.wantMessages(map[string]int{})
	if e.count(`SELECT count(*) FROM synthetic_state`)+e.count(`SELECT count(*) FROM synthetic_alerts`) != 0 {
		t.Fatal("a test run moved the state")
	}
	// A test run of an unsaved scenario has no scenario id.
	if err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error {
		return e.svc.ApplyOutcome(e.ctx, tx, RunOutcome{RunID: uuid.New(), ClusterID: cl, Status: StatusFailed, Test: true})
	}); err != nil {
		t.Fatal(err)
	}

	manual := simpleScenario(e, "run-now")
	e.applySeq(manual, cl, "MMM", true)
	e.wantMessages(map[string]int{notify.SyntheticFailing: 1})
}

// Review Focus 4: a skipped run neither counts nor resets a streak, whether
// it comes from the dispatcher (an offline probe) or a disconnect.
func TestSkippedKeepsStreak(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "skips")
	cl := e.cluster("c1", ProbeOnlineState)
	e.applySeq(sc, cl, "FFSS", true)
	if s := e.streak(sc, cl); s.failures != 2 || *s.lastStatus != StatusFailed {
		t.Fatalf("streak %+v", s)
	}
	// The probe goes offline: the dispatcher skips the due run
	// (probe_offline) through finishWhere and OnResult.
	e.exec(`UPDATE clusters SET probe_status = 'offline' WHERE id = $1`, cl)
	run := e.schedule(sc, cl, 0)
	e.dispatch()
	e.wantRun(run, StatusSkipped, ReasonProbeOffline)
	if s := e.streak(sc, cl); s.failures != 2 {
		t.Fatalf("streak after an offline skip %+v", s)
	}
	e.wantMessages(map[string]int{})
	e.outcome(sc, cl, 'F')
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticFailing: 1})

	// While firing: P, skipped, P recovers.
	e.applySeq(sc, cl, "PSSP", true)
	e.wantMessages(map[string]int{notify.SyntheticFailing: 1, notify.SyntheticRecovered: 1})
	if s := e.streak(sc, cl); s.passes != 2 || *s.lastStatus != StatusPassed {
		t.Fatalf("streak %+v", s)
	}
}

// What is missing is a no-op, not an error: a deleted scenario, an unknown
// one, a run applied twice.
func TestApplyOutcomeMissingRows(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "gone")
	cl := e.cluster("c1", ProbeOnlineState)
	apply := func(o RunOutcome) {
		t.Helper()
		if err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error { return e.svc.ApplyOutcome(e.ctx, tx, o) }); err != nil {
			t.Fatal(err)
		}
	}
	apply(RunOutcome{RunID: uuid.New(), ScenarioID: uuid.New(), ClusterID: cl, Status: StatusFailed, FinishedAt: e.clock.now()})

	run := e.outcome(sc, cl, 'F')
	apply(RunOutcome{RunID: run, ScenarioID: sc, ClusterID: cl, Status: StatusFailed, FinishedAt: e.clock.now()})
	if s := e.streak(sc, cl); s.failures != 1 {
		t.Fatalf("a run applied twice counted twice: %+v", s)
	}
	e.exec(`DELETE FROM scenarios WHERE id = $1`, sc)
	apply(RunOutcome{RunID: uuid.New(), ScenarioID: sc, ClusterID: cl, Status: StatusFailed, FinishedAt: e.clock.now()})
	e.notify()
}

// Clusters reaching the fleet threshold in concurrent transactions see each
// other: the fleet alert opens once.
func TestConcurrentOutcomesOpenFleet(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "race")
	var cls []uuid.UUID
	for _, n := range []string{"c1", "c2", "c3"} {
		cl := e.cluster(n, ProbeOnlineState)
		cls = append(cls, cl)
		e.applySeq(sc, cl, "FF", false)
	}
	type run struct{ id, cl uuid.UUID }
	var runs []run
	for _, cl := range cls {
		var id uuid.UUID
		if err := e.db.QueryRow(e.ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, status, finished_at, failure_reason, manual)
			VALUES ($1, $2, now(), 'failed', now(), $3, true) RETURNING id`, sc, cl, failReason).Scan(&id); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run{id, cl})
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(runs))
	for _, r := range runs {
		wg.Go(func() {
			errs <- store.Tx(e.ctx, e.db, func(tx pgx.Tx) error {
				return e.svc.ApplyOutcome(e.ctx, tx, RunOutcome{RunID: r.id, ScenarioID: sc, ClusterID: r.cl, Status: StatusFailed,
					Reason: failReason, FinishedAt: e.clock.now()})
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if c, f := e.firing(sc); c != 3 || f != 1 {
		t.Fatalf("firing %d cluster, %d fleet", c, f)
	}
	var clusters []string
	if err := e.db.QueryRow(e.ctx, `SELECT clusters FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id IS NULL`, sc).Scan(&clusters); err != nil ||
		len(clusters) != 3 {
		t.Fatalf("fleet clusters %v (%v)", clusters, err)
	}
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticCritical: 1})
}

// No alert message carries a credential or response text: the canary that
// a careless probe hands back in the reason, a step error, an assertion's
// actual value and the excerpt reaches none of them, and the reason is
// redacted again and cut short.
func TestAlertPayloadsNoCanary(t *testing.T) {
	const canary = "olympos-canary-alert-5e2b7c9d1f"
	const excerptText = "EXCERPT-BODY-MARKER-d41f"
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	bearer := e.credential("api", spec.CredBearer, "label", canary, "suffix:example.com")
	sc := e.scenario("secured", true, httpStep("https://api.example.com/a", &bearer))
	e.alertRule(sc, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 2, RecoveryAfter: 2, SendRecovery: true})
	var cls []uuid.UUID
	for _, n := range []string{"c1", "c2"} {
		cl := e.cluster(n, ProbeOnlineState)
		e.probes.connect(t, cl, 4)
		cls = append(cls, cl)
	}
	long := "assertion_failed: Authorization: Bearer " + canary + " " + strings.Repeat("x", 900)
	for i := range 3 {
		for _, cl := range cls {
			id := e.dispatched(sc, cl)
			reason := long
			if i == 2 && cl == cls[1] {
				reason = "Bearer " + canary
			}
			if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: id.String(), Status: StatusFailed, FailedStep: 0, FailureReason: reason,
				Steps: []*pb.StepResult{{Position: 0, Status: StatusFailed, Error: "connect_error: " + excerptText,
					Assertions:      []*pb.AssertionResult{{Subject: "body", Operator: "contains", Expected: "ok", Actual: excerptText}},
					ResponseExcerpt: []byte(excerptText + "\r\nAuthorization: Bearer " + canary)}}}); err != nil {
				t.Fatal(err)
			}
		}
		e.notify()
	}
	for _, cl := range cls {
		for range 2 {
			id := e.dispatched(sc, cl)
			if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: id.String(), Status: StatusPassed,
				Steps: []*pb.StepResult{{Position: 0, Status: StatusPassed, ResponseExcerpt: []byte(excerptText)}}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.notify()
	msgs := e.wantMessages(map[string]int{notify.SyntheticCritical: 1, notify.SyntheticRecovered: 1})
	for _, m := range msgs {
		for _, f := range []string{canary, excerptText, "label"} {
			if strings.Contains(m.Raw, f) {
				t.Errorf("%s carries %q: %s", m.Type, f, m.Raw)
			}
		}
		if r := m.Fields["reason"]; len(r) > maxMessageReason {
			t.Errorf("%s reason is %d bytes", m.Type, len(r))
		}
	}
	if !strings.Contains(msgs[0].Fields["reason"], secrets.Redacted) {
		t.Errorf("critical reason %q", msgs[0].Fields["reason"])
	}
}

// The notifier redacts and cuts the reason itself, whatever the row holds.
func TestAlertEventRedactsReason(t *testing.T) {
	const token = "tok-9f8e7d6c5b4a"
	a := &pendingAlert{id: uuid.New(), reason: "upstream said: Bearer " + token + " " + strings.Repeat("é", 400), failedStep: ptr(1), stepKind: "http"}
	ev := alertEvent(notify.SyntheticFailing, nil, a, uuid.New(), "t", "s", []string{"c1"}, true, []*pendingAlert{a})
	r := ev.Fields["reason"]
	if strings.Contains(r, token) || !strings.Contains(r, secrets.Redacted) || len(r) > maxMessageReason || !utf8.ValidString(r) {
		t.Fatalf("reason %q (%d bytes)", r, len(r))
	}
	if ev.Fields["failed step"] != "2 (http)" || ev.Key != "synthetic.failing:"+a.id.String() || ev.ChannelID != nil {
		t.Fatalf("event %+v", ev)
	}
	b, _ := json.Marshal(ev.Payload)
	if strings.Contains(string(b), token) {
		t.Fatalf("payload %s", b)
	}
}

// The alert loop's tick sends the messages (Notify joins CheckProbesOffline
// on LockSyntheticAlerts).
func TestAlertsTickNotifies(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "tick")
	cl := e.cluster("c1", ProbeOnlineState)
	e.applySeq(sc, cl, "FFF", false)
	if err := e.svc.alertsTick(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.wantMessages(map[string]int{notify.SyntheticFailing: 1})
}
