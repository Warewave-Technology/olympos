package synthetic

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

func (e *env) resolveUnmonitored() {
	e.t.Helper()
	if err := e.svc.ResolveUnmonitored(e.ctx); err != nil {
		e.t.Fatalf("ResolveUnmonitored: %v", err)
	}
}

// outboxOrder lists the synthetic.* rows by (next_attempt_at, created_at),
// the dispatcher's order, and checks that both strictly increase.
func (e *env) outboxOrder() []string {
	e.t.Helper()
	rows, err := e.db.Query(e.ctx, `SELECT idempotency_key, created_at, next_attempt_at FROM outbox
		WHERE event_type LIKE 'synthetic.%' ORDER BY next_attempt_at, created_at`)
	if err != nil {
		e.t.Fatal(err)
	}
	type row struct {
		key           string
		created, next time.Time
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.key, &x.created, &x.next)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	var keys []string
	for i, x := range got {
		if i > 0 && (!x.created.After(got[i-1].created) || !x.next.After(got[i-1].next)) {
			e.t.Fatalf("outbox rows %s and %s are not in a strict order", got[i-1].key, x.key)
		}
		keys = append(keys, x.key)
	}
	return keys
}

func (e *env) fleetAlerts(sc uuid.UUID) []uuid.UUID {
	e.t.Helper()
	rows, err := e.db.Query(e.ctx, `SELECT id FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id IS NULL ORDER BY opened_at, id`, sc)
	if err != nil {
		e.t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		e.t.Fatal(err)
	}
	return ids
}

// Fix round 1, Important 1: in one pass, fleet alert F1 resolves and F2
// opens. The critical channel reads "no longer critical" (with the count
// when F1 resolved), then "critical", in a defined delivery order.
func TestFleetResolveThenReopenInOrder(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "pay")
	crit := e.channel("crit")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2, SendRecovery: true, CriticalChannelID: &crit})
	c1, c2, c3, c4 := e.cluster("c1", ProbeOnlineState), e.cluster("c2", ProbeOnlineState), e.cluster("c3", ProbeOnlineState), e.cluster("c4", ProbeOnlineState)
	for _, cl := range []uuid.UUID{c1, c2, c3} {
		e.applySeq(sc, cl, "FFF", false)
	}
	e.notify()
	e.applySeq(sc, c1, "PP", false)  // F1 resolves, 2 still failing
	e.applySeq(sc, c4, "FFF", false) // F2 opens
	e.notify()

	fleets := e.fleetAlerts(sc)
	if len(fleets) != 2 {
		t.Fatalf("%d fleet alerts", len(fleets))
	}
	keys := e.outboxOrder()
	want := []string{"synthetic.critical:" + fleets[0].String(), "synthetic.recovered:" + fleets[0].String(), "synthetic.critical:" + fleets[1].String()}
	if len(keys) != 3 || keys[0] != want[0] || keys[1] != want[1] || keys[2] != want[2] {
		t.Fatalf("order %v, want %v", keys, want)
	}
	msgs := e.wantMessages(map[string]int{notify.SyntheticCritical: 2, notify.SyntheticRecovered: 1})
	for _, m := range msgs {
		if m.Channel == nil || *m.Channel != crit {
			t.Fatalf("%s to %v", m.Key, m.Channel)
		}
		switch m.Key {
		case want[1]:
			if m.Fields["still failing"] != "2 clusters" || m.Fields["clusters"] != "c1" {
				t.Fatalf("recovered %v", m.Fields)
			}
		case want[2]:
			if m.Fields["clusters"] != "c2, c3, c4" {
				t.Fatalf("second critical %v", m.Fields)
			}
		}
	}
}

// An alert that opens and resolves within one pass: open first, then
// resolve, in a defined order.
func TestBlipOrder(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "blip")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 1, FleetCriticalClusters: 3, RecoveryAfter: 1, SendRecovery: true})
	cl := e.cluster("c1", ProbeOnlineState)
	e.applySeq(sc, cl, "FP", false)
	e.notify()
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `SELECT id FROM synthetic_alerts WHERE scenario_id = $1`, sc).Scan(&id); err != nil {
		t.Fatal(err)
	}
	keys := e.outboxOrder()
	if len(keys) != 2 || keys[0] != "synthetic.failing:"+id.String() || keys[1] != "synthetic.recovered:"+id.String() {
		t.Fatalf("order %v", keys)
	}
}

// Minor 3: the critical message names every cluster alert it is sent for,
// also one that opened after the fleet alert's snapshot.
func TestCriticalNamesEveryAlert(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "names")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 2, RecoveryAfter: 2, SendRecovery: true})
	for _, n := range []string{"c1", "c2", "c3"} {
		e.applySeq(sc, e.cluster(n, ProbeOnlineState), "FFF", false)
	}
	e.notify()
	msgs := e.wantMessages(map[string]int{notify.SyntheticCritical: 1})
	if msgs[0].Title != "Synthetic check critical: names fails on 3 clusters" || msgs[0].Fields["clusters"] != "c1, c2, c3" {
		t.Fatalf("title %q fields %v", msgs[0].Title, msgs[0].Fields)
	}
}

type alertRow struct {
	state, reason      string
	notified, resolved bool
}

func (e *env) clusterAlert(sc, cl uuid.UUID) alertRow {
	e.t.Helper()
	var a alertRow
	if err := e.db.QueryRow(e.ctx, `SELECT state, reason, notified_at IS NOT NULL, resolved_notified_at IS NOT NULL FROM synthetic_alerts
		WHERE scenario_id = $1 AND cluster_id = $2 ORDER BY opened_at DESC LIMIT 1`, sc, cl).Scan(&a.state, &a.reason, &a.notified, &a.resolved); err != nil {
		e.t.Fatal(err)
	}
	return a
}

// Ruling P16: an alert whose pair is no longer monitored resolves silently
// (excluded cluster, probe not installed or revoked); an offline probe
// keeps it. The fleet alert is re-evaluated and resolves with its usual
// message. A pair monitored again starts a new streak.
func TestUnmonitoredClustersResolveSilently(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "watch")
	cls := map[string]uuid.UUID{}
	for _, n := range []string{"keep", "offline", "excluded", "revoked", "removed"} {
		cls[n] = e.cluster(n, ProbeOnlineState)
		e.applySeq(sc, cls[n], "FFF", false)
	}
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticCritical: 1})

	e.exec(`UPDATE scenarios SET exclude_selectors = '{olympos.io/cluster=excluded}' WHERE id = $1`, sc)
	e.exec(`UPDATE clusters SET probe_status = 'offline' WHERE id = $1`, cls["offline"])
	e.exec(`UPDATE clusters SET probe_status = 'revoked' WHERE id = $1`, cls["revoked"])
	e.exec(`UPDATE clusters SET probe_status = 'not_installed' WHERE id = $1`, cls["removed"])
	if err := e.svc.alertsTick(e.ctx); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{"keep": "firing", "offline": "firing", "excluded": "resolved", "revoked": "resolved", "removed": "resolved"} {
		a := e.clusterAlert(sc, cls[n])
		if a.state != want {
			t.Fatalf("%s: %s, want %s", n, a.state, want)
		}
		if want == "resolved" && (a.reason != ReasonNoLongerMonitored || !a.resolved) {
			t.Fatalf("%s: %+v", n, a)
		}
		if want == "resolved" && e.streak(sc, cls[n]).failures != 0 {
			t.Fatalf("%s: streak kept", n)
		}
	}
	// 2 firing < 3: the fleet alert resolves, with its message; the
	// silent ones are not in it.
	msgs := e.wantMessages(map[string]int{notify.SyntheticCritical: 1, notify.SyntheticRecovered: 1})
	rec := msgs[len(msgs)-1]
	if rec.Title != "Synthetic check no longer critical: watch" || rec.Fields["still failing"] != "2 clusters" || rec.Fields["clusters"] != "" {
		t.Fatalf("recovered %q %v", rec.Title, rec.Fields)
	}
	e.resolveUnmonitored()
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticCritical: 1, notify.SyntheticRecovered: 1})

	// Included again: the old failures do not count.
	e.exec(`UPDATE scenarios SET exclude_selectors = '{}' WHERE id = $1`, sc)
	e.outcome(sc, cls["excluded"], 'F')
	if a := e.clusterAlert(sc, cls["excluded"]); a.state != "resolved" {
		t.Fatal("one failure reopened the alert")
	}
	e.applySeq(sc, cls["excluded"], "FF", true)
	if a := e.clusterAlert(sc, cls["excluded"]); a.state != "firing" {
		t.Fatal("three new failures did not open the alert")
	}
}

// A disabled scenario's alerts, the fleet's included, resolve silently, also
// one that never had its message; a deleted cluster's alert goes with it and
// the fleet alert is re-evaluated on the next tick.
func TestUnmonitoredScenarioAndDeletedCluster(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "paused")
	var cls []uuid.UUID
	for _, n := range []string{"c1", "c2", "c3"} {
		cl := e.cluster(n, ProbeOnlineState)
		cls = append(cls, cl)
		e.applySeq(sc, cl, "FFF", false)
	}
	e.exec(`UPDATE scenarios SET enabled = false WHERE id = $1`, sc)
	e.resolveUnmonitored()
	e.notify()
	e.wantMessages(map[string]int{})
	if n := e.count(`SELECT count(*) FROM synthetic_alerts WHERE scenario_id = $1 AND (state <> 'resolved' OR reason <> $2 OR resolved_notified_at IS NULL)`,
		sc, ReasonNoLongerMonitored); n != 0 {
		t.Fatalf("%d alerts not resolved silently", n)
	}

	other := simpleScenario(e, "deleted-cluster")
	for _, cl := range cls {
		e.applySeq(other, cl, "FFF", false)
	}
	e.notify()
	e.exec(`DELETE FROM clusters WHERE id = $1`, cls[0])
	if _, f := e.firing(other); f != 1 {
		t.Fatal("fleet alert gone before the tick")
	}
	e.resolveUnmonitored()
	if c, f := e.firing(other); c != 2 || f != 0 {
		t.Fatalf("firing %d cluster, %d fleet", c, f)
	}
	e.notify()
	e.wantMessages(map[string]int{notify.SyntheticCritical: 1, notify.SyntheticRecovered: 1})
}

// Minor 2: ReevaluateFleet follows an edited fleet_critical_clusters; a
// deleted scenario is a no-op.
func TestReevaluateFleet(t *testing.T) {
	e := newAlertEnv(t)
	sc := simpleScenario(e, "edit")
	e.alertRule(sc, AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2, SendRecovery: true})
	for _, n := range []string{"c1", "c2"} {
		e.applySeq(sc, e.cluster(n, ProbeOnlineState), "FFF", false)
	}
	reeval := func(id uuid.UUID) {
		t.Helper()
		if err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error { return e.svc.ReevaluateFleet(e.ctx, tx, id) }); err != nil {
			t.Fatal(err)
		}
	}
	reeval(sc)
	if _, f := e.firing(sc); f != 0 {
		t.Fatal("fleet opened below the threshold")
	}
	e.exec(`UPDATE scenario_alerts SET fleet_critical_clusters = 2 WHERE scenario_id = $1`, sc)
	reeval(sc)
	if _, f := e.firing(sc); f != 1 {
		t.Fatal("fleet did not open")
	}
	var reason string
	var run *uuid.UUID
	if err := e.db.QueryRow(e.ctx, `SELECT reason, last_run_id FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id IS NULL`, sc).Scan(&reason, &run); err != nil ||
		reason != failReason || run == nil {
		t.Fatalf("fleet reason %q run %v (%v)", reason, run, err)
	}
	e.exec(`UPDATE scenario_alerts SET fleet_critical_clusters = 5 WHERE scenario_id = $1`, sc)
	reeval(sc)
	if _, f := e.firing(sc); f != 0 {
		t.Fatal("fleet did not resolve")
	}
	reeval(uuid.New())
}
