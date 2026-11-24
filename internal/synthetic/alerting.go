package synthetic

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The alert state machine (docs/design/synthetic-monitoring.md §5). Each
// scenario and cluster keeps a streak (synthetic_state): a cluster alert
// opens after ClusterFailAfter failed runs in a row and resolves after
// RecoveryAfter passed runs in a row. The fleet alert of a scenario
// (synthetic_alerts.cluster_id NULL) opens while FleetCriticalClusters or
// more of its cluster alerts fire, and resolves when fewer do.
//
// Only rows change here, in the transaction that finishes the run: the
// messages are sent by Notify, which groups what opened and resolved since
// its last pass.
//
// What counts: scheduled and manual (Run now) runs that passed, failed or
// errored. A test run never counts. A skipped run (probe offline or
// disconnected, scenario disabled, credential unavailable, not dispatched,
// ...) neither counts nor resets a streak (Review Focus 4): the scenario was
// not tried. Nor does a run that ended because a credential cannot be
// resolved or has expired: the credential alerts instead (counts).

// AlertRule is a scenario's alert settings (scenario_alerts). A nil channel
// means the event's routes decide.
type AlertRule struct {
	ClusterFailAfter, FleetCriticalClusters, RecoveryAfter int
	SendRecovery                                           bool
	ChannelID, CriticalChannelID                           *uuid.UUID
}

// DefaultAlertRule is the rule of a scenario with no scenario_alerts row:
// the column defaults of the table.
var DefaultAlertRule = AlertRule{ClusterFailAfter: 3, FleetCriticalClusters: 3, RecoveryAfter: 2, SendRecovery: true}

// StreakState is where a scenario stands on one cluster: the current run of
// failures or passes, and whether its cluster alert fires.
type StreakState struct {
	Failures, Passes int
	Firing           bool
}

// Transition is what a run does to a cluster alert.
type Transition int

const (
	// None: the alert stays as it was.
	None Transition = iota
	// Open: the alert opens.
	Open
	// Recover: the alert resolves. (The plan's name, Resolve, is taken in
	// this package by targeting's Resolve.)
	Recover
)

// Step applies one run's status to st. passed extends the passes and ends
// the failures; failed and error extend the failures and end the passes; any
// other status (skipped) changes nothing. The alert opens when the failures
// reach ClusterFailAfter while it does not fire, and resolves when it fires
// and the passes reach RecoveryAfter. A threshold below 1 counts as 1.
func Step(st StreakState, status string, r AlertRule) (StreakState, Transition) {
	switch status {
	case StatusPassed:
		st.Passes++
		st.Failures = 0
		if st.Firing && st.Passes >= max(r.RecoveryAfter, 1) {
			st.Firing = false
			return st, Recover
		}
	case StatusFailed, StatusError:
		st.Failures++
		st.Passes = 0
		if !st.Firing && st.Failures >= max(r.ClusterFailAfter, 1) {
			st.Firing = true
			return st, Open
		}
	}
	return st, None
}

// counts reports whether a run of this status and reason moves a streak.
// A credential that cannot be resolved (credential_broken) or has expired
// says nothing about the scenario: it alerts once, for the credential, not
// once per scenario and cluster (#54).
func counts(status, reason string) bool {
	if reason == ReasonCredentialBroken || reason == ReasonCredentialExpired {
		return false
	}
	return status == StatusPassed || status == StatusFailed || status == StatusError
}

// countedRunSQL is counts in SQL, over synthetic_runs: the runs that the
// stats (availability, percentiles, the timeline, the hourly rollups) are
// made of.
const countedRunSQL = "status IN ('passed','failed','error') AND COALESCE(failure_reason, '') NOT IN ('" +
	ReasonCredentialBroken + "','" + ReasonCredentialExpired + "')"

// loadAlertRule reads a scenario's alert settings, DefaultAlertRule when it
// has none.
func loadAlertRule(ctx context.Context, q pgx.Tx, scenarioID uuid.UUID) (AlertRule, error) {
	r := AlertRule{}
	err := q.QueryRow(ctx, `SELECT cluster_fail_after, fleet_critical_clusters, recovery_after, send_recovery, channel_id, critical_channel_id
		FROM scenario_alerts WHERE scenario_id = $1`, scenarioID).
		Scan(&r.ClusterFailAfter, &r.FleetCriticalClusters, &r.RecoveryAfter, &r.SendRecovery, &r.ChannelID, &r.CriticalChannelID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultAlertRule, nil
	}
	return r, err
}

// ApplyOutcome is the Service's OnResult: it moves the streak of the run's
// scenario and cluster, opens or resolves the cluster alert, then the fleet
// alert. Test runs and runs that do not count (skipped, a credential
// error) return at once.
// Nothing that is missing is an error: a scenario deleted meanwhile, or a
// run already applied, is a no-op, so that a batch that finishes many runs
// in one transaction is never rolled back by one of them.
//
// The scenario row is locked (FOR NO KEY UPDATE, which foreign key checks
// do not wait for) so that the outcomes of one scenario, and Notify, take
// their turn: two clusters that reach the fleet threshold at once must see
// each other's alert.
func (s *Service) ApplyOutcome(ctx context.Context, tx pgx.Tx, o RunOutcome) error {
	if o.Test || o.ScenarioID == uuid.Nil || !counts(o.Status, o.Reason) {
		return nil
	}
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM scenarios WHERE id = $1 FOR NO KEY UPDATE`, o.ScenarioID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rule, err := loadAlertRule(ctx, tx, o.ScenarioID)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO synthetic_state (scenario_id, cluster_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		o.ScenarioID, o.ClusterID); err != nil {
		return err
	}
	var st StreakState
	var lastRun *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT consecutive_failures, consecutive_passes, last_run_id FROM synthetic_state
		WHERE scenario_id = $1 AND cluster_id = $2 FOR UPDATE`, o.ScenarioID, o.ClusterID).Scan(&st.Failures, &st.Passes, &lastRun); err != nil {
		return err
	}
	if lastRun != nil && *lastRun == o.RunID {
		return nil // applied already
	}
	var firing *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id = $2 AND state = 'firing' FOR UPDATE`,
		o.ScenarioID, o.ClusterID).Scan(&firing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	st.Firing = firing != nil

	next, tr := Step(st, o.Status, rule)
	finished := o.FinishedAt
	if finished.IsZero() {
		finished = s.now()
	}
	if _, err := tx.Exec(ctx, `UPDATE synthetic_state SET consecutive_failures = $3, consecutive_passes = $4, last_run_id = $5,
		last_status = $6, last_finished_at = $7 WHERE scenario_id = $1 AND cluster_id = $2`,
		o.ScenarioID, o.ClusterID, next.Failures, next.Passes, o.RunID, o.Status, finished); err != nil {
		return err
	}
	switch tr {
	case Open:
		// ON CONFLICT: the partial unique index allows one firing alert
		// per pair; one that fires already stays as it is.
		if _, err := tx.Exec(ctx, `INSERT INTO synthetic_alerts (scenario_id, cluster_id, state, reason, opened_at, last_run_id)
			VALUES ($1, $2, 'firing', $3, $4, $5) ON CONFLICT DO NOTHING`,
			o.ScenarioID, o.ClusterID, cut(o.Reason, maxReason), finished, o.RunID); err != nil {
			return err
		}
	case Recover:
		if _, err := tx.Exec(ctx, `UPDATE synthetic_alerts SET state = 'resolved', resolved_at = $2, last_run_id = $3 WHERE id = $1`,
			*firing, finished, o.RunID); err != nil {
			return err
		}
	default:
		return nil
	}
	return s.reevaluateFleet(ctx, tx, o.ScenarioID, rule, finished, &o.RunID)
}

// ReevaluateFleet opens or resolves a scenario's fleet alert from the
// cluster alerts firing now and the current fleet_critical_clusters: after
// an edit of scenario_alerts, or after cluster alerts went away without a
// run (no longer monitored, or removed with their cluster). A scenario that
// is gone is a no-op.
func (s *Service) ReevaluateFleet(ctx context.Context, tx pgx.Tx, scenarioID uuid.UUID) error {
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM scenarios WHERE id = $1 FOR NO KEY UPDATE`, scenarioID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rule, err := loadAlertRule(ctx, tx, scenarioID)
	if err != nil {
		return err
	}
	return s.reevaluateFleet(ctx, tx, scenarioID, rule, s.now(), nil)
}

// reevaluateFleet opens the fleet alert when FleetCriticalClusters or more
// cluster alerts fire, and resolves it when fewer do (the caller holds the
// scenario row). It opens with the reason and run of the newest firing
// cluster alert (on the run path, the one that just opened), and clusters
// holds the firing clusters' ids, oldest alert first. It resolves with
// still_failing, the count at that moment, and the run that moved it when
// there is one (runID nil: no run did).
func (s *Service) reevaluateFleet(ctx context.Context, tx pgx.Tx, scenarioID uuid.UUID, rule AlertRule, at time.Time, runID *uuid.UUID) error {
	var ids []string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(cluster_id::text ORDER BY opened_at, cluster_id), '{}') FROM synthetic_alerts
		WHERE scenario_id = $1 AND cluster_id IS NOT NULL AND state = 'firing'`, scenarioID).Scan(&ids); err != nil {
		return err
	}
	var fleet *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM synthetic_alerts WHERE scenario_id = $1 AND cluster_id IS NULL AND state = 'firing' FOR UPDATE`,
		scenarioID).Scan(&fleet); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	critical := len(ids) >= max(rule.FleetCriticalClusters, 1)
	var err error
	switch {
	case critical && fleet == nil:
		_, err = tx.Exec(ctx, `INSERT INTO synthetic_alerts (scenario_id, cluster_id, state, reason, clusters, opened_at, last_run_id)
			SELECT $1, NULL, 'firing', a.reason, $2, $3, a.last_run_id FROM synthetic_alerts a
			WHERE a.scenario_id = $1 AND a.cluster_id IS NOT NULL AND a.state = 'firing'
			ORDER BY a.opened_at DESC, a.cluster_id DESC LIMIT 1
			ON CONFLICT DO NOTHING`, scenarioID, ids, at)
	case !critical && fleet != nil:
		_, err = tx.Exec(ctx, `UPDATE synthetic_alerts SET state = 'resolved', resolved_at = $2, still_failing = $3,
			last_run_id = COALESCE($4, last_run_id) WHERE id = $1`, *fleet, at, len(ids), runID)
	}
	return err
}
