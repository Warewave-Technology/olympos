package synthetic

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// ReasonNoLongerMonitored is synthetic_alerts.reason of an alert resolved
// because its pair stopped being monitored (ruling P16).
const ReasonNoLongerMonitored = "no_longer_monitored"

// ResolveUnmonitored is one pass of ruling P16 (alerts tick): a firing alert
// whose pair is no longer monitored resolves silently, with reason
// no_longer_monitored, no recovery message and its streak reset. A pair is
// no longer monitored when the scenario is disabled, the cluster is
// excluded by targeting, or the cluster's probe is not installed or
// revoked (a deleted scenario or cluster takes its alerts with it). A probe
// that is only offline keeps its alert: offline is not a recovery. A
// scenario whose stored targeting does not parse is left alone rather than
// read as "excluded everywhere". Then the fleet alert of every scenario
// with a firing alert is re-evaluated, which also catches cluster alerts
// removed with their cluster.
func (s *Service) ResolveUnmonitored(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT scenario_id FROM synthetic_alerts WHERE state = 'firing'`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(ids) == 0 {
		return err
	}
	clusters, err := LoadClusters(ctx, s.DB)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error { return s.resolveUnmonitored(ctx, tx, id, clusters) }); err != nil {
			errs = append(errs, fmt.Errorf("resolve unmonitored alerts of scenario %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) resolveUnmonitored(ctx context.Context, tx pgx.Tx, scenarioID uuid.UUID, clusters []ClusterInfo) error {
	var enabled bool
	var t Targeting
	err := tx.QueryRow(ctx, `SELECT enabled, run_on, run_on_selector, exclude_selectors FROM scenarios WHERE id = $1 FOR NO KEY UPDATE`,
		scenarioID).Scan(&enabled, &t.RunOn, &t.RunOnSelector, &t.Exclude)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	now := s.now()
	rows, err := tx.Query(ctx, `SELECT id, cluster_id FROM synthetic_alerts WHERE scenario_id = $1 AND state = 'firing' FOR UPDATE`, scenarioID)
	if err != nil {
		return err
	}
	type alert struct {
		id      uuid.UUID
		cluster *uuid.UUID
	}
	firing, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (alert, error) {
		var a alert
		return a, r.Scan(&a.id, &a.cluster)
	})
	if err != nil {
		return err
	}

	var gone []uuid.UUID
	var pairs []uuid.UUID // clusters whose streak restarts
	if !enabled {
		for _, a := range firing {
			gone = append(gone, a.id)
			if a.cluster != nil {
				pairs = append(pairs, *a.cluster)
			}
		}
	} else if _, perr := t.parse(); perr == nil {
		state := map[uuid.UUID]string{}
		for _, tc := range Resolve(t, clusters) {
			state[tc.ID] = tc.State
		}
		for _, a := range firing {
			if a.cluster == nil {
				continue
			}
			// A cluster added after the list was read waits for the
			// next pass.
			st, known := state[*a.cluster]
			if !known || st == TargetIncluded || st == TargetProbeOffline {
				continue
			}
			gone = append(gone, a.id)
			pairs = append(pairs, *a.cluster)
		}
	}
	if len(gone) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE synthetic_alerts SET state = 'resolved', resolved_at = $2, reason = $3,
			notified_at = COALESCE(notified_at, $2), resolved_notified_at = $2 WHERE id = ANY($1)`, gone, now, ReasonNoLongerMonitored); err != nil {
			return err
		}
		// Monitored again later, a pair starts from nothing: an old run
		// of failures must not open an alert at the first failure.
		if _, err := tx.Exec(ctx, `UPDATE synthetic_state SET consecutive_failures = 0, consecutive_passes = 0
			WHERE scenario_id = $1 AND cluster_id = ANY($2)`, scenarioID, pairs); err != nil {
			return err
		}
		s.Log.Info("synthetic alerts resolved: no longer monitored", "scenario_id", scenarioID, "alerts", len(gone))
	}
	if !enabled {
		return nil
	}
	rule, err := loadAlertRule(ctx, tx, scenarioID)
	if err != nil {
		return err
	}
	return s.reevaluateFleet(ctx, tx, scenarioID, rule, now, nil)
}
