package synthetic

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Retention (§8). Runs and their step results are kept RunRetention (30
// days) and rolled up to hourly rows kept AggregateRetention (400 days);
// response excerpts go after ExcerptRetention (7 days); test runs of the
// editor are kept TestRunRetention (7 days, "Decisions after review" 4).
// Alerts are never touched: they are small and they are the history.
const (
	// MaintenanceInterval is how often the leader of LockSyntheticMaintenance
	// rolls up and prunes.
	MaintenanceInterval = 10 * time.Minute
	// TestRunRetention is how long the runs of the editor's Test button stay.
	TestRunRetention = 7 * 24 * time.Hour

	defaultRunRetention       = 720 * time.Hour
	defaultAggregateRetention = 9600 * time.Hour
	defaultExcerptRetention   = 168 * time.Hour
)

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// RunMaintenance is the one leader loop of LockSyntheticMaintenance: every
// MaintenanceInterval it runs Maintain, and once a day (ExpiryInterval) the
// credential expiry check. Both are idempotent, so a new leader that starts
// its day over does no harm.
func (s *Service) RunMaintenance(ctx context.Context) {
	var lastExpiry time.Time
	schedule.RunLeader(ctx, s.DB, schedule.LockSyntheticMaintenance, MaintenanceInterval, s.Log.With("loop", "maintenance"),
		func(ctx context.Context) error {
			var err error
			lastExpiry, err = s.maintenanceTick(ctx, lastExpiry)
			return err
		})
}

// maintenanceTick runs Maintain, and the expiry check when it was last done
// ExpiryInterval ago or more (or never). It returns when the expiry check
// last succeeded; a failed one is tried again on the next tick, and neither
// failure hides the other.
func (s *Service) maintenanceTick(ctx context.Context, lastExpiry time.Time) (time.Time, error) {
	errM := s.Maintain(ctx)
	var errE error
	if now := s.now(); lastExpiry.IsZero() || now.Sub(lastExpiry) >= ExpiryInterval {
		if errE = s.CheckCredentialExpiry(ctx); errE == nil {
			lastExpiry = now
		}
	}
	return lastExpiry, errors.Join(errM, errE)
}

// Maintain, in one transaction:
//
//  1. rolls up the finished hours into synthetic_hourly, from the newest
//     rolled hour on (but not before the cut of step 3). That hour is
//     computed again: its row is replaced, not added to, so a second pass
//     changes nothing;
//  2. fills the hours of the runs about to be deleted that have no row yet
//     (a hole, never overwriting), so no run is deleted before it is
//     rolled up;
//  3. deletes terminal runs (their step results go with them) that
//     finished before the hour RunRetention ago falls in. Whole hours go at
//     a time, so a rolled hour never loses part of its runs afterwards;
//  4. deletes test runs older than TestRunRetention;
//  5. clears response excerpts older than ExcerptRetention;
//  6. deletes hourly rows older than AggregateRetention.
//
// A row of synthetic_hourly counts, per scenario, cluster and hour, the
// runs that ended passed, failed or error. A skipped run and a test run
// are never counted. runs is their number, passed the passed ones and
// failed the failed and error ones, so availability is passed / runs =
// passed / (passed + failed + error). p50_ms and p95_ms are
// percentile_cont of total_ms, rounded.
//
// The rollups insert in key order, so that two leaders that overlap (a
// lock lost and regained) take their row locks in the same order.
func (s *Service) Maintain(ctx context.Context) error {
	now := s.now().UTC()
	boundary := now.Truncate(time.Hour) // the current hour is not finished
	runCut := now.Add(-orDefault(s.Cfg.RunRetention, defaultRunRetention)).Truncate(time.Hour)
	if runCut.After(boundary) {
		runCut = boundary
	}
	aggCut := now.Add(-orDefault(s.Cfg.AggregateRetention, defaultAggregateRetention)).Truncate(time.Hour)
	excerptCut := now.Add(-orDefault(s.Cfg.ExcerptRetention, defaultExcerptRetention))
	testCut := now.Add(-TestRunRetention)

	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		// The newest rolled hour is computed again (it may have been rolled
		// while its last runs were still coming in).
		var last *time.Time
		if err := tx.QueryRow(ctx, `SELECT max(hour) FROM synthetic_hourly`).Scan(&last); err != nil {
			return err
		}
		// Not before runCut: what is older is the business of the second
		// step, which never overwrites.
		from := runCut
		if last != nil && last.After(from) {
			from = *last
		}
		if _, err := tx.Exec(ctx, rollupReplace, from, boundary); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, rollupFill, aggCut, runCut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM synthetic_runs
			WHERE NOT test AND status IN ('passed','failed','error','skipped') AND finished_at < $1`, runCut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM synthetic_runs
			WHERE test AND status IN ('passed','failed','error','skipped') AND finished_at < $1`, testCut); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE synthetic_step_results sr SET excerpt = NULL FROM synthetic_runs r
			WHERE sr.excerpt IS NOT NULL AND r.id = sr.run_id
			  AND r.status IN ('passed','failed','error','skipped') AND r.finished_at < $1`, excerptCut); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM synthetic_hourly WHERE hour < $1`, aggCut)
		return err
	})
}

// rollupSelect computes the hourly rows of the runs that finished in
// [$1, $2). The conflict clause is added by the caller.
const rollupSelect = `INSERT INTO synthetic_hourly (scenario_id, cluster_id, hour, runs, passed, failed, p50_ms, p95_ms)
SELECT scenario_id, cluster_id, date_trunc('hour', finished_at, 'UTC') AS h,
       count(*), count(*) FILTER (WHERE status = 'passed'), count(*) FILTER (WHERE status IN ('failed','error')),
       COALESCE(round(percentile_cont(0.5) WITHIN GROUP (ORDER BY total_ms))::int, 0),
       COALESCE(round(percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms))::int, 0)
FROM synthetic_runs
WHERE NOT test AND scenario_id IS NOT NULL AND ` + countedRunSQL + ` AND finished_at >= $1 AND finished_at < $2
GROUP BY scenario_id, cluster_id, h
ORDER BY scenario_id, cluster_id, h
`

const (
	// rollupReplace replaces a row that exists: the hour is computed again
	// from all of its runs, so doing it twice changes nothing.
	rollupReplace = rollupSelect + `ON CONFLICT (scenario_id, cluster_id, hour) DO UPDATE SET runs = EXCLUDED.runs,
  passed = EXCLUDED.passed, failed = EXCLUDED.failed, p50_ms = EXCLUDED.p50_ms, p95_ms = EXCLUDED.p95_ms`
	// rollupFill only adds the rows that are missing.
	rollupFill = rollupSelect + `ON CONFLICT (scenario_id, cluster_id, hour) DO NOTHING`
)
