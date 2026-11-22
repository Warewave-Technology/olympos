package backup

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/schedule"
)

const (
	// errAgentDisconnected: the run could not finish because the agent
	// was not connected (F18).
	errAgentDisconnected = "agent_disconnected"
	// MaxAttempts per scheduled activation (or manual request).
	MaxAttempts = 3
)

// RetryWindow is until when a run that started (or was due) at base may be
// retried: half the interval to the job's next activation.
func RetryWindow(cron, tz string, base time.Time) time.Time {
	spec, err := schedule.Parse(cron, tz)
	if err != nil {
		return base
	}
	next := spec.Next(base)
	return base.Add(next.Sub(base) / 2)
}

// disconnectedOutcome decides what a run that failed because the agent was
// gone becomes (F18): inside the window and below MaxAttempts it fails
// quietly and a new attempt is queued, which waits for the reconnect;
// otherwise it is missed.
func disconnectedOutcome(ctx context.Context, tx pgx.Tx, runID uuid.UUID, o outcome, now time.Time) (outcome, error) {
	r, err := loadRetryRun(ctx, tx, runID)
	if err != nil {
		return o, err
	}
	if r.trigger == "test" {
		return o, nil
	}
	attempt, until := r.attempt, r.until
	if attempt < MaxAttempts && now.Before(until) {
		// A repair's retry is the same repair: same original run and
		// missing set. A plain run's retry resolves its destinations again.
		var dests []uuid.UUID
		if r.repairOf != nil {
			dests = r.destIDs
		}
		if _, err := tx.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, attempt, retry_until, repair_of, destination_ids)
			VALUES ($1, $2, 'queued', $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`, r.jobID, r.trigger, r.sched, attempt+1, until, r.repairOf, dests); err != nil {
			return o, err
		}
		o.status = "failed"
		o.err = fmt.Sprintf("%s: retrying after the agent reconnects (attempt %d of %d, until %s)",
			errAgentDisconnected, attempt+1, MaxAttempts, until.UTC().Format(time.RFC3339))
		o.quiet = true
		return o, nil
	}
	o.status = "missed"
	o.err = errAgentDisconnected + ": the agent did not come back within the job's window"
	if attempt >= MaxAttempts {
		o.err = fmt.Sprintf("%s: still disconnected after %d attempts", errAgentDisconnected, attempt)
	}
	return o, nil
}

// retryRun is what retries and repairs need from a run.
type retryRun struct {
	jobID    uuid.UUID
	trigger  string
	status   string
	attempt  int
	sched    *time.Time
	until    time.Time // retry_until, else the job's window from scheduled_for (or created_at)
	repairOf *uuid.UUID
	destIDs  []uuid.UUID
}

func loadRetryRun(ctx context.Context, tx pgx.Tx, runID uuid.UUID) (retryRun, error) {
	var r retryRun
	var cron, tz string
	var until *time.Time
	var created time.Time
	err := tx.QueryRow(ctx, `SELECT r.job_id, r.trigger, r.status, r.attempt, r.scheduled_for, r.retry_until, r.created_at, r.repair_of,
		r.destination_ids, j.cron, j.timezone FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id WHERE r.id = $1`, runID).
		Scan(&r.jobID, &r.trigger, &r.status, &r.attempt, &r.sched, &until, &created, &r.repairOf, &r.destIDs, &cron, &tz)
	if err != nil {
		return r, err
	}
	if until != nil {
		r.until = *until
	} else {
		base := created
		if r.sched != nil {
			base = *r.sched
		}
		r.until = RetryWindow(cron, tz, base)
	}
	return r, nil
}

// queueRepairTx queues a repair after a finished partial run, or after a
// repair that ended partial or failed: a run that writes only to the
// missing set (see missingDestinationsTx, restricted to the job's current
// destinations), with repair_of = the original run, the same trigger,
// scheduled_for and retry window (so each copy gets the tier it would have
// had), and attempt + 1. It does nothing for test runs, outside the window,
// at MaxAttempts or when nothing is left to repair, and reports whether a
// repair was queued.
func queueRepairTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, now time.Time) (bool, error) {
	r, err := loadRetryRun(ctx, tx, runID)
	if err != nil {
		return false, err
	}
	due := r.status == "partial" || r.repairOf != nil && r.status == "failed"
	if r.trigger == "test" || !due || r.attempt >= MaxAttempts || !now.Before(r.until) {
		return false, nil
	}
	root := runID
	if r.repairOf != nil {
		root = *r.repairOf
	}
	missing, err := missingDestinationsTx(ctx, tx, root, true)
	if err != nil || len(missing) == 0 {
		return false, err
	}
	ids := make([]uuid.UUID, len(missing))
	for i, d := range missing {
		ids[i] = d.ID
	}
	tag, err := tx.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, attempt, retry_until, repair_of, destination_ids)
		VALUES ($1, $2, 'queued', $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`, r.jobID, r.trigger, r.sched, r.attempt+1, r.until, root, ids)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// missingDestinationsTx is the missing set of an original run (root): its
// destination_ids, in order, without those that have a succeeded copy in
// root or in any repair of it. With current, only the destinations the job
// still writes to are kept.
func missingDestinationsTx(ctx context.Context, tx pgx.Tx, root uuid.UUID, current bool) ([]destRef, error) {
	return scanDestRefs(tx.Query(ctx, `SELECT d.id, d.name, d.kind FROM backup_runs r
		CROSS JOIN LATERAL unnest(r.destination_ids) WITH ORDINALITY u(id, ord) JOIN destinations d ON d.id = u.id
		WHERE r.id = $1
		  AND NOT EXISTS (SELECT 1 FROM backup_run_copies c JOIN backup_runs x ON x.id = c.run_id
		    WHERE (x.id = $1 OR x.repair_of = $1) AND c.destination_id = u.id AND c.status = 'succeeded')
		  AND (NOT $2 OR u.id IN (SELECT COALESCE(j.destination_id, m.destination_id) FROM backup_jobs j
		    LEFT JOIN destination_group_members m ON m.group_id = j.destination_group_id WHERE j.id = r.job_id))
		ORDER BY u.ord`, root, current))
}
