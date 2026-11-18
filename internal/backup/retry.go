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
	var jobID uuid.UUID
	var trigger, cron, tz string
	var attempt int
	var sched, until *time.Time
	var created time.Time
	err := tx.QueryRow(ctx, `SELECT r.job_id, r.trigger, r.attempt, r.scheduled_for, r.retry_until, r.created_at, j.cron, j.timezone
		FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id WHERE r.id = $1`, runID).
		Scan(&jobID, &trigger, &attempt, &sched, &until, &created, &cron, &tz)
	if err != nil {
		return o, err
	}
	if trigger == "test" {
		return o, nil
	}
	if until == nil {
		base := created
		if sched != nil {
			base = *sched
		}
		w := RetryWindow(cron, tz, base)
		until = &w
	}
	if attempt < MaxAttempts && now.Before(*until) {
		if _, err := tx.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, attempt, retry_until)
			VALUES ($1, $2, 'queued', $3, $4, $5) ON CONFLICT DO NOTHING`, jobID, trigger, sched, attempt+1, *until); err != nil {
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
