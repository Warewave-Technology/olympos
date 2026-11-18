package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/schedule"
)

const (
	// reasonAgentDisconnected: the run could not finish because the agent
	// was not connected (F18).
	reasonAgentDisconnected = "agent_disconnected"
	maxAttempts             = 3
	// manualRetryWindow bounds retries of runs without a schedule.
	manualRetryWindow = 30 * time.Minute
)

// disconnectedStatus decides what a run that failed because the agent was
// gone becomes: inside the window (half the interval to the schedule's next
// activation) and below maxAttempts a new attempt is queued, which waits
// for the reconnect, and this one fails; otherwise it is missed.
func disconnectedStatus(ctx context.Context, tx pgx.Tx, runID uuid.UUID, now time.Time) (status, reason string, err error) {
	var attempt int
	var sched, until *time.Time
	var created time.Time
	var cron, tz *string
	err = tx.QueryRow(ctx, `SELECT r.attempt, r.scheduled_for, r.retry_until, r.created_at, s.cron, s.timezone
		FROM audit_runs r LEFT JOIN audit_schedules s ON s.id = r.schedule_id WHERE r.id = $1`, runID).
		Scan(&attempt, &sched, &until, &created, &cron, &tz)
	if err != nil {
		return "", "", err
	}
	if until == nil {
		w := created.Add(manualRetryWindow)
		if sched != nil && cron != nil && tz != nil {
			if spec, perr := schedule.Parse(*cron, *tz); perr == nil {
				w = sched.Add(spec.Next(*sched).Sub(*sched) / 2)
			}
		}
		until = &w
	}
	if attempt < maxAttempts && now.Before(*until) {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_runs (schedule_id, tool, cluster_id, status, scheduled_for, details, attempt, retry_until)
			SELECT schedule_id, tool, cluster_id, 'queued', scheduled_for, details, attempt + 1, $2 FROM audit_runs WHERE id = $1
			ON CONFLICT DO NOTHING`, runID, *until); err != nil {
			return "", "", err
		}
		return "failed", fmt.Sprintf("%s: retrying after the agent reconnects (attempt %d of %d, until %s)",
			reasonAgentDisconnected, attempt+1, maxAttempts, until.UTC().Format(time.RFC3339)), nil
	}
	if attempt >= maxAttempts {
		return "missed", fmt.Sprintf("%s: still disconnected after %d attempts", reasonAgentDisconnected, attempt), nil
	}
	return "missed", reasonAgentDisconnected + ": the agent did not come back within the schedule's window", nil
}
