package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Scheduler queues due runs (SPEC §10.5). Only the replica holding the
// advisory lock runs it.
type Scheduler struct {
	DB  *store.DB
	Log *slog.Logger
	// Interval between loops (default 30 s).
	Interval time.Duration
	// Grace: an activation older than this when first seen is recorded as
	// missed instead of queued (default 15 min).
	Grace time.Duration
	// DeadMansSwitchURL is GET after every successful loop (SPEC §10.6).
	DeadMansSwitchURL string
	HTTP              *http.Client
	Now               func() time.Time
	// MaxPerTick caps activations handled per job per loop (default 1000);
	// the rest are handled by the following loops.
	MaxPerTick int
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run blocks until ctx is done. The first loop runs as soon as leadership is
// acquired, so downtime is reported as missed runs right after startup.
func (s *Scheduler) Run(ctx context.Context) {
	iv := s.Interval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	schedule.RunLeader(ctx, s.DB, schedule.LockBackupScheduler, iv, s.Log, func(ctx context.Context) error {
		if err := s.Tick(ctx); err != nil {
			return err
		}
		s.Ping(ctx)
		return nil
	})
}

type schedJob struct {
	id        uuid.UUID
	cron, tz  string
	last      *time.Time
	channel   *uuid.UUID
	ns, svc   string
	cluster   string
	clusterID uuid.UUID
}

// Tick handles every enabled, unpaused job once.
func (s *Scheduler) Tick(ctx context.Context) error {
	now := s.now().UTC()
	rows, err := s.DB.Query(ctx, `SELECT j.id, j.cron, j.timezone, j.last_scheduled_for, j.notify_channel_id, t.namespace, t.service, c.name, c.id
		FROM backup_jobs j JOIN targets t ON t.id = j.target_id JOIN clusters c ON c.id = t.cluster_id
		WHERE j.enabled AND j.paused_reason = '' AND j.deleted_at IS NULL AND c.status <> 'revoked'`)
	if err != nil {
		return err
	}
	var jobs []schedJob
	for rows.Next() {
		var j schedJob
		if err := rows.Scan(&j.id, &j.cron, &j.tz, &j.last, &j.channel, &j.ns, &j.svc, &j.cluster, &j.clusterID); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var lag time.Duration
	var firstErr error
	for _, j := range jobs {
		l, err := s.scheduleJob(ctx, j, now)
		if err != nil {
			s.Log.Error("schedule backup job", "job_id", j.id, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if l > lag {
			lag = l
		}
	}
	metrics.SchedulerLag.Set(lag.Seconds())
	return firstErr
}

// scheduleJob queues or marks missed the activations in (last, now]. It
// returns the largest lag of newly queued runs.
func (s *Scheduler) scheduleJob(ctx context.Context, j schedJob, now time.Time) (time.Duration, error) {
	spec, err := schedule.Parse(j.cron, j.tz)
	if err != nil {
		return 0, fmt.Errorf("invalid schedule: %w", err)
	}
	grace := s.Grace
	if grace <= 0 {
		grace = 15 * time.Minute
	}
	max := s.MaxPerTick
	if max <= 0 {
		max = 1000
	}
	var lag time.Duration
	err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var last *time.Time
		var enabled bool
		var paused string
		err := tx.QueryRow(ctx, `SELECT last_scheduled_for, enabled, paused_reason FROM backup_jobs WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, j.id).
			Scan(&last, &enabled, &paused)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !enabled || paused != "" {
			return nil
		}
		if last == nil {
			// Never scheduled: start from now (no backfill).
			_, err := tx.Exec(ctx, `UPDATE backup_jobs SET last_scheduled_for = $2 WHERE id = $1`, j.id, now)
			return err
		}
		acts := spec.Between(*last, now, max)
		if len(acts) == 0 {
			return nil
		}
		var missed []time.Time
		for i, at := range acts {
			superseded := i < len(acts)-1
			late := now.Sub(at) > grace
			if superseded || late {
				reason := "missed: Olympos was not scheduling at this time"
				if superseded && !late {
					reason = "missed: superseded by a later activation"
				}
				tag, err := tx.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, finished_at, error)
					VALUES ($1, 'schedule', 'missed', $2, $3, $4) ON CONFLICT (job_id, scheduled_for) WHERE scheduled_for IS NOT NULL DO NOTHING`,
					j.id, at, now, reason)
				if err != nil {
					return err
				}
				if tag.RowsAffected() > 0 {
					missed = append(missed, at)
				}
				continue
			}
			// A previous scheduled run still waiting in the queue is
			// superseded by this activation.
			srows, err := tx.Query(ctx, `UPDATE backup_runs SET status = 'missed', finished_at = $3,
				error = 'missed: superseded while still queued (agent not connected?)'
				WHERE job_id = $1 AND trigger = 'schedule' AND status = 'queued' AND scheduled_for < $2 RETURNING scheduled_for`, j.id, at, now)
			if err != nil {
				return err
			}
			for srows.Next() {
				var t time.Time
				if err := srows.Scan(&t); err != nil {
					srows.Close()
					return err
				}
				missed = append(missed, t)
			}
			srows.Close()
			if err := srows.Err(); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for)
				VALUES ($1, 'schedule', 'queued', $2) ON CONFLICT (job_id, scheduled_for) WHERE scheduled_for IS NOT NULL DO NOTHING`, j.id, at)
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				if l := now.Sub(at); l > lag {
					lag = l
				}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE backup_jobs SET last_scheduled_for = $2 WHERE id = $1`, j.id, acts[len(acts)-1]); err != nil {
			return err
		}
		if len(missed) == 0 {
			return nil
		}
		latest := missed[0]
		for _, t := range missed {
			if t.After(latest) {
				latest = t
			}
		}
		title := fmt.Sprintf("Backup missed: %s/%s", j.ns, j.svc)
		if len(missed) > 1 {
			title = fmt.Sprintf("Backup missed: %s/%s (%d runs)", j.ns, j.svc, len(missed))
		}
		return notify.Emit(ctx, tx, notify.Event{
			Type: notify.BackupMissed, ChannelID: j.channel,
			Key:   fmt.Sprintf("backup.missed:%s:%s", j.id, latest.UTC().Format(time.RFC3339)),
			Title: title, Link: "/backups?job=" + j.id.String(),
			Fields: map[string]string{"cluster": j.cluster, "target": j.ns + "/" + j.svc,
				"scheduled_for": latest.UTC().Format(time.RFC3339), "count": fmt.Sprint(len(missed))},
			Payload: map[string]any{"job_id": j.id.String(), "missed": len(missed)},
		})
	})
	return lag, err
}

// Ping calls the dead man's switch URL. Failures are logged without the URL
// (it usually embeds a token).
func (s *Scheduler) Ping(ctx context.Context) {
	if s.DeadMansSwitchURL == "" {
		return
	}
	hc := s.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, s.DeadMansSwitchURL, nil)
	if err != nil {
		s.Log.Warn("dead man's switch: invalid url")
		return
	}
	req.Header.Set("User-Agent", "olympos-scheduler")
	resp, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		s.Log.Warn("dead man's switch ping failed", "err", secrets.RedactString(err.Error()))
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.Log.Warn("dead man's switch ping rejected", "status", resp.StatusCode)
	}
}
