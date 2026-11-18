// Package schedule provides cron parsing with time zones and a single-active
// leader loop guarded by a Postgres advisory lock (SPEC §10.5). Backups and
// audits both use it; the scheduling loop is ours, robfig/cron is only the
// parser.
package schedule

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/Warewave-Technology/olympos/internal/store"
)

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Spec is a parsed cron expression in a time zone.
type Spec struct {
	sched cron.Schedule
	loc   *time.Location
	Expr  string
}

// Parse validates a 5-field cron expression (or @daily etc.) and an IANA zone.
func Parse(expr, tz string) (Spec, error) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "TZ=") || strings.HasPrefix(expr, "CRON_TZ=") {
		return Spec{}, fmt.Errorf("set the time zone separately, not inside the cron expression")
	}
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return Spec{}, fmt.Errorf("unknown time zone %q", tz)
	}
	s, err := parser.Parse(expr)
	if err != nil {
		return Spec{}, fmt.Errorf("invalid cron expression: %w", err)
	}
	return Spec{sched: s, loc: loc, Expr: expr}, nil
}

// Next returns the first activation strictly after t.
func (s Spec) Next(t time.Time) time.Time { return s.sched.Next(t.In(s.loc)).UTC() }

// NextN returns n activations after t.
func (s Spec) NextN(t time.Time, n int) []time.Time {
	out := make([]time.Time, 0, n)
	for i := 0; i < n; i++ {
		t = s.Next(t)
		out = append(out, t)
	}
	return out
}

// Between returns activations in (from, to], capped at max.
func (s Spec) Between(from, to time.Time, max int) []time.Time {
	var out []time.Time
	for t := s.Next(from); !t.After(to) && len(out) < max; t = s.Next(t) {
		out = append(out, t)
	}
	return out
}

// Interval estimates the average period (for transfer estimates).
func (s Spec) Interval(from time.Time) time.Duration {
	ts := s.NextN(from, 8)
	if len(ts) < 2 {
		return 24 * time.Hour
	}
	return ts[len(ts)-1].Sub(ts[0]) / time.Duration(len(ts)-1)
}

// Lock keys for pg_try_advisory_lock; one per scheduler.
const (
	LockBackupScheduler int64 = 0x4f4c5901
	LockAuditScheduler  int64 = 0x4f4c5902
	LockMaintenance     int64 = 0x4f4c5903
)

// RunLeader runs tick every interval while holding the advisory lock. Only
// one replica holds it at a time; others retry each interval.
func RunLeader(ctx context.Context, db *store.DB, key int64, interval time.Duration, log *slog.Logger, tick func(ctx context.Context) error) {
	for {
		held := func() bool {
			conn, err := db.Acquire(ctx)
			if err != nil {
				return false
			}
			defer conn.Release()
			var ok bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil || !ok {
				return false
			}
			defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key) }()
			log.Info("scheduler leadership acquired", "lock", key)
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				if err := tick(ctx); err != nil && ctx.Err() == nil {
					log.Error("scheduler tick", "lock", key, "err", err)
				}
				// Keep the session alive and detect a lost connection.
				if err := conn.Ping(ctx); err != nil {
					return true
				}
				select {
				case <-ctx.Done():
					return true
				case <-t.C:
				}
			}
		}()
		_ = held
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
