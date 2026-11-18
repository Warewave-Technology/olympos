package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// SchedulerInterval is the leader loop period.
const SchedulerInterval = 30 * time.Second

// staleRunning fails runs stuck in running (replica died mid-run).
const staleRunning = 3 * time.Hour

// RunScheduler is the leader-elected scheduling loop (one replica at a time).
func (s *Service) RunScheduler(ctx context.Context) {
	s.init()
	schedule.RunLeader(ctx, s.DB, schedule.LockAuditScheduler, SchedulerInterval, s.Log.With("component", "audit-scheduler"), s.Tick)
}

// Tick queues runs that became due. Audits are not backfilled: if several
// activations were missed (scheduler down), only the latest is queued.
// Queuing is idempotent on (schedule, cluster, scheduled_for).
func (s *Service) Tick(ctx context.Context) error {
	s.init()
	now := s.now().UTC()
	if _, err := s.DB.Exec(ctx, `UPDATE audit_runs SET status = 'failed', finished_at = now(),
		error = 'interrupted: the server stopped during the run' WHERE status = 'running' AND started_at < $1`,
		now.Add(-staleRunning)); err != nil {
		return err
	}
	type sched struct {
		id         uuid.UUID
		tool       string
		frameworks []string
		scope      string
		cron, tz   string
		base       time.Time
	}
	rows, err := s.DB.Query(ctx, `SELECT id, tool, frameworks, scope_selector, cron, timezone, COALESCE(last_scheduled_for, created_at)
		FROM audit_schedules WHERE enabled`)
	if err != nil {
		return err
	}
	var list []sched
	for rows.Next() {
		var x sched
		if err := rows.Scan(&x.id, &x.tool, &x.frameworks, &x.scope, &x.cron, &x.tz, &x.base); err != nil {
			rows.Close()
			return err
		}
		list = append(list, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range list {
		spec, err := schedule.Parse(x.cron, x.tz)
		if err != nil {
			s.Log.Warn("audit schedule has an invalid cron", "schedule_id", x.id, "err", err)
			continue
		}
		var due time.Time
		for t, n := spec.Next(x.base), 0; !t.After(now) && n < 200000; t, n = spec.Next(t), n+1 {
			due = t
		}
		if due.IsZero() {
			continue
		}
		err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
			clusters, err := MatchingClusters(ctx, tx, x.scope, x.tool)
			if err != nil {
				return err
			}
			for _, c := range clusters {
				if _, err := tx.Exec(ctx, `INSERT INTO audit_runs (schedule_id, tool, cluster_id, status, scheduled_for, details)
					VALUES ($1, $2, $3, 'queued', $4, jsonb_build_object('trigger', 'schedule', 'frameworks', $5::text[]))
					ON CONFLICT (schedule_id, cluster_id, scheduled_for, attempt) WHERE scheduled_for IS NOT NULL DO NOTHING`,
					x.id, x.tool, c, due, x.frameworks); err != nil {
					return err
				}
			}
			_, err = tx.Exec(ctx, `UPDATE audit_schedules SET last_scheduled_for = $2 WHERE id = $1`, x.id, due)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// MatchingClusters returns enrolled clusters whose labels match scope. For
// kube-bench only clusters whose agent advertised the bench capability are
// returned.
func MatchingClusters(ctx context.Context, q store.Querier, scope, tool string) ([]uuid.UUID, error) {
	sc, err := authz.ParseScope(scope)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT id, labels, bench_enabled FROM clusters WHERE status IN ('online','offline') ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var labels map[string]string
		var bench bool
		if err := rows.Scan(&id, &labels, &bench); err != nil {
			return nil, err
		}
		if !sc.Matches(labels) || (tool == ToolKubeBench && !bench) {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- worker

// RunWorker executes queued runs for clusters whose agent is connected to
// this replica. Runs for clusters that are not online anywhere (or that
// waited longer than QueueTimeout) fail with agent_offline.
func (s *Service) RunWorker(ctx context.Context) {
	s.init()
	t := time.NewTicker(s.Poll)
	defer t.Stop()
	for {
		if err := s.Dispatch(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("audit worker", "err", err)
		}
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return
		case <-t.C:
		}
	}
}

// Dispatch claims and starts queued runs (one pass).
func (s *Service) Dispatch(ctx context.Context) error {
	s.init()
	type queued struct {
		id, cluster uuid.UUID
		tool        string
		online      bool
		created     time.Time
		retryUntil  *time.Time
	}
	rows, err := s.DB.Query(ctx, `SELECT r.id, r.cluster_id, r.tool, c.status = 'online', r.created_at, r.retry_until
		FROM audit_runs r JOIN clusters c ON c.id = r.cluster_id WHERE r.status = 'queued' ORDER BY r.created_at LIMIT 100`)
	if err != nil {
		return err
	}
	var list []queued
	for rows.Next() {
		var q queued
		if err := rows.Scan(&q.id, &q.cluster, &q.tool, &q.online, &q.created, &q.retryUntil); err != nil {
			rows.Close()
			return err
		}
		list = append(list, q)
	}
	rows.Close()
	now := s.now()
	for _, q := range list {
		if !s.Gateway.Connected(q.cluster) {
			if q.retryUntil != nil && now.Before(*q.retryUntil) {
				continue // F18: a retry waits for the reconnect
			}
			if !q.online || now.Sub(q.created) > s.QueueTimeout {
				if err := s.settleDisconnected(ctx, q.id, q.tool); err != nil {
					return err
				}
			}
			continue
		}
		if !s.reserve(q.cluster) {
			continue
		}
		tag, err := s.DB.Exec(ctx, `UPDATE audit_runs SET status = 'running', started_at = now() WHERE id = $1 AND status = 'queued'`, q.id)
		if err != nil || tag.RowsAffected() == 0 {
			s.release(q.cluster)
			if err != nil {
				return err
			}
			continue
		}
		s.wg.Add(1)
		go func(id, cluster uuid.UUID) {
			defer s.wg.Done()
			defer s.release(cluster)
			if err := s.Execute(ctx, id); err != nil {
				s.Log.Error("audit run", "run_id", id, "err", err)
			}
		}(q.id, q.cluster)
	}
	return nil
}

// settleDisconnected ends a queued run whose agent is not connected: a new
// attempt waits for the reconnect, or the run is missed (F18).
func (s *Service) settleDisconnected(ctx context.Context, id uuid.UUID, tool string) error {
	var st string
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var reason string
		var err error
		if st, reason, err = disconnectedStatus(ctx, tx, id, s.now()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE audit_runs SET status = $2, error = $3, finished_at = now() WHERE id = $1 AND status = 'queued'`, id, st, reason)
		return err
	})
	if err == nil {
		metrics.AuditRuns.WithLabelValues(tool, st).Inc()
	}
	return err
}

// reserve takes a global slot and the per-cluster slot (one run per cluster
// at a time keeps the agent's tunnel budget for backups).
func (s *Service) reserve(cluster uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clusters[cluster] {
		return false
	}
	select {
	case s.sem <- struct{}{}:
	default:
		return false
	}
	s.clusters[cluster] = true
	return true
}

func (s *Service) release(cluster uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clusters, cluster)
	<-s.sem
}

// Wait blocks until runs started by Dispatch have finished (tests).
func (s *Service) Wait() { s.wg.Wait() }
