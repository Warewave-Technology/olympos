package restore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Claim picks the approved request decided first whose target's agent is
// connected to this replica, whose approval has not expired
// (approved_expires_at) and whose target's cluster has a free per-cluster
// slot (running backup runs and restores together, backup.RunningInCluster),
// and starts it: running, started_at and restore.started in one
// transaction, under the backup claim lock so both claim loops count the
// same slots. It returns uuid.Nil when nothing is claimable. A request
// whose agent stays away is left approved and expires (ExpireDue).
func (x *Executor) Claim(ctx context.Context) (uuid.UUID, error) {
	_, per := x.limits()
	now := x.now()
	var claimed uuid.UUID
	err := store.Tx(ctx, x.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, schedule.LockBackupClaim); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT rr.id, t.cluster_id FROM restore_requests rr JOIN targets t ON t.id = rr.target_id
			WHERE rr.status = 'approved' AND (rr.approved_expires_at IS NULL OR rr.approved_expires_at > $1)
			ORDER BY rr.decided_at, rr.created_at LIMIT 200 FOR UPDATE OF rr SKIP LOCKED`, now)
		if err != nil {
			return err
		}
		type cand struct{ id, cluster uuid.UUID }
		var cands []cand
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.id, &c.cluster); err != nil {
				rows.Close()
				return err
			}
			cands = append(cands, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		full := map[uuid.UUID]bool{}
		for _, c := range cands {
			if full[c.cluster] || !x.Dialer.Connected(c.cluster) {
				continue
			}
			n, err := backup.RunningInCluster(ctx, tx, c.cluster)
			if err != nil {
				return err
			}
			if n >= per {
				full[c.cluster] = true
				continue
			}
			tag, err := tx.Exec(ctx, `UPDATE restore_requests SET status = 'running', started_at = $2 WHERE id = $1 AND status = 'approved'`, c.id, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				continue
			}
			if err := recordStarted(ctx, tx, c.id); err != nil {
				return err
			}
			claimed = c.id
			return nil
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return claimed, nil
}

// recordStarted writes restore.started (audit and event) for a request
// that just became running, on the backup's cluster (where the data comes
// from).
func recordStarted(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	rq, err := loadRequest(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := activity.Record(ctx, tx, activity.Entry{Action: "restore.started", ObjectType: "restore_request", ObjectID: id.String(),
		ClusterID: &rq.Source.ClusterID, Details: map[string]any{"run_id": rq.Source.RunID, "copy_run_id": rq.Source.CopyRunID,
			"target_id": rq.Target.ID, "engine": rq.Engine, "databases": rq.Databases}}); err != nil {
		return err
	}
	return notify.Emit(ctx, tx, notify.Event{Type: notify.RestoreStarted, Key: notify.RestoreStarted + ":" + id.String(),
		Title: "Restore started: " + rq.Target.Namespace + "/" + rq.Target.Service, Link: Link(id), Fields: summary(rq),
		Payload: eventPayload(rq)})
}

// eventPayload is the payload of every restore event: the request, and the
// backup's cluster (events of a restore are scoped to where the data comes
// from, like its audit rows).
func eventPayload(rq *Request) map[string]any {
	return map[string]any{"restore_id": rq.ID, "run_id": rq.Source.RunID, "target_id": rq.Target.ID, "engine": rq.Engine,
		"cluster_id": rq.Source.ClusterID}
}

func (x *Executor) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

func (x *Executor) limits() (global, perCluster int) {
	global, perCluster = x.Global, x.PerCluster
	if global <= 0 {
		global = 2
	}
	if perCluster <= 0 {
		perCluster = 2
	}
	return global, perCluster
}
