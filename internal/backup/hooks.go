package backup

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
)

// Dialer is the part of the gateway the backup module uses
// (*gateway.Gateway implements it; tests use fakes).
type Dialer interface {
	Connected(clusterID uuid.UUID) bool
	Dial(ctx context.Context, clusterID uuid.UUID, targetID string, opt gateway.DialOptions) (gateway.Conn, error)
}

// PausedTargetGone is the paused_reason set when a job's target disappears.
const PausedTargetGone = "target_gone"

// OnTargetGone pauses the target's jobs and emits backup.failed (reason
// target_gone) for each, inside the inventory transaction (SPEC §5).
func OnTargetGone(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, targetID string) error {
	rows, err := tx.Query(ctx, `UPDATE backup_jobs j SET paused_reason = $2
		FROM targets t WHERE t.id = j.target_id AND j.target_id = $1 AND j.deleted_at IS NULL AND j.paused_reason = ''
		RETURNING j.id, j.notify_channel_id, t.namespace, t.service`, targetID, PausedTargetGone)
	if err != nil {
		return err
	}
	type paused struct {
		id      uuid.UUID
		channel *uuid.UUID
		ns, svc string
	}
	var ps []paused
	for rows.Next() {
		var p paused
		if err := rows.Scan(&p.id, &p.channel, &p.ns, &p.svc); err != nil {
			rows.Close()
			return err
		}
		ps = append(ps, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var cluster string
	if len(ps) > 0 {
		_ = tx.QueryRow(ctx, `SELECT name FROM clusters WHERE id = $1`, clusterID).Scan(&cluster)
	}
	for _, p := range ps {
		if err := notify.Emit(ctx, tx, notify.Event{
			Type: notify.BackupFailed, ChannelID: p.channel,
			Title:   fmt.Sprintf("Backup paused: target %s/%s is gone", p.ns, p.svc),
			Link:    "/backups?job=" + p.id.String(),
			Fields:  map[string]string{"cluster": cluster, "target": p.ns + "/" + p.svc, "reason": PausedTargetGone},
			Payload: map[string]any{"job_id": p.id.String(), "reason": PausedTargetGone},
		}); err != nil {
			return err
		}
		cid := clusterID
		if err := activity.Record(ctx, tx, activity.Entry{Action: "backup.job.paused", ObjectType: "backup_job", ObjectID: p.id.String(),
			ClusterID: &cid, Details: map[string]any{"reason": PausedTargetGone}}); err != nil {
			return err
		}
	}
	return nil
}

// OnTargetUpsert unpauses jobs whose target reappeared. The schedule restarts
// from now: the time the target was gone is not reported as missed (the
// target_gone event already covered it).
func OnTargetUpsert(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, t *pb.Target) error {
	rows, err := tx.Query(ctx, `UPDATE backup_jobs SET paused_reason = '', last_scheduled_for = now()
		WHERE target_id = $1 AND deleted_at IS NULL AND paused_reason = $2 RETURNING id`, t.TargetId, PausedTargetGone)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		cid := clusterID
		if err := activity.Record(ctx, tx, activity.Entry{Action: "backup.job.resumed", ObjectType: "backup_job", ObjectID: id.String(),
			ClusterID: &cid, Details: map[string]any{"reason": "target_back"}}); err != nil {
			return err
		}
	}
	// Soft-deleted jobs must not keep a reappearing target "configured".
	_, err = tx.Exec(ctx, `UPDATE targets SET status = 'candidate' WHERE id = $1 AND status = 'configured'
		AND NOT EXISTS (SELECT 1 FROM backup_jobs j WHERE j.target_id = targets.id AND j.deleted_at IS NULL)
		AND NOT EXISTS (SELECT 1 FROM vaults v WHERE v.target_id = targets.id AND v.status = 'configured')`, t.TargetId)
	return err
}
