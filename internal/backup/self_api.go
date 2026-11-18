package backup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// SelfView answers GET /backup/self.
type SelfView struct {
	// Configured is false until an admin chose a destination: the
	// Dashboard keeps "Needs attention" until then.
	Configured bool     `json:"configured"`
	Job        *SelfJob `json:"job"`
	Runs       []*Run   `json:"runs"`
}

type selfInput struct {
	DestinationID   *uuid.UUID `json:"destination_id"`
	Cron            *string    `json:"cron"`
	Timezone        *string    `json:"timezone"`
	Retention       *Retention `json:"retention"`
	Enabled         *bool      `json:"enabled"`
	NotifyChannelID optUUID    `json:"notify_channel_id"`
}

// DefaultSelfCron: daily at 02:30 (job time zone).
const DefaultSelfCron = "30 2 * * *"

func (a *API) getSelf(w http.ResponseWriter, r *http.Request) {
	if !httpx.Subject(r).CanGlobal(authz.PermRead) {
		httpx.NotFound(w)
		return
	}
	v, err := LoadSelfView(r.Context(), a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// LoadSelfView is the GET /backup/self body.
func LoadSelfView(ctx context.Context, q store.Querier) (*SelfView, error) {
	v := &SelfView{Runs: []*Run{}}
	j, err := LoadSelfJob(ctx, q)
	if errors.Is(err, store.ErrNotFound) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	v.Configured, v.Job = true, j
	rows, err := q.Query(ctx, `SELECT id, job_id, trigger, status, scheduled_for, tier, started_at, finished_at, bytes, wire_bytes,
		blob_path, sha256, error, created_at, attempt FROM backup_runs WHERE job_id = $1 ORDER BY created_at DESC LIMIT 20`, j.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		run := &Run{TargetService: selfService, ClusterName: selfCluster, Engine: "postgresql"}
		if err := rows.Scan(&run.ID, &run.JobID, &run.Trigger, &run.Status, &run.ScheduledFor, &run.Tier, &run.StartedAt, &run.FinishedAt,
			&run.Bytes, &run.WireBytes, &run.BlobPath, &run.SHA256, &run.Error, &run.CreatedAt, &run.Attempt); err != nil {
			return nil, err
		}
		v.Runs = append(v.Runs, run)
	}
	return v, rows.Err()
}

// putSelf creates or updates the olympos-self job (admin). There is no
// delete: the job is built in.
func (a *API) putSelf(w http.ResponseWriter, r *http.Request) {
	sub := httpx.Subject(r)
	if !sub.CanGlobal(authz.PermAdmin) {
		httpx.Error(w, http.StatusForbidden, "only admins configure the Olympos self-backup")
		return
	}
	var in selfInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	cur, err := LoadSelfJob(ctx, a.DB)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	j := SelfJob{Cron: DefaultSelfCron, Timezone: "UTC", Retention: DefaultRetention, Enabled: true}
	if cur != nil {
		j = *cur
	}
	if in.DestinationID != nil {
		j.DestinationID = *in.DestinationID
	}
	if in.Cron != nil {
		j.Cron = *in.Cron
	}
	if in.Timezone != nil {
		j.Timezone = *in.Timezone
	}
	if in.Retention != nil {
		j.Retention = *in.Retention
	}
	if in.Enabled != nil {
		j.Enabled = *in.Enabled
	}
	if in.NotifyChannelID.Set {
		j.NotifyChannelID = in.NotifyChannelID.V
	}
	errs := map[string]string{}
	if j.DestinationID == uuid.Nil {
		errs["destination_id"] = "Choose where the Olympos database is backed up."
	} else {
		var ok bool
		if err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM destinations WHERE id = $1)`, j.DestinationID).Scan(&ok); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		} else if !ok {
			errs["destination_id"] = "Unknown destination."
		}
	}
	if _, err := schedule.Parse(j.Cron, j.Timezone); err != nil {
		errs["cron"] = err.Error()
	}
	if !validRetention(j.Retention) {
		errs["retention"] = "Out of range."
	}
	if len(errs) > 0 {
		httpx.FieldErrors(w, "invalid self-backup", errs)
		return
	}
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		ret, _ := json.Marshal(j.Retention)
		if cur == nil {
			if err := tx.QueryRow(ctx, `INSERT INTO backup_jobs (system, destination_id, cron, timezone, retention, enabled, notify_channel_id,
				created_by, last_scheduled_for) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now()) RETURNING id`,
				SelfSystem, j.DestinationID, j.Cron, j.Timezone, ret, j.Enabled, j.NotifyChannelID, sub.Principal.ID).Scan(&j.ID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `UPDATE backup_jobs SET destination_id = $2, cron = $3, timezone = $4, retention = $5, enabled = $6,
			notify_channel_id = $7, updated_at = now() WHERE id = $1`, j.ID, j.DestinationID, j.Cron, j.Timezone, ret, j.Enabled, j.NotifyChannelID); err != nil {
			return err
		}
		action := "backup.self_updated"
		if cur == nil {
			action = "backup.self_configured"
		}
		return httpx.Record(r, tx, action, "backup_job", j.ID.String(), nil,
			map[string]any{"destination_id": j.DestinationID, "cron": j.Cron, "timezone": j.Timezone, "enabled": j.Enabled})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	v, err := LoadSelfView(ctx, a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *API) runSelf(w http.ResponseWriter, r *http.Request) {
	sub := httpx.Subject(r)
	if !sub.CanGlobal(authz.PermOperate) {
		httpx.Error(w, http.StatusForbidden, "your role does not allow running backups")
		return
	}
	ctx := r.Context()
	j, err := LoadSelfJob(ctx, a.DB)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusConflict, "choose a destination for the Olympos self-backup first")
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var id uuid.UUID
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		var busy bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_runs WHERE job_id = $1 AND status IN ('queued','running'))`, j.ID).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return errBusy
		}
		var err error
		if id, err = QueueSelfRun(ctx, tx, j.ID); err != nil {
			return err
		}
		return httpx.Record(r, tx, "backup.run_requested", "backup_job", j.ID.String(), nil, map[string]any{"run_id": id, "system": SelfSystem})
	})
	if errors.Is(err, errBusy) {
		httpx.Error(w, http.StatusConflict, "a run of this job is already queued or running")
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"run_id": id})
}
