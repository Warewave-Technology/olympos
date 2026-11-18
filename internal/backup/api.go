package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/findings"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /api/v1/backup/* (SPEC §10, §16).
type API struct {
	DB     *store.DB
	Log    *slog.Logger
	Dialer Dialer
	Creds  *Credentials
	Now    func() time.Time
	// TestTimeout bounds a connection test (default 60 s).
	TestTimeout time.Duration
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Get("/backup/jobs", a.listJobs)
	r.Post("/backup/jobs", a.createJob)
	r.Get("/backup/jobs/{id}", a.getJob)
	r.Patch("/backup/jobs/{id}", a.patchJob)
	r.Delete("/backup/jobs/{id}", a.deleteJob)
	r.Post("/backup/jobs/{id}/run", a.runJob)
	r.Get("/backup/runs", a.listRuns)
	r.Get("/backup/runs/{id}", a.getRun)
	r.Post("/backup/test-connection", a.testConnection)
	r.Get("/backup/schedule-preview", a.schedulePreview)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// optUUID distinguishes an absent field from an explicit null in PATCH.
type optUUID struct {
	Set bool
	V   *uuid.UUID
}

func (o *optUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.V = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		o.V = nil
		return nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return err
	}
	o.V = &u
	return nil
}

// JobInput is BackupJobInput (all fields optional for PATCH).
type JobInput struct {
	TargetID        *string          `json:"target_id"`
	Credential      *CredentialInput `json:"credential"`
	DestinationID   *uuid.UUID       `json:"destination_id"`
	EngineOptions   json.RawMessage  `json:"engine_options"`
	Cron            *string          `json:"cron"`
	Timezone        *string          `json:"timezone"`
	Retention       *Retention       `json:"retention"`
	Enabled         *bool            `json:"enabled"`
	NotifyChannelID optUUID          `json:"notify_channel_id"`
}

// needsCredential reports whether jobs for engine need a user credential
// (engines with a registered CredentialProvider, e.g. Vault, do not).
func needsCredential(engine string) bool {
	_, ok := CredentialProviderFor(engine)
	return !ok
}

func validOptions(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var m map[string]any
	return json.Unmarshal(raw, &m) == nil
}

func validRetention(r Retention) bool {
	return r.Daily >= 0 && r.Weekly >= 0 && r.Monthly >= 0 && r.Daily <= 3660 && r.Weekly <= 520 && r.Monthly <= 1200
}

// targetScope loads a target's cluster and checks p. Returns found=false
// when the target is missing or outside the caller's scope.
func (a *API) targetScope(ctx context.Context, s *authz.Subject, targetID string, p authz.Permission) (clusterID uuid.UUID, status, engine string, found, allowed bool, err error) {
	err = a.DB.QueryRow(ctx, `SELECT t.cluster_id, t.status, t.engine FROM targets t JOIN clusters c ON c.id = t.cluster_id
		WHERE t.id = $1 AND c.status <> 'revoked'`, targetID).Scan(&clusterID, &status, &engine)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", "", false, false, nil
	}
	if err != nil {
		return
	}
	allowed, visible, err := httpx.CanCluster(ctx, a.DB, s, clusterID, p)
	return clusterID, status, engine, visible, allowed, err
}

func (a *API) checkRefs(ctx context.Context, in *JobInput, fields map[string]string) error {
	if in.DestinationID != nil {
		var ok bool
		if err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM destinations WHERE id = $1)`, *in.DestinationID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			fields["destination_id"] = "unknown destination"
		}
	}
	if in.NotifyChannelID.V != nil {
		var ok bool
		if err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_channels WHERE id = $1)`, *in.NotifyChannelID.V).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			fields["notify_channel_id"] = "unknown channel"
		}
	}
	return nil
}

func (a *API) writeJob(w http.ResponseWriter, r *http.Request, code int, id uuid.UUID) {
	j, err := LoadJob(r.Context(), a.DB, id)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	v, err := j.View(r.Context(), a.DB, a.Creds, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, code, v)
}

func (a *API) listJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	where := ` AND t.cluster_id = ANY($1)`
	args := []any{ids}
	if tid := r.URL.Query().Get("target_id"); tid != "" {
		where += ` AND j.target_id = $2`
		args = append(args, tid)
	}
	jobs, err := listJobs(ctx, a.DB, where, args...)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	out := []*JobView{}
	now := a.now()
	for _, j := range jobs {
		v, err := j.View(ctx, a.DB, a.Creds, now)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		out = append(out, v)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

// loadScopedJob loads a job and checks p on its cluster, writing 404/403.
func (a *API) loadScopedJob(w http.ResponseWriter, r *http.Request, p authz.Permission) (*Job, bool) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	j, err := LoadJob(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return nil, false
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return nil, false
	}
	s := httpx.Subject(r)
	if !s.Can(authz.PermRead, j.ClusterLabels) {
		httpx.NotFound(w)
		return nil, false
	}
	if !s.Can(p, j.ClusterLabels) {
		httpx.Forbidden(w, "")
		return nil, false
	}
	return j, true
}

func (a *API) getJob(w http.ResponseWriter, r *http.Request) {
	j, ok := a.loadScopedJob(w, r, authz.PermRead)
	if !ok {
		return
	}
	v, err := j.View(r.Context(), a.DB, a.Creds, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *API) createJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in JobInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	fields := map[string]string{}
	if in.TargetID == nil || *in.TargetID == "" {
		fields["target_id"] = "required"
		httpx.FieldErrors(w, "invalid job", fields)
		return
	}
	clusterID, tstatus, engine, found, allowed, err := a.targetScope(ctx, httpx.Subject(r), *in.TargetID, authz.PermOperate)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !found {
		httpx.NotFound(w)
		return
	}
	if !allowed {
		httpx.Forbidden(w, "")
		return
	}
	if tstatus == "gone" {
		fields["target_id"] = "target is gone"
	}
	if engine == "" {
		fields["target_id"] = "target has no backup engine annotation"
	}
	if in.DestinationID == nil {
		fields["destination_id"] = "required"
	}
	cron, tz := "", "UTC"
	if in.Cron != nil {
		cron = *in.Cron
	}
	if in.Timezone != nil && *in.Timezone != "" {
		tz = *in.Timezone
	}
	if cron == "" {
		fields["cron"] = "required"
	} else if _, err := schedule.Parse(cron, tz); err != nil {
		if strings.Contains(err.Error(), "time zone") {
			fields["timezone"] = err.Error()
		} else {
			fields["cron"] = err.Error()
		}
	}
	if in.Credential != nil {
		for k, v := range in.Credential.Validate("credential.") {
			fields[k] = v
		}
	} else if engine != "" && needsCredential(engine) {
		fields["credential"] = "required"
	}
	if !validOptions(in.EngineOptions) {
		fields["engine_options"] = "must be an object"
	}
	ret := DefaultRetention
	if in.Retention != nil {
		ret = *in.Retention
		if !validRetention(ret) {
			fields["retention"] = "invalid counts"
		}
	}
	if err := a.checkRefs(ctx, &in, fields); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid job", fields)
		return
	}
	opts := in.EngineOptions
	if len(opts) == 0 {
		opts = json.RawMessage(`{}`)
	}
	enabled := in.Enabled != nil && *in.Enabled
	retB, _ := json.Marshal(ret)
	var id uuid.UUID
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		var credID *uuid.UUID
		if in.Credential != nil {
			cid, err := a.Creds.Insert(ctx, tx, *in.Credential)
			if err != nil {
				return err
			}
			credID = &cid
		}
		if err := tx.QueryRow(ctx, `INSERT INTO backup_jobs (target_id, credential_id, destination_id, engine_options, cron, timezone,
			retention, enabled, notify_channel_id, created_by, last_scheduled_for)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, CASE WHEN $8 THEN now() END) RETURNING id`,
			*in.TargetID, credID, *in.DestinationID, opts, cron, tz, retB, enabled, in.NotifyChannelID.V, httpx.ActorID(r)).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET status = 'configured' WHERE id = $1 AND status = 'candidate'`, *in.TargetID); err != nil {
			return err
		}
		details := map[string]any{"target_id": *in.TargetID, "destination_id": in.DestinationID.String(), "cron": cron,
			"timezone": tz, "enabled": enabled}
		if in.Credential != nil {
			details["credential_source"] = in.Credential.Source
		}
		return httpx.Record(r, tx, "backup.job.created", "backup_job", id.String(), &clusterID, details)
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.writeJob(w, r, http.StatusCreated, id)
}

func (a *API) patchJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	j, ok := a.loadScopedJob(w, r, authz.PermOperate)
	if !ok {
		return
	}
	var in JobInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	fields := map[string]string{}
	var changed []string
	if in.TargetID != nil && *in.TargetID != j.Target.ID {
		fields["target_id"] = "cannot be changed; create a new job"
	}
	dest := j.DestinationID
	if in.DestinationID != nil && *in.DestinationID != dest {
		dest = *in.DestinationID
		changed = append(changed, "destination_id")
	}
	cron, tz := j.Cron, j.Timezone
	if in.Cron != nil && *in.Cron != cron {
		cron = *in.Cron
		changed = append(changed, "cron")
	}
	if in.Timezone != nil && *in.Timezone != tz {
		tz = *in.Timezone
		if tz == "" {
			tz = "UTC"
		}
		changed = append(changed, "timezone")
	}
	if _, err := schedule.Parse(cron, tz); err != nil {
		if strings.Contains(err.Error(), "time zone") {
			fields["timezone"] = err.Error()
		} else {
			fields["cron"] = err.Error()
		}
	}
	opts := j.EngineOptions
	if len(in.EngineOptions) > 0 {
		if !validOptions(in.EngineOptions) {
			fields["engine_options"] = "must be an object"
		}
		opts = in.EngineOptions
		changed = append(changed, "engine_options")
	}
	ret := j.Retention
	if in.Retention != nil {
		ret = *in.Retention
		if !validRetention(ret) {
			fields["retention"] = "invalid counts"
		}
		changed = append(changed, "retention")
	}
	enabled := j.Enabled
	if in.Enabled != nil && *in.Enabled != enabled {
		enabled = *in.Enabled
		changed = append(changed, "enabled")
	}
	notifyCh := j.NotifyChannelID
	if in.NotifyChannelID.Set {
		notifyCh = in.NotifyChannelID.V
		changed = append(changed, "notify_channel_id")
	}
	if in.Credential != nil {
		for k, v := range in.Credential.Validate("credential.") {
			fields[k] = v
		}
		changed = append(changed, "credential")
	}
	if err := a.checkRefs(ctx, &in, fields); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid job", fields)
		return
	}
	// Restart the schedule from now when it is (re)enabled or changed, so
	// time while disabled is not reported as missed.
	resetSchedule := enabled && (!j.Enabled || cron != j.Cron || tz != j.Timezone)
	retB, _ := json.Marshal(ret)
	clusterID := j.Target.ClusterID
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		credID := j.CredentialID
		if in.Credential != nil {
			cid, err := a.Creds.Insert(ctx, tx, *in.Credential)
			if err != nil {
				return err
			}
			credID = &cid
		}
		if _, err := tx.Exec(ctx, `UPDATE backup_jobs SET credential_id = $2, destination_id = $3, engine_options = $4, cron = $5,
			timezone = $6, retention = $7, enabled = $8, notify_channel_id = $9,
			last_scheduled_for = CASE WHEN $10 THEN now() ELSE last_scheduled_for END WHERE id = $1`,
			j.ID, credID, dest, opts, cron, tz, retB, enabled, notifyCh, resetSchedule); err != nil {
			return err
		}
		if in.Credential != nil && j.CredentialID != nil {
			if err := a.Creds.Delete(ctx, tx, *j.CredentialID); err != nil {
				return err
			}
		}
		details := map[string]any{"changed": changed}
		if in.Credential != nil {
			details["credential_source"] = in.Credential.Source
		}
		return httpx.Record(r, tx, "backup.job.updated", "backup_job", j.ID.String(), &clusterID, details)
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.writeJob(w, r, http.StatusOK, j.ID)
}

func (a *API) deleteJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	j, ok := a.loadScopedJob(w, r, authz.PermOperate)
	if !ok {
		return
	}
	clusterID := j.Target.ClusterID
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE backup_jobs SET deleted_at = now(), enabled = false, credential_id = NULL WHERE id = $1`, j.ID); err != nil {
			return err
		}
		if j.CredentialID != nil {
			if err := a.Creds.Delete(ctx, tx, *j.CredentialID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE backup_runs SET status = 'failed', error = 'job deleted', finished_at = now()
			WHERE job_id = $1 AND status = 'queued'`, j.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE targets SET status = 'candidate' WHERE id = $1 AND status = 'configured'
			AND NOT EXISTS (SELECT 1 FROM backup_jobs x WHERE x.target_id = targets.id AND x.deleted_at IS NULL)
			AND NOT EXISTS (SELECT 1 FROM vaults v WHERE v.target_id = targets.id AND v.status = 'configured')`, j.Target.ID); err != nil {
			return err
		}
		return httpx.Record(r, tx, "backup.job.deleted", "backup_job", j.ID.String(), &clusterID,
			map[string]any{"target_id": j.Target.ID})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) runJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	j, ok := a.loadScopedJob(w, r, authz.PermOperate)
	if !ok {
		return
	}
	var in struct {
		Trigger string `json:"trigger"`
	}
	if r.ContentLength != 0 {
		if err := httpx.Decode(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if in.Trigger == "" {
		in.Trigger = "manual"
	}
	if in.Trigger != "manual" && in.Trigger != "test" {
		httpx.FieldErrors(w, "invalid trigger", map[string]string{"trigger": "must be manual or test"})
		return
	}
	if j.Target.Status == "gone" {
		httpx.Error(w, http.StatusConflict, "target is gone")
		return
	}
	var runID uuid.UUID
	clusterID := j.Target.ClusterID
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		// Serialize run requests per job.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM backup_jobs WHERE id = $1 FOR UPDATE`, j.ID); err != nil {
			return err
		}
		var busy bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_runs WHERE job_id = $1 AND status IN ('queued','running'))`, j.ID).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return errBusy
		}
		if err := tx.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, triggered_by) VALUES ($1, $2, 'queued', $3) RETURNING id`,
			j.ID, in.Trigger, httpx.ActorID(r)).Scan(&runID); err != nil {
			return err
		}
		return httpx.Record(r, tx, "backup.run.requested", "backup_run", runID.String(), &clusterID,
			map[string]any{"job_id": j.ID.String(), "trigger": in.Trigger})
	})
	if errors.Is(err, errBusy) {
		httpx.Error(w, http.StatusConflict, "a run of this job is already queued or running")
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	run, err := LoadRun(ctx, a.DB, runID)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, run)
}

var errBusy = errors.New("busy")

func (a *API) listRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	q := r.URL.Query()
	var jobID *uuid.UUID
	if s := q.Get("job_id"); s != "" {
		u, err := uuid.Parse(s)
		if err != nil {
			httpx.FieldErrors(w, "invalid filter", map[string]string{"job_id": "must be a uuid"})
			return
		}
		jobID = &u
	}
	limit := httpx.IntQuery(r, "limit", 50)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := a.DB.Query(ctx, runSelect+` WHERE c.id = ANY($1) AND ($2::uuid IS NULL OR r.job_id = $2) AND ($3 = '' OR r.status = $3)
		ORDER BY r.created_at DESC LIMIT $4`, ids, jobID, q.Get("status"), limit)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	out := []*Run{}
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *API) getRun(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	run, err := LoadRun(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !httpx.Subject(r).Can(authz.PermRead, run.clusterLabels) {
		httpx.NotFound(w)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// TestConnectionInput is the body of POST /backup/test-connection.
type TestConnectionInput struct {
	TargetID      string           `json:"target_id"`
	Credential    *CredentialInput `json:"credential"`
	CredentialID  *uuid.UUID       `json:"credential_id"`
	EngineOptions json.RawMessage  `json:"engine_options"`
}

func (a *API) testConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in TestConnectionInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.TargetID == "" {
		httpx.FieldErrors(w, "invalid request", map[string]string{"target_id": "required"})
		return
	}
	clusterID, tstatus, engineName, found, allowed, err := a.targetScope(ctx, httpx.Subject(r), in.TargetID, authz.PermOperate)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !found {
		httpx.NotFound(w)
		return
	}
	if !allowed {
		httpx.Forbidden(w, "")
		return
	}
	fields := map[string]string{}
	eng, ok := EngineFor(engineName)
	if !ok {
		fields["target_id"] = fmt.Sprintf("no backup engine for %q", engineName)
	}
	if tstatus == "gone" {
		fields["target_id"] = "target is gone"
	}
	if in.Credential != nil {
		for k, v := range in.Credential.Validate("credential.") {
			fields[k] = v
		}
	} else if in.CredentialID != nil {
		// Only a credential already used for this very target may be
		// reused: it must never be sent to a different target.
		var ok bool
		if err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_jobs WHERE credential_id = $1 AND target_id = $2 AND deleted_at IS NULL)`,
			*in.CredentialID, in.TargetID).Scan(&ok); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if !ok {
			fields["credential_id"] = "unknown credential for this target"
		}
	} else if needsCredential(engineName) {
		fields["credential"] = "required"
	}
	if !validOptions(in.EngineOptions) {
		fields["engine_options"] = "must be an object"
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid request", fields)
		return
	}
	t, err := loadTargetInfo(ctx, a.DB, in.TargetID)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	tr := &secretTracker{}
	defer tr.zero()
	credFn := func(ctx context.Context) (Credential, error) {
		switch {
		case in.Credential != nil:
			c, err := a.Creds.FromInput(ctx, *in.Credential)
			return tr.track(c), err
		case in.CredentialID != nil:
			c, err := a.Creds.Resolve(ctx, a.DB, *in.CredentialID)
			return tr.track(c), err
		}
		p, ok := CredentialProviderFor(engineName)
		if !ok {
			return Credential{}, errors.New("no credential configured")
		}
		c, err := p(ctx, t.info)
		return tr.track(c), err
	}
	timeout := a.TestTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	opts := in.EngineOptions
	if len(opts) == 0 {
		opts = json.RawMessage(`{}`)
	}
	ec, _ := newEngineContext(a.Dialer, t, opts, credFn, false)
	var ct *ConnectionTest
	if !a.Dialer.Connected(clusterID) {
		ct = &ConnectionTest{Error: "agent_offline: the cluster's agent is not connected to this server"}
	} else {
		ct, err = eng.TestConnection(tctx, ec)
		if err != nil {
			if ct == nil {
				ct = &ConnectionTest{}
			}
			ct.OK = false
			if ct.Error == "" {
				ct.Error = err.Error()
			}
		}
	}
	ct.Error = tr.scrub(ct.Error)
	for i := range ct.Privileges {
		ct.Privileges[i].Detail = tr.scrub(ct.Privileges[i].Detail)
	}
	if ct.Privileges == nil {
		ct.Privileges = []Privilege{}
	}
	if ct.Databases == nil {
		ct.Databases = []string{}
	}
	reached := ct.OK || ct.ServerVersion != "" || ct.TLS
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		if reached {
			if err := recordTargetTLS(ctx, tx, t, ct.ServerVersion, ct.TLS); err != nil {
				return err
			}
		}
		return httpx.Record(r, tx, "backup.connection_tested", "target", in.TargetID, &clusterID,
			map[string]any{"ok": ct.OK, "tls": ct.TLS, "server_version": ct.ServerVersion})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ct)
}

// tlsFindingControl is the finding control for targets without TLS.
const tlsFindingControl = "tls.missing"

// recordTargetTLS stores detected version/TLS and opens or resolves the
// tls.missing finding (SPEC §13.4).
func recordTargetTLS(ctx context.Context, q store.Querier, t *targetRow, version string, tlsOK bool) error {
	if _, err := q.Exec(ctx, `UPDATE targets SET detected_version = CASE WHEN $2 = '' THEN detected_version ELSE $2 END, tls_ok = $3 WHERE id = $1`,
		t.info.ID, version, tlsOK); err != nil {
		return err
	}
	ref := fmt.Sprintf("%s/%s:%d", t.info.Namespace, t.info.Service, t.info.Port)
	if tlsOK {
		_, err := findings.Resolve(ctx, q, findings.SourceTLS, t.clusterID, tlsFindingControl, ref, nil)
		return err
	}
	_, err := findings.Open(ctx, q, findings.Finding{
		Source: findings.SourceTLS, ClusterID: t.clusterID, ControlID: tlsFindingControl, Severity: "medium", ResourceRef: ref,
		Title:   fmt.Sprintf("Target %s/%s does not speak TLS", t.info.Namespace, t.info.Service),
		Details: map[string]any{"target_id": t.info.ID, "engine": t.info.Engine},
	}, nil)
	return err
}

// targetRow is a target with the cluster fields engines need.
type targetRow struct {
	info         TargetInfo
	clusterID    uuid.UUID
	transferMode string
	status       string
}

func loadTargetInfo(ctx context.Context, q store.Querier, id string) (*targetRow, error) {
	var t targetRow
	var port int
	err := q.QueryRow(ctx, `SELECT t.id, t.cluster_id, c.name, t.namespace, t.service, t.port, t.engine, t.vault_provider, t.tls_server_name,
		c.transfer_mode, c.status FROM targets t JOIN clusters c ON c.id = t.cluster_id WHERE t.id = $1`, id).
		Scan(&t.info.ID, &t.clusterID, &t.info.ClusterName, &t.info.Namespace, &t.info.Service, &port, &t.info.Engine,
			&t.info.VaultProvider, &t.info.TLSServerName, &t.transferMode, &t.status)
	if err != nil {
		return nil, store.NotFound(err)
	}
	t.info.Port = port
	t.info.ClusterID = t.clusterID.String()
	if t.info.TLSServerName == "" {
		t.info.TLSServerName = t.info.Service + "." + t.info.Namespace + ".svc"
	}
	return &t, nil
}

// wireCounter sums WireBytes over every tunnel an engine opened.
type wireCounter struct {
	mu    sync.Mutex
	conns []gateway.Conn
}

func (wc *wireCounter) add(c gateway.Conn) {
	wc.mu.Lock()
	wc.conns = append(wc.conns, c)
	wc.mu.Unlock()
}

func (wc *wireCounter) total() int64 {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	var n int64
	for _, c := range wc.conns {
		n += c.WireBytes()
	}
	return n
}

// newEngineContext builds the EngineContext for a target: Dial goes through
// the agent tunnel with the cluster's transfer mode.
func newEngineContext(d Dialer, t *targetRow, opts json.RawMessage, cred func(ctx context.Context) (Credential, error), test bool) (EngineContext, *wireCounter) {
	wc := &wireCounter{}
	compressed := t.transferMode == "compressed"
	ec := EngineContext{
		Target:        t.info,
		UseTLS:        t.transferMode != "compressed",
		TLSServerName: t.info.TLSServerName,
		Credential:    cred,
		Options:       opts,
		Test:          test,
		Dial: func(ctx context.Context) (net.Conn, error) {
			c, err := d.Dial(ctx, t.clusterID, t.info.ID, gateway.DialOptions{Compressed: compressed})
			if err != nil {
				return nil, err
			}
			wc.add(c)
			return c, nil
		},
	}
	return ec, wc
}

// schedulePreview answers GET /backup/schedule-preview.
func (a *API) schedulePreview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tz := q.Get("timezone")
	if tz == "" {
		tz = "UTC"
	}
	spec, err := schedule.Parse(q.Get("cron"), tz)
	if err != nil {
		field := "cron"
		if strings.Contains(err.Error(), "time zone") {
			field = "timezone"
		}
		httpx.FieldErrors(w, err.Error(), map[string]string{field: err.Error()})
		return
	}
	n := httpx.IntQuery(r, "count", 5)
	if n <= 0 || n > 50 {
		n = 5
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"next": spec.NextN(a.now(), n), "description": Describe(spec.Expr, tz)})
}
