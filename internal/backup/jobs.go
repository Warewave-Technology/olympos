package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Retention is the GFS retention (enforced by Blob lifecycle rules, not by
// the server; stored for rendering the rules and the UI).
type Retention struct {
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// DefaultRetention matches the column default.
var DefaultRetention = Retention{Daily: 7, Weekly: 4, Monthly: 12}

// Job is a backup_jobs row joined with its target, cluster and destination
// (or destination group).
type Job struct {
	ID              uuid.UUID
	Target          inventory.Target
	ClusterLabels   map[string]string
	ClusterStatus   string
	TransferMode    string
	EgressRatePerGB *float64
	CredentialID    *uuid.UUID
	// Exactly one of DestinationID and DestinationGroupID is set;
	// DestinationName is the destination's or the group's name.
	DestinationID      *uuid.UUID
	DestinationGroupID *uuid.UUID
	DestinationName    string
	EngineOptions      json.RawMessage
	Cron               string
	Timezone           string
	Retention          Retention
	Enabled            bool
	PausedReason       string
	NotifyChannelID    *uuid.UUID
	NotifyOnSuccess    bool
	LastScheduledFor   *time.Time
	CreatedAt          time.Time
}

// TargetInfo converts the job's target for engines.
func (j *Job) TargetInfo() TargetInfo {
	t := j.Target
	name := t.TLSServerName
	if name == "" {
		name = t.Service + "." + t.Namespace + ".svc"
	}
	return TargetInfo{ID: t.ID, ClusterID: t.ClusterID.String(), ClusterName: t.ClusterName, Namespace: t.Namespace,
		Service: t.Service, Port: t.Port, Engine: t.Engine, VaultProvider: t.VaultProvider, TLSServerName: name}
}

const jobSelectBase = `SELECT j.id, j.credential_id, j.destination_id, j.destination_group_id, COALESCE(d.name, g.name, ''),
	j.engine_options, j.cron, j.timezone, j.retention, j.enabled, j.paused_reason, j.notify_channel_id, j.notify_on_success, j.last_scheduled_for, j.created_at,
	t.id, t.cluster_id, c.name, c.labels, c.status, c.transfer_mode, c.egress_rate_per_gb::float8, t.namespace, t.service, t.port,
	t.port_name, t.engine, t.vault_provider, t.tls_server_name, t.detected_version, t.tls_ok, t.status, t.first_seen_at, t.last_seen_at
	FROM backup_jobs j JOIN targets t ON t.id = j.target_id JOIN clusters c ON c.id = t.cluster_id
	LEFT JOIN destinations d ON d.id = j.destination_id LEFT JOIN destination_groups g ON g.id = j.destination_group_id`

const jobSelect = jobSelectBase + ` WHERE j.deleted_at IS NULL`

func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	var ret []byte
	t := &j.Target
	if err := row.Scan(&j.ID, &j.CredentialID, &j.DestinationID, &j.DestinationGroupID, &j.DestinationName,
		&j.EngineOptions, &j.Cron, &j.Timezone, &ret, &j.Enabled, &j.PausedReason, &j.NotifyChannelID, &j.NotifyOnSuccess, &j.LastScheduledFor, &j.CreatedAt,
		&t.ID, &t.ClusterID, &t.ClusterName, &j.ClusterLabels, &j.ClusterStatus, &j.TransferMode, &j.EgressRatePerGB,
		&t.Namespace, &t.Service, &t.Port, &t.PortName, &t.Engine, &t.VaultProvider, &t.TLSServerName, &t.DetectedVersion,
		&t.TLSOK, &t.Status, &t.FirstSeenAt, &t.LastSeenAt); err != nil {
		return nil, err
	}
	j.Retention = DefaultRetention
	_ = json.Unmarshal(ret, &j.Retention)
	if len(j.EngineOptions) == 0 {
		j.EngineOptions = json.RawMessage(`{}`)
	}
	return &j, nil
}

// LoadJob loads a live (not deleted) job.
func LoadJob(ctx context.Context, q store.Querier, id uuid.UUID) (*Job, error) {
	j, err := scanJob(q.QueryRow(ctx, jobSelect+` AND j.id = $1`, id))
	return j, store.NotFound(err)
}

func listJobs(ctx context.Context, q store.Querier, where string, args ...any) ([]*Job, error) {
	rows, err := q.Query(ctx, jobSelect+where+` ORDER BY c.name, t.namespace, t.service, j.created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Run is the API shape of a backup run.
type Run struct {
	ID            uuid.UUID  `json:"id"`
	JobID         uuid.UUID  `json:"job_id"`
	TargetService string     `json:"target_service"`
	ClusterName   string     `json:"cluster_name"`
	Engine        string     `json:"engine"`
	Trigger       string     `json:"trigger"`
	Status        string     `json:"status"`
	ScheduledFor  *time.Time `json:"scheduled_for"`
	Tier          string     `json:"tier"`
	StartedAt     *time.Time `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	Bytes         int64      `json:"bytes"`
	WireBytes     int64      `json:"wire_bytes"`
	BlobPath      string     `json:"blob_path"`
	SHA256        string     `json:"sha256"`
	Error         string     `json:"error"`
	CreatedAt     time.Time  `json:"created_at"`
	// Attempt > 1: a retry after the agent reconnected (F18).
	Attempt int `json:"attempt"`
	// Steps: dry-run checklist (F10); empty for other runs.
	Steps []Step `json:"steps"`

	clusterID     uuid.UUID
	clusterLabels map[string]string
}

const runSelect = `SELECT r.id, r.job_id, t.service, c.name, t.engine, r.trigger, r.status, r.scheduled_for, r.tier,
	r.started_at, r.finished_at, r.bytes, r.wire_bytes, r.blob_path, r.sha256, r.error, r.created_at, r.attempt, r.steps, c.id, c.labels
	FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id JOIN targets t ON t.id = j.target_id JOIN clusters c ON c.id = t.cluster_id`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	err := row.Scan(&r.ID, &r.JobID, &r.TargetService, &r.ClusterName, &r.Engine, &r.Trigger, &r.Status, &r.ScheduledFor, &r.Tier,
		&r.StartedAt, &r.FinishedAt, &r.Bytes, &r.WireBytes, &r.BlobPath, &r.SHA256, &r.Error, &r.CreatedAt, &r.Attempt, &r.Steps, &r.clusterID, &r.clusterLabels)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// LoadRun loads one run.
func LoadRun(ctx context.Context, q store.Querier, id uuid.UUID) (*Run, error) {
	r, err := scanRun(q.QueryRow(ctx, runSelect+` WHERE r.id = $1`, id))
	return r, store.NotFound(err)
}

// JobView is the API shape of a job (BackupJob in openapi).
type JobView struct {
	ID          uuid.UUID        `json:"id"`
	Target      inventory.Target `json:"target"`
	Engine      string           `json:"engine"`
	Credential  *CredentialView  `json:"credential"`
	Destination struct {
		ID   uuid.UUID `json:"id"`
		Name string    `json:"name"`
	} `json:"destination"`
	EngineOptions         json.RawMessage `json:"engine_options"`
	Cron                  string          `json:"cron"`
	Timezone              string          `json:"timezone"`
	Retention             Retention       `json:"retention"`
	Enabled               bool            `json:"enabled"`
	PausedReason          string          `json:"paused_reason"`
	NotifyChannelID       *uuid.UUID      `json:"notify_channel_id"`
	NotifyOnSuccess       bool            `json:"notify_on_success"`
	NextRunAt             *time.Time      `json:"next_run_at"`
	LastRun               *Run            `json:"last_run"`
	EstimatedMonthlyBytes int64           `json:"estimated_monthly_bytes"`
	EstimatedMonthlyCost  *float64        `json:"estimated_monthly_cost"`
	CreatedAt             time.Time       `json:"created_at"`
}

// estimateRuns is how many recent runs the transfer estimate averages.
const estimateRuns = 5

// bytesPerGB is the unit of clusters.egress_rate_per_gb (GiB, as cloud
// egress price sheets bill).
const bytesPerGB = 1 << 30

// MonthlyEstimate returns wire bytes per month for an average run size and
// a schedule (SPEC §7: last runs × frequency).
func MonthlyEstimate(avgWireBytes float64, spec schedule.Spec, now time.Time) int64 {
	iv := spec.Interval(now)
	if iv <= 0 || avgWireBytes <= 0 {
		return 0
	}
	perMonth := float64(30*24*time.Hour) / float64(iv)
	return int64(avgWireBytes * perMonth)
}

// View builds the API shape: next run, last run and transfer estimates.
func (j *Job) View(ctx context.Context, q store.Querier, creds *Credentials, now time.Time) (*JobView, error) {
	v := &JobView{ID: j.ID, Target: j.Target, Engine: j.Target.Engine, EngineOptions: j.EngineOptions, Cron: j.Cron, Timezone: j.Timezone,
		Retention: j.Retention, Enabled: j.Enabled, PausedReason: j.PausedReason, NotifyChannelID: j.NotifyChannelID, NotifyOnSuccess: j.NotifyOnSuccess, CreatedAt: j.CreatedAt}
	v.Destination.Name = j.DestinationName
	if j.DestinationID != nil {
		v.Destination.ID = *j.DestinationID
	} else if j.DestinationGroupID != nil {
		v.Destination.ID = *j.DestinationGroupID
	}
	if j.CredentialID != nil {
		cv, err := creds.View(ctx, q, *j.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("credential view: %w", err)
		}
		v.Credential = cv
	}
	spec, specErr := schedule.Parse(j.Cron, j.Timezone)
	if specErr == nil && j.Enabled && j.PausedReason == "" {
		n := spec.Next(now)
		v.NextRunAt = &n
	}
	last, err := scanRun(q.QueryRow(ctx, runSelect+` WHERE r.job_id = $1 AND r.trigger <> 'test' ORDER BY r.created_at DESC LIMIT 1`, j.ID))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	v.LastRun = last
	var avg *float64
	if err := q.QueryRow(ctx, `SELECT avg(wire_bytes)::float8 FROM (SELECT wire_bytes FROM backup_runs
		WHERE job_id = $1 AND status = 'succeeded' AND trigger <> 'test' ORDER BY finished_at DESC LIMIT $2) x`, j.ID, estimateRuns).Scan(&avg); err != nil {
		return nil, err
	}
	if avg != nil && specErr == nil {
		v.EstimatedMonthlyBytes = MonthlyEstimate(*avg, spec, now)
		if j.EgressRatePerGB != nil {
			c := float64(v.EstimatedMonthlyBytes) / bytesPerGB * *j.EgressRatePerGB
			c = float64(int64(c*100+0.5)) / 100
			v.EstimatedMonthlyCost = &c
		}
	}
	return v, nil
}
