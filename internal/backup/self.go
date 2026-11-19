package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// SelfSystem marks the built-in backup job of Olympos' own database (F17).
// It has no target: it is not reached through an agent but dialed directly
// (Unix socket or TCP, as the server connects). It cannot be deleted; its
// runs live in backup_runs, so manifest, tags and retention tiers are the
// same as for any job.
const SelfSystem = "olympos-self"

// selfLabel is the cluster/namespace/service used in blob paths and the
// manifest: {prefix}/olympos/olympos/olympos-db/postgresql/...
const (
	selfCluster   = "olympos"
	selfNamespace = "olympos"
	selfService   = "olympos-db"
)

// SelfBackup schedules and runs the olympos-self job on the leader.
type SelfBackup struct {
	DB    *store.DB
	Log   *slog.Logger
	Blobs blob.Resolver
	// DSN and Password: the login the server itself uses.
	DSN, Password string
	// Tick is the leader interval (default 10 s).
	Tick time.Duration
	Now  func() time.Time
}

func (s *SelfBackup) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SelfJob is the olympos-self job (API shape).
type SelfJob struct {
	ID              uuid.UUID  `json:"id"`
	DestinationID   uuid.UUID  `json:"destination_id"`
	DestinationName string     `json:"destination_name"`
	Cron            string     `json:"cron"`
	Timezone        string     `json:"timezone"`
	Retention       Retention  `json:"retention"`
	Enabled         bool       `json:"enabled"`
	NotifyChannelID *uuid.UUID `json:"notify_channel_id"`
	CreatedAt       time.Time  `json:"created_at"`
	lastScheduled   *time.Time
}

// LoadSelfJob returns the olympos-self job, or store.ErrNotFound before the
// admin chose a destination.
func LoadSelfJob(ctx context.Context, q store.Querier) (*SelfJob, error) {
	var j SelfJob
	var ret []byte
	err := q.QueryRow(ctx, `SELECT j.id, j.destination_id, d.name, j.cron, j.timezone, j.retention, j.enabled, j.notify_channel_id,
		j.created_at, j.last_scheduled_for
		FROM backup_jobs j JOIN destinations d ON d.id = j.destination_id WHERE j.system = $1`, SelfSystem).
		Scan(&j.ID, &j.DestinationID, &j.DestinationName, &j.Cron, &j.Timezone, &ret, &j.Enabled, &j.NotifyChannelID,
			&j.CreatedAt, &j.lastScheduled)
	if err != nil {
		return nil, store.NotFound(err)
	}
	j.Retention = DefaultRetention
	_ = json.Unmarshal(ret, &j.Retention)
	return &j, nil
}

// Run is the leader loop: it queues scheduled runs and executes queued
// runs of the olympos-self job, one at a time.
func (s *SelfBackup) Run(ctx context.Context) {
	iv := s.Tick
	if iv <= 0 {
		iv = 10 * time.Second
	}
	schedule.RunLeader(ctx, s.DB, schedule.LockSelfBackup, iv, s.Log, func(ctx context.Context) error {
		// A run left 'running' belonged to a previous leader that stopped.
		if _, err := s.DB.Exec(ctx, `UPDATE backup_runs SET status = 'failed', error = 'interrupted: server stopped during the run', finished_at = now()
			WHERE status = 'running' AND updated_at < now() - interval '2 minutes'
			  AND job_id IN (SELECT id FROM backup_jobs WHERE system = $1)`, SelfSystem); err != nil {
			return err
		}
		if err := s.schedule(ctx); err != nil {
			return err
		}
		for {
			id, err := s.claim(ctx)
			if err != nil || id == uuid.Nil {
				return err
			}
			s.execute(ctx, id)
		}
	})
}

// schedule queues the latest due activation (missed older ones are not
// replayed: the next dump covers them).
func (s *SelfBackup) schedule(ctx context.Context) error {
	j, err := LoadSelfJob(ctx, s.DB)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil || !j.Enabled {
		return err
	}
	spec, err := schedule.Parse(j.Cron, j.Timezone)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	from := j.CreatedAt
	if j.lastScheduled != nil {
		from = *j.lastScheduled
	}
	due := spec.Between(from, now, 1000)
	if len(due) == 0 {
		return nil
	}
	at := due[len(due)-1]
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE backup_jobs SET last_scheduled_for = $2 WHERE id = $1`, j.ID, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for) VALUES ($1, 'schedule', 'queued', $2)`, j.ID, at)
		return err
	})
}

func (s *SelfBackup) claim(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.DB.QueryRow(ctx, `UPDATE backup_runs SET status = 'running', started_at = now() WHERE id = (
		SELECT r.id FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id
		WHERE j.system = $1 AND r.status = 'queued' ORDER BY r.created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id`, SelfSystem).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// QueueSelfRun queues a manual run (POST /backup/self/run).
func QueueSelfRun(ctx context.Context, q store.Querier, jobID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status) VALUES ($1, 'manual', 'queued') RETURNING id`, jobID).Scan(&id)
	return id, err
}

// selfTarget derives the dial and login from the server's own DSN.
type selfTarget struct {
	network, addr string
	host          string
	port          int
	user, db      string
	password      []byte
	tls           bool
}

func parseSelfDSN(dsn, password string) (*selfTarget, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database dsn: %w", err)
	}
	t := &selfTarget{host: cfg.Host, port: int(cfg.Port), user: cfg.User, db: cfg.Database, tls: cfg.TLSConfig != nil}
	if t.port == 0 {
		t.port = 5432
	}
	pw := cfg.Password
	if password != "" {
		pw = password
	}
	t.password = []byte(pw)
	if strings.HasPrefix(t.host, "/") {
		t.network, t.addr = "unix", filepath.Join(t.host, ".s.PGSQL."+strconv.Itoa(t.port))
		t.tls = false
	} else {
		t.network, t.addr = "tcp", net.JoinHostPort(t.host, strconv.Itoa(t.port))
	}
	if t.db == "" {
		t.db = t.user
	}
	return t, nil
}

type runInfo struct {
	id, jobID    uuid.UUID
	trigger      string
	scheduledFor *time.Time
	startedAt    time.Time
}

func (s *SelfBackup) execute(ctx context.Context, runID uuid.UUID) {
	var r runInfo
	r.id = runID
	if err := s.DB.QueryRow(ctx, `SELECT job_id, trigger, scheduled_for, started_at FROM backup_runs WHERE id = $1`, runID).
		Scan(&r.jobID, &r.trigger, &r.scheduledFor, &r.startedAt); err != nil {
		s.Log.Error("load olympos-self run", "run_id", runID, "err", err)
		return
	}
	hb, stop := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hb.Done():
				return
			case <-t.C:
				_, _ = s.DB.Exec(hb, `UPDATE backup_runs SET status = status WHERE id = $1 AND finished_at IS NULL`, runID)
			}
		}
	}()
	o, j := s.perform(ctx, r)
	stop()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err := store.Tx(fctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(fctx, `UPDATE backup_runs SET status = $2, finished_at = now(), bytes = $3, wire_bytes = $4, blob_path = $5,
			sha256 = $6, error = $7, tier = CASE WHEN $8 = '' THEN tier ELSE $8 END WHERE id = $1 AND finished_at IS NULL`,
			runID, o.status, o.bytes, o.wire, o.blobPath, o.sha256, o.err, o.tier)
		if err != nil || tag.RowsAffected() == 0 || o.status == "succeeded" {
			return err
		}
		var channel *uuid.UUID
		if j != nil {
			channel = j.NotifyChannelID
		}
		return notify.Emit(fctx, tx, notify.Event{Type: notify.BackupFailed, Key: notify.BackupFailed + ":" + runID.String(), ChannelID: channel,
			Title: "Backup failed: Olympos database (olympos-self)", Link: "/backups?self=1&run=" + runID.String(),
			Fields:  map[string]string{"target": "olympos-self", "trigger": r.trigger, "error": o.err},
			Payload: map[string]any{"job_id": r.jobID.String(), "run_id": runID.String()}})
	})
	if err != nil {
		s.Log.Error("finish olympos-self run", "run_id", runID, "err", err)
		return
	}
	s.Log.Info("olympos-self backup finished", "run_id", runID, "status", o.status, "bytes", o.bytes, "error", o.err)
}

func (s *SelfBackup) perform(ctx context.Context, r runInfo) (outcome, *SelfJob) {
	fail := func(msg string) outcome { return outcome{status: "failed", err: msg} }
	j, err := LoadSelfJob(ctx, s.DB)
	if err != nil {
		return fail("job not found"), nil
	}
	tt, err := parseSelfDSN(s.DSN, s.Password)
	if err != nil {
		return fail(err.Error()), j
	}
	defer zeroBytes(tt.password)
	eng, ok := EngineFor("postgresql")
	if !ok {
		return fail("the postgresql engine is not registered"), j
	}
	tier := "daily"
	if r.trigger == "schedule" {
		loc, err := time.LoadLocation(j.Timezone)
		if err != nil {
			loc = time.UTC
		}
		ref := r.startedAt
		if r.scheduledFor != nil {
			ref = *r.scheduledFor
		}
		if tier, err = TierFor(ctx, s.DB, j.ID, r.id, ref, loc); err != nil {
			return fail("decide retention tier: " + err.Error()), j
		}
	}
	writer, err := s.Blobs.ForDestination(ctx, j.DestinationID)
	if err != nil {
		return fail("open destination: " + err.Error()), j
	}
	opts, _ := json.Marshal(map[string]any{"databases": []string{tt.db}, "globals": false})
	ec := EngineContext{
		Target: TargetInfo{ID: SelfSystem, ClusterName: selfCluster, Namespace: selfNamespace, Service: selfService,
			Port: tt.port, Engine: "postgresql", TLSServerName: tt.host},
		TLSServerName:    tt.host,
		TrustSystemRoots: true,
		UseTLS:           tt.tls,
		Options:          opts,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, tt.network, tt.addr)
		},
		Credential: func(context.Context) (Credential, error) {
			return Credential{Username: tt.user, Secret: append([]byte(nil), tt.password...)}, nil
		},
	}
	path := BlobPath(writer.Prefix(), selfCluster, selfNamespace, selfService, eng.Name(), r.startedAt, r.id, eng.Ext())
	tags := map[string]string{TierTag: tier}
	pr, pw := io.Pipe()
	type engRes struct {
		rr  *RunResult
		err error
	}
	resc := make(chan engRes, 1)
	go func() {
		rr, err := eng.Run(ctx, ec, pw)
		_ = pw.CloseWithError(err)
		resc <- engRes{rr, err}
	}()
	ch := &countingHash{h: sha256.New()}
	_, upErr := writer.Upload(ctx, path, io.TeeReader(pr, ch), eng.ContentType(), tags)
	if upErr != nil {
		_ = pr.CloseWithError(upErr)
	} else {
		_, _ = io.Copy(io.Discard, pr)
	}
	res := <-resc
	o := outcome{bytes: ch.n, wire: ch.n, tier: tier} // no tunnel: wire = bytes
	switch {
	case res.err != nil:
		o.status, o.err = "failed", scrubPassword(res.err.Error(), tt.password)
		return o, j
	case upErr != nil:
		o.status, o.err = "failed", scrubPassword("upload: "+upErr.Error(), tt.password)
		return o, j
	}
	rr := res.rr
	if rr == nil {
		rr = &RunResult{}
	}
	o.sha256 = hex.EncodeToString(ch.h.Sum(nil))
	o.blobPath = path
	details := map[string]any{"system": SelfSystem, "database": tt.db}
	for k, v := range rr.Details {
		details[k] = v
	}
	m := Manifest{
		Format: ManifestFormat, RunID: r.id, JobID: j.ID, Trigger: r.trigger, Tier: tier, ScheduledFor: r.scheduledFor,
		StartedAt: r.startedAt.UTC(), FinishedAt: time.Now().UTC(),
		Cluster: ManifestCluster{Name: selfCluster},
		Target:  ManifestTarget{ID: SelfSystem, Namespace: selfNamespace, Service: selfService, Port: tt.port, TLSServerName: tt.host},
		Engine:  eng.Name(), EngineOptions: opts,
		Blob:      ManifestBlob{Path: path, ContentType: eng.ContentType(), Ext: eng.Ext(), Size: o.bytes, SHA256: o.sha256},
		WireBytes: o.wire, TransferMode: "direct", TLS: rr.TLS, ServerVersion: rr.ServerVersion, ToolVersion: rr.ToolVersion,
		Details: details,
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		o.status, o.err = "failed", "encode manifest: "+err.Error()
		return o, j
	}
	if _, err := writer.Upload(ctx, ManifestPath(path, r.id), bytes.NewReader(mb), "application/json", tags); err != nil {
		o.status, o.err = "failed", "upload manifest: "+err.Error()
		return o, j
	}
	o.status = "succeeded"
	return o, j
}

func scrubPassword(msg string, pw []byte) string {
	if len(pw) >= 4 {
		msg = strings.ReplaceAll(msg, string(pw), "[redacted]")
	}
	return msg
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
