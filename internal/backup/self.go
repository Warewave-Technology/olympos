package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// SelfJob is the olympos-self job (API shape). Exactly one of
// DestinationID and DestinationGroupID is set; DestinationName is the name
// of that destination or group.
type SelfJob struct {
	ID                 uuid.UUID  `json:"id"`
	DestinationID      *uuid.UUID `json:"destination_id"`
	DestinationGroupID *uuid.UUID `json:"destination_group_id"`
	DestinationName    string     `json:"destination_name"`
	Cron               string     `json:"cron"`
	Timezone           string     `json:"timezone"`
	Retention          Retention  `json:"retention"`
	Enabled            bool       `json:"enabled"`
	NotifyChannelID    *uuid.UUID `json:"notify_channel_id"`
	CreatedAt          time.Time  `json:"created_at"`
	lastScheduled      *time.Time
}

// LoadSelfJob returns the olympos-self job, or store.ErrNotFound before the
// admin chose a destination.
func LoadSelfJob(ctx context.Context, q store.Querier) (*SelfJob, error) {
	var j SelfJob
	var ret []byte
	err := q.QueryRow(ctx, `SELECT j.id, j.destination_id, j.destination_group_id, COALESCE(d.name, g.name, ''), j.cron, j.timezone,
		j.retention, j.enabled, j.notify_channel_id, j.created_at, j.last_scheduled_for
		FROM backup_jobs j LEFT JOIN destinations d ON d.id = j.destination_id LEFT JOIN destination_groups g ON g.id = j.destination_group_id
		WHERE j.system = $1`, SelfSystem).
		Scan(&j.ID, &j.DestinationID, &j.DestinationGroupID, &j.DestinationName, &j.Cron, &j.Timezone, &ret, &j.Enabled, &j.NotifyChannelID,
			&j.CreatedAt, &j.lastScheduled)
	if err != nil {
		return nil, store.NotFound(err)
	}
	j.Retention = DefaultRetention
	_ = json.Unmarshal(ret, &j.Retention)
	return &j, nil
}

// Run is the leader loop: it queues scheduled runs and executes queued
// runs of the olympos-self job, one at a time. Repairs of partial runs are
// queued runs of the job too, so this loop runs them once they are due.
func (s *SelfBackup) Run(ctx context.Context) {
	iv := s.Tick
	if iv <= 0 {
		iv = 10 * time.Second
	}
	schedule.RunLeader(ctx, s.DB, schedule.LockSelfBackup, iv, s.Log, func(ctx context.Context) error {
		if err := s.reapStale(ctx); err != nil {
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

// reapStale fails runs left 'running' by a previous leader that stopped
// (no heartbeat for 2 minutes), through finishRunTx like any run: an
// interrupted repair continues the repair chain, an interrupted run sends
// backup.failed.
func (s *SelfBackup) reapStale(ctx context.Context) error {
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id
			WHERE j.system = $1 AND r.status = 'running' AND r.updated_at < now() - interval '2 minutes'
			ORDER BY r.created_at FOR UPDATE OF r SKIP LOCKED`, SelfSystem)
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
			if _, err := finishRunTx(ctx, tx, id, outcome{status: "failed", err: "interrupted: server stopped during the run"}); err != nil {
				return err
			}
		}
		return nil
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

// claim marks the oldest queued run of the job running; a repair waits for
// its not_before (RepairDelays).
func (s *SelfBackup) claim(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.DB.QueryRow(ctx, `UPDATE backup_runs SET status = 'running', started_at = now() WHERE id = (
		SELECT r.id FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id
		WHERE j.system = $1 AND r.status = 'queued' AND (r.not_before IS NULL OR r.not_before <= $2)
		ORDER BY r.created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id`, SelfSystem, s.now()).Scan(&id)
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

func (s *SelfBackup) execute(ctx context.Context, runID uuid.UUID) {
	var r runRow
	r.id = runID
	if err := s.DB.QueryRow(ctx, `SELECT job_id, trigger, scheduled_for, started_at, repair_of FROM backup_runs WHERE id = $1`, runID).
		Scan(&r.jobID, &r.trigger, &r.scheduledFor, &r.startedAt, &r.repairOf); err != nil {
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
	o := s.perform(ctx, &r)
	stop()
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	// The same finish as job runs: copy rows, repair, event (self texts).
	var f finished
	err := store.Tx(fctx, s.DB, func(tx pgx.Tx) error {
		var err error
		f, err = finishRunTx(fctx, tx, runID, o)
		return err
	})
	if err != nil {
		s.Log.Error("finish olympos-self run", "run_id", runID, "err", err)
		return
	}
	f.observeCopies() // self runs are not in the run metrics
	s.Log.Info("olympos-self backup finished", "run_id", runID, "status", o.status, "bytes", o.bytes, "error", o.err)
}

// perform dumps the database once and streams it to every destination of
// the run (runDestinations: the job's destination or group members, or a
// repair's missing set), like a job run.
func (s *SelfBackup) perform(ctx context.Context, r *runRow) outcome {
	fail := func(msg string) outcome { return outcome{status: "failed", err: msg} }
	j, err := LoadSelfJob(ctx, s.DB)
	if err != nil {
		return fail("job not found")
	}
	tt, err := parseSelfDSN(s.DSN, s.Password)
	if err != nil {
		return fail(err.Error())
	}
	defer zeroBytes(tt.password)
	scrub := func(msg string) string { return scrubPassword(msg, tt.password) }
	eng, ok := EngineFor("postgresql")
	if !ok {
		return fail("the postgresql engine is not registered")
	}
	dests, err := runDestinations(ctx, s.DB, r.id)
	if err != nil {
		return fail(scrub("resolve destinations: " + err.Error()))
	}
	if len(dests) == 0 {
		if r.repairOf != nil {
			return fail(errNothingToRepair)
		}
		return fail("the job has no destination")
	}
	tiers, err := copyTiers(ctx, s.DB, j.ID, j.Timezone, r, dests)
	if err != nil {
		return fail(scrub("decide retention tier: " + err.Error()))
	}
	var group *ManifestGroup
	if j.DestinationGroupID != nil {
		members, err := groupMembers(ctx, s.DB, *j.DestinationGroupID)
		if err != nil {
			return fail(scrub("load destination group: " + err.Error()))
		}
		group = &ManifestGroup{Name: j.DestinationName, Members: members}
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
	path := func(prefix string) string {
		return BlobPath(prefix, selfCluster, selfNamespace, selfService, eng.Name(), r.startedAt, r.id, eng.Ext())
	}
	manifest := func(d destRef, b ManifestBlob, tier string) Manifest {
		return Manifest{
			Format: ManifestFormat, RunID: r.id, JobID: j.ID, Trigger: r.trigger, Tier: tier, ScheduledFor: r.scheduledFor,
			StartedAt: r.startedAt.UTC(), FinishedAt: time.Now().UTC(),
			Cluster: ManifestCluster{Name: selfCluster},
			Target:  ManifestTarget{ID: SelfSystem, Namespace: selfNamespace, Service: selfService, Port: tt.port, TLSServerName: tt.host},
			Engine:  eng.Name(), EngineOptions: opts,
			Blob: b, WireBytes: b.Size, TransferMode: "direct", // no tunnel: wire = bytes
			Details:     map[string]any{"system": SelfSystem, "database": tt.db},
			Destination: &ManifestDestination{Name: d.Name, Kind: d.Kind}, Group: group,
		}
	}
	_, copies, streamed, engErr := streamCopies(ctx, eng, ec, dests, s.Blobs.ForDestination, path, tiers, manifest, scrub)
	return copiesOutcome(ctx, copies, streamed, streamed, tiers[dests[0].ID], engErr, scrub)
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
