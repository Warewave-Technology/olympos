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
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// lockClaim serializes run claims across replicas (transaction-scoped), so
// per-cluster limits hold.
const lockClaim int64 = 0x4f4c5910

// ErrAgentOffline is the error stored on runs whose cluster is offline.
const errAgentOffline = "agent_offline"

// Worker executes queued runs (SPEC §10.5).
type Worker struct {
	DB     *store.DB
	Log    *slog.Logger
	Dialer Dialer
	Blobs  blob.Resolver
	Creds  *Credentials
	// Global is the max concurrent runs on this replica; PerCluster the max
	// running runs per cluster (across replicas).
	Global, PerCluster int
	// Poll is the idle wait between claims (default 2 s).
	Poll time.Duration
	// Heartbeat refreshes running rows; runs without one for StaleAfter are
	// failed by any replica (crashed worker). Defaults 30 s / 5 min.
	Heartbeat, StaleAfter time.Duration

	active atomic.Int32
}

func (w *Worker) limits() (int, int) {
	g, p := w.Global, w.PerCluster
	if g <= 0 {
		g = 4
	}
	if p <= 0 {
		p = 2
	}
	return g, p
}

// Run claims and executes runs until ctx is done, then waits for in-flight
// runs (they are interrupted by ctx and recorded as failed).
func (w *Worker) Run(ctx context.Context) {
	global, _ := w.limits()
	poll := w.Poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	sem := make(chan struct{}, global)
	done := make(chan struct{}, global)
	var lastReap time.Time
	inflight := 0
	defer func() {
		for ; inflight > 0; inflight-- {
			<-done
		}
	}()
	for {
		if time.Since(lastReap) > time.Minute {
			lastReap = time.Now()
			if err := w.ReapStale(ctx); err != nil && ctx.Err() == nil {
				w.Log.Error("reap stale backup runs", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
			inflight--
			continue
		case sem <- struct{}{}:
		}
		id, err := w.Claim(ctx)
		if err != nil && ctx.Err() == nil {
			w.Log.Error("claim backup run", "err", err)
		}
		if id == uuid.Nil {
			<-sem
			select {
			case <-ctx.Done():
				return
			case <-done:
				inflight--
			case <-time.After(poll):
			}
			continue
		}
		inflight++
		go func() {
			defer func() { <-sem; done <- struct{}{} }()
			w.Execute(ctx, id)
		}()
	}
}

// Active returns runs executing on this worker.
func (w *Worker) Active() int { return int(w.active.Load()) }

// Claim picks the oldest queued run this replica can execute and marks it
// running. Runs of offline clusters are failed with agent_offline. Returns
// uuid.Nil when nothing is claimable.
func (w *Worker) Claim(ctx context.Context) (uuid.UUID, error) {
	_, per := w.limits()
	var claimed uuid.UUID
	var failed []finished
	err := store.Tx(ctx, w.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockClaim); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT r.id, t.cluster_id, c.status FROM backup_runs r
			JOIN backup_jobs j ON j.id = r.job_id JOIN targets t ON t.id = j.target_id JOIN clusters c ON c.id = t.cluster_id
			WHERE r.status = 'queued' ORDER BY r.created_at LIMIT 200 FOR UPDATE OF r SKIP LOCKED`)
		if err != nil {
			return err
		}
		type cand struct {
			id, cluster uuid.UUID
			status      string
		}
		var cands []cand
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.id, &c.cluster, &c.status); err != nil {
				rows.Close()
				return err
			}
			cands = append(cands, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		running := map[uuid.UUID]int{}
		for _, c := range cands {
			switch c.status {
			case "offline", "revoked", "pending":
				f, err := finishRunTx(ctx, tx, c.id, outcome{status: "failed", err: errAgentOffline})
				if err != nil {
					return err
				}
				failed = append(failed, f)
				continue
			}
			if claimed != uuid.Nil || !w.Dialer.Connected(c.cluster) {
				continue
			}
			n, ok := running[c.cluster]
			if !ok {
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id
					JOIN targets t ON t.id = j.target_id WHERE r.status = 'running' AND t.cluster_id = $1`, c.cluster).Scan(&n); err != nil {
					return err
				}
				running[c.cluster] = n
			}
			if n >= per {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE backup_runs SET status = 'running', started_at = now() WHERE id = $1`, c.id); err != nil {
				return err
			}
			claimed = c.id
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	for _, f := range failed {
		f.observe()
	}
	return claimed, nil
}

// ReapStale fails running runs whose worker stopped heartbeating.
func (w *Worker) ReapStale(ctx context.Context) error {
	stale := w.StaleAfter
	if stale <= 0 {
		stale = 5 * time.Minute
	}
	var done []finished
	err := store.Tx(ctx, w.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM backup_runs WHERE status = 'running' AND updated_at < now() - $1::interval
			FOR UPDATE SKIP LOCKED`, fmt.Sprintf("%d seconds", int(stale.Seconds())))
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
		for _, id := range ids {
			f, err := finishRunTx(ctx, tx, id, outcome{status: "failed", err: "interrupted: the worker running this backup stopped"})
			if err != nil {
				return err
			}
			done = append(done, f)
		}
		return rows.Err()
	})
	for _, f := range done {
		f.observe()
	}
	return err
}

// outcome is how a run ended.
type outcome struct {
	status   string // succeeded | failed
	err      string // already scrubbed
	bytes    int64
	wire     int64
	blobPath string
	sha256   string
	tier     string
}

// finished carries what metrics need after commit.
type finished struct {
	engine, status string
	started        *time.Time
	ok             bool
}

func (f finished) observe() {
	if !f.ok {
		return
	}
	metrics.BackupRuns.WithLabelValues(f.engine, f.status).Inc()
	if f.started != nil {
		metrics.BackupDuration.WithLabelValues(f.engine, f.status).Observe(time.Since(*f.started).Seconds())
	}
}

// finishRunTx records the terminal state (the row freezes afterwards) and
// emits backup.failed / backup.succeeded in the same transaction. Test runs
// do not notify.
func finishRunTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, o outcome) (finished, error) {
	var jobID uuid.UUID
	var trigger, ns, svc, cluster, engine string
	var channel *uuid.UUID
	var started *time.Time
	err := tx.QueryRow(ctx, `SELECT r.job_id, r.trigger, r.started_at, j.notify_channel_id, t.namespace, t.service, c.name, t.engine
		FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id JOIN targets t ON t.id = j.target_id JOIN clusters c ON c.id = t.cluster_id
		WHERE r.id = $1`, runID).Scan(&jobID, &trigger, &started, &channel, &ns, &svc, &cluster, &engine)
	if err != nil {
		return finished{}, err
	}
	tag, err := tx.Exec(ctx, `UPDATE backup_runs SET status = $2, finished_at = now(), bytes = $3, wire_bytes = $4, blob_path = $5,
		sha256 = $6, error = $7, tier = CASE WHEN $8 = '' THEN tier ELSE $8 END WHERE id = $1 AND finished_at IS NULL`,
		runID, o.status, o.bytes, o.wire, o.blobPath, o.sha256, o.err, o.tier)
	if err != nil {
		return finished{}, err
	}
	if tag.RowsAffected() == 0 {
		return finished{}, nil
	}
	f := finished{engine: engine, status: o.status, started: started, ok: true}
	if trigger == "test" {
		return f, nil
	}
	fields := map[string]string{"cluster": cluster, "target": ns + "/" + svc, "trigger": trigger}
	ev := notify.Event{ChannelID: channel, Link: "/backups?job=" + jobID.String() + "&run=" + runID.String(), Fields: fields,
		Payload: map[string]any{"job_id": jobID.String(), "run_id": runID.String()}}
	if o.status == "succeeded" {
		ev.Type, ev.Key = notify.BackupSucceeded, "backup.succeeded:"+runID.String()
		ev.Title = fmt.Sprintf("Backup succeeded: %s/%s", ns, svc)
		fields["size"] = humanBytes(o.bytes)
		fields["tier"] = o.tier
	} else {
		ev.Type, ev.Key = notify.BackupFailed, "backup.failed:"+runID.String()
		ev.Title = fmt.Sprintf("Backup failed: %s/%s", ns, svc)
		fields["error"] = shortError(o.err)
		ev.Payload["reason"] = shortError(o.err)
	}
	return f, notify.Emit(ctx, tx, ev)
}

func shortError(s string) string {
	if i := bytes.IndexByte([]byte(s), '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// runRow is what Execute needs from backup_runs.
type runRow struct {
	id           uuid.UUID
	jobID        uuid.UUID
	trigger      string
	scheduledFor *time.Time
	startedAt    time.Time
}

// Execute runs one claimed run to completion and records the result.
func (w *Worker) Execute(ctx context.Context, runID uuid.UUID) {
	w.active.Add(1)
	defer w.active.Add(-1)
	var r runRow
	var started *time.Time
	err := w.DB.QueryRow(ctx, `SELECT id, job_id, trigger, scheduled_for, started_at FROM backup_runs WHERE id = $1`, runID).
		Scan(&r.id, &r.jobID, &r.trigger, &r.scheduledFor, &started)
	if err != nil {
		w.Log.Error("load backup run", "run_id", runID, "err", err)
		return
	}
	if started != nil {
		r.startedAt = *started
	} else {
		r.startedAt = time.Now()
	}
	hbCtx, stopHB := context.WithCancel(ctx)
	go w.heartbeat(hbCtx, runID)
	o, rr, job := w.perform(ctx, &r)
	stopHB()

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var f finished
	err = store.Tx(fctx, w.DB, func(tx pgx.Tx) error {
		var err error
		if f, err = finishRunTx(fctx, tx, runID, o); err != nil {
			return err
		}
		if job != nil && rr != nil && rr.TLS != nil {
			t := targetFromJob(job)
			return recordTargetTLS(fctx, tx, t, rr.ServerVersion, *rr.TLS)
		}
		return nil
	})
	if err != nil {
		w.Log.Error("finish backup run", "run_id", runID, "err", err)
		return
	}
	f.observe()
	lvl := slog.LevelInfo
	if o.status != "succeeded" {
		lvl = slog.LevelWarn
	}
	w.Log.Log(fctx, lvl, "backup run finished", "run_id", runID, "job_id", r.jobID, "status", o.status, "bytes", o.bytes,
		"wire_bytes", o.wire, "error", o.err)
}

func (w *Worker) heartbeat(ctx context.Context, runID uuid.UUID) {
	iv := w.Heartbeat
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := w.DB.Exec(ctx, `UPDATE backup_runs SET status = status WHERE id = $1 AND finished_at IS NULL`, runID); err != nil && ctx.Err() == nil {
			w.Log.Warn("backup run heartbeat", "run_id", runID, "err", err)
		}
	}
}

func targetFromJob(j *Job) *targetRow {
	return &targetRow{info: j.TargetInfo(), clusterID: j.Target.ClusterID, transferMode: j.TransferMode, status: j.Target.Status}
}

// countingHash hashes and counts what passes through.
type countingHash struct {
	n int64
	h hashWriter
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func (c *countingHash) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

// perform does the work of a run and returns its outcome. Errors are
// scrubbed of secrets before they are returned.
func (w *Worker) perform(ctx context.Context, r *runRow) (outcome, *RunResult, *Job) {
	fail := func(msg string) outcome { return outcome{status: "failed", err: msg} }
	var job *Job
	jj, err := scanJob(w.DB.QueryRow(ctx, jobSelectAny+` AND j.id = $1`, r.jobID))
	if err != nil {
		return fail("job not found"), nil, nil
	}
	job = jj
	tr := &secretTracker{}
	defer tr.zero()
	if job.ClusterStatus == "offline" || job.ClusterStatus == "revoked" {
		return fail(errAgentOffline), nil, job
	}
	eng, ok := EngineFor(job.Target.Engine)
	if !ok {
		return fail(fmt.Sprintf("no backup engine registered for %q", job.Target.Engine)), nil, job
	}
	tier := "test"
	if r.trigger != "test" {
		if tier, err = w.tier(ctx, job, r); err != nil {
			return fail(tr.scrub("decide retention tier: " + err.Error())), nil, job
		}
	}
	writer, err := w.Blobs.ForDestination(ctx, job.DestinationID)
	if err != nil {
		return fail(tr.scrub("open destination: " + err.Error())), nil, job
	}
	credFn := func(ctx context.Context) (Credential, error) {
		if job.CredentialID != nil {
			c, err := w.Creds.Resolve(ctx, w.DB, *job.CredentialID)
			return tr.track(c), err
		}
		p, ok := CredentialProviderFor(job.Target.Engine)
		if !ok {
			return Credential{}, errors.New("no credential configured for this job")
		}
		c, err := p(ctx, job.TargetInfo())
		return tr.track(c), err
	}
	t := targetFromJob(job)
	ec, wc := newEngineContext(w.Dialer, t, job.EngineOptions, credFn, r.trigger == "test")

	path := BlobPath(writer.Prefix(), job.Target.ClusterName, job.Target.Namespace, job.Target.Service, eng.Name(), r.startedAt, r.id, eng.Ext())
	tags := map[string]string{TierTag: tier}
	pr, pw := io.Pipe()
	type engRes struct {
		rr  *RunResult
		err error
	}
	resc := make(chan engRes, 1)
	var engineFailed atomic.Bool
	go func() {
		rr, err := eng.Run(ctx, ec, pw)
		if err != nil {
			engineFailed.Store(true)
		}
		_ = pw.CloseWithError(err) // nil → EOF
		resc <- engRes{rr, err}
	}()
	ch := &countingHash{h: sha256.New()}
	_, upErr := writer.Upload(ctx, path, io.TeeReader(pr, ch), eng.ContentType(), tags)
	// Root cause: did the upload fail on its own, or because the engine
	// failed (the pipe hands the engine error to the uploader)?
	uploadFirst := upErr != nil && !engineFailed.Load()
	if upErr != nil {
		_ = pr.CloseWithError(upErr)
	} else {
		// Drain anything the uploader did not read (should be nothing).
		_, _ = io.Copy(ch, pr)
	}
	res := <-resc
	o := outcome{bytes: ch.n, wire: wc.total(), tier: tier}
	switch {
	case uploadFirst:
		// The engine failed because the upload did.
		o.status, o.err = "failed", tr.scrub("upload: "+upErr.Error())
		return o, res.rr, job
	case res.err != nil:
		msg := res.err.Error()
		if errors.Is(res.err, gateway.ErrAgentOffline) {
			msg = errAgentOffline
		}
		o.status, o.err = "failed", tr.scrub(msg)
		return o, res.rr, job
	case upErr != nil:
		o.status, o.err = "failed", tr.scrub("upload: "+upErr.Error())
		return o, res.rr, job
	case ctx.Err() != nil:
		o.status, o.err = "failed", "interrupted: server shutting down"
		return o, res.rr, job
	}
	rr := res.rr
	if rr == nil {
		rr = &RunResult{}
	}
	o.sha256 = hex.EncodeToString(ch.h.Sum(nil))
	o.blobPath = path
	finishedAt := time.Now().UTC()
	m := Manifest{
		Format: ManifestFormat, RunID: r.id, JobID: job.ID, Trigger: r.trigger, Tier: tier, ScheduledFor: r.scheduledFor,
		StartedAt: r.startedAt.UTC(), FinishedAt: finishedAt,
		Cluster: ManifestCluster{ID: job.Target.ClusterID, Name: job.Target.ClusterName},
		Target: ManifestTarget{ID: job.Target.ID, Namespace: job.Target.Namespace, Service: job.Target.Service, Port: job.Target.Port,
			TLSServerName: ec.TLSServerName},
		Engine: eng.Name(), EngineOptions: redactOptions(job.EngineOptions),
		Blob:      ManifestBlob{Path: path, ContentType: eng.ContentType(), Ext: eng.Ext(), Size: o.bytes, SHA256: o.sha256},
		WireBytes: o.wire, TransferMode: job.TransferMode, TLS: rr.TLS, ServerVersion: rr.ServerVersion, ToolVersion: rr.ToolVersion,
		Details: rr.Details, Test: r.trigger == "test",
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		o.status, o.err = "failed", "encode manifest: "+err.Error()
		return o, rr, job
	}
	if _, err := writer.Upload(ctx, ManifestPath(path, r.id), bytes.NewReader(mb), "application/json", tags); err != nil {
		o.status, o.err = "failed", tr.scrub("upload manifest: "+err.Error())
		return o, rr, job
	}
	o.status = "succeeded"
	return o, rr, job
}

// jobSelectAny is jobSelect without the deleted filter (a run of a job
// deleted after it was claimed still finishes).
const jobSelectAny = jobSelectBase + ` WHERE true`

// redactOptions drops option keys that look sensitive before they are
// written to the manifest (options are not supposed to hold secrets).
func redactOptions(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return json.RawMessage(`{}`)
	}
	for k := range m {
		switch k {
		case "password", "secret", "token":
			delete(m, k)
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// tier decides the GFS tier at write time (SPEC §10.3): the first
// successful scheduled run of the month (job time zone) is monthly, else the
// first of the ISO week is weekly, else daily. Manual runs are daily.
func (w *Worker) tier(ctx context.Context, j *Job, r *runRow) (string, error) {
	if r.trigger != "schedule" {
		return "daily", nil
	}
	loc, err := time.LoadLocation(j.Timezone)
	if err != nil {
		loc = time.UTC
	}
	ref := r.startedAt
	if r.scheduledFor != nil {
		ref = *r.scheduledFor
	}
	return TierFor(ctx, w.DB, j.ID, r.id, ref, loc)
}

// TierFor implements the GFS decision for a run at ref.
func TierFor(ctx context.Context, q store.Querier, jobID, runID uuid.UUID, ref time.Time, loc *time.Location) (string, error) {
	t := ref.In(loc)
	monthStart := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
	monthEnd := monthStart.AddDate(0, 1, 0)
	wd := (int(t.Weekday()) + 6) % 7 // Monday = 0 (ISO week)
	weekStart := time.Date(t.Year(), t.Month(), t.Day()-wd, 0, 0, 0, 0, loc)
	weekEnd := weekStart.AddDate(0, 0, 7)
	count := func(from, to time.Time) (int, error) {
		var n int
		err := q.QueryRow(ctx, `SELECT count(*) FROM backup_runs WHERE job_id = $1 AND id <> $2 AND trigger = 'schedule'
			AND status = 'succeeded' AND COALESCE(scheduled_for, started_at) >= $3 AND COALESCE(scheduled_for, started_at) < $4`,
			jobID, runID, from, to).Scan(&n)
		return n, err
	}
	n, err := count(monthStart, monthEnd)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "monthly", nil
	}
	if n, err = count(weekStart, weekEnd); err != nil {
		return "", err
	}
	if n == 0 {
		return "weekly", nil
	}
	return "daily", nil
}
