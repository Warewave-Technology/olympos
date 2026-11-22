package backup

import (
	"github.com/Warewave-Technology/olympos/internal/schedule"

	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
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
const lockClaim = schedule.LockBackupClaim

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
// running; a run whose not_before is still ahead is left in the queue. Runs
// of offline clusters are failed with agent_offline. Returns uuid.Nil when
// nothing is claimable.
func (w *Worker) Claim(ctx context.Context) (uuid.UUID, error) {
	_, per := w.limits()
	var claimed uuid.UUID
	var failed []finished
	err := store.Tx(ctx, w.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockClaim); err != nil {
			return err
		}
		// A repair waits for its not_before (RepairDelays).
		rows, err := tx.Query(ctx, `SELECT r.id, t.cluster_id, c.status, r.retry_until FROM backup_runs r
			JOIN backup_jobs j ON j.id = r.job_id JOIN targets t ON t.id = j.target_id JOIN clusters c ON c.id = t.cluster_id
			WHERE r.status = 'queued' AND (r.not_before IS NULL OR r.not_before <= $1)
			ORDER BY r.created_at LIMIT 200 FOR UPDATE OF r SKIP LOCKED`, time.Now())
		if err != nil {
			return err
		}
		type cand struct {
			id, cluster uuid.UUID
			status      string
			retryUntil  *time.Time
		}
		var cands []cand
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.id, &c.cluster, &c.status, &c.retryUntil); err != nil {
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
			case "offline":
				// F18: wait for the reconnect inside the retry window.
				if c.retryUntil != nil && time.Now().Before(*c.retryUntil) {
					continue
				}
				o, err := disconnectedOutcome(ctx, tx, c.id, outcome{status: "failed", err: errAgentOffline}, time.Now())
				if err != nil {
					return err
				}
				f, err := finishRunTx(ctx, tx, c.id, o)
				if err != nil {
					return err
				}
				failed = append(failed, f)
				continue
			case "revoked", "pending":
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
		// The olympos-self runner settles its own runs (SelfBackup).
		rows, err := tx.Query(ctx, `SELECT id FROM backup_runs WHERE status = 'running' AND updated_at < now() - $1::interval
			AND job_id NOT IN (SELECT id FROM backup_jobs WHERE system <> '')
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
	status string // succeeded | partial | failed | missed
	err    string // already scrubbed
	// quiet: no notification (a failed attempt that is retried, F18).
	quiet bool
	// steps: dry-run checklist (F10), stored with the run.
	steps    []Step
	bytes    int64
	wire     int64
	blobPath string
	sha256   string
	tier     string
	// copies: one per destination the run wrote to (or tried to).
	copies []copyResult
	// engineFailed: the run failed in the engine (or was interrupted), not
	// in its copies; the dry-run checklist stops at the engine.
	engineFailed bool
}

// fromFirstCopy fills the run's blob columns from its first succeeded copy
// (copies are in destination_ids order), so existing readers keep working.
// Without one, it takes the first copy whose data blob was written (its
// manifest failed), as a single-destination run always did.
func (o *outcome) fromFirstCopy() {
	for _, c := range o.copies {
		if c.Status == "succeeded" {
			o.blobPath, o.bytes, o.sha256, o.tier = c.BlobPath, c.Bytes, c.SHA256, c.Tier
			return
		}
	}
	for _, c := range o.copies {
		if c.BlobPath != "" {
			o.blobPath, o.bytes, o.sha256 = c.BlobPath, c.Bytes, c.SHA256
			return
		}
	}
}

// finished carries what metrics need after commit.
type finished struct {
	engine, status string
	started        *time.Time
	copies         []copyResult
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
	f.observeCopies()
}

// observeCopies counts the run's copies only (the olympos-self runner,
// whose runs are not in the run metrics).
func (f finished) observeCopies() {
	for _, c := range f.copies {
		metrics.BackupCopies.WithLabelValues(c.Name, c.Status).Inc()
	}
}

// finishRunTx records the terminal state and the run's copies (the rows
// freeze afterwards), queues a repair when one is due and emits the run's
// event (settleRunTx) in the same transaction. The run's blob_path, bytes,
// sha256 and tier come from its first succeeded copy. Both runners use it:
// a run of the olympos-self job (no target) gets the self event texts.
func finishRunTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, o outcome) (finished, error) {
	var jobID uuid.UUID
	var trigger, system, ns, svc, cluster, engine string
	var channel *uuid.UUID
	var started *time.Time
	var notifySuccess bool
	err := tx.QueryRow(ctx, `SELECT r.job_id, r.trigger, r.started_at, j.notify_channel_id, j.notify_on_success, j.system,
		COALESCE(t.namespace, ''), COALESCE(t.service, ''), COALESCE(c.name, ''), COALESCE(t.engine, 'postgresql')
		FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id LEFT JOIN targets t ON t.id = j.target_id LEFT JOIN clusters c ON c.id = t.cluster_id
		WHERE r.id = $1`, runID).Scan(&jobID, &trigger, &started, &channel, &notifySuccess, &system, &ns, &svc, &cluster, &engine)
	if err != nil {
		return finished{}, err
	}
	o.fromFirstCopy()
	steps, _ := json.Marshal(nonNilSteps(o.steps))
	tag, err := tx.Exec(ctx, `UPDATE backup_runs SET status = $2, finished_at = now(), bytes = $3, wire_bytes = $4, blob_path = $5,
		sha256 = $6, error = $7, tier = CASE WHEN $8 = '' THEN tier ELSE $8 END, steps = $9 WHERE id = $1 AND finished_at IS NULL`,
		runID, o.status, o.bytes, o.wire, o.blobPath, o.sha256, o.err, o.tier, steps)
	if err != nil {
		return finished{}, err
	}
	if tag.RowsAffected() == 0 {
		return finished{}, nil
	}
	for _, c := range o.copies {
		var cStarted *time.Time
		if !c.StartedAt.IsZero() {
			cStarted = &c.StartedAt
		}
		if _, err := tx.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, blob_path, bytes, sha256, tier, error,
			started_at, finished_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10, now()))`,
			runID, c.DestinationID, c.Status, c.BlobPath, c.Bytes, c.SHA256, c.Tier, c.Err, cStarted, nonZeroTime(c.FinishedAt)); err != nil {
			return finished{}, err
		}
	}
	f := finished{engine: engine, status: o.status, started: started, copies: o.copies, ok: true}
	n, err := settleRunTx(ctx, tx, runID, o, time.Now())
	if err != nil {
		return finished{}, err
	}
	if n.Type == "" || n.Type == notify.BackupSucceeded && !notifySuccess {
		return f, nil // backup.succeeded is opt-in per job
	}
	subject, errText := ns+"/"+svc, shortError(o.err)
	fields := map[string]string{"cluster": cluster, "target": subject, "trigger": trigger}
	ev := notify.Event{Type: n.Type, Key: n.Type + ":" + runID.String(), ChannelID: channel,
		Link: "/backups?job=" + jobID.String() + "&run=" + runID.String(), Fields: fields,
		Payload: map[string]any{"job_id": jobID.String(), "run_id": runID.String()}}
	if system == SelfSystem {
		// The self runner always sent the whole error.
		subject, errText = "Olympos database ("+SelfSystem+")", o.err
		fields = map[string]string{"target": SelfSystem, "trigger": trigger}
		ev.Link, ev.Fields = "/backups?self=1&run="+runID.String(), fields
	}
	n.addPayload(ev.Payload)
	switch n.Type {
	case notify.BackupSucceeded:
		ev.Title = "Backup succeeded: " + subject
		fields["size"] = humanBytes(o.bytes)
		fields["tier"] = o.tier
	case notify.BackupPartial:
		ev.Title = "Backup incomplete: " + subject
		fields["missing"] = strings.Join(n.Missing, ", ")
		fields["error"] = errText
		if n.NextAttemptAt != nil {
			fields["next_attempt"] = n.NextAttemptAt.UTC().Format(time.RFC3339)
		}
	case notify.BackupMissed:
		ev.Title = "Backup missed: " + subject
		fields["error"] = errText
		ev.Payload["reason"] = shortError(o.err)
	default:
		ev.Title = "Backup failed: " + subject
		if n.Missing != nil {
			fields["missing"] = strings.Join(n.Missing, ", ")
		}
		fields["error"] = errText
		ev.Payload["reason"] = shortError(o.err)
	}
	return f, notify.Emit(ctx, tx, ev)
}

// runNotice is the event a finished run emits (settleRunTx).
type runNotice struct {
	// Type is a notify.Backup* event type, or "" for none.
	Type string
	// RepairOf is the original run when the run is a repair.
	RepairOf *uuid.UUID
	// Missing names the destinations without a copy, in destination_ids
	// order (backup.partial, and backup.failed of a repair that gives up).
	Missing []string
	// RepairQueued: a repair of the partial run is queued (backup.partial),
	// to start at NextAttemptAt.
	RepairQueued  bool
	NextAttemptAt *time.Time
}

// addPayload adds the notice's payload keys to p.
func (n runNotice) addPayload(p map[string]any) {
	if n.RepairOf != nil {
		p["repair_of"] = n.RepairOf.String()
	}
	if n.Missing != nil {
		p["missing_destinations"] = n.Missing
	}
	if n.Type == notify.BackupPartial {
		p["repair_queued"] = n.RepairQueued
		if n.NextAttemptAt != nil {
			p["next_attempt_at"] = n.NextAttemptAt.UTC().Format(time.RFC3339)
		}
	}
}

// settleRunTx runs after a run's status and copies are recorded, in the same
// transaction: it queues a repair when one is due (queueRepairTx) and
// decides which event the run emits.
//   - Test runs, retried attempts (o.quiet) and a repair with nothing left
//     to repair emit nothing.
//   - A partial run emits backup.partial with its missing destinations,
//     whether a repair is queued and when it starts.
//   - A repair that ends partial, failed or missed (agent away past the
//     disconnect limit) is quiet while another repair is queued; when none
//     is (MaxRepairs used, or the next one would start after the window),
//     it gives up with backup.failed naming the copies still missing, never
//     backup.missed.
//   - Otherwise succeeded, missed and failed map to their events (a
//     succeeded repair completed every missing copy). backup.succeeded is
//     opt-in: the caller checks the job's setting.
func settleRunTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, o outcome, now time.Time) (runNotice, error) {
	var trigger string
	var repairOf *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT trigger, repair_of FROM backup_runs WHERE id = $1`, runID).Scan(&trigger, &repairOf); err != nil {
		return runNotice{}, err
	}
	if trigger == "test" || o.quiet || repairOf != nil && o.err == errNothingToRepair {
		return runNotice{}, nil
	}
	n := runNotice{RepairOf: repairOf}
	switch {
	case o.status == "partial" && repairOf == nil:
		next, err := queueRepairTx(ctx, tx, runID, now)
		if err != nil {
			return runNotice{}, err
		}
		missing, err := missingDestinationsTx(ctx, tx, runID, false)
		if err != nil {
			return runNotice{}, err
		}
		n.Type, n.Missing, n.RepairQueued, n.NextAttemptAt = notify.BackupPartial, destNames(missing), next != nil, next
	case repairOf != nil && (o.status == "partial" || o.status == "failed" || o.status == "missed"):
		next, err := queueRepairTx(ctx, tx, runID, now)
		if err != nil || next != nil {
			return runNotice{}, err
		}
		missing, err := missingDestinationsTx(ctx, tx, *repairOf, true)
		if err != nil || len(missing) == 0 {
			return runNotice{}, err // nothing missing that the job still writes to
		}
		n.Type, n.Missing = notify.BackupFailed, destNames(missing)
	case o.status == "succeeded":
		n.Type = notify.BackupSucceeded
	case o.status == "missed":
		n.Type = notify.BackupMissed
	default:
		n.Type = notify.BackupFailed
	}
	return n, nil
}

func destNames(ds []destRef) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Name
	}
	return out
}

func nonZeroTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
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

// Step is one line of the dry-run checklist (F10).
type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func nonNilSteps(s []Step) []Step {
	if s == nil {
		return []Step{}
	}
	return s
}

// dryRunSteps turns a dry run's outcome into the checklist the wizard shows:
// each stage that ran, with its result; stages after a failure are left out.
// A run with several destinations gets an upload step per destination and
// a manifest step per uploaded copy; a single-destination run reads as it
// always did.
func dryRunSteps(o outcome, rr *RunResult, job *Job) []Step {
	var out []Step
	add := func(name string, ok bool, detail string) { out = append(out, Step{Name: name, OK: ok, Detail: detail}) }
	target := "the target"
	if job != nil {
		target = job.Target.Namespace + "/" + job.Target.Service
	}
	failed := o.status != "succeeded"
	if o.err == errAgentOffline || strings.HasPrefix(o.err, errAgentDisconnected) {
		add("agent", false, "The cluster's agent is not connected")
		return out
	}
	add("agent", true, "Agent connected; tunnel to "+target)
	if failed && strings.HasPrefix(o.err, "credential") {
		add("credential", false, o.err)
		return out
	}
	add("credential", true, "Credential resolved")
	if len(o.copies) > 1 {
		return append(out, copySteps(o, rr)...)
	}
	if failed && strings.HasPrefix(o.err, "open destination") {
		add("destination", false, o.err)
		return out
	}
	if failed && !strings.HasPrefix(o.err, "upload") {
		add("engine", false, o.err)
		return out
	}
	add("engine", true, engineDetail(rr))
	if failed && strings.HasPrefix(o.err, "upload manifest") {
		add("upload", true, fmt.Sprintf("Wrote %s", humanBytes(o.bytes)))
		add("manifest", false, o.err)
		return out
	}
	if failed {
		add("upload", false, o.err)
		return out
	}
	dest := "the destination"
	if len(o.copies) == 1 {
		dest = o.copies[0].Name
	} else if job != nil && job.DestinationName != "" {
		dest = job.DestinationName
	}
	add("upload", true, fmt.Sprintf("Wrote %s to %s (%s on the wire)", humanBytes(o.bytes), dest, humanBytes(o.wire)))
	add("manifest", true, "Manifest with checksum written")
	return out
}

// copySteps is the rest of the checklist for a run with several copies: the
// destinations when none could be opened, else the engine, one upload step
// per destination and one manifest step per uploaded copy.
func copySteps(o outcome, rr *RunResult) []Step {
	var out []Step
	add := func(name string, ok bool, detail string) { out = append(out, Step{Name: name, OK: ok, Detail: detail}) }
	opened := false
	for _, c := range o.copies {
		opened = opened || !strings.HasPrefix(c.Err, "open destination")
	}
	if !opened {
		for _, c := range o.copies {
			add("destination", false, c.Name+": "+c.Err)
		}
		return out
	}
	if o.engineFailed {
		add("engine", false, o.err)
		return out
	}
	add("engine", true, engineDetail(rr))
	uploaded := func(c copyResult) bool {
		return c.Status == "succeeded" || strings.HasPrefix(c.Err, "upload manifest") || strings.HasPrefix(c.Err, "encode manifest")
	}
	for _, c := range o.copies {
		switch {
		case c.Status == "succeeded":
			add("upload", true, fmt.Sprintf("Wrote %s to %s (%s on the wire)", humanBytes(c.Bytes), c.Name, humanBytes(o.wire)))
		case uploaded(c):
			add("upload", true, "Wrote the backup to "+c.Name)
		default:
			add("upload", false, c.Name+": "+c.Err)
		}
	}
	for _, c := range o.copies {
		if c.Status == "succeeded" {
			add("manifest", true, "Manifest with checksum written to "+c.Name)
		} else if uploaded(c) {
			add("manifest", false, c.Name+": "+c.Err)
		}
	}
	return out
}

func engineDetail(rr *RunResult) string {
	detail := "Connected and dumped the schema"
	if rr != nil && rr.ServerVersion != "" {
		detail += " · server " + rr.ServerVersion
	}
	if rr != nil && rr.ToolVersion != "" {
		detail += " · " + rr.ToolVersion
	}
	if rr != nil && rr.TLS != nil {
		if *rr.TLS {
			detail += " · TLS verified"
		} else {
			detail += " · no TLS"
		}
	}
	return detail
}

// runRow is what Execute needs from backup_runs.
type runRow struct {
	id           uuid.UUID
	jobID        uuid.UUID
	trigger      string
	scheduledFor *time.Time
	startedAt    time.Time
	repairOf     *uuid.UUID
}

// Execute runs one claimed run to completion and records the result.
func (w *Worker) Execute(ctx context.Context, runID uuid.UUID) {
	w.active.Add(1)
	defer w.active.Add(-1)
	var r runRow
	var started *time.Time
	err := w.DB.QueryRow(ctx, `SELECT id, job_id, trigger, scheduled_for, started_at, repair_of FROM backup_runs WHERE id = $1`, runID).
		Scan(&r.id, &r.jobID, &r.trigger, &r.scheduledFor, &started, &r.repairOf)
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
	if r.trigger == "test" {
		o.steps = dryRunSteps(o, rr, job)
	}

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var f finished
	// F18: a run that failed because the agent is gone is retried after
	// the reconnect while inside the job's window, else it is missed.
	disconnected := o.status == "failed" && job != nil && r.trigger != "test" &&
		(o.err == errAgentOffline || w.Dialer != nil && !w.Dialer.Connected(job.Target.ClusterID))
	err = store.Tx(fctx, w.DB, func(tx pgx.Tx) error {
		var err error
		if disconnected {
			if o, err = disconnectedOutcome(fctx, tx, runID, o, time.Now()); err != nil {
				return err
			}
		}
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
	dests, err := runDestinations(ctx, w.DB, r.id)
	if err != nil {
		return fail(tr.scrub("resolve destinations: " + err.Error())), nil, job
	}
	if len(dests) == 0 {
		if r.repairOf != nil {
			return fail(errNothingToRepair), nil, job
		}
		return fail("the job has no destination"), nil, job
	}
	tiers, err := copyTiers(ctx, w.DB, job.ID, job.Timezone, r, dests)
	if err != nil {
		return fail(tr.scrub("decide retention tier: " + err.Error())), nil, job
	}
	var group *ManifestGroup
	if job.DestinationGroupID != nil {
		members, err := groupMembers(ctx, w.DB, *job.DestinationGroupID)
		if err != nil {
			return fail(tr.scrub("load destination group: " + err.Error())), nil, job
		}
		group = &ManifestGroup{Name: job.DestinationName, Members: members}
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

	path := func(prefix string) string {
		return BlobPath(prefix, job.Target.ClusterName, job.Target.Namespace, job.Target.Service, eng.Name(), r.startedAt, r.id, eng.Ext())
	}
	manifest := func(d destRef, b ManifestBlob, tier string) Manifest {
		return Manifest{
			Format: ManifestFormat, RunID: r.id, JobID: job.ID, Trigger: r.trigger, Tier: tier, ScheduledFor: r.scheduledFor,
			StartedAt: r.startedAt.UTC(), FinishedAt: time.Now().UTC(),
			Cluster: ManifestCluster{ID: job.Target.ClusterID, Name: job.Target.ClusterName},
			Target: ManifestTarget{ID: job.Target.ID, Namespace: job.Target.Namespace, Service: job.Target.Service, Port: job.Target.Port,
				TLSServerName: ec.TLSServerName},
			Engine: eng.Name(), EngineOptions: redactOptions(job.EngineOptions),
			Blob: b, WireBytes: wc.total(), TransferMode: job.TransferMode, Test: r.trigger == "test",
			Destination: &ManifestDestination{Name: d.Name, Kind: d.Kind}, Group: group,
		}
	}
	rr, copies, streamed, engErr := streamCopies(ctx, eng, ec, dests, w.Blobs.ForDestination, path, tiers, manifest, tr.scrub)
	return copiesOutcome(ctx, copies, streamed, wc.total(), tiers[dests[0].ID], engErr, tr.scrub), rr, job
}

// copiesOutcome is the outcome of a run from what streamCopies returned
// (both runners): its status from the engine and the copies, its error and
// its blob columns from the first succeeded copy (without one, bytes stays
// what was streamed).
func copiesOutcome(ctx context.Context, copies []copyResult, streamed, wire int64, tier string, engErr error, scrub func(string) string) outcome {
	o := outcome{bytes: streamed, wire: wire, tier: tier, copies: copies}
	o.fromFirstCopy()
	o.status = runStatus(engErr, copies)
	switch {
	case engErr != nil:
		msg := engErr.Error()
		if errors.Is(engErr, gateway.ErrAgentOffline) {
			msg = errAgentOffline
		}
		o.err, o.engineFailed = scrub(msg), true
	case o.status == "failed" && ctx.Err() != nil:
		o.err, o.engineFailed = "interrupted: server shutting down", true
	case o.status == "failed":
		// Every copy failed: the first one is the root cause.
		o.err = copies[0].Err
	case o.status == "partial":
		o.err = scrub(copiesError(copies))
	}
	return o
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

// copyTiers decides the GFS tier of each copy at write time (SPEC §10.3):
// the first successful scheduled copy of the month (job time zone tz) on a
// destination is monthly, else the first of the ISO week is weekly, else
// daily. Manual runs are daily, test runs test.
func copyTiers(ctx context.Context, q store.Querier, jobID uuid.UUID, tz string, r *runRow, dests []destRef) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(dests))
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	ref := r.startedAt
	if r.scheduledFor != nil {
		ref = *r.scheduledFor
	}
	for _, d := range dests {
		switch r.trigger {
		case "test":
			out[d.ID] = "test"
		case "schedule":
			t, err := TierForDestination(ctx, q, jobID, r.id, d.ID, ref, loc)
			if err != nil {
				return nil, err
			}
			out[d.ID] = t
		default:
			out[d.ID] = "daily"
		}
	}
	return out, nil
}

// gfsTier is monthly when count finds nothing in ref's month (in loc), else
// weekly when it finds nothing in ref's ISO week, else daily.
func gfsTier(ref time.Time, loc *time.Location, count func(from, to time.Time) (int, error)) (string, error) {
	t := ref.In(loc)
	monthStart := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
	monthEnd := monthStart.AddDate(0, 1, 0)
	wd := (int(t.Weekday()) + 6) % 7 // Monday = 0 (ISO week)
	weekStart := time.Date(t.Year(), t.Month(), t.Day()-wd, 0, 0, 0, 0, loc)
	weekEnd := weekStart.AddDate(0, 0, 7)
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
