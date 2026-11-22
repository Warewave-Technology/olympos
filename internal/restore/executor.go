package restore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Executor runs approved restore requests (docs/design/ui-restore.md
// "Execution"): it claims them like the backup worker claims runs, checks
// the copy and the target again, and hands the copy to the engine's
// Restorer. There are no retries: a failed restore is a new request.
type Executor struct {
	DB       *store.DB
	Log      *slog.Logger
	Dialer   backup.Dialer
	Blobs    blob.ReaderResolver
	Creds    *backup.Credentials
	Envelope *secrets.Envelope
	// Global is the max restores at once on this replica (default 2);
	// PerCluster the max running backup runs and restores together per
	// cluster, across replicas (backup.perClusterConcurrency, default 2).
	Global, PerCluster int
	// Poll is the idle wait between claims (default 5 s).
	Poll time.Duration
	// Heartbeat writes progress at least this often (default 30 s); a
	// running request without a write for StaleAfter (default 5 min) is
	// failed by any replica (ReapStale).
	Heartbeat, StaleAfter time.Duration
	// ProgressEvery throttles progress writes between heartbeats (default
	// 2 s). A newly created database is written at once.
	ProgressEvery time.Duration
	// InspectTimeout bounds the start-time check of the target (default 60 s).
	InspectTimeout time.Duration
	Now            func() time.Time
}

// Error texts of interrupted restores.
const (
	reapedMessage      = "interrupted: server stopped during the restore"
	interruptedMessage = reapedMessage
)

// Run claims and executes approved requests until ctx is done, then waits
// for the restores in flight (they are interrupted by ctx and recorded as
// failed). It also reaps requests left running by a stopped replica.
func (x *Executor) Run(ctx context.Context) {
	global, _ := x.limits()
	poll := x.Poll
	if poll <= 0 {
		poll = 5 * time.Second
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
			if err := x.ReapStale(ctx); err != nil && ctx.Err() == nil {
				x.Log.Error("reap stale restores", "err", err.Error())
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
		id, err := x.Claim(ctx)
		if err != nil && ctx.Err() == nil {
			x.Log.Error("claim restore request", "err", err.Error())
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
			x.Execute(ctx, id)
		}()
	}
}

// job is a claimed request as the executor reads it.
type job struct {
	id        uuid.UUID
	status    Status
	engine    string
	runID     uuid.UUID
	destID    uuid.UUID
	copyRunID uuid.UUID
	targetID  string
	databases []string
	opts      Options
	credID    *uuid.UUID
	sealed    secrets.Sealed
}

func (x *Executor) load(ctx context.Context, id uuid.UUID) (*job, error) {
	j := &job{id: id}
	var st string
	var opts []byte
	err := x.DB.QueryRow(ctx, `SELECT status, engine, source_run_id, source_destination_id, source_copy_run_id, target_id, databases, options,
		credential_id, sealed_token, wrapped_dek, kek_version FROM restore_requests WHERE id = $1`, id).
		Scan(&st, &j.engine, &j.runID, &j.destID, &j.copyRunID, &j.targetID, &j.databases, &opts, &j.credID,
			&j.sealed.Ciphertext, &j.sealed.WrappedDEK, &j.sealed.KEKVersion)
	if err != nil {
		return nil, err
	}
	j.status = Status(st)
	if err := json.Unmarshal(opts, &j.opts); err != nil {
		return nil, fmt.Errorf("restore options: %w", err)
	}
	if j.databases == nil {
		j.databases = []string{}
	}
	return j, nil
}

// Execute runs one claimed (running) request to its end: the rules again,
// the copy's SHA-256 before anything connects to the target, the target's
// check over the tunnel (reads only), then the engine's Restorer. It
// records succeeded or failed with the result and wipes the request's
// secrets. A request that is not running (reaped meanwhile) is left alone.
func (x *Executor) Execute(ctx context.Context, id uuid.UUID) {
	j, err := x.load(ctx, id)
	if err != nil {
		x.Log.Error("load restore request", "restore_id", id, "err", err.Error())
		return
	}
	if j.status != StatusRunning {
		x.Log.Info("restore request not running; not executed", "restore_id", id, "status", string(j.status))
		return
	}
	pw := newProgressWriter(x, id)
	hbCtx, stopHB := context.WithCancel(ctx)
	hbDone := make(chan struct{})
	go func() { pw.run(hbCtx); close(hbDone) }()
	res, msg := x.perform(ctx, j, pw)
	stopHB()
	<-hbDone

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	pw.flush(fctx)
	res.Created = union(res.Created, pw.createdSoFar())
	if msg != "" && ctx.Err() != nil {
		msg = interruptedMessage
	}
	st := StatusSucceeded
	if msg != "" {
		st = StatusFailed
	}
	var finished bool
	err = store.Tx(fctx, x.DB, func(tx pgx.Tx) error {
		var err error
		finished, err = finishTx(fctx, tx, id, st, res, msg, x.now())
		return err
	})
	if err != nil {
		x.Log.Error("finish restore request", "restore_id", id, "err", err.Error())
		return
	}
	if !finished {
		x.Log.Warn("restore request ended elsewhere while it ran (reaped)", "restore_id", id)
		return
	}
	lvl := slog.LevelInfo
	if st == StatusFailed {
		lvl = slog.LevelWarn
	}
	x.Log.Log(fctx, lvl, "restore finished", "restore_id", id, "target_id", j.targetID, "status", string(st),
		"created", strings.Join(res.Created, ","), "error", msg)
}

// perform does the work of a request and returns its result (never nil) and
// the failure ("" when it succeeded). Messages are scrubbed of the
// request's secrets.
func (x *Executor) perform(ctx context.Context, j *job, pw *progressWriter) (*backup.RestoreResult, string) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
	tr := &backup.SecretScrubber{}
	defer tr.Zero()
	fail := func(msg string) (*backup.RestoreResult, string) { return res, tr.Scrub(msg) }
	internal := func(what string, err error) (*backup.RestoreResult, string) {
		x.Log.Error("restore: "+what, "restore_id", j.id, "err", tr.Scrub(err.Error()))
		return res, "internal error: could not " + what
	}

	// 1. The rules that need only Olympos' database: nothing is read from
	// the backup or sent to the target before they pass.
	run, err := loadSourceRun(ctx, x.DB, j.runID)
	if err != nil {
		return internal("load the backup run", err)
	}
	if run.targetID == nil {
		return fail(selfRunMessage)
	}
	// The backup's engine is the one the request recorded at open.
	run.engine = j.engine
	t, err := loadTargetInfo(ctx, x.DB, j.targetID)
	if err != nil {
		return internal("load the target", err)
	}
	fields := map[string]string{}
	src, err := sourceRules(ctx, x.DB, run, j.runID, &j.destID, fields)
	if err != nil {
		return internal("find the backup copy", err)
	}
	if src != nil && src.CopyRunID != j.copyRunID {
		fields["copy_destination_id"] = "the copy approved for this request is no longer the one this destination offers; open a new request"
	}
	if t.clusterStatus == "revoked" {
		fields["target_id"] = "the target's cluster is revoked"
	} else {
		targetRules(run, t, j.targetID, fields)
	}
	if len(fields) > 0 {
		return fail("the restore cannot start: " + describeFields(fields))
	}
	restorer, ok := backup.RestorerFor(j.engine)
	if !ok {
		return fail(noInspectorMessage(j.engine))
	}
	if _, ok := InspectorFor(j.engine); !ok {
		return fail(noInspectorMessage(j.engine))
	}

	// 2. Verify the copy: one sequential pass, before any connection to
	// the target. The same opened object (its ETag pinned) is restored.
	pw.phase("verify")
	if src.SHA256 == "" {
		return fail("the copy has no recorded SHA-256, so it cannot be verified; nothing was written to the target")
	}
	rd, err := x.Blobs.ReaderFor(ctx, src.DestinationID)
	if err != nil {
		return fail("open the backup's destination: " + err.Error())
	}
	obj, err := rd.Open(ctx, src.BlobPath)
	if err != nil {
		return fail("open the backup: " + err.Error())
	}
	defer obj.Close()
	pw.setTotal(obj.Size())
	counted := &countingObject{Object: obj, p: pw}
	sum, err := blob.SequentialSHA256(ctx, counted)
	if err != nil {
		return fail("read the backup: " + err.Error())
	}
	if !strings.EqualFold(sum, src.SHA256) {
		return fail(fmt.Sprintf("the backup copy is corrupted: its SHA-256 is %s, the backup recorded %s; nothing was written to the target",
			sum, strings.ToLower(src.SHA256)))
	}
	if msg, note := x.checkManifest(ctx, rd, src, sum); msg != "" {
		return fail(msg)
	} else if note != "" {
		res.Notes = append(res.Notes, note)
	}

	// 3. The target again, over the tunnel and with the request's
	// credential (reads only): time passed since the approval.
	pw.phase("check")
	cred := func(ctx context.Context) (backup.Credential, error) {
		if j.engine == "vault" {
			if len(j.sealed.Ciphertext) == 0 {
				return backup.Credential{}, errors.New("the request holds no Vault token")
			}
			tok, err := x.Envelope.Open(ctx, j.sealed, TokenAAD(j.id))
			if err != nil {
				return backup.Credential{}, fmt.Errorf("unseal the restore token: %w", err)
			}
			return tr.Track(backup.Credential{Secret: tok}), nil
		}
		if j.credID == nil {
			return backup.Credential{}, errors.New("the request holds no credential")
		}
		c, err := x.Creds.Resolve(ctx, x.DB, *j.credID)
		return tr.Track(c), err
	}
	ec, _, err := backup.TargetEngineContext(ctx, x.DB, x.Dialer, j.targetID, EngineOptions(j.engine, j.opts), cred)
	if err != nil {
		return internal("build the target's connection", err)
	}
	rep, fields, notes, err := inspectTarget(ctx, j.engine, ec, j.databases, x.InspectTimeout)
	if err != nil {
		return fail("the target check failed: " + err.Error())
	}
	if len(fields) > 0 {
		return fail("the target cannot take this restore: " + describeFields(fields))
	}
	opts := j.opts
	superuser := false
	if j.engine == "postgresql" {
		approved := opts.Superuser != nil && *opts.Superuser
		superuser = approved && rep.Superuser
		if approved && !rep.Superuser {
			// Restore what the credential allows; the approval covered more.
			f := false
			opts.Superuser, opts.Globals = &f, &f
		}
	}
	res.Notes = append(res.Notes, notes...)
	raw, err := json.Marshal(opts)
	if err != nil {
		return internal("encode the options", err)
	}

	// 4. The engine.
	pw.phase("restore")
	window := newWindowObject(counted, readWindow)
	rc := backup.RestoreContext{EngineContext: ec, Databases: j.databases, Options: raw, Superuser: superuser, Progress: pw.report}
	if j.engine == "vault" {
		rc.Snapshot = io.NewSectionReader(window, 0, window.Size())
	} else {
		rc.Archive = window
	}
	out, err := restorer.Restore(ctx, rc)
	if out != nil {
		if out.Items != nil {
			res.Items = out.Items
		}
		res.Notes = append(res.Notes, out.Notes...)
		res.Created = union(out.Created, nil)
	}
	// Engines report what the target said: never with the credential in it.
	for i := range res.Items {
		res.Items[i].Error = tr.Scrub(res.Items[i].Error)
		for k, sk := range res.Items[i].Skipped {
			res.Items[i].Skipped[k] = tr.Scrub(sk)
		}
	}
	for i, n := range res.Notes {
		res.Notes[i] = tr.Scrub(n)
	}
	if err != nil {
		return fail("the restore failed: " + err.Error())
	}
	var failed []string
	for _, it := range res.Items {
		if it.Status == "failed" {
			failed = append(failed, it.Name)
		}
	}
	if len(failed) > 0 {
		return fail("the restore failed for: " + strings.Join(failed, ", "))
	}
	return res, ""
}

// checkManifest compares the copy's digest with the one its sidecar
// manifest records. A different digest fails the request; a manifest that
// cannot be read (or records none) is a note: the copy row is the
// authority and was checked already.
func (x *Executor) checkManifest(ctx context.Context, rd blob.Reader, src *backup.RestoreSource, sum string) (fail, note string) {
	const unread = "The copy was verified against the SHA-256 Olympos recorded; its sidecar manifest "
	o, err := rd.Open(ctx, backup.ManifestPath(src.BlobPath, src.CopyRunID))
	if err != nil {
		return "", unread + "could not be read"
	}
	defer o.Close()
	if o.Size() > maxSidecarManifest {
		return "", unread + "is too large"
	}
	b, err := io.ReadAll(io.NewSectionReader(o, 0, o.Size()))
	if err != nil {
		return "", unread + "could not be read"
	}
	var m struct {
		Blob struct {
			SHA256 string `json:"sha256"`
		} `json:"blob"`
	}
	if json.Unmarshal(b, &m) != nil || m.Blob.SHA256 == "" {
		return "", unread + "records no checksum"
	}
	if !strings.EqualFold(m.Blob.SHA256, sum) {
		return fmt.Sprintf("the backup copy does not match its manifest: its SHA-256 is %s, the manifest records %s; nothing was written to the target",
			sum, strings.ToLower(m.Blob.SHA256)), ""
	}
	return "", ""
}

// describeFields turns rule failures into one sentence, in key order.
func describeFields(f map[string]string) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + f[k]
	}
	return strings.Join(parts, "; ")
}

// union returns a followed by the names of b it lacks, without duplicates
// (never nil).
func union(a, b []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------- finish and reap

// finishTx ends a running request: status, result, error and finished_at,
// its secrets wiped (Wipe) in the same transaction, and restore.succeeded or
// restore.failed in the audit log and as an event, on the backup's cluster.
// A failure names the databases created (they stay on the target). It
// returns false when the request was no longer running.
func finishTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, st Status, res *backup.RestoreResult, msg string, now time.Time) (bool, error) {
	if st == StatusFailed && len(res.Created) > 0 {
		msg += "; databases created and left in place: " + strings.Join(res.Created, ", ")
	}
	b, err := json.Marshal(res)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE restore_requests SET status = $2, result = $3, error = $4, finished_at = $5
		WHERE id = $1 AND status = 'running'`, id, string(st), b, msg, now)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if err := Wipe(ctx, tx, id); err != nil {
		return false, err
	}
	rq, err := loadRequest(ctx, tx, id)
	if err != nil {
		return false, err
	}
	details := map[string]any{"run_id": rq.Source.RunID, "target_id": rq.Target.ID, "engine": rq.Engine, "created": res.Created}
	fields := summary(rq)
	payload := eventPayload(rq)
	evType, title := notify.RestoreSucceeded, "Restore succeeded: "
	if st == StatusFailed {
		evType, title = notify.RestoreFailed, "Restore failed: "
		details["error"] = msg
		fields["Error"] = shortError(msg)
		payload["reason"] = shortError(msg)
	}
	if len(res.Created) > 0 {
		fields["Created"] = strings.Join(res.Created, ", ")
	}
	payload["created"] = res.Created
	if err := activity.Record(ctx, tx, activity.Entry{Action: evType, ObjectType: "restore_request", ObjectID: id.String(),
		ClusterID: &rq.Source.ClusterID, Details: details}); err != nil {
		return false, err
	}
	return true, notify.Emit(ctx, tx, notify.Event{Type: evType, Key: evType + ":" + id.String(),
		Title: title + rq.Target.Namespace + "/" + rq.Target.Service, Link: Link(id), Fields: fields, Payload: payload})
}

func shortError(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ReapStale fails running requests without a progress write for StaleAfter
// (the replica running them stopped): the databases created so far (from
// the last progress) are listed and stay on the target, the secrets are
// wiped and the target is free for a new request.
func (x *Executor) ReapStale(ctx context.Context) error {
	n := 0
	err := store.Tx(ctx, x.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, progress FROM restore_requests
			WHERE status = 'running' AND updated_at < now() - make_interval(secs => $1::double precision)
			FOR UPDATE SKIP LOCKED`, x.staleAfter().Seconds())
		if err != nil {
			return err
		}
		type stale struct {
			id       uuid.UUID
			progress backup.Progress
		}
		var ss []stale
		for rows.Next() {
			var s stale
			var b []byte
			if err := rows.Scan(&s.id, &b); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(b, &s.progress)
			ss = append(ss, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, s := range ss {
			res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: union(s.progress.Created, nil)}
			ok, err := finishTx(ctx, tx, s.id, StatusFailed, res, reapedMessage, x.now())
			if err != nil {
				return err
			}
			if ok {
				n++
			}
		}
		return nil
	})
	if n > 0 {
		x.Log.Warn("stale restores failed", "count", n)
	}
	return err
}

func (x *Executor) staleAfter() time.Duration {
	if x.StaleAfter > 0 {
		return x.StaleAfter
	}
	return 5 * time.Minute
}

// ---------------------------------------------------------------- progress

// progressWriter keeps a request's latest progress and writes it: at most
// every ProgressEvery, at least every Heartbeat (the heartbeat the reaper
// looks for), and at once when a database was created, so that a stopped
// server still lists it. Bytes and Total are the executor's: bytes of the
// backup read in the current phase, of its size.
type progressWriter struct {
	x    *Executor
	id   uuid.UUID
	read atomic.Int64
	kick chan struct{}

	mu      sync.Mutex
	cur     backup.Progress
	created []string
	size    int64
	last    time.Time

	writeMu sync.Mutex
}

func newProgressWriter(x *Executor, id uuid.UUID) *progressWriter {
	return &progressWriter{x: x, id: id, kick: make(chan struct{}, 1)}
}

func (p *progressWriter) poke() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// phase starts a phase: the byte count starts again.
func (p *progressWriter) phase(name string) {
	p.mu.Lock()
	p.cur = backup.Progress{Phase: name}
	p.read.Store(0)
	p.mu.Unlock()
	p.poke()
}

func (p *progressWriter) setTotal(n int64) {
	p.mu.Lock()
	p.size = n
	p.mu.Unlock()
}

// report is RestoreContext.Progress.
func (p *progressWriter) report(pr backup.Progress) {
	p.mu.Lock()
	grew := false
	for _, d := range pr.Created {
		if !contains(p.created, d) {
			p.created = append(p.created, d)
			grew = true
		}
	}
	if pr.Phase == "" {
		pr.Phase = p.cur.Phase
	}
	pr.Done = append([]string{}, pr.Done...)
	p.cur = pr
	p.mu.Unlock()
	if grew {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p.flush(ctx)
		return
	}
	p.poke()
}

func (p *progressWriter) createdSoFar() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.created...)
}

func (p *progressWriter) flush(ctx context.Context) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	snap := p.cur
	snap.Bytes, snap.Total = p.read.Load(), p.size
	snap.Created = append([]string{}, p.created...)
	p.last = time.Now()
	p.mu.Unlock()
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	if _, err := p.x.DB.Exec(ctx, `UPDATE restore_requests SET progress = $2 WHERE id = $1 AND status = 'running'`, p.id, b); err != nil && ctx.Err() == nil {
		p.x.Log.Warn("restore progress", "restore_id", p.id, "err", err.Error())
	}
}

func (p *progressWriter) run(ctx context.Context) {
	hb := p.x.Heartbeat
	if hb <= 0 {
		hb = 30 * time.Second
	}
	every := p.x.ProgressEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	tick := time.NewTicker(hb)
	defer tick.Stop()
	var timer <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.flush(ctx)
		case <-timer:
			timer = nil
			p.flush(ctx)
		case <-p.kick:
			p.mu.Lock()
			wait := every - time.Since(p.last)
			p.mu.Unlock()
			if wait <= 0 {
				p.flush(ctx)
			} else if timer == nil {
				timer = time.After(wait)
			}
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// countingObject counts the bytes read from the backup for the progress.
type countingObject struct {
	blob.Object
	p *progressWriter
}

func (c *countingObject) ReadAt(b []byte, off int64) (int, error) {
	n, err := c.Object.ReadAt(b, off)
	c.p.read.Add(int64(n))
	c.p.poke()
	return n, err
}

// readWindow is the read-ahead of the object handed to restorers.
const readWindow = 8 << 20

// windowObject serves small reads at nearby offsets from one read-ahead
// window, so that the small reads of archive/zip and of the decompressors
// (a few KiB each) do not each become a ranged GET of the storage. Reads of
// at least the window's size go straight through. It is safe for
// concurrent use; readers at far apart offsets take turns with the window.
type windowObject struct {
	blob.Object
	mu  sync.Mutex
	buf []byte
	off int64 // offset of buf[0]
	n   int   // valid bytes in buf
	max int
}

func newWindowObject(o blob.Object, size int) *windowObject {
	return &windowObject{Object: o, max: size}
}

func (w *windowObject) ReadAt(p []byte, off int64) (int, error) {
	if len(p) >= w.max {
		return w.Object.ReadAt(p, off)
	}
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	size := w.Size()
	if off >= size {
		return 0, io.EOF
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	end := off + int64(len(p))
	if end > size {
		end = size
	}
	if off < w.off || end > w.off+int64(w.n) {
		if w.buf == nil {
			w.buf = make([]byte, w.max)
		}
		want := int64(w.max)
		if rest := size - off; rest < want {
			want = rest
		}
		n, err := w.Object.ReadAt(w.buf[:want], off)
		if err != nil && !(errors.Is(err, io.EOF) && int64(n) == want) {
			w.n = 0
			return 0, err
		}
		w.off, w.n = off, n
	}
	n := copy(p, w.buf[off-w.off:w.n])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
