package backup

// Native backups (ClickHouse, design docs/design/clickhouse-native.md): the
// target runs its own BACKUP and writes it through the Olympos ingest
// endpoint (internal/ingest), which streams every object to the job's
// destinations. The worker opens the run's ingest session, with a credential
// that may write only the run's own prefix, hands the engine the run's URL
// and credential, and fans every object out to every destination
// (nativeSink), tagged incomplete. When the target reports the backup
// created, it signs the run's manifest, writes it next to the run's
// directory on each destination, still incomplete, re-tags the run's objects
// complete there, and the manifest last. The credential is revoked on every
// way out. Objects stay
// incomplete on a destination that did not get that far, and a lifecycle
// rule removes them.

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
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// NativeEngine is implemented by engines that also take native backups. The
// worker takes the native path for a job whose NativeJob says so, and the
// engine's Run for every other job.
type NativeEngine interface {
	Engine
	// NativeJob reads a job's engine_options: whether it takes native
	// backups, and of which databases.
	NativeJob(options json.RawMessage) (NativeJob, error)
	// BackupNative runs one native backup on the target and returns its
	// server version. When run.Stop delivers, or ctx ends, it ends the
	// backup on the target and returns an error; one that wraps
	// ErrNativeOrphan says the backup may still run there. The secret goes
	// to the target and nowhere else.
	BackupNative(ctx context.Context, ec EngineContext, run NativeRun) (serverVersion string, err error)
	// SignNativeManifest builds the manifest of a run whose backup the
	// target created, from what its ingest session stored and kept, signs it
	// with the Key Vault key in.KeyName and verifies what it signed.
	SignNativeManifest(ctx context.Context, in NativeManifestInput) (*NativeManifestResult, error)
}

// NativeJob is what a job's engine_options say about native backups.
type NativeJob struct {
	Native bool
	// Databases are backed up whole; empty means every database the backup
	// user sees, except the system databases.
	Databases []string
}

// NativeRun is one native backup, as the engine runs it.
type NativeRun struct {
	// URL is the run's directory on the ingest endpoint,
	// "<ingest.url>/olympos/<run-id>/".
	URL string
	// AccessKey and Secret are the run's ingest credential.
	AccessKey, Secret string
	// RunID is the backup run, a lower-case UUID.
	RunID     string
	Databases []string
	// Stop delivers why the run's ingest session stopped (a quota, a failed
	// destination, a server shutting down): the engine ends the backup.
	Stop <-chan string
}

// String and LogValue keep the secret out of every print and log of a run.
func (nr NativeRun) String() string {
	return fmt.Sprintf("backup.NativeRun{run %s, key %s, secret redacted}", nr.RunID, nr.AccessKey)
}
func (nr NativeRun) GoString() string { return nr.String() }

func (nr NativeRun) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run", nr.RunID), slog.String("access_key", nr.AccessKey))
}

// NativeManifestInput is what a native run's manifest is built from.
type NativeManifestInput struct {
	KV            secrets.KeyVault
	KeyName       string // keyVault.manifestKeyName
	RunID         string
	ServerVersion string
	// Objects are the objects the session stored (Session.Objects).
	Objects []ingest.ObjectRecord
	// Captured returns a body the session kept (Session.Captured).
	Captured func(key string) ([]byte, bool)
}

// NativeManifestResult is a signed native manifest.
type NativeManifestResult struct {
	// Signed is its stored form, as signed and verified: it goes into the
	// sidecar's Details unchanged (NativeManifestDetail).
	Signed json.RawMessage
	// SHA256 is the hex SHA-256 of the canonical manifest, what the
	// signature covers and what an incremental names as its base: the run's
	// and its copies' sha256.
	SHA256 string
}

// ErrNativeOrphan says a native backup may still run on the target after its
// run ended: the run lost track of it, and ending it failed.
var ErrNativeOrphan = errors.New("the native backup may still be running on the target")

// NativeConfig is what native runs need from the server.
type NativeConfig struct {
	// Registry holds the ingest sessions; URL is ingest.url, the endpoint
	// as the target reaches it.
	Registry *ingest.Registry
	URL      string
	// MaxRunDuration is the longest a run's credential lives
	// (ingest.maxRunDuration, 6 h when 0).
	MaxRunDuration time.Duration
	// KV and ManifestKeyName sign the manifests (keyVault.manifestKeyName).
	KV              secrets.KeyVault
	ManifestKeyName string
}

const (
	// NativeManifestDetail is the key of a native run's sidecar Details
	// that holds its signed manifest, as signed: a reader passes exactly
	// those bytes to the manifest's verification.
	NativeManifestDetail = "native"
	// MaxNativeSidecarBytes caps a native run's sidecar: the signed
	// manifest (at most 64 MiB) and the rest of the sidecar. Readers cap
	// what they read at the same size.
	MaxNativeSidecarBytes = 64<<20 + 1<<20

	errIngestOff    = "the ingest endpoint is off: set ingest.url"
	errNativeRepair = "a native run is not repaired; the next run is a full backup"
	// nativeQuotaDefault is how much a run may write when the job has no
	// full native run yet; nativeQuotaMin the least it may write after one.
	nativeQuotaDefault = 50 << 30
	nativeQuotaMin     = 1 << 30
	// nativeTTL is the credential's lifetime when MaxRunDuration is 0.
	nativeTTL = 6 * time.Hour
	// nativeTaggers is how many objects are re-tagged at once per
	// destination.
	nativeTaggers = 16
	// The revoke reason of a run that ended, and the stop reason of one
	// whose server shuts down.
	nativeRunEnded = "run ended"
	nativeShutdown = "server shutting down"
)

// StateTag marks the objects of a native run (design §3): StateIncomplete
// while the run writes them, StateComplete once its signed manifest is
// written. A lifecycle rule deletes incomplete objects after 7 days.
const (
	StateTag        = "olympos-state"
	StateIncomplete = "incomplete"
	StateComplete   = "complete"
)

// tagSetter is a destination that changes the tags of a stored object.
type tagSetter interface {
	SetTags(ctx context.Context, path string, tags map[string]string) error
}

// nativeDest is one destination of a native run.
type nativeDest struct {
	i    int // the copy's index in the run's destinations
	ref  destRef
	w    blob.Writer
	dir  string // the run's directory there (RunDir)
	tier string

	mu  sync.Mutex
	err error // its first error: the destination is detached
}

func (d *nativeDest) tags(state string) map[string]string {
	return map[string]string{TierTag: d.tier, StateTag: state}
}

func (d *nativeDest) detach(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err == nil {
		d.err = err
	}
}

func (d *nativeDest) failed() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// nativeSink is the ingest.Sink of one native run: each object fans out
// (NewFanOut) to every destination still live, under the run's directory
// there, tagged incomplete and with the destination's tier. A destination
// that fails an object is detached for the rest of the run; Put fails only
// when no destination took the object.
type nativeSink struct {
	runID string
	dests []*nativeDest
	// ctx ends the uploads still running when the run ends (close). It is
	// not the worker's context: a server shutting down stops the session,
	// which ends the bodies; a Put cut by the worker's context while the
	// session is live would be taken for a failed destination.
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	puts   sync.WaitGroup
}

var errSinkClosed = errors.New("the native run has ended")

func newNativeSink(ctx context.Context, runID string, dests []*nativeDest) *nativeSink {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &nativeSink{runID: runID, dests: dests, ctx: ctx, cancel: cancel}
}

// Put implements ingest.Sink.
func (s *nativeSink) Put(ctx context.Context, key string, r io.Reader) (ingest.ObjectRecord, error) {
	rel, ok := strings.CutPrefix(key, s.runID+"/")
	if !ok || rel == "" {
		return ingest.ObjectRecord{}, fmt.Errorf("native sink: %q is not an object of run %s", key, s.runID)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ingest.ObjectRecord{}, errSinkClosed
	}
	s.puts.Add(1)
	s.mu.Unlock()
	defer s.puts.Done()

	var live []*nativeDest
	for _, d := range s.dests {
		if d.failed() == nil {
			live = append(live, d)
		}
	}
	if len(live) == 0 {
		return ingest.ObjectRecord{}, fmt.Errorf("no destination is left to take %s", rel)
	}
	// The uploads run under the run's context, not the request's: once the
	// body is whole, a client that hangs up does not cancel what is being
	// stored, so its disconnect is not taken for a failed destination.
	// Before that, the request's end ends them.
	uctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	var whole atomic.Bool
	defer context.AfterFunc(ctx, func() {
		if !whole.Load() {
			cancel()
		}
	})()
	branches := make([]Branch, len(live))
	for i, d := range live {
		branches[i] = Branch{Name: d.ref.Name, Upload: func(ctx context.Context, r io.Reader) error {
			_, err := d.w.Upload(ctx, d.dir+"/"+rel, r, "application/octet-stream", d.tags(StateIncomplete))
			return err
		}}
	}
	fo := NewFanOut(uctx, branches, 0)
	h := &countingHash{h: sha256.New()}
	buf := make([]byte, fanOutSegment)
	var readErr, writeErr error
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, writeErr = fo.Write(buf[:n]); writeErr != nil {
				break
			}
			_, _ = h.Write(buf[:n])
		}
		if err == io.EOF {
			whole.Store(true)
			break
		}
		if err != nil {
			readErr = err
			break
		}
	}
	results := fo.Close(readErr)
	if readErr == nil && !whole.Load() && (ctx.Err() != nil || s.ctx.Err() != nil) {
		readErr = context.Canceled
	}
	if readErr != nil {
		// The body did not arrive whole: the object is dropped everywhere,
		// and no destination answers for it.
		return ingest.ObjectRecord{}, readErr
	}
	if s.ctx.Err() != nil {
		// The run ended (close) and cut the uploads: not theirs either.
		return ingest.ObjectRecord{}, errSinkClosed
	}
	stored := 0
	for i, res := range results {
		if res.Err != nil {
			live[i].detach(fmt.Errorf("upload %s: %w", rel, res.Err))
			continue
		}
		stored++
	}
	if writeErr != nil || stored == 0 {
		return ingest.ObjectRecord{}, fmt.Errorf("no destination took %s", rel)
	}
	return ingest.ObjectRecord{Key: key, Size: h.n, SHA256: hex.EncodeToString(h.h.Sum(nil))}, nil
}

// close refuses further objects, ends the uploads still running and waits
// for them.
func (s *nativeSink) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.puts.Wait()
}

// nativeJob is one native run as perform set it up.
type nativeJob struct {
	eng   NativeEngine
	opts  NativeJob
	ec    EngineContext
	dests []destRef
	tiers map[uuid.UUID]string
	// envelope builds a copy's sidecar; wire is the tunnel bytes so far.
	envelope func(destRef, ManifestBlob, string) Manifest
	wire     func() int64
	scrub    func(string) string
}

// nativeURL is the run's directory on the ingest endpoint.
func nativeURL(ingestURL, runID string) string {
	return strings.TrimRight(ingestURL, "/") + "/olympos/" + runID + "/"
}

// runNative runs a native backup (design §4) and returns its outcome. Every
// copy is one destination's: it succeeds when every object reached the
// destination, the signed manifest is written there and every object is
// tagged complete. The copy's blob path is the run's directory, its size
// the objects' and its sha256 the signed manifest's.
func (w *Worker) runNative(ctx context.Context, r *runRow, job *Job, n nativeJob) (outcome, *RunResult) {
	cfg := w.Native
	tier := n.tiers[n.dests[0].ID]
	if cfg == nil || cfg.Registry == nil {
		return outcome{status: "failed", err: errIngestOff, engineFailed: true, native: true}, nil
	}
	runID := r.id.String()
	started := time.Now().UTC()
	copies := make([]copyResult, len(n.dests))
	var live []*nativeDest
	for i, d := range n.dests {
		copies[i] = copyResult{DestinationID: d.ID, Name: d.Name, Status: "failed", StartedAt: started}
		bw, err := w.Blobs.ForDestination(ctx, d.ID)
		if err == nil {
			if _, ok := bw.(tagSetter); !ok {
				err = errors.New("it cannot change the tags of stored objects")
			}
		}
		if err != nil {
			copies[i].Err, copies[i].FinishedAt = n.scrub("open destination: "+err.Error()), time.Now().UTC()
			continue
		}
		live = append(live, &nativeDest{i: i, ref: d, w: bw, tier: n.tiers[d.ID],
			dir: RunDir(bw.Prefix(), job.Target.ClusterName, job.Target.Namespace, job.Target.Service, n.eng.Name(), r.startedAt, r.id)})
	}
	stored := 0 // objects the session stored, set when the engine returned
	finish := func(total int64, engErr error) outcome {
		o := copiesOutcome(ctx, copies, total, n.wire(), tier, engErr, n.scrub)
		o.native, o.objects = true, stored
		return o
	}
	if len(live) == 0 {
		return finish(0, nil), nil
	}
	fail := func(msg string) outcome {
		return outcome{status: "failed", err: n.scrub(msg), engineFailed: true, native: true, wire: n.wire()}
	}
	quota, err := nativeQuota(ctx, w.DB, job.ID)
	if err != nil {
		return fail("native byte limit: " + err.Error()), nil
	}
	ttl := cfg.MaxRunDuration
	if ttl <= 0 {
		ttl = nativeTTL
	}

	sink := newNativeSink(ctx, runID, live)
	sess, cred, err := cfg.Registry.Open(ctx, ingest.OpenOptions{RunID: r.id, Kind: ingest.KindBackup,
		Scope: ingest.Scope{Write: runID + "/"}, TTL: ttl, Sink: sink, MaxBytes: quota})
	if err != nil {
		sink.close()
		return fail("open the ingest session: " + err.Error()), nil
	}
	// Revoked below as soon as the engine returns; this covers a panic.
	defer sink.close()
	defer sess.Revoke(nativeRunEnded)
	// The engine masks the secret in what it returns; the run masks it once
	// more in what it records.
	secret := cred.Secret
	scrub := func(s string) string { return n.scrub(strings.ReplaceAll(s, secret, "[HIDDEN]")) }
	stopped := &stopForward{}
	done := stopped.run(ctx, sess)
	version, runErr := n.eng.BackupNative(ctx, n.ec, NativeRun{URL: nativeURL(cfg.URL, runID), AccessKey: cred.AccessKey,
		Secret: secret, RunID: runID, Databases: n.opts.Databases, Stop: stopped.ch})
	cred = ingest.Credential{}
	reason := done()
	sess.Revoke(nativeRunEnded)
	sink.close()

	objects := sess.Objects()
	stored = len(objects)
	var total int64
	for _, o := range objects {
		total += o.Size
	}
	rr := &RunResult{ServerVersion: version}
	if runErr != nil {
		msg := scrub(runErr.Error())
		if errors.Is(runErr, ErrNativeOrphan) {
			w.Log.Error("native backup: the BACKUP may still be running on the target, and its revoked credential does not end "+
				"an upload in flight; end it with KILL QUERY", "run_id", r.id, "job_id", job.ID, "err", msg)
		}
		if reason == ingest.ReasonDestination {
			// No destination took an object: each copy failed on its own.
			for _, d := range live {
				copies[d.i].Err, copies[d.i].FinishedAt = nativeCopyError(d, n.scrub, "upload: no destination took an object"), time.Now().UTC()
			}
			return finish(total, nil), rr
		}
		detached := false
		for _, d := range live {
			detached = detached || d.failed() != nil
		}
		if len(objects) == 0 && !detached {
			copies = nil // nothing reached a destination
		} else {
			for _, d := range live {
				copies[d.i].Err, copies[d.i].FinishedAt = nativeCopyError(d, n.scrub, msg), time.Now().UTC()
			}
		}
		// The error keeps its chain (an agent that went away is retried, F18).
		return finish(total, scrubbedError{msg, runErr}), rr
	}
	if reason != "" {
		w.Log.Warn("native backup: created, and its ingest session stopped meanwhile", "run_id", r.id, "reason", reason)
	}

	res, err := n.eng.SignNativeManifest(ctx, NativeManifestInput{KV: cfg.KV, KeyName: cfg.ManifestKeyName, RunID: runID,
		ServerVersion: version, Objects: objects, Captured: sess.Captured})
	if err != nil {
		msg := n.scrub("native manifest: " + err.Error())
		for _, d := range live {
			copies[d.i].Err, copies[d.i].FinishedAt = nativeCopyError(d, n.scrub, msg), time.Now().UTC()
		}
		return finish(total, errors.New(msg)), rr
	}
	var wg sync.WaitGroup
	for _, d := range live {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &copies[d.i]
			if err := d.failed(); err != nil {
				c.Err, c.FinishedAt = n.scrub(err.Error()), time.Now().UTC()
				return
			}
			err := w.completeNative(ctx, d, r.id, objects, total, version, res, n.envelope)
			c.FinishedAt = time.Now().UTC()
			c.BlobPath, c.Bytes, c.SHA256 = d.dir, total, res.SHA256
			if err != nil {
				c.Err = n.scrub(err.Error())
				return
			}
			c.Status, c.Tier = "succeeded", d.tier
		}()
	}
	wg.Wait()
	return finish(total, nil), rr
}

// scrubbedError is err with its message scrubbed.
type scrubbedError struct {
	msg string
	err error
}

func (e scrubbedError) Error() string { return e.msg }
func (e scrubbedError) Unwrap() error { return e.err }

// nativeCopyError is a failed copy's error: its destination's own, else msg.
func nativeCopyError(d *nativeDest, scrub func(string) string, msg string) string {
	if err := d.failed(); err != nil {
		return scrub(err.Error())
	}
	return msg
}

// completeNative finishes a native copy on one destination whose objects are
// all stored: its sidecar, holding the signed manifest, next to the run's
// directory, then every object tagged complete, then the sidecar tagged
// complete. Until that last step the sidecar is incomplete like the objects:
// a copy left half tagged (a failed SetTags, a shutdown) never shows a
// complete manifest over objects the lifecycle rule is going to delete.
func (w *Worker) completeNative(ctx context.Context, d *nativeDest, runID uuid.UUID, objects []ingest.ObjectRecord, total int64,
	version string, res *NativeManifestResult, envelope func(destRef, ManifestBlob, string) Manifest) error {
	m := envelope(d.ref, ManifestBlob{Path: d.dir, Size: total, SHA256: res.SHA256}, d.tier)
	m.ServerVersion = version
	m.Details = map[string]any{NativeManifestDetail: res.Signed}
	b, err := nativeSidecar(m)
	if err != nil {
		return errors.New("encode manifest: " + err.Error())
	}
	side := ManifestPath(d.dir, runID)
	if _, err := d.w.Upload(ctx, side, bytes.NewReader(b), "application/json", d.tags(StateIncomplete)); err != nil {
		return errors.New("upload manifest: " + err.Error())
	}
	if err := retag(ctx, d, runID.String(), objects); err != nil {
		return errors.New("tag the objects complete: " + err.Error())
	}
	if err := d.w.(tagSetter).SetTags(ctx, side, d.tags(StateComplete)); err != nil {
		return errors.New("tag the manifest complete: " + err.Error())
	}
	return nil
}

// nativeSidecar encodes a native run's sidecar. HTML is not escaped, so the
// signed manifest in Details is written byte for byte as it was signed.
func nativeSidecar(m Manifest) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	if b.Len() > MaxNativeSidecarBytes {
		return nil, fmt.Errorf("the sidecar is %d bytes, over the %d bytes a reader takes", b.Len(), MaxNativeSidecarBytes)
	}
	return b.Bytes(), nil
}

// retag tags every object of the run on d complete, nativeTaggers at a
// time, and returns the first error.
func retag(ctx context.Context, d *nativeDest, runID string, objects []ingest.ObjectRecord) error {
	ts := d.w.(tagSetter)
	tags := d.tags(StateComplete)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	paths := make(chan string)
	var once sync.Once
	var first error
	var wg sync.WaitGroup
	for range min(nativeTaggers, len(objects)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				if err := ts.SetTags(ctx, p, maps.Clone(tags)); err != nil {
					once.Do(func() { first = fmt.Errorf("%s: %w", p, err); cancel() })
				}
			}
		}()
	}
feed:
	for _, o := range objects {
		select {
		case paths <- d.dir + "/" + strings.TrimPrefix(o.Key, runID+"/"):
		case <-ctx.Done():
			break feed
		}
	}
	close(paths)
	wg.Wait()
	if first == nil {
		first = ctx.Err()
	}
	return first
}

// stopForward hands the session's stop reason to the engine (NativeRun.Stop)
// and keeps it for the outcome. When the run's context ends first it stops
// the session itself: that ends what still streams at once, so the engine's
// KILL is not held up by an upload in flight.
type stopForward struct {
	ch     chan string
	mu     sync.Mutex
	reason string
}

// run starts forwarding; the function it returns stops it and returns the
// reason the session stopped for, if it did.
func (f *stopForward) run(ctx context.Context, sess *ingest.Session) func() string {
	f.ch = make(chan string, 1)
	quit, done := make(chan struct{}), make(chan struct{})
	keep := func(reason string) {
		f.mu.Lock()
		f.reason = reason
		f.mu.Unlock()
		f.ch <- reason // buffered: one reason, once
	}
	go func() {
		defer close(done)
		cancelled := ctx.Done()
		for {
			select {
			case reason := <-sess.Stopped():
				keep(reason)
				return
			case <-cancelled:
				cancelled = nil
				sess.Stop(nativeShutdown)
			case <-quit:
				return
			}
		}
	}()
	return func() string {
		close(quit)
		<-done
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.reason == "" {
			select {
			case reason := <-sess.Stopped():
				f.reason = reason
			default:
			}
		}
		return f.reason
	}
}

// nativeQuota is how many bytes a native run of the job may write (design
// §9): twice the job's last full native run, at least nativeQuotaMin, or
// nativeQuotaDefault before its first. A native run is one with an ingest
// credential; a full one's credential reads nothing.
func nativeQuota(ctx context.Context, q store.Querier, jobID uuid.UUID) (int64, error) {
	var last int64
	err := q.QueryRow(ctx, `SELECT r.bytes FROM backup_runs r WHERE r.job_id = $1 AND r.status IN ('succeeded', 'partial')
		AND EXISTS (SELECT 1 FROM ingest_credentials c WHERE c.run_id = r.id AND c.kind = 'backup' AND c.scope -> 'read' IS NULL)
		ORDER BY r.finished_at DESC LIMIT 1`, jobID).Scan(&last)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nativeQuotaDefault, nil
	case err != nil:
		return 0, err
	}
	return max(2*last, nativeQuotaMin), nil
}
