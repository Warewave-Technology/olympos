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
	// VerifyNativeChain verifies the signed manifests of a backup chain, the
	// full first, whose last is run runID's, signed by the Key Vault key
	// keyName. It returns what the worker needs of each, in the same order.
	VerifyNativeChain(ctx context.Context, kv secrets.KeyVault, keyName, runID string, signed [][]byte) ([]NativeChainManifest, error)
}

// NativeChainManifest is a verified manifest of a backup chain.
type NativeChainManifest struct {
	RunID string
	// SHA256 is the hex SHA-256 of the canonical manifest, as
	// NativeManifestResult.SHA256.
	SHA256 string
	// Objects are the run's objects, under "<run-id>/".
	Objects []ingest.ObjectRecord
}

// NativeJob is what a job's engine_options say about native backups.
type NativeJob struct {
	Native bool
	// Incremental takes a full backup weekly and incrementals on the other
	// days (design §7).
	Incremental bool
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
	// StructureOnly backs up the databases' structure and no data: a test
	// run's (R40), which checks the whole path (egress, certificate,
	// credential, signing, tagging) without copying the data.
	StructureOnly bool
	// Base is an incremental's base, nil for a full backup. The run's own
	// credential reads it.
	Base *NativeBase
	// SkipSize: the run's byte limit is set (ingest.maxRunBytes), so the
	// engine does not read the databases' size; Before gets 0 Bytes.
	SkipSize bool
	// Stop delivers why the run's ingest session stopped (a quota, a failed
	// destination, a server shutting down): the engine ends the backup.
	Stop <-chan string
	// Before, when set, is called once the target is checked and before the
	// BACKUP is sent, with what the engine read on the target. It returns
	// the runs among t.Running whose backups the engine ends first (R41). An
	// error ends the run there, with no backup started.
	Before func(ctx context.Context, t NativeTarget) (end []string, err error)
}

// NativeBase is the backup an incremental is taken on: the base run's
// directory on the ingest endpoint, "<ingest.url>/olympos/<run-id>/", and
// the run.
type NativeBase struct {
	URL, RunID string
}

// NativeTarget is what the engine reads on the target before its BACKUP.
type NativeTarget struct {
	// Bytes is what the run's databases hold on disk: the bytes of their
	// active parts (R39).
	Bytes int64
	// Running are the runs, other than this one, whose native backups run
	// on the target (by their query id, NativeQueryID).
	Running []string
}

// NativeQueryID is the query id of a native run's BACKUP on the target
// (ClickHouse, the engine that takes native backups).
func NativeQueryID(runID string) string { return "olympos-backup-" + runID }

// NativeKillQuery is the statement that ends a native run's BACKUP on the
// target, for an operator to run when Olympos could not.
func NativeKillQuery(runID string) string {
	return "KILL QUERY WHERE query_id = '" + NativeQueryID(runID) + "' SYNC"
}

// nativeOrphanHint is how a native run's BACKUP that may still run on the
// target ends.
func nativeOrphanHint(runID uuid.UUID) string {
	return "if its BACKUP still runs on the target, the next native run on that target ends it, or run " +
		NativeKillQuery(runID.String()) + " there"
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
	// StructureOnly is a test run's backup (NativeRun.StructureOnly).
	StructureOnly bool
	// Base is an incremental's base chain; nil for a full backup.
	Base *NativeManifestBase
}

// NativeManifestBase is the base chain of an incremental, as the manifest is
// built from it.
type NativeManifestBase struct {
	// RunID and URL are the base's (NativeRun.Base).
	RunID, URL string
	// Signed are the chain's signed manifests, as stored, the full first and
	// the base last. The engine verifies them itself.
	Signed [][]byte
	// Read returns an object of the chain by bucket-relative key, at most
	// limit bytes: only an object of one of those manifests, checked against
	// it.
	Read func(ctx context.Context, key string, limit int64) ([]byte, error)
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
	// Objects are the objects the manifest holds, which the run tags
	// complete. Unlisted are the keys of the objects the session stored
	// that the backup does not declare (R43): not signed, left incomplete.
	Objects  []ingest.ObjectRecord
	Unlisted []string
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
	// FirstRequest is how long a run waits for the target's first request
	// (NativeFirstRequest when 0).
	FirstRequest time.Duration
	// MaxRunBytes is how many bytes a run may write (ingest.maxRunBytes);
	// 0 is the automatic limit (nativeQuota).
	MaxRunBytes int64
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
	// nativeQuotaMin is the least a run may write (nativeQuota).
	nativeQuotaMin = 1 << 30
	// nativeTTL is the credential's lifetime when MaxRunDuration is 0.
	nativeTTL = 6 * time.Hour
	// nativeTaggers is how many objects are re-tagged at once per
	// destination.
	nativeTaggers = 16
	// nativeCompleteTimeout bounds completeNative, which a server shutting
	// down does not cut (about 250,000 objects at 16 at a time).
	nativeCompleteTimeout = 30 * time.Minute
	// The revoke reason of a run that ended, and the stop reason of one
	// whose server shuts down.
	nativeRunEnded = "run ended"
	nativeShutdown = "server shutting down"
	// NativeFirstRequest is how long a native backup or restore waits for
	// the target's first signed request to the endpoint before the session
	// stops (ingest.ReasonNoRequest) and the run ends. ClickHouse sends one
	// within seconds of its BACKUP or RESTORE; a target that cannot reach the
	// endpoint would retry until the credential's TTL.
	NativeFirstRequest = 5 * time.Minute
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

// NativeRunURL is a run's directory on the ingest endpoint: where its
// BACKUP writes, and the URL an incremental names its base by.
func NativeRunURL(ingestURL, runID string) string {
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
	// A test run (a dry run) backs up the structure only (R40).
	test := r.trigger == "test"
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
	lastFull, err := nativeLastFull(ctx, w.DB, job.ID)
	if err != nil {
		return fail("native byte limit: " + err.Error()), nil
	}
	// An incremental's base chain (design §7). A test run is always a full,
	// and so is a run with a weekly or monthly copy (R45): only daily copies
	// depend on a chain.
	var chain *nativeChain
	var src *chainSource
	if n.opts.Incremental && !test && !longTier(n.tiers) {
		ref := r.startedAt
		if r.scheduledFor != nil {
			ref = *r.scheduledFor
		}
		chain, err = selectBase(ctx, w.DB, job, ref)
		switch {
		case errors.Is(err, errChainUnusable):
			w.Log.Warn("native backup: the latest run is no base; the run is a full backup", "run_id", r.id, "err", err)
		case err != nil:
			return fail("select the base of the incremental: " + err.Error()), nil
		}
		if chain != nil {
			err := w.loadChain(ctx, n.eng, chain, live)
			if err == nil {
				src, err = newChainSource(chain, w.Log.With("run_id", r.id, "base_run_id", chain.base()))
			}
			if err != nil {
				w.Log.Warn("native backup: the base chain cannot be used; the run is a full backup", "run_id", r.id,
					"base_run_id", chain.base(), "err", n.scrub(err.Error()))
				chain = nil
			}
		}
	}
	// Until the engine read the databases' size (Before), the limit leaves
	// it out; no one has the credential yet.
	quota := nativeQuota(lastFull, 0, cfg.MaxRunBytes)
	ttl := cfg.MaxRunDuration
	if ttl <= 0 {
		ttl = nativeTTL
	}

	sink := newNativeSink(ctx, runID, live)
	opts := ingest.OpenOptions{RunID: r.id, Kind: ingest.KindBackup, Scope: ingest.Scope{Write: runID + "/"}, TTL: ttl, Sink: sink,
		MaxBytes: quota, FirstRequest: FirstRequestOr(cfg.FirstRequest)}
	var base *NativeBase
	if chain != nil {
		opts.Scope.Read, opts.Source = chain.prefixes(), src
		base = &NativeBase{URL: NativeRunURL(cfg.URL, chain.base().String()), RunID: chain.base().String()}
	}
	sess, cred, err := cfg.Registry.Open(ctx, opts)
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
	before := func(ctx context.Context, t NativeTarget) ([]string, error) {
		quota = nativeQuota(lastFull, t.Bytes, cfg.MaxRunBytes)
		sess.SetMaxBytes(quota)
		w.Log.Info("native backup: byte limit", "run_id", r.id, "max_bytes", quota, "databases_bytes", t.Bytes,
			"last_full_bytes", lastFull, "configured", cfg.MaxRunBytes > 0)
		return w.nativeOrphans(ctx, r.id, t.Running), nil
	}
	version, runErr := n.eng.BackupNative(ctx, n.ec, NativeRun{URL: NativeRunURL(cfg.URL, runID), AccessKey: cred.AccessKey,
		Secret: secret, RunID: runID, Databases: n.opts.Databases, StructureOnly: test, Base: base, SkipSize: cfg.MaxRunBytes > 0,
		Stop: stopped.ch, Before: before})
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
		switch reason {
		case ingest.ReasonQuota:
			msg = quotaError(quota, cfg.MaxRunBytes > 0) + ": " + msg
		case ingest.ReasonNoRequest:
			msg = NoRequestError(cfg.URL, FirstRequestOr(cfg.FirstRequest)) + ": " + msg
		}
		if errors.Is(runErr, ErrNativeOrphan) {
			w.Log.Error("native backup: the BACKUP may still be running on the target, and its revoked credential does not end "+
				"an upload in flight; the next native run on that target ends it", "run_id", r.id, "job_id", job.ID,
				"kill", NativeKillQuery(runID), "err", msg)
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

	in := NativeManifestInput{KV: cfg.KV, KeyName: cfg.ManifestKeyName, RunID: runID,
		ServerVersion: version, Objects: objects, Captured: sess.Captured, StructureOnly: test}
	if chain != nil {
		in.Base = &NativeManifestBase{RunID: base.RunID, URL: base.URL, Signed: chain.signed, Read: src.read}
	}
	res, err := n.eng.SignNativeManifest(ctx, in)
	if err != nil {
		msg := n.scrub("native manifest: " + err.Error())
		for _, d := range live {
			copies[d.i].Err, copies[d.i].FinishedAt = nativeCopyError(d, n.scrub, msg), time.Now().UTC()
		}
		return finish(total, errors.New(msg)), rr
	}
	if len(res.Unlisted) > 0 {
		// Stored, not declared by the backup: not signed, so not tagged
		// complete; the lifecycle rule removes them.
		w.Log.Warn("native backup: objects the backup does not declare are left out of the manifest and stay incomplete",
			"run_id", r.id, "count", len(res.Unlisted), "keys", res.Unlisted[:min(len(res.Unlisted), 100)])
	}
	objects, total = res.Objects, 0
	for _, o := range objects {
		total += o.Size
	}
	stored = len(objects)
	// A shutdown does not cut the copies' completion: a copy left half
	// tagged has complete objects under an incomplete manifest, so the
	// incomplete rule removes the manifest, and those objects stay until
	// their tier's rule removes them.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), nativeCompleteTimeout)
	defer cancel()
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
			var dc *nativeChain
			if chain != nil {
				dc = chain.on(d)
			}
			err := w.completeNative(cctx, d, r.id, objects, total, version, res, dc, n.envelope)
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

// longTier reports whether a copy of the run is weekly or monthly.
func longTier(tiers map[uuid.UUID]string) bool {
	for _, t := range tiers {
		if t == "weekly" || t == "monthly" {
			return true
		}
	}
	return false
}

// nativeOrphans is which of the native backups running on the target
// (NativeTarget.Running) run self ends before its own (R41): those whose
// runs are over in this server's database, left behind by a server that
// crashed or an agent lost mid-run. The backup of a run that is running,
// another job's on the same target, is never ended, nor one of a run this
// server does not know (another installation's). When the runs cannot be
// read, none is ended.
func (w *Worker) nativeOrphans(ctx context.Context, self uuid.UUID, running []string) []string {
	var ids []uuid.UUID
	for _, s := range running {
		if id, err := uuid.Parse(s); err == nil && id.String() == s && id != self {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	status := map[uuid.UUID]string{}
	rows, err := w.DB.Query(ctx, `SELECT id, status FROM backup_runs WHERE id = ANY($1)`, ids)
	if err == nil {
		for rows.Next() {
			var id uuid.UUID
			var st string
			if err = rows.Scan(&id, &st); err != nil {
				break
			}
			status[id] = st
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
	}
	if err != nil {
		w.Log.Warn("native backup: cannot tell which native backups on the target are left over; none is ended", "run_id", self, "err", err)
		return nil
	}
	var end []string
	for _, id := range ids {
		switch st, ok := status[id]; {
		case !ok:
			w.Log.Warn("native backup: a native backup of a run this server does not know runs on the target; left alone",
				"run_id", self, "other_run_id", id, "kill", NativeKillQuery(id.String()))
		case st == "running":
		default:
			w.Log.Warn("native backup: ending the native backup of a run that is over", "run_id", self, "orphan_run_id", id,
				"orphan_status", st)
			end = append(end, id.String())
		}
	}
	return end
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
// directory, then an incremental's base chain kept for the copy's tier
// (retagChain), then every object tagged complete, then the sidecar tagged
// complete. Until that last step the sidecar is incomplete like the objects:
// a copy left half tagged (a failed SetTags, a shutdown) never shows a
// complete manifest over objects the lifecycle rule is going to delete, and
// an incremental is never complete over a base kept for less long.
func (w *Worker) completeNative(ctx context.Context, d *nativeDest, runID uuid.UUID, objects []ingest.ObjectRecord, total int64,
	version string, res *NativeManifestResult, chain *nativeChain, envelope func(destRef, ManifestBlob, string) Manifest) error {
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
	if chain != nil {
		if err := retagChain(ctx, chain, d.tier); err != nil {
			return errors.New("keep the base chain: " + err.Error())
		}
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

// nativeLastFull is the bytes of the job's last full native run that
// succeeded or partly succeeded, 0 before its first. A native run is one with
// an ingest credential; a full one's credential reads nothing. A test run
// is structure only (R40), so it does not count; it is no base for an
// incremental either (task 13's base selection leaves it out the same way).
func nativeLastFull(ctx context.Context, q store.Querier, jobID uuid.UUID) (int64, error) {
	var last int64
	err := q.QueryRow(ctx, `SELECT r.bytes FROM backup_runs r WHERE r.job_id = $1 AND r.status IN ('succeeded', 'partial')
		AND r.trigger <> 'test' AND EXISTS (SELECT 1 FROM ingest_credentials c WHERE c.run_id = r.id AND c.kind = 'backup' AND c.scope -> 'read' IS NULL)
		ORDER BY r.finished_at DESC LIMIT 1`, jobID).Scan(&last)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return last, err
}

// nativeQuota is how many bytes a native run may write (design §9, R39):
// the largest of twice the job's last full native run, 1.5 times what the
// run's databases hold and nativeQuotaMin; override (ingest.maxRunBytes),
// when set, instead. The databases' size lets a large database with no full
// yet, or one that grew since, be backed up. Twice the last full counts up
// to twice the databases' size (R44): a run that wrote far more than its
// databases hold does not raise the limit of the next, and so on.
func nativeQuota(lastFull, databases, override int64) int64 {
	if override > 0 {
		return override
	}
	return max(min(2*lastFull, 2*databases), databases+databases/2, nativeQuotaMin)
}

// FirstRequestOr is d, or NativeFirstRequest when d is 0: how long a run
// waits for the target's first request.
func FirstRequestOr(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return NativeFirstRequest
}

// NoRequestError says that the target sent no request to the endpoint at
// url within d, and what to check.
func NoRequestError(url string, d time.Duration) string {
	within := d.String()
	if d%time.Minute == 0 {
		within = fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("no request from the target reached the ingest endpoint %s within %s: check the egress of the "+
		"ClickHouse pods to its host and port, and that ClickHouse trusts its certificate", url, within)
}

// quotaError says that a run went over its byte limit, and how to allow more.
func quotaError(quota int64, configured bool) string {
	if configured {
		return fmt.Sprintf("native byte limit: the run wrote more than %s (ingest.maxRunBytes); raise ingest.maxRunBytes, "+
			"or set it to 0 for the automatic limit", humanBytes(quota))
	}
	return fmt.Sprintf("native byte limit: the run wrote more than %s (the largest of twice the last full native run, "+
		"at most twice the databases' size on disk; 1.5 times that size; and 1 GiB); set ingest.maxRunBytes to allow more",
		humanBytes(quota))
}
