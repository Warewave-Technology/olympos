package backup

// The restore check of a native backup (design docs/design/clickhouse-native.md
// §6 and §7, task 16). A restore reads one copy of a native run: its
// directory on one destination. The copy's chain is the run's base chain,
// the full first (its backup credential's read scope, as selectBase reads
// it), and the run itself. Every run of the chain must have a succeeded copy
// on the copy's destination; their sidecars are read from there, at most
// MaxNativeSidecarBytes each, and the engine verifies the signed manifests
// as a chain (VerifyNativeChain's rules), then reads each object's
// definition from the chain through chainSource, which serves only objects
// the verified manifests list and checks each against its size and SHA-256,
// and decides what the restore creates. A copy whose chain does not verify
// is never restored (ErrNativeNotVerified).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// NativeRestoreEngine is implemented by engines whose native backups are
// restored (ClickHouse).
type NativeRestoreEngine interface {
	// CheckNativeRestore verifies in.Signed as the chain of run in.RunID,
	// the full first, binds the verified manifests for reads (in.Bind),
	// reads the definitions of the selected databases' objects through the
	// reader it gets, and decides for each whether the restore creates it.
	// A chain that does not verify, or an object that cannot be read, is
	// ErrNativeNotVerified; a chain that verifies but cannot be restored
	// here is ErrNativeChain. With ErrNativeNotVerified the result, when not
	// nil, lists what the copy's own signed manifest holds, every object
	// left out; it is never bound for reads.
	CheckNativeRestore(ctx context.Context, in NativeRestoreInput) (*NativeRestoreCheck, error)
	// NativeServed returns the keys of the objects of the verified chain ms
	// (the full first) that the restore of decisions, for databases (empty:
	// every one), reads: what its RestoreSource serves, nothing else
	// (security review v0.4, finding 5). read is the chain's checked reader.
	// A chain whose files cannot be resolved is ErrNativeChain; one that
	// cannot be read, ErrNativeNotVerified.
	NativeServed(ctx context.Context, read NativeObjectReader, ms []NativeChainManifest, databases []string,
		decisions []NativeDecision) (map[string]bool, error)
}

// NativeRestoreInput is what an engine checks a native restore with.
type NativeRestoreInput struct {
	// KV and KeyName verify the manifests (keyVault.manifestKeyName).
	KV      secrets.KeyVault
	KeyName string
	// RunID is the copy's run, the chain's last, and SHA256 the SHA-256 of
	// its manifest as its copy row records it.
	RunID, SHA256 string
	// Signed are the chain's signed manifests as stored, the full first.
	Signed [][]byte
	// IngestURL is ingest.url: an incremental's .backup names its base by
	// its URL under the endpoint it was taken through, and the restore's
	// ClickHouse reads it there.
	IngestURL string
	// Bind takes the verified manifests, in the order of Signed, and returns
	// the reader of the chain's objects: only those the manifests list,
	// each checked against its size and SHA-256.
	Bind func(ms []NativeChainManifest) (NativeObjectReader, error)
	// Databases are the selected databases; empty selects every one.
	Databases []string
}

// NativeObjectReader returns an object of a verified chain whole, by
// bucket-relative key, at most limit bytes.
type NativeObjectReader func(ctx context.Context, key string, limit int64) ([]byte, error)

// NativeDecision is what a native restore does with one object of the
// backup: Allowed objects are created by the restore; the others are left
// out, with the reason shown to the maker and the checker.
type NativeDecision struct {
	Database string `json:"database"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
}

// NativeRestoreCheck is what the check of a native copy found.
type NativeRestoreCheck struct {
	// Databases are every database of the backup, in the manifest's order.
	Databases []string
	// Objects are the decisions for the objects of the selected databases.
	Objects []NativeDecision
	// Manifests are the chain's verified manifests, the full first; nil
	// when the chain does not verify.
	Manifests []NativeChainManifest
	// DDL, Rows and Definitions are what the engine's restore of the chain
	// needs, by keys of the engine's own (NativeRestoreRun): the definitions
	// it creates itself before RESTORE, the row counts it checks after, and
	// the definition of every allowed object, which it compares what the
	// target created with (security review v0.4, finding 1). nil when the
	// chain does not verify.
	DDL         map[string][]byte
	Rows        map[string]uint64
	Definitions map[string][]byte
	// RefusedDatabases are the selected databases the restore cannot
	// create, with the reason (R52: a native restore creates Atomic
	// databases only): a request with one of them is refused.
	RefusedDatabases map[string]string
}

var (
	// ErrNativeNotVerified: the copy's chain was not read and verified
	// whole: a sidecar could not be read, a manifest or a link does not
	// verify, or an object does not match its manifest. Its message is
	// what the check shows; the cause is logged, never shown.
	ErrNativeNotVerified = errors.New("the backup's manifest does not verify")
	// ErrNativeChain: the copy's chain cannot be restored from this
	// destination or through this endpoint; the error says why.
	ErrNativeChain = errors.New("the backup chain cannot be restored")
)

// NativeRestoreConfig is what a native restore needs from the server.
type NativeRestoreConfig struct {
	// KV and ManifestKeyName verify the manifests.
	KV              secrets.KeyVault
	ManifestKeyName string
	// URL is ingest.url.
	URL string
	// Registry holds the ingest sessions a restore's credential is minted
	// in, and MaxRunDuration is the longest one lives
	// (ingest.maxRunDuration, 6 h when 0). Only the executor uses them.
	Registry       *ingest.Registry
	MaxRunDuration time.Duration
}

// NativeRestore is a native copy checked for a restore: the chain, read
// from the copy's destination and verified, and the decisions for the
// selected databases. Source serves the chain to the restore's ClickHouse.
// It lives only inside WithNativeRestore's callback; RestoreSource is what
// may outlive it.
type NativeRestore struct {
	NativeRestoreCheck
	// Runs are the chain's runs, the full first, the copy's run last.
	Runs []uuid.UUID
	src  *chainSource
	// r and dirs are where the chain is read from: the copy's destination
	// and each run's directory on it, as Runs.
	r    blob.Reader
	dirs []string
	log  *slog.Logger
	// eng and databases are the check's engine and selection: what the
	// restore source serves (NativeServed). ctx is the check's, with its
	// limit: RestoreSource reads within it.
	eng       NativeRestoreEngine
	databases []string
	ctx       context.Context
}

// Source serves the chain's objects as the verified manifests list them,
// each checked against its manifest while it streams; nil when the chain
// was not verified.
func (n *NativeRestore) Source() ingest.Source {
	if n.src == nil {
		return nil
	}
	return n.src
}

// The slots of native checks bound how many native chains are held at once:
// a chain holds up to nativeMaxChain sidecars of up to MaxNativeSidecarBytes
// in memory while it is verified, and its verified manifests while it is
// used. A parsed chain lives only while its caller holds the slot.
//
// The API's checks (POST /restores/check and /restores) and the executor's
// check at the start of an approved restore have slots of their own, so
// checks sent in a loop never hold up a restore (security review v0.4,
// finding 6): nativeAPISlots for the API, of which a user holds at most
// nativeChecksPerUser at once, and one for the executor, whose restores
// verify one after another. A check, the wait for an API slot included,
// ends after nativeCheckTimeout; the executor's waits for its slot as long
// as its restore may.
const (
	nativeAPISlots      = 2
	nativeChecksPerUser = 1
)

var (
	nativeAPICheckSlots = make(chan struct{}, nativeAPISlots)
	nativeExecutorSlots = make(chan struct{}, 1)
	nativeCheckTimeout  = 5 * time.Minute // a test lowers it

	nativeUserChecks = struct {
		sync.Mutex
		n map[string]int
	}{n: map[string]int{}}
)

// ErrNativeCheckLimit: a native check was not run, or was ended, by one of
// its limits (one check per user at a time, nativeCheckTimeout); the error
// says which. Nothing was decided.
var ErrNativeCheckLimit = errors.New("the native backup's check hit a limit")

// CheckNativeRestore is the API's restore check of the native copy src for
// databases (empty: every one), for user: WithNativeRestore on an API slot,
// keeping only the databases and the decisions, so nothing of the parsed
// chain outlives the slot (Manifests is nil). A user who has a check
// running gets ErrNativeCheckLimit at once. Errors are as
// WithNativeRestore's.
func CheckNativeRestore(ctx context.Context, q store.Querier, r blob.Reader, eng NativeRestoreEngine, cfg NativeRestoreConfig,
	src *RestoreSource, databases []string, user string, log *slog.Logger) (*NativeRestoreCheck, error) {
	nativeUserChecks.Lock()
	if nativeUserChecks.n[user] >= nativeChecksPerUser {
		nativeUserChecks.Unlock()
		return nil, fmt.Errorf("%w: a check of yours runs already (one at a time); check again when it has ended", ErrNativeCheckLimit)
	}
	nativeUserChecks.n[user]++
	nativeUserChecks.Unlock()
	defer func() {
		nativeUserChecks.Lock()
		if nativeUserChecks.n[user]--; nativeUserChecks.n[user] <= 0 {
			delete(nativeUserChecks.n, user)
		}
		nativeUserChecks.Unlock()
	}()
	var out *NativeRestoreCheck
	err := withNativeRestore(ctx, nativeAPICheckSlots, true, q, r, eng, cfg, src, databases, log, func(n *NativeRestore) error {
		if n != nil {
			out = &NativeRestoreCheck{Databases: n.Databases, Objects: n.Objects, RefusedDatabases: n.RefusedDatabases}
		}
		return nil
	})
	return out, err
}

// WithNativeRestore is the executor's check: it resolves the chain of the
// native copy src, reads its sidecars from r (the copy's destination), has
// eng verify and decide for databases (empty: every one), and calls use
// with the result while it holds the executor's slot; the result must not be
// kept after use returns. The check, use included, ends after
// nativeCheckTimeout once it holds the slot (ErrNativeCheckLimit). use is called with the chain verified and its source bound, or,
// with ErrNativeNotVerified, with the decisions eng could list (every
// object left out, no source). It is not called at all on other errors:
// an ErrNativeChain, a chain that eng verified but did not bind
// (ErrNativeNotVerified, "the engine did not bind the chain"), a chain past
// the serving path's bound (ErrNativeChain), an internal error, or ctx
// ending; use's error is returned as it is. Errors are ErrNativeChain or
// ErrNativeNotVerified, with the cause, an internal error of q, or the
// context's error when ctx ended (the caller is gone: nothing to show; a
// verification error it cut is logged at Debug).
func WithNativeRestore(ctx context.Context, q store.Querier, r blob.Reader, eng NativeRestoreEngine, cfg NativeRestoreConfig,
	src *RestoreSource, databases []string, log *slog.Logger, use func(*NativeRestore) error) error {
	return withNativeRestore(ctx, nativeExecutorSlots, false, q, r, eng, cfg, src, databases, log, use)
}

// withNativeRestore is WithNativeRestore on slots; waitCounts: the check's
// limit (nativeCheckTimeout) runs from the start, the wait for a slot
// included, not from when it holds one.
func withNativeRestore(parent context.Context, slots chan struct{}, waitCounts bool, q store.Querier, r blob.Reader, eng NativeRestoreEngine,
	cfg NativeRestoreConfig, src *RestoreSource, databases []string, log *slog.Logger, use func(*NativeRestore) error) error {
	if log == nil {
		log = slog.Default()
	}
	limit := nativeCheckTimeout
	ctx, cancel := parent, context.CancelFunc(func() {})
	if waitCounts {
		ctx, cancel = context.WithTimeout(parent, limit)
	}
	defer cancel()
	timedOut := false
	err := func() error {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-ctx.Done():
			timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
			return ctx.Err()
		}
		ctx := ctx
		if !waitCounts {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(parent, limit)
			defer cancel()
		}
		err := checkNativeChain(ctx, q, r, eng, cfg, src, databases, log, use)
		timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		return err
	}()
	if err != nil && parent.Err() == nil && timedOut {
		// The check's own limit, not its caller's end.
		log.Warn("native restore: a check took longer than its limit", "copy_run_id", src.CopyRunID, "limit", limit.String(),
			"err", err.Error())
		return fmt.Errorf("%w: it took longer than %s; check again, or restore a run with a shorter chain", ErrNativeCheckLimit, limit)
	}
	return err
}

// checkNativeChain is withNativeRestore once it holds a slot.
func checkNativeChain(ctx context.Context, q store.Querier, r blob.Reader, eng NativeRestoreEngine, cfg NativeRestoreConfig,
	src *RestoreSource, databases []string, log *slog.Logger, use func(*NativeRestore) error) error {
	runs, copies, err := restoreChain(ctx, q, src)
	if err != nil {
		return ended(ctx, log, src, err)
	}
	signed := make([][]byte, len(runs))
	for i, run := range runs {
		raw, err := readSidecarManifest(ctx, r, ManifestPath(copies[i].dir, run))
		if err != nil {
			return ended(ctx, log, src, fmt.Errorf("%w: the manifest of run %s: %v", ErrNativeNotVerified, run, err))
		}
		signed[i] = raw
	}
	var cs *chainSource
	var bound []string
	bind := func(ms []NativeChainManifest) (NativeObjectReader, error) {
		if len(ms) != len(runs) {
			return nil, fmt.Errorf("%d manifests for a chain of %d runs", len(ms), len(runs))
		}
		dirs := make([]string, len(runs))
		for i, m := range ms {
			if m.RunID != runs[i].String() || m.SHA256 != copies[i].sha256 {
				return nil, fmt.Errorf("the manifest of run %s is not the one its copy was written with", runs[i])
			}
			dirs[i] = copies[i].dir
		}
		s, err := newChainSourceOn(r, dirs, ms, log)
		if err != nil {
			return nil, err
		}
		cs, bound = s, dirs
		return s.read, nil
	}
	check, err := eng.CheckNativeRestore(ctx, NativeRestoreInput{KV: cfg.KV, KeyName: cfg.ManifestKeyName, RunID: src.CopyRunID.String(),
		SHA256: copies[len(copies)-1].sha256, Signed: signed, IngestURL: cfg.URL, Bind: bind, Databases: databases})
	var out *NativeRestore
	if check != nil {
		out = &NativeRestore{NativeRestoreCheck: *check, Runs: runs, r: r, log: log, eng: eng, databases: databases, ctx: ctx}
	}
	switch {
	case ctx.Err() != nil && err != nil:
		return ended(ctx, log, src, err)
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, ErrNativeChain):
		return err
	case err != nil:
		if !errors.Is(err, ErrNativeNotVerified) {
			err = fmt.Errorf("%w: %v", ErrNativeNotVerified, err)
		}
		// What eng could list of a chain that did not verify: no
		// manifests, no source.
		if out != nil {
			out.Manifests, out.DDL, out.Rows, out.Definitions, out.RefusedDatabases = nil, nil, nil, nil, nil
			if uerr := use(out); uerr != nil {
				return uerr
			}
		}
		return err
	case check == nil || cs == nil:
		return fmt.Errorf("%w: the engine did not bind the chain", ErrNativeNotVerified)
	}
	out.src, out.dirs = cs, bound
	// What the restore would serve must be within its bound: refused at
	// the check, not when the restore starts.
	if _, err := servedBound(out.Manifests); err != nil {
		return err
	}
	return use(out)
}

// ended is ctx's error when ctx ended (what failed then is the request
// going away; err, its cause, is logged at Debug), else err.
func ended(ctx context.Context, log *slog.Logger, src *RestoreSource, err error) error {
	if ctx.Err() != nil {
		log.Debug("native restore: the check ended with its request", "copy_run_id", src.CopyRunID, "err", err.Error())
		return ctx.Err()
	}
	return err
}

// restoreChain is the chain of the native copy src, the full first, and
// each run's succeeded copy on src's destination: the copy's run and its
// backup credential's read scope (its base chain, as selectBase gave it),
// at most nativeMaxChain runs.
func restoreChain(ctx context.Context, q store.Querier, src *RestoreSource) ([]uuid.UUID, []chainCopy, error) {
	run := src.CopyRunID
	// ingest_credentials has no uniqueness on (run_id, kind): one run has
	// one backup credential, and a run with records that differ is refused
	// rather than one of them picked.
	var read []byte
	var scopes int
	err := q.QueryRow(ctx, `SELECT count(DISTINCT COALESCE(scope -> 'read', '[]'::jsonb)), min(COALESCE(scope -> 'read', '[]'::jsonb)::text)
		FROM ingest_credentials WHERE run_id = $1 AND kind = 'backup'`, run).Scan(&scopes, &read)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case scopes == 0:
		return nil, nil, fmt.Errorf("%w: run %s has no record of the chain it was taken on", ErrNativeChain, run)
	case scopes > 1:
		return nil, nil, fmt.Errorf("%w: run %s has records of more than one chain it was taken on", ErrNativeChain, run)
	}
	var prefixes []string
	if err := json.Unmarshal(read, &prefixes); err != nil {
		return nil, nil, fmt.Errorf("%w: the base chain of run %s is not readable", ErrNativeChain, run)
	}
	if len(prefixes)+1 > nativeMaxChain {
		return nil, nil, fmt.Errorf("%w: its chain has %d runs, more than the %d a restore reads", ErrNativeChain, len(prefixes)+1, nativeMaxChain)
	}
	runs := make([]uuid.UUID, 0, len(prefixes)+1)
	for _, p := range prefixes {
		id, err := uuid.Parse(strings.TrimSuffix(p, "/"))
		if err != nil || id.String()+"/" != p {
			return nil, nil, fmt.Errorf("%w: the base chain of run %s holds %q, not a run's prefix", ErrNativeChain, run, p)
		}
		runs = append(runs, id)
	}
	runs = append(runs, run)

	rows, err := q.Query(ctx, `SELECT run_id, blob_path, sha256 FROM backup_run_copies
		WHERE run_id = ANY($1) AND destination_id = $2 AND status = 'succeeded'`, runs, src.DestinationID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	found := map[uuid.UUID]chainCopy{}
	for rows.Next() {
		var id uuid.UUID
		var cc chainCopy
		if err := rows.Scan(&id, &cc.dir, &cc.sha256); err != nil {
			return nil, nil, err
		}
		found[id] = cc
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	copies := make([]chainCopy, len(runs))
	for i, id := range runs {
		cc, ok := found[id]
		if !ok || cc.dir == "" {
			return nil, nil, fmt.Errorf("%w: run %s of its chain has no succeeded copy on %s", ErrNativeChain, id, src.DestinationName)
		}
		copies[i] = cc
	}
	return runs, copies, nil
}

// ---------------------------------------------------------------- the restore run (task 17)

// NativeRestorer is implemented by the Restorer of an engine whose native
// backups are restored (ClickHouse): RestoreNativeBackup restores the chain
// the target reads at run.URL with run's credential, as run's decisions say
// (design docs/design/clickhouse-native.md §6, Execute).
type NativeRestorer interface {
	// RestoreNativeBackup creates the selected databases (rc.Databases) and what
	// the engine creates itself (run.DDL), has the target restore the rest
	// of the allowed objects, leaving out every other object, and checks
	// the row counts against run.Rows and what it created against
	// run.Definitions. When run.Stop delivers, or ctx ends,
	// it ends the restore on the target and returns an error. The result is
	// filled as far as it got, Created listing the databases it created.
	// The secret goes to the target and nowhere else.
	RestoreNativeBackup(ctx context.Context, rc RestoreContext, run NativeRestoreRun) (*RestoreResult, error)
}

// NativeRestoreRun is one native restore: where the target reads the copy,
// with which ingest credential, and what the check decided.
type NativeRestoreRun struct {
	// URL is the copy's run directory on the endpoint,
	// NativeRunURL(ingest.url, RunID); RunID is that run (the chain's last).
	URL   string
	RunID string
	// AccessKey and Secret are the restore's read-only ingest credential.
	AccessKey, Secret string
	// Decisions are the check's, for the selected databases.
	Decisions []NativeDecision
	// DDL, Rows and Definitions are the check's (NativeRestoreCheck), by
	// the engine's keys.
	DDL         map[string][]byte
	Rows        map[string]uint64
	Definitions map[string][]byte
	// Stop delivers why the restore's ingest session stopped (a source that
	// failed, expiry): the restore is then ended on the target.
	Stop <-chan string
}

// String and LogValue keep the secret out of every print and log of a run.
func (nr NativeRestoreRun) String() string {
	return fmt.Sprintf("backup.NativeRestoreRun{run %s, key %s, secret redacted}", nr.RunID, nr.AccessKey)
}
func (nr NativeRestoreRun) GoString() string { return nr.String() }

func (nr NativeRestoreRun) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run", nr.RunID), slog.String("access_key", nr.AccessKey))
}

// NativeRestoreQueryID is the query id of a restore request's RESTORE,
// which KILL names; the restore's id in system.backups is the request id.
func NativeRestoreQueryID(requestID string) string { return "olympos-restore-" + requestID }

// NativeRestoreKillQuery is the statement that ends a restore request's
// RESTORE on the target, for an operator to run when Olympos could not.
func NativeRestoreKillQuery(requestID string) string {
	return "KILL QUERY WHERE query_id = '" + NativeRestoreQueryID(requestID) + "' SYNC"
}

// RestoreSource is the source a native restore's ingest session serves the
// chain from, for as long as the RESTORE runs: unlike the NativeRestore, it
// may be kept after WithNativeRestore's callback returns, so the check's
// slot is held only while the chain is verified and bound. It is nil when
// the chain was not verified.
//
// It serves only what the restore's RESTORE reads (the engine's
// NativeServed: the .backup of every run, the definitions of the selected
// databases and the data of the objects the restore creates), so the
// target, which holds the restore's credential while it runs, reads nothing
// else of the backup: not the databases left unselected, not the objects
// left out (security review v0.4, finding 5). It reads the chain's .backup
// files to know that, so it is called while the check's slot is held.
//
// Its memory bound: it keeps one entry per object it serves (the key, the
// size, the SHA-256 as 32 bytes and the run), none of the parsed manifests,
// definitions or decisions, and refuses a chain past maxServedObjects or
// maxServedKeyBytes. A server runs at most the executor's Global restores at
// once.
//
// A manifest key that the endpoint would not serve (ingest.ValidKey: a
// backslash, a control character, an empty, "." or ".." segment), or that
// is not under its run, refuses the source: keys are only ever looked up,
// and mapped to a path only below their run's directory.
func (n *NativeRestore) RestoreSource() (*NativeRestoreSource, error) {
	if n == nil || n.src == nil || n.eng == nil {
		return nil, errors.New("the chain was not verified")
	}
	served, err := n.eng.NativeServed(n.ctx, n.src.read, n.Manifests, n.databases, n.Objects)
	if err != nil {
		return nil, err
	}
	return NewNativeRestoreSource(n.r, n.Manifests, n.dirs, served, n.log)
}

// NewNativeRestoreSource serves, of the verified manifests ms (the full
// first), the objects whose keys are in served, from r, each run's objects
// from its directory in dirs (as ms): the RestoreSource of a NativeRestore.
// Only verified manifests may be given; a served key they do not list is
// refused (ErrNativeChain).
func NewNativeRestoreSource(r blob.Reader, ms []NativeChainManifest, dirs []string, served map[string]bool,
	log *slog.Logger) (*NativeRestoreSource, error) {
	if len(ms) == 0 || len(ms) != len(dirs) || len(ms) > nativeMaxChain {
		return nil, fmt.Errorf("%d manifests for %d directories", len(ms), len(dirs))
	}
	if log == nil {
		log = slog.Default()
	}
	if _, err := servedBound(ms); err != nil {
		return nil, err
	}
	s := &NativeRestoreSource{r: r, log: log, objects: make(map[string]servedObject, len(served))}
	for i, m := range ms {
		s.runs = append(s.runs, m.RunID+"/")
		s.dirs = append(s.dirs, dirs[i]+"/")
		for _, o := range m.Objects {
			rel, ok := strings.CutPrefix(o.Key, m.RunID+"/")
			if !ok || rel == "" || !ingest.ValidKey(o.Key) {
				return nil, fmt.Errorf("%w: the manifest of run %s lists %q, which the endpoint does not serve", ErrNativeChain, m.RunID, clipKey(o.Key))
			}
			if !served[o.Key] {
				continue
			}
			sum, err := hex.DecodeString(o.SHA256)
			if err != nil || len(sum) != sha256.Size || o.Size < 0 {
				return nil, fmt.Errorf("%w: the manifest of run %s lists %q without a size and SHA-256", ErrNativeChain, m.RunID, clipKey(o.Key))
			}
			var so servedObject
			so.size, so.run = o.Size, uint8(i)
			copy(so.sha[:], sum)
			s.objects[o.Key] = so
		}
	}
	for k := range served {
		if _, ok := s.objects[k]; !ok {
			return nil, fmt.Errorf("%w: the restore reads %q, which the verified manifests do not list", ErrNativeChain, clipKey(k))
		}
	}
	return s, nil
}

func clipKey(k string) string {
	if len(k) > 128 {
		return k[:128] + "…"
	}
	return k
}

// The serving path's memory bound (NewNativeRestoreSource): at most
// maxServedObjects entries and maxServedKeyBytes of keys in all, so 32 runs
// of 256 Ki objects each, twice the ~250k files a native run holds at most
// (its .backup is capped at 64 MiB). An entry is its key and about 100
// bytes more (the SHA-256, the size, the map), so a source at the cap
// holds about 1.8 GiB; a full of 250k files with ~100-byte keys about
// 50 MiB. A chain past the cap is refused, not served in part.
var (
	maxServedObjects  = nativeMaxChain << 18 // 8 Mi; a test lowers it
	maxServedKeyBytes = 1 << 30
)

// servedBound returns how many objects the chain ms holds, or an
// ErrNativeChain error when that, or their keys, are past the serving
// path's bound.
func servedBound(ms []NativeChainManifest) (int, error) {
	var count, keyBytes int
	for _, m := range ms {
		count += len(m.Objects)
		for _, o := range m.Objects {
			keyBytes += len(o.Key)
		}
	}
	if count > maxServedObjects || keyBytes > maxServedKeyBytes {
		return 0, fmt.Errorf("%w: the chain holds %d objects (%d bytes of keys), more than the %d objects (%d bytes of keys) a restore serves",
			ErrNativeChain, count, keyBytes, maxServedObjects, maxServedKeyBytes)
	}
	return count, nil
}

// NativeRestoreSource is the ingest.Source of a native restore
// (NativeRestore.RestoreSource): the objects of the chain's verified
// manifests that the restore reads, read from the copy's destination, each
// checked against its size and SHA-256 while it streams (the last read of an
// object that does not match fails, so the endpoint aborts the connection
// and the reader never gets all of it). Any other key, of the manifests or
// not, is refused (ingest.ErrNotServed, 403). It serves whole objects only.
type NativeRestoreSource struct {
	r          blob.Reader
	runs, dirs []string // "<run-id>/" and "<dir>/", the full first
	objects    map[string]servedObject
	log        *slog.Logger

	mu     sync.Mutex
	failed string
}

// servedObject is an object of the chain: its size, SHA-256 and run (an
// index in runs).
type servedObject struct {
	size int64
	sha  [sha256.Size]byte
	run  uint8
}

var _ ingest.WholeSource = (*NativeRestoreSource)(nil)

// WholeObjects implements ingest.WholeSource: each object is checked when
// it ends, so a range would reach the client unchecked.
func (*NativeRestoreSource) WholeObjects() {}

// Open implements ingest.Source.
func (s *NativeRestoreSource) Open(ctx context.Context, key string) (io.ReadCloser, ingest.ObjectRecord, error) {
	obj, ok := s.objects[key]
	if !ok {
		return nil, ingest.ObjectRecord{}, fmt.Errorf("%s is not an object of the backup that this restore reads: %w", clipKey(key), ingest.ErrNotServed)
	}
	rec := ingest.ObjectRecord{Key: key, Size: obj.size, SHA256: hex.EncodeToString(obj.sha[:])}
	o, err := s.r.Open(ctx, s.dirs[obj.run]+strings.TrimPrefix(key, s.runs[obj.run]))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			// The reader went away: the request's own end, which the
			// endpoint does not take for a failed source.
			return nil, ingest.ObjectRecord{}, fmt.Errorf("%s: %w", key, cerr)
		}
		// A signed object that cannot be read is the source's failure, not
		// a key that does not exist: not wrapped.
		return nil, ingest.ObjectRecord{}, fmt.Errorf("%s: %v", key, err)
	}
	if o.Size() != obj.size {
		_ = o.Close()
		s.log.Error("native restore: an object of the chain does not match its signed manifest", "key", key,
			"stored_bytes", o.Size(), "signed_bytes", obj.size)
		s.fail(key)
		return nil, ingest.ObjectRecord{}, fmt.Errorf("%s: %w (%d bytes stored, %d signed)", key, errChainObject, o.Size(), obj.size)
	}
	return &checkedObject{o: o, key: key, size: obj.size, want: rec.SHA256, h: sha256.New(), log: s.log, onFail: s.fail}, rec, nil
}

// List implements ingest.Source: the objects it serves under prefix.
func (s *NativeRestoreSource) List(_ context.Context, prefix string) ([]ingest.ObjectRecord, error) {
	var out []ingest.ObjectRecord
	for k, o := range s.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, ingest.ObjectRecord{Key: k, Size: o.size, SHA256: hex.EncodeToString(o.sha[:])})
		}
	}
	slices.SortFunc(out, func(a, b ingest.ObjectRecord) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

// Failed is the first object that did not match its signed manifest when
// it was served, "" when none did.
func (s *NativeRestoreSource) Failed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

func (s *NativeRestoreSource) fail(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == "" {
		s.failed = key
	}
}

// Objects is how many objects the source serves.
func (s *NativeRestoreSource) Objects() int { return len(s.objects) }
