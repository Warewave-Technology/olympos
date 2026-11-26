package backup

// Incrementals of native backups (design docs/design/clickhouse-native.md
// §7): a job with incrementals takes a full backup on the first run of the
// week, by its time zone, and an incremental on the other runs. The base is
// the latest run of the job that succeeded on every destination and whose
// manifests verify; a partial run is never a base, nor a test run (R40). The
// run's credential reads the base chain, and the endpoint serves it from
// the run's first destination: only objects the chain's verified manifests
// list, each checked against its manifest while it streams (chainSource).
// When the incremental's tier is longer than its base's, the base chain is
// re-tagged to that tier on the destination (retagChain).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// nativeMaxChain is the longest chain, its full included, an incremental is
// taken on; a longer one makes the run a full. It bounds what a run reads
// and verifies before its BACKUP (each manifest up to 64 MiB): a job that
// runs more often than daily gets a full every nativeMaxChain runs.
const nativeMaxChain = 32

// nativeChain is the base chain of an incremental: its runs, the full first
// and the base last, and where each run's copies are. loadChain adds the
// verified manifests and the destinations they are on.
type nativeChain struct {
	Runs []uuid.UUID
	// copies are each run's succeeded copies by destination, as Runs.
	copies []map[uuid.UUID]chainCopy
	// Set by loadChain: the signed manifests as stored and as verified, as
	// Runs, and the run's destinations, the one the chain is read from
	// first.
	signed    [][]byte
	manifests []NativeChainManifest
	dests     []*nativeDest
}

// chainCopy is one run's copy on a destination.
type chainCopy struct {
	dir, sha256, tier string
}

// base is the chain's last run, the incremental's base.
func (c *nativeChain) base() uuid.UUID { return c.Runs[len(c.Runs)-1] }

// prefixes are the chain's bucket prefixes, base first: the credential's
// read scope.
func (c *nativeChain) prefixes() []string {
	out := make([]string, len(c.Runs))
	for i, r := range c.Runs {
		out[i] = r.String() + "/"
	}
	return out
}

// on is the chain on one of its destinations only.
func (c *nativeChain) on(d *nativeDest) *nativeChain {
	o := *c
	o.dests = []*nativeDest{d}
	return &o
}

// weekStart is the start of now's ISO week (Monday 00:00) in loc.
func weekStart(now time.Time, loc *time.Location) time.Time {
	t := now.In(loc)
	wd := (int(t.Weekday()) + 6) % 7 // Monday = 0
	return time.Date(t.Year(), t.Month(), t.Day()-wd, 0, 0, 0, 0, loc)
}

// selectBase returns the base chain of the job's next native run at now, or
// nil when the run is a full backup. The candidate is the latest native run
// of the job in now's week (job time zone) that ended succeeded or partial,
// other than a test run. It is no base, and the run a full, when it is
// partial, when an incremental of the job failed after it (it may have
// failed on its base), or when its chain is longer than nativeMaxChain,
// starts before the week, or holds a run that did not succeed. Its chain is
// its credential's read scope and itself. Whether the chain is on every
// destination, and verifies, is loadChain's.
func selectBase(ctx context.Context, q store.Querier, job *Job, now time.Time) (*nativeChain, error) {
	loc, err := time.LoadLocation(job.Timezone)
	if err != nil {
		loc = time.UTC
	}
	week := weekStart(now, loc)
	var base uuid.UUID
	var status string
	var read []byte
	var at time.Time
	err = q.QueryRow(ctx, `SELECT r.id, r.status, COALESCE(c.scope -> 'read', '[]'::jsonb), COALESCE(r.scheduled_for, r.started_at)
		FROM backup_runs r JOIN ingest_credentials c ON c.run_id = r.id AND c.kind = 'backup'
		WHERE r.job_id = $1 AND r.trigger <> 'test' AND r.status IN ('succeeded', 'partial') AND r.finished_at IS NOT NULL
			AND COALESCE(r.scheduled_for, r.started_at) >= $2
		ORDER BY COALESCE(r.scheduled_for, r.started_at) DESC, r.started_at DESC LIMIT 1`, job.ID, week).Scan(&base, &status, &read, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if status != "succeeded" {
		return nil, nil
	}
	var failed bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM backup_runs r JOIN ingest_credentials c ON c.run_id = r.id AND c.kind = 'backup'
		WHERE r.job_id = $1 AND r.trigger <> 'test' AND r.status = 'failed' AND c.scope -> 'read' IS NOT NULL
			AND COALESCE(r.scheduled_for, r.started_at) > $2)`, job.ID, at).Scan(&failed); err != nil {
		return nil, err
	}
	if failed {
		return nil, nil
	}
	var prefixes []string
	if err := json.Unmarshal(read, &prefixes); err != nil {
		return nil, fmt.Errorf("the read scope of run %s: %w", base, err)
	}
	if len(prefixes)+1 > nativeMaxChain {
		return nil, nil
	}
	c := &nativeChain{}
	for _, p := range prefixes {
		id, err := uuid.Parse(strings.TrimSuffix(p, "/"))
		if err != nil || id.String()+"/" != p {
			return nil, fmt.Errorf("the read scope of run %s holds %q, not a run's prefix", base, p)
		}
		c.Runs = append(c.Runs, id)
	}
	c.Runs = append(c.Runs, base)

	rows, err := q.Query(ctx, `SELECT id, job_id, status, trigger, COALESCE(scheduled_for, started_at) FROM backup_runs WHERE id = ANY($1)`, c.Runs)
	if err != nil {
		return nil, err
	}
	good := map[uuid.UUID]bool{}
	var first time.Time
	for rows.Next() {
		var id, jobID uuid.UUID
		var st, trigger string
		var at time.Time
		if err := rows.Scan(&id, &jobID, &st, &trigger, &at); err != nil {
			rows.Close()
			return nil, err
		}
		good[id] = jobID == job.ID && st == "succeeded" && trigger != "test"
		if id == c.Runs[0] {
			first = at
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range c.Runs {
		if !good[id] {
			return nil, nil
		}
	}
	if first.Before(week) {
		return nil, nil
	}

	c.copies = make([]map[uuid.UUID]chainCopy, len(c.Runs))
	index := map[uuid.UUID]int{}
	for i, id := range c.Runs {
		c.copies[i], index[id] = map[uuid.UUID]chainCopy{}, i
	}
	rows, err = q.Query(ctx, `SELECT run_id, destination_id, blob_path, sha256, tier FROM backup_run_copies
		WHERE run_id = ANY($1) AND status = 'succeeded'`, c.Runs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var run, dest uuid.UUID
		var cc chainCopy
		if err := rows.Scan(&run, &dest, &cc.dir, &cc.sha256, &cc.tier); err != nil {
			return nil, err
		}
		c.copies[index[run]][dest] = cc
	}
	return c, rows.Err()
}

// loadChain checks that every run of the chain has a succeeded copy, of the
// same manifest, on every destination of the run (live), reads the chain's
// signed manifests from the first of them and verifies them as a chain
// whose last is the base (NativeEngine.VerifyNativeChain). An error says the
// chain is no base.
func (w *Worker) loadChain(ctx context.Context, eng NativeEngine, c *nativeChain, live []*nativeDest) error {
	if len(live) == 0 {
		return errors.New("no destination")
	}
	for i, run := range c.Runs {
		var sha string
		for _, d := range live {
			cc, ok := c.copies[i][d.ref.ID]
			switch {
			case !ok:
				return fmt.Errorf("run %s has no copy on %s", run, d.ref.Name)
			case sha != "" && cc.sha256 != sha:
				return fmt.Errorf("run %s has another manifest on %s", run, d.ref.Name)
			}
			sha = cc.sha256
		}
	}
	r, ok := live[0].w.(blob.Reader)
	if !ok {
		return fmt.Errorf("%s cannot be read", live[0].ref.Name)
	}
	signed := make([][]byte, len(c.Runs))
	for i, run := range c.Runs {
		raw, err := readSidecarManifest(ctx, r, ManifestPath(c.copies[i][live[0].ref.ID].dir, run))
		if err != nil {
			return fmt.Errorf("the manifest of run %s: %w", run, err)
		}
		signed[i] = raw
	}
	ms, err := eng.VerifyNativeChain(ctx, w.Native.KV, w.Native.ManifestKeyName, c.base().String(), signed)
	if err != nil {
		return err
	}
	for i, m := range ms {
		if m.RunID != c.Runs[i].String() || m.SHA256 != c.copies[i][live[0].ref.ID].sha256 {
			return fmt.Errorf("the manifest of run %s is not the one its copies were written with", c.Runs[i])
		}
	}
	c.signed, c.manifests, c.dests = signed, ms, live
	return nil
}

// readSidecarManifest reads a native run's sidecar at path, at most
// MaxNativeSidecarBytes, and returns the signed manifest in its Details, as
// stored.
func readSidecarManifest(ctx context.Context, r blob.Reader, path string) ([]byte, error) {
	o, err := r.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer o.Close()
	if o.Size() > MaxNativeSidecarBytes {
		return nil, fmt.Errorf("the sidecar is %d bytes, over the %d bytes a reader takes", o.Size(), MaxNativeSidecarBytes)
	}
	b, err := io.ReadAll(io.NewSectionReader(o, 0, o.Size()))
	if err != nil {
		return nil, err
	}
	var side struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(b, &side); err != nil {
		return nil, fmt.Errorf("the sidecar: %w", err)
	}
	raw := side.Details[NativeManifestDetail]
	if len(raw) == 0 {
		return nil, errors.New("the sidecar holds no native manifest")
	}
	return raw, nil
}

// tierRank orders the tiers by how long they are kept.
func tierRank(tier string) int {
	return slices.Index([]string{"test", "daily", "weekly", "monthly"}, tier)
}

// retagChain keeps the chain as long as an incremental of tier on it (design
// §7, Retention): on each of the chain's destinations, every run whose copy
// is of a shorter tier gets its objects and its manifest re-tagged tier,
// complete. The copies' rows keep the tier they were written with.
func retagChain(ctx context.Context, chain *nativeChain, tier string) error {
	for _, d := range chain.dests {
		for i, run := range chain.Runs {
			cc := chain.copies[i][d.ref.ID]
			if tierRank(cc.tier) >= tierRank(tier) {
				continue
			}
			rd := &nativeDest{ref: d.ref, w: d.w, dir: cc.dir, tier: tier}
			if err := retag(ctx, rd, run.String(), chain.manifests[i].Objects); err != nil {
				return fmt.Errorf("run %s: %w", run, err)
			}
			if err := d.w.(tagSetter).SetTags(ctx, ManifestPath(cc.dir, run), rd.tags(StateComplete)); err != nil {
				return fmt.Errorf("run %s: the manifest: %w", run, err)
			}
		}
	}
	return nil
}

// chainSource is the ingest.Source of an incremental's run: the objects of
// its base chain, read from the chain's first destination. It serves only
// objects the chain's verified manifests list, by bucket-relative key, and
// checks each against its manifest's size and SHA-256 while it streams: a
// reader never gets an object that is not the one signed.
type chainSource struct {
	r       blob.Reader
	objects map[string]chainObject
	log     *slog.Logger
}

// chainObject is an object of the chain and where it is stored.
type chainObject struct {
	rec  ingest.ObjectRecord
	path string
}

var _ ingest.Source = (*chainSource)(nil)

// errChainObject: an object of the chain is not the one its manifest signed.
var errChainObject = errors.New("the stored object is not the one its signed manifest lists")

// newChainSource serves the loaded chain c from its first destination.
func newChainSource(c *nativeChain, log *slog.Logger) (*chainSource, error) {
	d := c.dests[0]
	r, ok := d.w.(blob.Reader)
	if !ok {
		return nil, fmt.Errorf("%s cannot be read", d.ref.Name)
	}
	s := &chainSource{r: r, objects: map[string]chainObject{}, log: log}
	for i, m := range c.manifests {
		dir := c.copies[i][d.ref.ID].dir
		for _, o := range m.Objects {
			rel, ok := strings.CutPrefix(o.Key, m.RunID+"/")
			if !ok {
				return nil, fmt.Errorf("object %s is not under run %s", o.Key, m.RunID)
			}
			s.objects[o.Key] = chainObject{rec: o, path: dir + "/" + rel}
		}
	}
	return s, nil
}

// Open implements ingest.Source.
func (s *chainSource) Open(ctx context.Context, key string) (io.ReadCloser, ingest.ObjectRecord, error) {
	obj, ok := s.objects[key]
	if !ok {
		return nil, ingest.ObjectRecord{}, fmt.Errorf("%s is not an object of the base chain: %w", key, fs.ErrNotExist)
	}
	o, err := s.r.Open(ctx, obj.path)
	if err != nil {
		return nil, ingest.ObjectRecord{}, err
	}
	if o.Size() != obj.rec.Size {
		_ = o.Close()
		s.log.Error("native backup: an object of the base chain does not match its signed manifest", "key", key,
			"stored_bytes", o.Size(), "signed_bytes", obj.rec.Size)
		return nil, ingest.ObjectRecord{}, fmt.Errorf("%s: %w (%d bytes stored, %d signed)", key, errChainObject, o.Size(), obj.rec.Size)
	}
	return &checkedObject{o: o, key: key, size: obj.rec.Size, want: obj.rec.SHA256, h: sha256.New(), log: s.log}, obj.rec, nil
}

// List implements ingest.Source: the chain's objects under prefix.
func (s *chainSource) List(_ context.Context, prefix string) ([]ingest.ObjectRecord, error) {
	var out []ingest.ObjectRecord
	for k, o := range s.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, o.rec)
		}
	}
	slices.SortFunc(out, func(a, b ingest.ObjectRecord) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

// read returns an object of the chain whole, at most limit bytes
// (NativeManifestBase.Read).
func (s *chainSource) read(ctx context.Context, key string, limit int64) ([]byte, error) {
	rc, rec, err := s.Open(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if rec.Size > limit {
		return nil, fmt.Errorf("%s is %d bytes, over %d", key, rec.Size, limit)
	}
	var b bytes.Buffer
	if _, err := io.Copy(&b, rc); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// checkedObject streams a stored object and checks its SHA-256 against the
// signed one. It holds back the object's last bytes until the whole object
// is checked: on a mismatch the read fails, so the reader never gets all of
// an object that is not the signed one.
type checkedObject struct {
	o         blob.Object
	key, want string
	off, size int64
	h         hash.Hash
	log       *slog.Logger
	failed    error
}

func (c *checkedObject) Read(p []byte) (int, error) {
	if c.failed != nil {
		return 0, c.failed
	}
	if c.off >= c.size {
		if c.size == 0 && hex.EncodeToString(c.h.Sum(nil)) != c.want {
			return 0, c.fail()
		}
		return 0, io.EOF
	}
	if rest := c.size - c.off; int64(len(p)) > rest {
		p = p[:rest]
	}
	n, err := c.o.ReadAt(p, c.off)
	if n > 0 {
		_, _ = c.h.Write(p[:n])
		if c.off+int64(n) == c.size && hex.EncodeToString(c.h.Sum(nil)) != c.want {
			return 0, c.fail()
		}
		c.off += int64(n)
	}
	switch {
	case errors.Is(err, io.EOF) && c.off < c.size:
		return n, io.ErrUnexpectedEOF
	case errors.Is(err, io.EOF):
		return n, nil
	}
	return n, err
}

func (c *checkedObject) fail() error {
	c.failed = fmt.Errorf("%s: %w", c.key, errChainObject)
	c.log.Error("native backup: an object of the base chain does not match its signed manifest", "key", c.key)
	return c.failed
}

func (c *checkedObject) Close() error { return c.o.Close() }
