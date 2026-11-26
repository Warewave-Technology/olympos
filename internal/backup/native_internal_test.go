//go:build dev

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// memWriter is a destination in memory. hold, when set, keeps an upload that
// read its whole body from returning until it is closed.
type memWriter struct {
	mu   sync.Mutex
	objs map[string][]byte
	tags map[string]map[string]string
	fail error
	hold chan struct{}
	read chan struct{} // closed when an upload read its body to the end
}

func newMemWriter() *memWriter {
	return &memWriter{objs: map[string][]byte{}, tags: map[string]map[string]string{}, read: make(chan struct{})}
}

func (m *memWriter) Prefix() string { return "p" }

func (m *memWriter) Upload(ctx context.Context, path string, r io.Reader, _ string, tags map[string]string) (blob.UploadResult, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return blob.UploadResult{}, err
	}
	if m.fail != nil {
		return blob.UploadResult{}, m.fail
	}
	if m.hold != nil {
		close(m.read)
		select {
		case <-m.hold:
		case <-ctx.Done():
			return blob.UploadResult{}, ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[path], m.tags[path] = b, tags
	return blob.UploadResult{Bytes: int64(len(b))}, nil
}

const sinkRun = "0f6b2a4e-8d1c-4f3a-9b7e-2c5d8a1f6e30"

func testSink(ws ...*memWriter) (*nativeSink, []*nativeDest) {
	var ds []*nativeDest
	for i, w := range ws {
		ds = append(ds, &nativeDest{i: i, ref: destRef{Name: string(rune('a' + i))}, w: w, dir: "p/run", tier: "daily"})
	}
	return newNativeSink(context.Background(), sinkRun, ds), ds
}

// errReader fails after its data.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		return n, e.err
	}
	return n, err
}

func TestNativeSinkDetaches(t *testing.T) {
	a, b := newMemWriter(), newMemWriter()
	b.fail = errors.New("503 ServerBusy")
	s, ds := testSink(a, b)
	defer s.close()
	rec, err := s.Put(context.Background(), sinkRun+"/data/x.bin", strings.NewReader("abc"))
	if err != nil || rec.Size != 3 || rec.Key != sinkRun+"/data/x.bin" || len(rec.SHA256) != 64 {
		t.Fatalf("put: %+v %v", rec, err)
	}
	if ds[0].failed() != nil || ds[1].failed() == nil || ds[1].failed().Error() != "upload data/x.bin: 503 ServerBusy" {
		t.Fatalf("detached: %v / %v", ds[0].failed(), ds[1].failed())
	}
	if tg := a.tags["p/run/data/x.bin"]; string(a.objs["p/run/data/x.bin"]) != "abc" || tg[StateTag] != StateIncomplete || tg[TierTag] != "daily" {
		t.Fatalf("stored: %v %v", a.objs, tg)
	}
	// Detached for the rest of the run, even when it would work again.
	b.fail = nil
	if _, err := s.Put(context.Background(), sinkRun+"/data/y.bin", strings.NewReader("y")); err != nil || len(b.objs) != 0 {
		t.Fatalf("second put: %v, detached destination got %v", err, b.objs)
	}
	a.fail = errors.New("gone")
	if _, err := s.Put(context.Background(), sinkRun+"/data/z.bin", strings.NewReader("z")); err == nil || ds[0].failed() == nil {
		t.Fatalf("no destination left: %v", err)
	}
	if _, err := s.Put(context.Background(), "other/data/z.bin", strings.NewReader("z")); err == nil {
		t.Fatal("a key outside the run")
	}
}

// A body that does not arrive whole is dropped, and no destination is to
// blame for it.
func TestNativeSinkBodyLost(t *testing.T) {
	a := newMemWriter()
	s, ds := testSink(a)
	defer s.close()
	lost := errors.New("unexpected EOF")
	if _, err := s.Put(context.Background(), sinkRun+"/data/x.bin", &errReader{r: strings.NewReader("ab"), err: lost}); !errors.Is(err, lost) {
		t.Fatalf("put: %v", err)
	}
	if ds[0].failed() != nil || len(a.objs) != 0 {
		t.Fatalf("detached %v, stored %v", ds[0].failed(), a.objs)
	}
	// The request ends before the body: the same.
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("ab"))
		cancel()
		time.Sleep(50 * time.Millisecond)
		pw.CloseWithError(context.Canceled)
	}()
	if _, err := s.Put(ctx, sinkRun+"/data/y.bin", pr); err == nil || ds[0].failed() != nil {
		t.Fatalf("put of a cancelled request: %v, detached %v", err, ds[0].failed())
	}
}

// Once the body is whole, the request's end does not cancel what is being
// stored: a client that hangs up after its body is not a failed destination
// (the handler would stop the run as one).
func TestNativeSinkClientGoneAfterBody(t *testing.T) {
	a := newMemWriter()
	a.hold = make(chan struct{})
	s, ds := testSink(a)
	defer s.close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-a.read
		cancel() // the client hangs up while the destination commits
		time.Sleep(50 * time.Millisecond)
		close(a.hold)
	}()
	if _, err := s.Put(ctx, sinkRun+"/data/x.bin", bytes.NewReader([]byte("whole"))); err != nil {
		t.Fatal(err)
	}
	if ds[0].failed() != nil || string(a.objs["p/run/data/x.bin"]) != "whole" {
		t.Fatalf("detached %v, stored %v", ds[0].failed(), a.objs)
	}
}

func TestNativeSinkClosed(t *testing.T) {
	a := newMemWriter()
	a.hold = make(chan struct{})
	s, ds := testSink(a)
	done := make(chan error)
	go func() {
		_, err := s.Put(context.Background(), sinkRun+"/data/x.bin", strings.NewReader("x"))
		done <- err
	}()
	<-a.read
	s.close() // ends the upload still running, and waits for it
	if err := <-done; err == nil {
		t.Fatal("an upload cut by the run's end succeeded")
	}
	if ds[0].failed() != nil {
		t.Fatalf("the run's end is not the destination's failure: %v", ds[0].failed())
	}
	if _, err := s.Put(context.Background(), sinkRun+"/data/y.bin", strings.NewReader("y")); !errors.Is(err, errSinkClosed) {
		t.Fatalf("put after close: %v", err)
	}
}

// nativeLastFull: the bytes of the job's last full native run, 0 before
// the first; logical runs, incrementals and test runs do not count.
func TestNativeLastFull(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	var cluster, job, dest uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, status) VALUES ('q', 'online') RETURNING id`).Scan(&cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ('t-q', $1, 'db', 'q', 9000, 'clickhouse')`, cluster); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('dq', 'acct', 'b', 'o', 'managed_identity')
		RETURNING id`).Scan(&dest); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone) VALUES ('t-q', $1, '0 2 * * *', 'UTC') RETURNING id`,
		dest).Scan(&job); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	trigger := "manual"
	finished := func(status string, bytes int64, scope string) {
		t.Helper()
		at = at.Add(time.Hour)
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, bytes) VALUES ($1, $5, $2, $3, $3, $4)
			RETURNING id`, job, status, at, bytes, trigger).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if scope != "" {
			if _, err := db.Exec(ctx, `INSERT INTO ingest_credentials (access_key, run_id, kind, scope, fingerprint, expires_at)
				VALUES ($1, $2, 'backup', $3, 'hm:x', now())`, "OLY"+id.String()[:17], id, scope); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := func(n int64) {
		t.Helper()
		if got, err := nativeLastFull(ctx, db, job); err != nil || got != n {
			t.Fatalf("last full %d %v, want %d", got, err, n)
		}
	}
	want(0)
	finished("succeeded", 10<<30, "") // logical
	want(0)
	finished("succeeded", 3<<30, `{"write": "x/"}`)
	want(3 << 30)
	finished("failed", 20<<30, `{"write": "y/"}`)
	finished("succeeded", 30<<30, `{"write": "z/", "read": ["x/"]}`) // an incremental
	want(3 << 30)
	finished("partial", 1<<20, `{"write": "w/"}`)
	want(1 << 20)
	// A dry run backs up the structure only (R40): it is no full.
	trigger = "test"
	finished("succeeded", 2<<10, `{"write": "v/"}`)
	want(1 << 20)
}

// nativeQuota (R39, R44): the largest of twice the last full native run
// (at most twice the databases' size), 1.5 times the databases' size and
// 1 GiB; ingest.maxRunBytes, when set, instead. A database with no full yet,
// or one that grew, is not stopped by an earlier, smaller run; a full that
// wrote far more than the databases hold does not raise the next limit.
func TestNativeQuota(t *testing.T) {
	for _, tc := range []struct {
		last, size, override, want int64
	}{
		{0, 0, 0, 1 << 30},                       // an empty database, no full yet
		{0, 200 << 30, 0, 300 << 30},             // a large database, no full yet
		{100 << 20, 5 << 30, 0, 15 << 29},        // a tiny first full, then 5 GiB loaded
		{3 << 30, 2 << 30, 0, 4 << 30},           // twice the last full, at most twice the size
		{5 << 30, 4 << 30, 0, 8 << 30},           // a full larger than the size on disk
		{7 << 30, 4 << 30, 0, 8 << 30},           // bounded by twice the size
		{100 << 30, 2 << 30, 0, 4 << 30},         // R44: no ratchet from a full of junk
		{3 << 30, 0, 0, 1 << 30},                 // no size read: the floor
		{1 << 20, 1 << 20, 0, 1 << 30},           // the floor
		{3 << 30, 100 << 30, 10 << 30, 10 << 30}, // ingest.maxRunBytes
		{0, 0, 1 << 20, 1 << 20},                 // under the floor too
	} {
		if got := nativeQuota(tc.last, tc.size, tc.override); got != tc.want {
			t.Errorf("nativeQuota(%d, %d, %d) = %d, want %d", tc.last, tc.size, tc.override, got, tc.want)
		}
	}
}

// Minor 4: the worker's context does not cut the sink's uploads. A server
// that shuts down stops the session (stopForward), which ends the bodies; an
// upload the worker's context cut while the session is still live would be
// taken by the handler for a failed destination. Only close ends them.
func TestNativeSinkOutlivesWorkerContext(t *testing.T) {
	a := newMemWriter()
	a.hold = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s := newNativeSink(ctx, sinkRun, []*nativeDest{{ref: destRef{Name: "a"}, w: a, dir: "p/run", tier: "daily"}})
	defer s.close()
	done := make(chan error, 1)
	go func() {
		_, err := s.Put(context.Background(), sinkRun+"/data/x.bin", strings.NewReader("x"))
		done <- err
	}()
	<-a.read
	cancel()
	select {
	case err := <-done:
		t.Fatalf("the worker's context cut the upload: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(a.hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// memReader is a blob.Reader over memWriter's objects.
type memReader struct{ *memWriter }

func (m memReader) Open(_ context.Context, path string) (blob.Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return memObj{bytes.NewReader(b)}, nil
}

type memObj struct{ *bytes.Reader }

func (memObj) Close() error { return nil }

// chainSource serves only the objects of the chain's verified manifests,
// from the run's directory on its first destination, and checks each while
// it streams: a changed object never reaches the reader whole.
func TestChainSource(t *testing.T) {
	const base, other = "7c2e9d14-3b6a-4e8f-a1d5-9f0b4c7e2a61", "d41e7a90-5c2b-4b8e-9e3f-61a0c8b7d2f4"
	m := newMemWriter()
	body := bytes.Repeat([]byte("signed bytes "), 1000)
	sum := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	m.objs["p/base/.backup"] = body
	m.objs["p/base/data/x.bin"] = append(bytes.Clone(body[:len(body)-1]), '!') // changed in storage
	m.objs["p/base/data/short.bin"] = body[:10]
	m.objs["p/base/data/stray.bin"] = body // stored, not signed
	id := uuid.MustParse(base)
	d := &nativeDest{ref: destRef{ID: uuid.New(), Name: "a"}, w: memReader{m}}
	c := &nativeChain{Runs: []uuid.UUID{id}, copies: []map[uuid.UUID]chainCopy{{d.ref.ID: {dir: "p/base"}}}, dests: []*nativeDest{d},
		manifests: []NativeChainManifest{{RunID: base, Objects: []ingest.ObjectRecord{
			{Key: base + "/.backup", Size: int64(len(body)), SHA256: sum(body)},
			{Key: base + "/data/x.bin", Size: int64(len(body)), SHA256: sum(body)},
			{Key: base + "/data/short.bin", Size: int64(len(body)), SHA256: sum(body)},
		}}}}
	s, err := newChainSource(c, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if b, err := s.read(ctx, base+"/.backup", 1<<20); err != nil || !bytes.Equal(b, body) {
		t.Fatalf(".backup: %v", err)
	}
	if _, err := s.read(ctx, base+"/.backup", 10); err == nil {
		t.Fatal("over the limit")
	}
	for _, key := range []string{base + "/data/stray.bin", other + "/.backup", base + "/"} {
		if _, _, err := s.Open(ctx, key); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v", key, err)
		}
	}
	if _, _, err := s.Open(ctx, base+"/data/short.bin"); !errors.Is(err, errChainObject) {
		t.Fatalf("a shorter object: %v", err)
	}
	// A signed object gone from storage fails the source; it is no missing key.
	delete(m.objs, "p/base/.backup")
	if _, _, err := s.Open(ctx, base+"/.backup"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a signed object gone: %v", err)
	}
	m.objs["p/base/.backup"] = body
	// The changed object: everything but its last bytes, then the error.
	rc, rec, err := s.Open(ctx, base+"/data/x.bin")
	if err != nil || rec.SHA256 != sum(body) {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if !errors.Is(err, errChainObject) || len(got) >= len(body) {
		t.Fatalf("read %d of %d bytes: %v", len(got), len(body), err)
	}
	recs, err := s.List(ctx, base+"/data/")
	if err != nil || len(recs) != 2 || recs[0].Key != base+"/data/short.bin" || recs[1].Key != base+"/data/x.bin" {
		t.Fatalf("list: %+v %v", recs, err)
	}
	if recs, _ := s.List(ctx, other+"/"); len(recs) != 0 {
		t.Fatalf("list of another run: %+v", recs)
	}
}

// retagChain (R45): an incremental keeps its chain at least weekly: every
// run whose copy is of a shorter tier than weekly, or than the incremental's
// when that is longer, gets its objects and its manifest re-tagged, on each
// of the chain's destinations. A tier is never lowered; an unknown tier
// fails the re-tag.
func TestRetagChain(t *testing.T) {
	const full, inc = "7c2e9d14-3b6a-4e8f-a1d5-9f0b4c7e2a61", "d41e7a90-5c2b-4b8e-9e3f-61a0c8b7d2f4"
	chain := func(tiers ...string) (*nativeChain, *memWriter) {
		m := newMemWriter()
		for _, p := range []string{"p/" + full + "/.backup", "p/" + full + ".manifest.json", "p/" + inc + "/.backup", "p/" + inc + ".manifest.json"} {
			m.objs[p] = []byte("x")
		}
		d := &nativeDest{ref: destRef{ID: uuid.New(), Name: "a"}, w: tagMem{m}}
		return &nativeChain{Runs: []uuid.UUID{uuid.MustParse(full), uuid.MustParse(inc)}, dests: []*nativeDest{d},
			copies: []map[uuid.UUID]chainCopy{{d.ref.ID: {dir: "p/" + full, tier: tiers[0]}}, {d.ref.ID: {dir: "p/" + inc, tier: tiers[1]}}},
			manifests: []NativeChainManifest{{RunID: full, Objects: []ingest.ObjectRecord{{Key: full + "/.backup"}}},
				{RunID: inc, Objects: []ingest.ObjectRecord{{Key: inc + "/.backup"}}}}}, m
	}
	tagged := func(m *memWriter, run string) [2]string {
		return [2]string{m.tags["p/"+run+"/.backup"][TierTag], m.tags["p/"+run+".manifest.json"][TierTag]}
	}
	// Daily on daily: the daily member is kept weekly; a weekly or longer
	// one is left as it is.
	c, m := chain("weekly", "daily")
	if err := retagChain(context.Background(), c, "daily"); err != nil {
		t.Fatal(err)
	}
	if got := tagged(m, inc); got != [2]string{"weekly", "weekly"} || m.tags["p/"+inc+"/.backup"][StateTag] != StateComplete {
		t.Fatalf("the daily member: %v %v", got, m.tags)
	}
	if got := tagged(m, full); got != [2]string{} {
		t.Fatalf("the weekly member re-tagged: %v", got)
	}
	// An incremental of a longer tier takes its chain to that tier, never
	// lower: a monthly member stays monthly.
	c, m = chain("weekly", "monthly")
	if err := retagChain(context.Background(), c, "monthly"); err != nil {
		t.Fatal(err)
	}
	if tagged(m, full) != [2]string{"monthly", "monthly"} || tagged(m, inc) != [2]string{} {
		t.Fatalf("monthly: %v", m.tags)
	}
	c, m = chain("monthly", "daily")
	if err := retagChain(context.Background(), c, "daily"); err != nil {
		t.Fatal(err)
	}
	if tagged(m, full) != [2]string{} || tagged(m, inc) != [2]string{"weekly", "weekly"} {
		t.Fatalf("a monthly member lowered: %v", m.tags)
	}
	// An unknown tier, of a member or of the incremental, fails closed.
	for _, tc := range [][3]string{{"weekly", "yearly", "daily"}, {"", "daily", "daily"}, {"weekly", "daily", "hourly"}} {
		c, _ := chain(tc[0], tc[1])
		if err := retagChain(context.Background(), c, tc[2]); err == nil || !strings.Contains(err.Error(), "tier") {
			t.Errorf("tiers %v: %v", tc, err)
		}
	}
}

// chainDB is a job with one destination whose native runs a test writes
// into the database directly, as selectBase reads them.
type chainDB struct {
	t    *testing.T
	db   *store.DB
	job  *Job
	dest uuid.UUID
}

func newChainDB(t *testing.T, tz string) *chainDB {
	t.Helper()
	db := testutil.DB(t)
	ctx := context.Background()
	var cluster, job, dest uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, status) VALUES ('c', 'online') RETURNING id`).Scan(&cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine) VALUES ('t-c', $1, 'db', 'c', 9000, 'clickhouse')`, cluster); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('dc', 'acct', 'b', 'o', 'managed_identity')
		RETURNING id`).Scan(&dest); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone) VALUES ('t-c', $1, '0 2 * * *', $2) RETURNING id`,
		dest, tz).Scan(&job); err != nil {
		t.Fatal(err)
	}
	return &chainDB{t: t, db: db, job: &Job{ID: job, Timezone: tz}, dest: dest}
}

// run records a finished native run of job at at, with its credential
// reading read and, when it succeeded, a copy on the destination.
func (c *chainDB) run(job uuid.UUID, at time.Time, status, trigger string, read ...string) uuid.UUID {
	c.t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := c.db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $4, $4) RETURNING id`, job, trigger, status, at).Scan(&id); err != nil {
		c.t.Fatal(err)
	}
	scope := map[string]any{"write": id.String() + "/"}
	if len(read) > 0 {
		scope["read"] = read
	}
	if _, err := c.db.Exec(ctx, `INSERT INTO ingest_credentials (access_key, run_id, kind, scope, fingerprint, expires_at)
		VALUES ($1, $2, 'backup', $3, 'hm:x', now())`, "OLY"+id.String()[:17], id, scope); err != nil {
		c.t.Fatal(err)
	}
	if status == "succeeded" {
		if _, err := c.db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, blob_path, sha256, tier)
			VALUES ($1, $2, 'succeeded', $3, $4, 'daily')`, id, c.dest, "o/"+id.String(), "sha-"+id.String()); err != nil {
			c.t.Fatal(err)
		}
	}
	return id
}

// base is what selectBase returns at now: the chain's runs, nil for a full.
func (c *chainDB) base(now time.Time) []uuid.UUID {
	c.t.Helper()
	ch, err := selectBase(context.Background(), c.db, c.job, now)
	if err != nil {
		c.t.Fatal(err)
	}
	if ch == nil {
		return nil
	}
	return ch.Runs
}

func prefixesOf(ids ...uuid.UUID) []string {
	var out []string
	for _, id := range ids {
		out = append(out, id.String()+"/")
	}
	return out
}

// selectBase: the chain of the latest run of the week and month, when every
// run of it is a succeeded run of the job, not a test run, within the
// period, and not longer than nativeMaxChain with the new run.
func TestSelectBase(t *testing.T) {
	day := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, time.UTC) }
	c := newChainDB(t, "UTC")
	if b := c.base(day(24, 2)); b != nil {
		t.Fatalf("no run yet: %v", b)
	}
	full := c.run(c.job.ID, day(23, 2), "succeeded", "schedule")
	if b := c.base(day(24, 2)); !slices.Equal(b, []uuid.UUID{full}) {
		t.Fatalf("on the full: %v", b)
	}
	inc := c.run(c.job.ID, day(24, 2), "succeeded", "schedule", prefixesOf(full)...)
	if b := c.base(day(25, 2)); !slices.Equal(b, []uuid.UUID{full, inc}) {
		t.Fatalf("on the incremental: %v", b)
	}
	// The next week, and the first run of a month, are fulls.
	if b := c.base(day(30, 2)); b != nil {
		t.Fatalf("next week: %v", b)
	}

	for name, read := range map[string]func(c *chainDB) []string{
		// The chain's full is in the week before.
		"a full before the week": func(c *chainDB) []string { return prefixesOf(c.run(c.job.ID, day(22, 2), "succeeded", "schedule")) },
		"a run of another job": func(c *chainDB) []string {
			var job uuid.UUID
			if err := c.db.QueryRow(context.Background(), `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone)
				VALUES ('t-c', $1, '0 3 * * *', 'UTC') RETURNING id`, c.dest).Scan(&job); err != nil {
				t.Fatal(err)
			}
			return prefixesOf(c.run(job, day(23, 3), "succeeded", "schedule"))
		},
		"a failed run":   func(c *chainDB) []string { return prefixesOf(c.run(c.job.ID, day(23, 4), "failed", "schedule")) },
		"a partial run":  func(c *chainDB) []string { return prefixesOf(c.run(c.job.ID, day(23, 5), "partial", "schedule")) },
		"a test run":     func(c *chainDB) []string { return prefixesOf(c.run(c.job.ID, day(23, 6), "succeeded", "test")) },
		"an unknown run": func(*chainDB) []string { return prefixesOf(uuid.New()) },
	} {
		c := newChainDB(t, "UTC")
		base := c.run(c.job.ID, day(25, 2), "succeeded", "schedule", read(c)...)
		if b := c.base(day(26, 2)); b != nil {
			t.Errorf("%s: based on %v (base %s)", name, b, base)
		}
	}

	// R45: the first run of a month is a full, even within the week.
	c = newChainDB(t, "UTC")
	c.run(c.job.ID, time.Date(2026, 11, 30, 2, 0, 0, 0, time.UTC), "succeeded", "schedule")
	if b := c.base(time.Date(2026, 12, 1, 2, 0, 0, 0, time.UTC)); b != nil {
		t.Fatalf("the first run of December: %v", b)
	}
	// By the job's time zone: 30 Nov 16:00 UTC is 1 Dec in Tokyo.
	c = newChainDB(t, "Asia/Tokyo")
	c.run(c.job.ID, time.Date(2026, 11, 30, 2, 0, 0, 0, time.UTC), "succeeded", "schedule")
	if b := c.base(time.Date(2026, 11, 30, 16, 0, 0, 0, time.UTC)); b != nil {
		t.Fatalf("the first run of December in Tokyo: %v", b)
	}
	if b := c.base(time.Date(2026, 11, 30, 14, 0, 0, 0, time.UTC)); len(b) != 1 {
		t.Fatalf("still November in Tokyo: %v", b)
	}
}

// The chain, the new run included, is at most nativeMaxChain runs.
func TestSelectBaseChainCap(t *testing.T) {
	c := newChainDB(t, "UTC")
	at := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	var runs []uuid.UUID
	for range nativeMaxChain - 1 {
		at = at.Add(time.Minute)
		runs = append(runs, c.run(c.job.ID, at, "succeeded", "schedule", prefixesOf(runs...)...))
	}
	// A chain of 31: the new run makes 32.
	if b := c.base(at.Add(time.Hour)); len(b) != nativeMaxChain-1 {
		t.Fatalf("a chain of %d: based on %d runs", nativeMaxChain-1, len(b))
	}
	at = at.Add(time.Minute)
	c.run(c.job.ID, at, "succeeded", "schedule", prefixesOf(runs...)...)
	if b := c.base(at.Add(time.Hour)); b != nil {
		t.Fatalf("a chain of %d: based on %d runs", nativeMaxChain, len(b))
	}
}

// A read scope that is not a chain's is no base (errChainUnusable): the run
// is a full, not failed.
func TestSelectBaseBadScope(t *testing.T) {
	c := newChainDB(t, "UTC")
	c.run(c.job.ID, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC), "succeeded", "schedule", "not-a-run/")
	if _, err := selectBase(context.Background(), c.db, c.job, time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC)); !errors.Is(err, errChainUnusable) {
		t.Fatalf("a bad read scope: %v", err)
	}
}

// loadChain: every run of the chain has a copy, of one manifest, on every
// destination of the run.
func TestLoadChainCopies(t *testing.T) {
	a := &nativeDest{ref: destRef{ID: uuid.New(), Name: "a"}, w: memReader{newMemWriter()}}
	b := &nativeDest{ref: destRef{ID: uuid.New(), Name: "b"}, w: memReader{newMemWriter()}}
	run := uuid.New()
	w := &Worker{}
	missing := &nativeChain{Runs: []uuid.UUID{run}, copies: []map[uuid.UUID]chainCopy{{a.ref.ID: {dir: "p/a", sha256: "s1"}}}}
	if err := w.loadChain(context.Background(), nil, missing, []*nativeDest{a, b}); err == nil || !strings.Contains(err.Error(), "no copy on b") {
		t.Fatalf("a copy missing: %v", err)
	}
	other := &nativeChain{Runs: []uuid.UUID{run}, copies: []map[uuid.UUID]chainCopy{{a.ref.ID: {dir: "p/a", sha256: "s1"},
		b.ref.ID: {dir: "p/b", sha256: "s2"}}}}
	if err := w.loadChain(context.Background(), nil, other, []*nativeDest{a, b}); err == nil || !strings.Contains(err.Error(), "another manifest on b") {
		t.Fatalf("another manifest: %v", err)
	}
}

// tagMem is memWriter with SetTags.
type tagMem struct{ *memWriter }

func (m tagMem) SetTags(_ context.Context, path string, tags map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objs[path]; !ok {
		return fs.ErrNotExist
	}
	m.tags[path] = tags
	return nil
}

// A job time zone that is not known: its weeks and months are taken in UTC,
// with a warning.
func TestSelectBaseUnknownTimezone(t *testing.T) {
	c := newChainDB(t, "UTC")
	c.job.Timezone = "Mars/Olympus"
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	full := c.run(c.job.ID, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC), "succeeded", "schedule")
	if b := c.base(time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC)); !slices.Equal(b, []uuid.UUID{full}) {
		t.Fatalf("based on %v", b)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "Mars/Olympus") {
		t.Fatalf("no warning: %q", logs.String())
	}
}

// blockingReader holds every Open until its context ends, then fails it
// with an error of its own that does not wrap the context's, as a
// destination's SDK may.
type blockingReader struct{ opened chan struct{} }

func (b blockingReader) Open(ctx context.Context, _ string) (blob.Object, error) {
	close(b.opened)
	<-ctx.Done()
	return nil, errors.New("destination: the request was cancelled")
}

// TestSourcesKeepTheRequestsEnd: when the request reading an object ends
// while the destination opens it, both chain sources return the context's
// error (the endpoint then cuts the reply and does not stop the run); a
// destination's own failure with the context alive stays a failure, never
// a missing key nor a context error.
func TestSourcesKeepTheRequestsEnd(t *testing.T) {
	const run = "3c1d5e2f-0a4b-4c6d-8e9f-0a1b2c3d4e5f"
	key := run + "/data/x.bin"
	ms := []NativeChainManifest{{RunID: run, Objects: []ingest.ObjectRecord{{Key: key, Size: 1, SHA256: strings.Repeat("0", 64)}}}}
	sources := map[string]func(r blob.Reader) (ingest.Source, error){
		"chain": func(r blob.Reader) (ingest.Source, error) {
			return newChainSourceOn(r, []string{"p/" + run}, ms, slog.New(slog.DiscardHandler))
		},
		"restore": func(r blob.Reader) (ingest.Source, error) {
			return NewNativeRestoreSource(r, ms, []string{"p/" + run}, slog.New(slog.DiscardHandler))
		},
	}
	for name, mk := range sources {
		t.Run(name, func(t *testing.T) {
			br := blockingReader{opened: make(chan struct{})}
			s, err := mk(br)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			go func() { <-br.opened; cancel() }()
			if _, _, err := s.Open(ctx, key); !errors.Is(err, context.Canceled) {
				t.Fatalf("a request that ended: %v", err)
			}
			s, _ = mk(memReader{&memWriter{objs: map[string][]byte{}}})
			_, _, err = s.Open(context.Background(), key)
			if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, ingest.ErrNotServed) {
				t.Fatalf("a signed object gone: %v", err)
			}
		})
	}
}
