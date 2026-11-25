//go:build dev

package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/blob"
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
// the first; logical runs and incrementals do not count.
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
	finished := func(status string, bytes int64, scope string) {
		t.Helper()
		at = at.Add(time.Hour)
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, bytes) VALUES ($1, 'manual', $2, $3, $3, $4)
			RETURNING id`, job, status, at, bytes).Scan(&id); err != nil {
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
}

// nativeQuota (R39): the largest of twice the last full native run, 1.5
// times the databases' size on disk and 1 GiB; ingest.maxRunBytes, when
// set, instead. A database with no full yet, or one that grew, is not
// stopped by an earlier, smaller run.
func TestNativeQuota(t *testing.T) {
	for _, tc := range []struct {
		last, size, override, want int64
	}{
		{0, 0, 0, 1 << 30},                       // an empty database, no full yet
		{0, 200 << 30, 0, 300 << 30},             // a large database, no full yet
		{100 << 20, 5 << 30, 0, 15 << 29},        // a tiny first full, then 5 GiB loaded
		{3 << 30, 1 << 30, 0, 6 << 30},           // twice the last full
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
