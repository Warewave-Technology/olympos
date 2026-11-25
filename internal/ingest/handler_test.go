package ingest_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// env is one handler on a real HTTP server, with a registry on a settable
// clock that starts at the real time (the SDK signs with time.Now).
type env struct {
	reg      *ingest.Registry
	clock    *clock
	metrics  *ingest.Metrics
	handler  http.Handler
	srv      *httptest.Server
	logs     *syncBuffer
	spillDir string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testutil.DB(t)
	fp, err := secrets.NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now()}
	reg := ingest.NewRegistry(db, fp, 64, c.now)
	m := ingest.NewMetrics()
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := ingest.NewHandler(reg, log, m)
	dir := t.TempDir()
	ingest.SetSpill(h, dir, 1<<30)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &env{reg: reg, clock: c, metrics: m, handler: h, srv: srv, logs: logs, spillDir: dir}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// run is one open session and what it writes to.
type run struct {
	s      *ingest.Session
	cred   ingest.Credential
	prefix string // "<run-id>/"
	sink   *fakeSink
}

func (e *env) backup(t *testing.T, mod ...func(*ingest.OpenOptions)) *run {
	t.Helper()
	id := uuid.New()
	sink := newSink()
	o := ingest.OpenOptions{
		RunID: id, Kind: ingest.KindBackup, Scope: ingest.Scope{Write: id.String() + "/"},
		TTL: time.Hour, Sink: sink, MaxBytes: 1 << 30,
	}
	for _, m := range mod {
		m(&o)
	}
	s, cred, err := e.reg.Open(context.Background(), o)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	return &run{s: s, cred: cred, prefix: id.String() + "/", sink: sink}
}

func (e *env) restore(t *testing.T, src ingest.Source, read ...string) *run {
	t.Helper()
	s, cred, err := e.reg.Open(context.Background(), ingest.OpenOptions{
		RunID: uuid.New(), Kind: ingest.KindRestore, Scope: ingest.Scope{Read: read},
		TTL: time.Hour, Source: src,
	})
	if err != nil {
		t.Fatalf("open restore: %v", err)
	}
	return &run{s: s, cred: cred}
}

// reply is a response, its body read.
type reply struct {
	status int
	header http.Header
	body   string
}

// code is the S3 error code of the reply's XML body, or "".
func (r reply) code() string {
	var e struct {
		Code    string
		Message string
	}
	if xml.Unmarshal([]byte(r.body), &e) != nil {
		return ""
	}
	return e.Code
}

func (r reply) String() string { return fmt.Sprintf("%d %s", r.status, r.body) }

// do sends a request signed by the SDK for cred, the way ClickHouse does:
// path style, with the real body hash in x-amz-content-sha256. mutate runs
// before signing.
func (e *env) do(t *testing.T, cred ingest.Credential, method, target, body string, mutate ...func(*http.Request)) reply {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Content-Sha256", hexSHA256(body))
	for _, m := range mutate {
		m(req)
	}
	return e.send(t, signer.SignV4(*req, cred.AccessKey, cred.Secret, "", testRegion))
}

func (e *env) send(t *testing.T, req *http.Request) reply {
	t.Helper()
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

func wantRefused(t *testing.T, r reply, status int, code string) {
	t.Helper()
	if r.status != status || r.code() != code {
		t.Fatalf("reply %s, want %d %s", r, status, code)
	}
}

func wantStatus(t *testing.T, r reply, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("reply %s, want %d", r, status)
	}
}

func stopReason(t *testing.T, s *ingest.Session) string {
	t.Helper()
	select {
	case r := <-s.Stopped():
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the session was not stopped")
		return ""
	}
}

func notStopped(t *testing.T, s *ingest.Session) {
	t.Helper()
	select {
	case r := <-s.Stopped():
		t.Fatalf("the session was stopped: %s", r)
	default:
	}
}

func withHeader(name, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

func md5Header(body string) func(*http.Request) {
	sum := md5.Sum([]byte(body))
	return withHeader("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
}

func md5Hex(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

// fakeSink records every Put. With failAfter >= 0 it reads that many bytes
// and fails without draining the reader, as a sink with no destination left.
type fakeSink struct {
	failAfter int
	// first, when not nil, is closed once the first bytes arrived.
	first     chan struct{}
	firstOnce sync.Once

	mu   sync.Mutex
	puts []sinkPut
}

type sinkPut struct {
	key  string
	body []byte
	err  error // the reader's error: the object was aborted
}

var errNoDestination = errors.New("fake sink: no destination left")

func newSink() *fakeSink { return &fakeSink{failAfter: -1} }

func (f *fakeSink) Put(ctx context.Context, key string, r io.Reader) (ingest.ObjectRecord, error) {
	var buf bytes.Buffer
	var err error
	chunk := make([]byte, 32<<10)
	for {
		if f.failAfter >= 0 && buf.Len() >= f.failAfter {
			buf.Truncate(f.failAfter)
			f.record(sinkPut{key: key, body: buf.Bytes(), err: errNoDestination})
			return ingest.ObjectRecord{}, errNoDestination
		}
		n, rerr := r.Read(chunk)
		buf.Write(chunk[:n])
		if n > 0 && f.first != nil {
			f.firstOnce.Do(func() { close(f.first) })
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	f.record(sinkPut{key: key, body: buf.Bytes(), err: err})
	if err != nil {
		return ingest.ObjectRecord{}, err
	}
	sum := sha256.Sum256(buf.Bytes())
	return ingest.ObjectRecord{Key: key, Size: int64(buf.Len()), SHA256: hex.EncodeToString(sum[:])}, nil
}

func (f *fakeSink) record(p sinkPut) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, p)
}

func (f *fakeSink) all() []sinkPut {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.puts)
}

// waitPuts waits until the sink has n puts.
func (f *fakeSink) waitPuts(t *testing.T, n int) []sinkPut {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := f.all(); len(p) >= n {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the sink has %d puts, want %d", len(f.all()), n)
	return nil
}

// fakeSource serves objects from a map. List ignores the prefix and returns
// everything, so that the tests see the handler filter what a source returns.
// It records every key and prefix it is asked for.
type fakeSource struct {
	objects map[string]string

	mu    sync.Mutex
	asked []string
}

func (f *fakeSource) ask(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, s)
}

func (f *fakeSource) Open(_ context.Context, key string) (io.ReadCloser, ingest.ObjectRecord, error) {
	f.ask(key)
	b, ok := f.objects[key]
	if !ok {
		return nil, ingest.ObjectRecord{}, fmt.Errorf("fake source %s: %w", key, fs.ErrNotExist)
	}
	return io.NopCloser(strings.NewReader(b)), ingest.ObjectRecord{Key: key, Size: int64(len(b)), SHA256: hexSHA256(b)}, nil
}

func (f *fakeSource) List(_ context.Context, prefix string) ([]ingest.ObjectRecord, error) {
	f.ask(prefix)
	var out []ingest.ObjectRecord
	for k, b := range f.objects {
		out = append(out, ingest.ObjectRecord{Key: k, Size: int64(len(b)), SHA256: hexSHA256(b)})
	}
	return out, nil
}

// listResult is the ListObjects v1 XML.
type listResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	Name        string
	Prefix      string
	Marker      string
	NextMarker  string
	MaxKeys     int
	IsTruncated bool
	Contents    []struct {
		Key  string
		Size int64
	}
}

func (l listResult) keys() []string {
	var k []string
	for _, c := range l.Contents {
		k = append(k, c.Key)
	}
	return k
}

func (e *env) list(t *testing.T, cred ingest.Credential, query string) listResult {
	t.Helper()
	r := e.do(t, cred, http.MethodGet, "/olympos/?"+query, "")
	wantStatus(t, r, http.StatusOK)
	var l listResult
	if err := xml.Unmarshal([]byte(r.body), &l); err != nil {
		t.Fatalf("list XML %q: %v", r.body, err)
	}
	return l
}

func TestHandlerRefusesAddressing(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	cases := []struct {
		name, target string
		mutate       []func(*http.Request)
	}{
		{"wrong bucket", "/other/" + a.prefix + "x", nil},
		{"bucket name prefix", "/olymposx/" + a.prefix + "x", nil},
		{"root", "/", nil},
		{"virtual host", "/" + a.prefix + "x", []func(*http.Request){func(r *http.Request) { r.Host = "olympos.ingest.test" }}},
		{"virtual host with path bucket", "/olympos/" + a.prefix + "x",
			[]func(*http.Request){func(r *http.Request) { r.Host = "olympos.ingest.test:9444" }}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantRefused(t, e.do(t, a.cred, http.MethodPut, tc.target, "body", tc.mutate...), http.StatusForbidden, "AccessDenied")
		})
	}
	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("the sink got %d puts", len(p))
	}
}

func TestHandlerAuthentication(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	target := "/olympos/" + a.prefix + "data/x.bin"

	t.Run("unsigned", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, e.srv.URL+target, strings.NewReader("body"))
		wantRefused(t, e.send(t, req), http.StatusForbidden, "AccessDenied")
	})
	t.Run("unknown key", func(t *testing.T) {
		wantRefused(t, e.do(t, ingest.Credential{AccessKey: "OLYUNKNOWNUNKNOWNUNK", Secret: a.cred.Secret},
			http.MethodPut, target, "body"), http.StatusForbidden, "InvalidAccessKeyId")
	})
	t.Run("wrong secret", func(t *testing.T) {
		wantRefused(t, e.do(t, ingest.Credential{AccessKey: a.cred.AccessKey, Secret: "wrong"},
			http.MethodPut, target, "body"), http.StatusForbidden, "SignatureDoesNotMatch")
	})
	t.Run("unsigned payload", func(t *testing.T) {
		wantRefused(t, e.do(t, a.cred, http.MethodPut, target, "body", withHeader("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")),
			http.StatusForbidden, "AccessDenied")
	})
	t.Run("aws-chunked with a real hash", func(t *testing.T) {
		wantRefused(t, e.do(t, a.cred, http.MethodPut, target, "body", withHeader("Content-Encoding", "gzip,aws-chunked")),
			http.StatusForbidden, "AccessDenied")
	})
	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("the sink got %d puts", len(p))
	}
	notStopped(t, a.s)

	t.Run("revoked", func(t *testing.T) {
		b := e.backup(t)
		b.s.Revoke("done")
		wantRefused(t, e.do(t, b.cred, http.MethodGet, "/olympos/?prefix="+b.prefix, ""), http.StatusForbidden, "InvalidAccessKeyId")
	})
	t.Run("stopped", func(t *testing.T) {
		b := e.backup(t)
		b.s.Stop("test")
		wantRefused(t, e.do(t, b.cred, http.MethodGet, "/olympos/?prefix="+b.prefix, ""), http.StatusForbidden, "InvalidAccessKeyId")
	})
	t.Run("expired", func(t *testing.T) {
		b := e.backup(t, func(o *ingest.OpenOptions) { o.TTL = time.Minute })
		e.clock.add(2 * time.Minute)
		defer e.clock.add(-2 * time.Minute)
		wantRefused(t, e.do(t, b.cred, http.MethodGet, "/olympos/?prefix="+b.prefix, ""), http.StatusForbidden, "InvalidAccessKeyId")
	})
}

func TestHandlerRefusedOperations(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	obj := "/olympos/" + a.prefix + "data/x.bin"
	copySource := withHeader("X-Amz-Copy-Source", "/olympos/"+a.prefix+"data/y.bin")
	cases := []struct {
		name, method, target, body string
		mutate                     []func(*http.Request)
	}{
		{"CopyObject", http.MethodPut, obj, "", []func(*http.Request){copySource}},
		{"UploadPartCopy", http.MethodPut, obj + "?partNumber=1&uploadId=abc", "", []func(*http.Request){copySource}},
		{"DeleteObjects", http.MethodPost, "/olympos/?delete", "<Delete><Object><Key>" + a.prefix + ".lock</Key></Object></Delete>", nil},
		{"ListObjectsV2", http.MethodGet, "/olympos/?list-type=2&prefix=" + a.prefix, "", nil},
		{"ListObjects with a delimiter", http.MethodGet, "/olympos/?prefix=" + a.prefix + "&delimiter=/", "", nil},
		{"ListMultipartUploads", http.MethodGet, "/olympos/?uploads", "", nil},
		{"GetBucketLocation", http.MethodGet, "/olympos/?location", "", nil},
		{"CreateBucket", http.MethodPut, "/olympos/", "", nil},
		{"DeleteBucket", http.MethodDelete, "/olympos/", "", nil},
		{"GetObjectAcl", http.MethodGet, obj + "?acl", "", nil},
		{"PutObjectTagging", http.MethodPut, obj + "?tagging", "<Tagging/>", nil},
		{"ListParts", http.MethodGet, obj + "?uploadId=abc", "", nil},
		{"PostObject", http.MethodPost, obj, "", nil},
		{"DeleteObject of data", http.MethodDelete, obj, "", nil},
		{"DeleteObject of .backup", http.MethodDelete, "/olympos/" + a.prefix + ".backup", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantRefused(t, e.do(t, a.cred, tc.method, tc.target, tc.body, tc.mutate...), http.StatusForbidden, "AccessDenied")
		})
	}
	// HEAD has no body, so only the status tells.
	for _, target := range []string{"/olympos/", "/olympos", obj} {
		if r := e.do(t, a.cred, http.MethodHead, target, ""); r.status != http.StatusForbidden {
			t.Errorf("HEAD %s: %d, want 403", target, r.status)
		}
	}
	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("the sink got %d puts", len(p))
	}
	notStopped(t, a.s)
}

func TestHandlerPutObject(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	body := "some backup bytes"
	key := a.prefix + "data/all_1_1_0/data.bin"
	r := e.do(t, a.cred, http.MethodPut, "/olympos/"+key, body, md5Header(body))
	wantStatus(t, r, http.StatusOK)
	if got, want := r.header.Get("ETag"), `"`+md5Hex(body)+`"`; got != want {
		t.Errorf("ETag %s, want %s", got, want)
	}
	puts := a.sink.all()
	if len(puts) != 1 || puts[0].key != key || string(puts[0].body) != body || puts[0].err != nil {
		t.Fatalf("sink puts %+v", puts)
	}
	want := []ingest.ObjectRecord{{Key: key, Size: int64(len(body)), SHA256: hexSHA256(body)}}
	if got := a.s.Objects(); !slices.Equal(got, want) {
		t.Errorf("objects %+v, want %+v", got, want)
	}
	if _, ok := a.s.Captured(key); ok {
		t.Error("a data file was captured")
	}

	// The bodies the manifest needs are kept.
	backup := "<backup>...</backup>"
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+".backup", backup), http.StatusOK)
	if b, ok := a.s.Captured(a.prefix + ".backup"); !ok || string(b) != backup {
		t.Errorf("captured .backup %q %v", b, ok)
	}
	notStopped(t, a.s)
}

func TestHandlerScope(t *testing.T) {
	e := newEnv(t)
	base := uuid.NewString() + "/"
	other := uuid.NewString() + "/"
	src := &fakeSource{objects: map[string]string{
		base + ".backup":       "base backup",
		base + "data/c.bin":    "base data",
		other + "secret.bin":   "not yours",
		other + "data/x.bin":   "not yours",
		base + "metadata/a.sq": "x",
	}}
	a := e.backup(t, func(o *ingest.OpenOptions) { o.Scope.Read = []string{base}; o.Source = src })
	ro := e.restore(t, src, base)

	t.Run("backup reads its base", func(t *testing.T) {
		r := e.do(t, a.cred, http.MethodGet, "/olympos/"+base+".backup", "")
		if r.status != http.StatusOK || r.body != "base backup" {
			t.Fatalf("reply %s", r)
		}
		l := e.list(t, a.cred, "prefix="+base+"data/")
		if !slices.Equal(l.keys(), []string{base + "data/c.bin"}) {
			t.Errorf("list %v", l.keys())
		}
	})
	t.Run("backup writes its base", func(t *testing.T) {
		wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+base+"data/new.bin", "x"), http.StatusForbidden, "AccessDenied")
		wantRefused(t, e.do(t, a.cred, http.MethodPost, "/olympos/"+base+"data/new.bin?uploads", ""), http.StatusForbidden, "AccessDenied")
		wantRefused(t, e.do(t, a.cred, http.MethodDelete, "/olympos/"+base+".lock", ""), http.StatusForbidden, "AccessDenied")
	})
	t.Run("backup reads another prefix", func(t *testing.T) {
		wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/"+other+"secret.bin", ""), http.StatusForbidden, "AccessDenied")
		wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+other, ""), http.StatusForbidden, "AccessDenied")
	})
	t.Run("restore reads its chain", func(t *testing.T) {
		r := e.do(t, ro.cred, http.MethodGet, "/olympos/"+base+"data/c.bin", "")
		if r.status != http.StatusOK || r.body != "base data" {
			t.Fatalf("reply %s", r)
		}
		wantRefused(t, e.do(t, ro.cred, http.MethodGet, "/olympos/"+base+"data/none.bin", ""), http.StatusNotFound, "NoSuchKey")
		l := e.list(t, ro.cred, "prefix="+base)
		// The source returned other's keys too; they are filtered out.
		want := []string{base + ".backup", base + "data/c.bin", base + "metadata/a.sq"}
		if !slices.Equal(l.keys(), want) {
			t.Errorf("list %v, want %v", l.keys(), want)
		}
	})
	t.Run("restore writes", func(t *testing.T) {
		for _, target := range []string{
			"/olympos/" + base + "data/new.bin",
			"/olympos/" + base + ".lock",
			"/olympos/" + uuid.NewString() + "/data/new.bin",
		} {
			wantRefused(t, e.do(t, ro.cred, http.MethodPut, target, "x"), http.StatusForbidden, "AccessDenied")
		}
		wantRefused(t, e.do(t, ro.cred, http.MethodPost, "/olympos/"+base+"x?uploads", ""), http.StatusForbidden, "AccessDenied")
		wantRefused(t, e.do(t, ro.cred, http.MethodDelete, "/olympos/"+base+".lock", ""), http.StatusForbidden, "AccessDenied")
	})
	t.Run("restore reads another prefix", func(t *testing.T) {
		wantRefused(t, e.do(t, ro.cred, http.MethodGet, "/olympos/"+other+"secret.bin", ""), http.StatusForbidden, "AccessDenied")
		wantRefused(t, e.do(t, ro.cred, http.MethodGet, "/olympos/?prefix="+other, ""), http.StatusForbidden, "AccessDenied")
	})
	src.mu.Lock()
	for _, k := range src.asked {
		if !strings.HasPrefix(k, base) {
			t.Errorf("the source was asked for %q", k)
		}
	}
	src.mu.Unlock()
}

func TestHandlerLock(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	lock := "/olympos/" + a.prefix + ".lock"

	wantRefused(t, e.do(t, a.cred, http.MethodGet, lock, ""), http.StatusNotFound, "NoSuchKey")
	wantStatus(t, e.do(t, a.cred, http.MethodPut, lock, "the-backup-uuid", md5Header("the-backup-uuid")), http.StatusOK)
	if r := e.do(t, a.cred, http.MethodGet, lock, ""); r.status != http.StatusOK || r.body != "the-backup-uuid" {
		t.Fatalf("GET .lock: %s", r)
	}
	l := e.list(t, a.cred, "prefix="+a.prefix+".lock&max-keys=1")
	if len(l.Contents) != 1 || l.Contents[0].Key != a.prefix+".lock" || l.Contents[0].Size != int64(len("the-backup-uuid")) {
		t.Fatalf("list %+v", l)
	}
	wantStatus(t, e.do(t, a.cred, http.MethodDelete, lock, ""), http.StatusNoContent)
	wantRefused(t, e.do(t, a.cred, http.MethodGet, lock, ""), http.StatusNotFound, "NoSuchKey")
	if l := e.list(t, a.cred, "prefix="+a.prefix+".lock&max-keys=1"); len(l.Contents) != 0 {
		t.Errorf("list after delete %v", l.keys())
	}
	// A second delete is still a success, as on S3.
	wantStatus(t, e.do(t, a.cred, http.MethodDelete, lock, ""), http.StatusNoContent)

	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("the lock reached the sink: %+v", p)
	}
	if o := a.s.Objects(); len(o) != 0 {
		t.Errorf("the lock was recorded: %+v", o)
	}
	notStopped(t, a.s)
}

func TestHandlerOwnPrefixReads(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+".backup", "<backup/>"), http.StatusOK)
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/x.bin", "data"), http.StatusOK)

	if r := e.do(t, a.cred, http.MethodGet, "/olympos/"+a.prefix+".backup", ""); r.status != http.StatusOK || r.body != "<backup/>" {
		t.Errorf("GET .backup: %s", r)
	}
	// A data file streamed away and is not read back.
	wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/"+a.prefix+"data/x.bin", ""), http.StatusForbidden, "AccessDenied")
	wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/"+a.prefix+"data/none.bin", ""), http.StatusNotFound, "NoSuchKey")
	l := e.list(t, a.cred, "prefix="+a.prefix)
	if want := []string{a.prefix + ".backup", a.prefix + "data/x.bin"}; !slices.Equal(l.keys(), want) {
		t.Errorf("list %v, want %v", l.keys(), want)
	}
}

func TestHandlerDigests(t *testing.T) {
	e := newEnv(t)
	key := "data/x.bin"

	t.Run("body hash mismatch", func(t *testing.T) {
		a := e.backup(t)
		r := e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+key, "body", withHeader("X-Amz-Content-Sha256", hexSHA256("other")))
		wantRefused(t, r, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
		if got := stopReason(t, a.s); got != ingest.ReasonBadDigest {
			t.Errorf("stop reason %q", got)
		}
		puts := a.sink.waitPuts(t, 1)
		if puts[0].err == nil {
			t.Error("the sink stored the object")
		}
		if o := a.s.Objects(); len(o) != 0 {
			t.Errorf("objects %+v", o)
		}
	})
	t.Run("Content-MD5 mismatch", func(t *testing.T) {
		a := e.backup(t)
		r := e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+key, "body", md5Header("other"))
		wantRefused(t, r, http.StatusBadRequest, "BadDigest")
		if got := stopReason(t, a.s); got != ingest.ReasonBadDigest {
			t.Errorf("stop reason %q", got)
		}
		if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
			t.Error("the sink stored the object")
		}
	})
	t.Run("malformed Content-MD5", func(t *testing.T) {
		a := e.backup(t)
		r := e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+key, "body", withHeader("Content-MD5", "not-base64"))
		wantRefused(t, r, http.StatusForbidden, "InvalidDigest")
		if p := a.sink.all(); len(p) != 0 {
			t.Errorf("the sink got %+v", p)
		}
		notStopped(t, a.s)
	})
	t.Run("lock hash mismatch", func(t *testing.T) {
		a := e.backup(t)
		r := e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+".lock", "uuid", withHeader("X-Amz-Content-Sha256", hexSHA256("other")))
		wantRefused(t, r, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
		if _, ok := a.s.Lock(); ok {
			t.Error("the lock was stored")
		}
		if got := stopReason(t, a.s); got != ingest.ReasonBadDigest {
			t.Errorf("stop reason %q", got)
		}
	})
	t.Run("a body on a GET", func(t *testing.T) {
		a := e.backup(t)
		wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+a.prefix, "unexpected"), http.StatusForbidden, "AccessDenied")
	})
}

func TestHandlerSinkFailure(t *testing.T) {
	e := newEnv(t)
	for _, failAfter := range []int{0, 1000} {
		t.Run(fmt.Sprintf("after %d bytes", failAfter), func(t *testing.T) {
			a := e.backup(t)
			a.sink.failAfter = failAfter
			// Several chunks, so that the handler would block on a sink that
			// stopped reading (an io.Pipe holds nothing). The server drains
			// the rest of a body this small, so the client gets the reply.
			body := strings.Repeat("x", 200<<10)
			r := e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/x.bin", body)
			wantRefused(t, r, http.StatusForbidden, "AccessDenied")
			if got := stopReason(t, a.s); got != ingest.ReasonDestination {
				t.Errorf("stop reason %q", got)
			}
			if o := a.s.Objects(); len(o) != 0 {
				t.Errorf("objects %+v", o)
			}
		})
	}
}

func TestHandlerQuota(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t, func(o *ingest.OpenOptions) { o.MaxBytes = 10 })
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/a.bin", "12345"), http.StatusOK)
	wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/b.bin", "123456"), http.StatusForbidden, "AccessDenied")
	if got := stopReason(t, a.s); got != ingest.ReasonQuota {
		t.Errorf("stop reason %q", got)
	}
	puts := a.sink.waitPuts(t, 2)
	if puts[1].err == nil || len(puts[1].body) > 0 {
		t.Errorf("the object over the quota reached the sink: %+v", puts[1])
	}
	if o := a.s.Objects(); len(o) != 1 {
		t.Errorf("objects %+v", o)
	}
}

func TestHandlerRate(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	b := e.backup(t)
	// The clock stands still, so every request falls in the same second.
	for i := range 200 {
		if r := e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+a.prefix, ""); r.status != http.StatusOK {
			t.Fatalf("request %d: %s", i+1, r)
		}
	}
	wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+a.prefix, ""), http.StatusForbidden, "SlowDown")
	if got := stopReason(t, a.s); got != ingest.ReasonRate {
		t.Errorf("stop reason %q", got)
	}
	// The limit is per session.
	wantStatus(t, e.do(t, b.cred, http.MethodGet, "/olympos/?prefix="+b.prefix, ""), http.StatusOK)
	notStopped(t, b.s)
}

func TestHandlerRateRefills(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	for i := range 400 {
		if i%100 == 0 {
			// 100 requests every half second: 200 per second.
			e.clock.add(500 * time.Millisecond)
		}
		if r := e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+a.prefix, ""); r.status != http.StatusOK {
			t.Fatalf("request %d: %s", i+1, r)
		}
	}
	notStopped(t, a.s)
}

func TestHandlerListObjects(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	for _, k := range []string{"metadata/db/t.sql", "data/b.bin", ".backup", "data/a.bin"} {
		wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+k, "body of "+k), http.StatusOK)
	}
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+".lock", "lock"), http.StatusOK)
	p := a.prefix
	all := []string{p + ".backup", p + ".lock", p + "data/a.bin", p + "data/b.bin", p + "metadata/db/t.sql"}

	l := e.list(t, a.cred, "prefix="+p+"&max-keys=2&marker=")
	if l.Name != "olympos" || l.Prefix != p || l.MaxKeys != 2 || !l.IsTruncated || l.NextMarker != p+".lock" {
		t.Errorf("first page %+v", l)
	}
	if !slices.Equal(l.keys(), all[:2]) {
		t.Errorf("first page %v, want %v", l.keys(), all[:2])
	}
	l = e.list(t, a.cred, "prefix="+p+"&marker="+p+".lock")
	if l.Marker != p+".lock" || l.IsTruncated || l.MaxKeys != 1000 {
		t.Errorf("second page %+v", l)
	}
	if !slices.Equal(l.keys(), all[2:]) {
		t.Errorf("second page %v, want %v", l.keys(), all[2:])
	}
	if l.Contents[0].Size != int64(len("body of data/a.bin")) {
		t.Errorf("size %d", l.Contents[0].Size)
	}
	if l = e.list(t, a.cred, "prefix="+p+"data/"); !slices.Equal(l.keys(), all[2:4]) {
		t.Errorf("data/ %v", l.keys())
	}
	if l = e.list(t, a.cred, "prefix="+p+".backup&max-keys=1"); !slices.Equal(l.keys(), all[:1]) || l.IsTruncated {
		t.Errorf(".backup %+v", l)
	}
	if l = e.list(t, a.cred, "prefix="+p+"&max-keys=5000"); l.MaxKeys != 1000 || len(l.Contents) != 5 {
		t.Errorf("max-keys over 1000: %+v", l)
	}
	for _, q := range []string{"max-keys=abc", "max-keys=-1"} {
		wantRefused(t, e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+p+"&"+q, ""), http.StatusForbidden, "InvalidArgument")
	}
}

func TestHandlerRange(t *testing.T) {
	e := newEnv(t)
	base := uuid.NewString() + "/"
	src := &fakeSource{objects: map[string]string{base + "data/x.bin": "0123456789"}}
	ro := e.restore(t, src, base)
	target := "/olympos/" + base + "data/x.bin"
	cases := []struct {
		rng, body, contentRange string
	}{
		{"bytes=2-4", "234", "bytes 2-4/10"},
		{"bytes=7-", "789", "bytes 7-9/10"},
		{"bytes=8-20", "89", "bytes 8-9/10"},
		{"bytes=0-0", "0", "bytes 0-0/10"},
	}
	for _, tc := range cases {
		r := e.do(t, ro.cred, http.MethodGet, target, "", withHeader("Range", tc.rng))
		if r.status != http.StatusPartialContent || r.body != tc.body || r.header.Get("Content-Range") != tc.contentRange {
			t.Errorf("%s: %d %q %q", tc.rng, r.status, r.body, r.header.Get("Content-Range"))
		}
	}
	for _, rng := range []string{"bytes=0-1,3-4", "bytes=-3", "bytes=4-2", "items=0-1", "bytes=a-b"} {
		wantRefused(t, e.do(t, ro.cred, http.MethodGet, target, "", withHeader("Range", rng)), http.StatusForbidden, "AccessDenied")
	}
	wantRefused(t, e.do(t, ro.cred, http.MethodGet, target, "", withHeader("Range", "bytes=10-")),
		http.StatusRequestedRangeNotSatisfiable, "InvalidRange")

	// A captured body serves ranges too.
	a := e.backup(t)
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+".backup", "abcdef"), http.StatusOK)
	r := e.do(t, a.cred, http.MethodGet, "/olympos/"+a.prefix+".backup", "", withHeader("Range", "bytes=1-2"))
	if r.status != http.StatusPartialContent || r.body != "bc" {
		t.Errorf("captured range: %s", r)
	}
}

// multipart drives one multipart upload.
type multipart struct {
	e   *env
	r   *run
	key string
	id  string
}

func (e *env) createUpload(t *testing.T, r *run, key string) *multipart {
	t.Helper()
	rep := e.do(t, r.cred, http.MethodPost, "/olympos/"+key+"?uploads", "")
	wantStatus(t, rep, http.StatusOK)
	var res struct {
		Bucket, Key, UploadId string
	}
	if err := xml.Unmarshal([]byte(rep.body), &res); err != nil || res.UploadId == "" || res.Key != key || res.Bucket != "olympos" {
		t.Fatalf("initiate %q: %v", rep.body, err)
	}
	return &multipart{e: e, r: r, key: key, id: res.UploadId}
}

func (m *multipart) part(t *testing.T, n int, body string) reply {
	t.Helper()
	return m.e.do(t, m.r.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=%d&uploadId=%s", m.key, n, m.id), body, md5Header(body))
}

func (m *multipart) complete(t *testing.T, etags ...string) reply {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for i, tag := range etags {
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", i+1, tag)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return m.e.do(t, m.r.cred, http.MethodPost, "/olympos/"+m.key+"?uploadId="+m.id, b.String())
}

func (m *multipart) abort(t *testing.T) reply {
	t.Helper()
	return m.e.do(t, m.r.cred, http.MethodDelete, "/olympos/"+m.key+"?uploadId="+m.id, "")
}

func etagOf(t *testing.T, r reply) string {
	t.Helper()
	wantStatus(t, r, http.StatusOK)
	return r.header.Get("ETag")
}

func multipartETag(parts ...string) string {
	var sums []byte
	for _, p := range parts {
		s := md5.Sum([]byte(p))
		sums = append(sums, s[:]...)
	}
	s := md5.Sum(sums)
	return fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(s[:]), len(parts))
}

func spillFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestHandlerMultipart(t *testing.T) {
	e := newEnv(t)
	parts := []string{strings.Repeat("a", 100<<10), strings.Repeat("b", 70<<10), "the last part"}
	whole := strings.Join(parts, "")

	t.Run("in order", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		var tags []string
		for i, p := range parts {
			tag := etagOf(t, m.part(t, i+1, p))
			if tag != `"`+md5Hex(p)+`"` {
				t.Errorf("part %d ETag %s", i+1, tag)
			}
			tags = append(tags, tag)
		}
		r := m.complete(t, tags...)
		wantStatus(t, r, http.StatusOK)
		var res struct{ Bucket, Key, ETag string }
		if err := xml.Unmarshal([]byte(r.body), &res); err != nil || res.Key != m.key || res.ETag != multipartETag(parts...) {
			t.Errorf("complete %q: %v", r.body, err)
		}
		puts := a.sink.all()
		if len(puts) != 1 || puts[0].key != m.key || string(puts[0].body) != whole || puts[0].err != nil {
			t.Fatalf("sink puts: %d", len(puts))
		}
		want := []ingest.ObjectRecord{{Key: m.key, Size: int64(len(whole)), SHA256: hexSHA256(whole)}}
		if got := a.s.Objects(); !slices.Equal(got, want) {
			t.Errorf("objects %+v", got)
		}
		// The upload is gone.
		wantRefused(t, m.part(t, 4, "late"), http.StatusForbidden, "NoSuchUpload")
		notStopped(t, a.s)
	})
	t.Run("out of order", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		tags := make([]string, 3)
		tags[2] = etagOf(t, m.part(t, 3, parts[2]))
		tags[1] = etagOf(t, m.part(t, 2, parts[1]))
		if n := spillFiles(t, e.spillDir); n != 2 {
			t.Errorf("%d spill files, want 2", n)
		}
		if p := a.sink.all(); len(p) != 0 {
			t.Errorf("the sink finished early: %d", len(p))
		}
		tags[0] = etagOf(t, m.part(t, 1, parts[0]))
		wantStatus(t, m.complete(t, tags...), http.StatusOK)
		puts := a.sink.all()
		if len(puts) != 1 || string(puts[0].body) != whole {
			t.Fatalf("sink puts: %d", len(puts))
		}
		if n := spillFiles(t, e.spillDir); n != 0 {
			t.Errorf("%d spill files left", n)
		}
		notStopped(t, a.s)
	})
	t.Run("a part sent twice", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		tag := etagOf(t, m.part(t, 1, parts[0]))
		// The same part again (a retry) is answered, not streamed twice.
		if again := etagOf(t, m.part(t, 1, parts[0])); again != tag {
			t.Errorf("retry ETag %s, want %s", again, tag)
		}
		wantStatus(t, m.complete(t, tag), http.StatusOK)
		if puts := a.sink.all(); len(puts) != 1 || string(puts[0].body) != parts[0] {
			t.Fatalf("sink puts %d", len(puts))
		}
		notStopped(t, a.s)
	})
	t.Run("a different part with the same number", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		etagOf(t, m.part(t, 1, parts[0]))
		wantRefused(t, m.part(t, 1, "something else"), http.StatusForbidden, "InvalidPart")
		if got := stopReason(t, a.s); got != ingest.ReasonMultipart {
			t.Errorf("stop reason %q", got)
		}
		if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
			t.Error("the object was stored")
		}
	})
	t.Run("spill over the limit", func(t *testing.T) {
		e := newEnv(t)
		ingest.SetSpill(e.handler, e.spillDir, 10)
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		etagOf(t, m.part(t, 2, "12345"))
		wantRefused(t, m.part(t, 3, "678901"), http.StatusForbidden, "AccessDenied")
		if got := stopReason(t, a.s); got != ingest.ReasonSpill {
			t.Errorf("stop reason %q", got)
		}
		if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
			t.Error("the object was stored")
		}
		deadline := time.Now().Add(5 * time.Second)
		for spillFiles(t, e.spillDir) != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := spillFiles(t, e.spillDir); n != 0 {
			t.Errorf("%d spill files left", n)
		}
	})
	t.Run("abort", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		etagOf(t, m.part(t, 1, parts[0]))
		etagOf(t, m.part(t, 3, parts[2]))
		wantStatus(t, m.abort(t), http.StatusNoContent)
		puts := a.sink.all()
		if len(puts) != 1 || puts[0].err == nil {
			t.Fatalf("the put was not aborted: %+v", len(puts))
		}
		if n := spillFiles(t, e.spillDir); n != 0 {
			t.Errorf("%d spill files left", n)
		}
		wantRefused(t, m.part(t, 2, parts[1]), http.StatusForbidden, "NoSuchUpload")
		wantRefused(t, m.complete(t, "x"), http.StatusForbidden, "NoSuchUpload")
		if o := a.s.Objects(); len(o) != 0 {
			t.Errorf("objects %+v", o)
		}
	})
	t.Run("complete with a wrong part list", func(t *testing.T) {
		for name, tags := range map[string]func(t1, t2 string) []string{
			"wrong ETag":   func(t1, t2 string) []string { return []string{t1, `"0000"`} },
			"missing part": func(t1, t2 string) []string { return []string{t1} },
			"no parts":     func(t1, t2 string) []string { return nil },
		} {
			t.Run(name, func(t *testing.T) {
				a := e.backup(t)
				m := e.createUpload(t, a, a.prefix+"data/big.bin")
				t1 := etagOf(t, m.part(t, 1, parts[0]))
				t2 := etagOf(t, m.part(t, 2, parts[1]))
				wantRefused(t, m.complete(t, tags(t1, t2)...), http.StatusForbidden, "InvalidPart")
				if got := stopReason(t, a.s); got != ingest.ReasonMultipart {
					t.Errorf("stop reason %q", got)
				}
				if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
					t.Error("the object was stored")
				}
			})
		}
	})
	t.Run("part hash mismatch", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		r := e.do(t, a.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=1&uploadId=%s", m.key, m.id), "part",
			withHeader("X-Amz-Content-Sha256", hexSHA256("other")))
		wantRefused(t, r, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
		if got := stopReason(t, a.s); got != ingest.ReasonBadDigest {
			t.Errorf("stop reason %q", got)
		}
		if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
			t.Error("the object was stored")
		}
	})
	t.Run("a multipart .backup is captured", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+".backup")
		t1 := etagOf(t, m.part(t, 1, "<backup>"))
		t2 := etagOf(t, m.part(t, 2, "</backup>"))
		wantStatus(t, m.complete(t, t1, t2), http.StatusOK)
		if b, ok := a.s.Captured(a.prefix + ".backup"); !ok || string(b) != "<backup></backup>" {
			t.Errorf("captured %q %v", b, ok)
		}
	})
	t.Run("the session stops", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		etagOf(t, m.part(t, 1, parts[0]))
		etagOf(t, m.part(t, 3, parts[2]))
		a.s.Revoke("run ended")
		if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
			t.Error("the object was stored")
		}
		deadline := time.Now().Add(5 * time.Second)
		for spillFiles(t, e.spillDir) != 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := spillFiles(t, e.spillDir); n != 0 {
			t.Errorf("%d spill files left", n)
		}
	})
	t.Run("multipart .lock", func(t *testing.T) {
		a := e.backup(t)
		wantRefused(t, e.do(t, a.cred, http.MethodPost, "/olympos/"+a.prefix+".lock?uploads", ""), http.StatusForbidden, "AccessDenied")
	})
	t.Run("bad part numbers", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		for _, n := range []string{"0", "10001", "x", "-1"} {
			r := e.do(t, a.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=%s&uploadId=%s", m.key, n, m.id), "p")
			wantRefused(t, r, http.StatusForbidden, "InvalidArgument")
		}
		// The upload belongs to its key.
		r := e.do(t, a.cred, http.MethodPut, fmt.Sprintf("/olympos/%sdata/other.bin?partNumber=1&uploadId=%s", a.prefix, m.id), "p")
		wantRefused(t, r, http.StatusForbidden, "NoSuchUpload")
	})
}

// TestHandlerStopAbortsStream: a PUT that is streaming when its session stops
// is aborted at once; nothing is stored.
func TestHandlerStopAbortsStream(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	a.sink.first = make(chan struct{})
	body := strings.Repeat("y", 1<<20)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPut, e.srv.URL+"/olympos/"+a.prefix+"data/slow.bin", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("X-Amz-Content-Sha256", hexSHA256(body))
	signed := signer.SignV4(*req, a.cred.AccessKey, a.cred.Secret, "", testRegion)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := e.srv.Client().Do(signed)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				t.Errorf("the stopped PUT succeeded")
			}
			_ = resp.Body.Close()
		}
	}()
	if _, err := pw.Write([]byte(body[:4096])); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.sink.first:
	case <-time.After(5 * time.Second):
		t.Fatal("the body never reached the sink")
	}
	a.s.Stop("test stop")
	puts := a.sink.waitPuts(t, 1)
	if puts[0].err == nil {
		t.Error("the object was stored")
	}
	pw.CloseWithError(errors.New("the client gave up"))
	<-done
	if o := a.s.Objects(); len(o) != 0 {
		t.Errorf("objects %+v", o)
	}
}

// TestHandlerSessionsIsolated (Review Focus 3): one credential can neither
// read, list nor write another run's prefix, nor touch its uploads.
func TestHandlerSessionsIsolated(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	b := e.backup(t)
	wantStatus(t, e.do(t, b.cred, http.MethodPut, "/olympos/"+b.prefix+".lock", "b-lock"), http.StatusOK)
	wantStatus(t, e.do(t, b.cred, http.MethodPut, "/olympos/"+b.prefix+".backup", "b-backup"), http.StatusOK)
	bm := e.createUpload(t, b, b.prefix+"data/big.bin")
	bTag := etagOf(t, bm.part(t, 1, "b part"))

	// Both write at once; each sink sees only its own keys.
	var wg sync.WaitGroup
	for _, r := range []*run{a, b} {
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key := fmt.Sprintf("/olympos/%sdata/%d.bin", r.prefix, i)
				if rep := e.do(t, r.cred, http.MethodPut, key, "body"); rep.status != http.StatusOK {
					t.Errorf("PUT %s: %s", key, rep)
				}
			}()
		}
	}
	wg.Wait()

	refused := []struct {
		name, method, target, body string
		code                       string
	}{
		{"write into b", http.MethodPut, "/olympos/" + b.prefix + "data/evil.bin", "x", "AccessDenied"},
		{"overwrite b's lock", http.MethodPut, "/olympos/" + b.prefix + ".lock", "x", "AccessDenied"},
		{"read b's lock", http.MethodGet, "/olympos/" + b.prefix + ".lock", "", "AccessDenied"},
		{"read b's .backup", http.MethodGet, "/olympos/" + b.prefix + ".backup", "", "AccessDenied"},
		{"list b", http.MethodGet, "/olympos/?prefix=" + b.prefix, "", "AccessDenied"},
		{"delete b's lock", http.MethodDelete, "/olympos/" + b.prefix + ".lock", "", "AccessDenied"},
		{"upload into b", http.MethodPost, "/olympos/" + b.prefix + "data/evil.bin?uploads", "", "AccessDenied"},
		{"part of b's upload under b's key", http.MethodPut,
			"/olympos/" + bm.key + "?partNumber=2&uploadId=" + bm.id, "x", "AccessDenied"},
		{"part of b's upload under a's key", http.MethodPut,
			"/olympos/" + a.prefix + "data/big.bin?partNumber=2&uploadId=" + bm.id, "x", "NoSuchUpload"},
		{"complete b's upload under a's key", http.MethodPost,
			"/olympos/" + a.prefix + "data/big.bin?uploadId=" + bm.id, "<CompleteMultipartUpload/>", "NoSuchUpload"},
		{"abort b's upload under a's key", http.MethodDelete,
			"/olympos/" + a.prefix + "data/big.bin?uploadId=" + bm.id, "", "NoSuchUpload"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			wantRefused(t, e.do(t, a.cred, tc.method, tc.target, tc.body), http.StatusForbidden, tc.code)
		})
	}

	if lock, ok := b.s.Lock(); !ok || string(lock) != "b-lock" {
		t.Errorf("b's lock %q %v", lock, ok)
	}
	wantStatus(t, bm.complete(t, bTag), http.StatusOK)
	for _, r := range []*run{a, b} {
		for _, p := range r.sink.all() {
			if !strings.HasPrefix(p.key, r.prefix) || p.err != nil {
				t.Errorf("sink of %s got %s (%v)", r.prefix, p.key, p.err)
			}
		}
		for _, o := range r.s.Objects() {
			if !strings.HasPrefix(o.Key, r.prefix) {
				t.Errorf("session %s recorded %s", r.prefix, o.Key)
			}
		}
	}
	if n := len(a.sink.all()); n != 20 {
		t.Errorf("a's sink has %d puts, want 20", n)
	}
	if n := len(b.sink.all()); n != 22 {
		t.Errorf("b's sink has %d puts, want 22", n)
	}
	notStopped(t, a.s)
	notStopped(t, b.s)
}

// TestHandlerKeyTricks (Review Focus 5): no spelling of a key or a prefix gets
// out of the run's prefix.
func TestHandlerKeyTricks(t *testing.T) {
	e := newEnv(t)
	base := uuid.NewString() + "/"
	src := &fakeSource{objects: map[string]string{base + ".backup": "base"}}
	a := e.backup(t, func(o *ingest.OpenOptions) { o.Scope.Read = []string{base}; o.Source = src })
	b := e.backup(t)
	wantStatus(t, e.do(t, b.cred, http.MethodPut, "/olympos/"+b.prefix+".lock", "b-lock"), http.StatusOK)
	A := strings.TrimSuffix(a.prefix, "/")
	B := strings.TrimSuffix(b.prefix, "/")
	baseID := strings.TrimSuffix(base, "/")

	cases := []struct {
		name, method, target string
	}{
		{"dot-dot", http.MethodPut, "/olympos/" + A + "/../" + B + "/x.bin"},
		{"encoded dot-dot", http.MethodPut, "/olympos/" + A + "/%2E%2E/" + B + "/x.bin"},
		{"encoded slashes out", http.MethodPut, "/olympos/" + A + "%2F..%2F" + B + "/x.bin"},
		{"encoded slash inside", http.MethodPut, "/olympos/" + A + "%2Fdata/x.bin"},
		{"lower-case encoded slash", http.MethodPut, "/olympos/" + A + "/data%2fx.bin"},
		{"double slash", http.MethodPut, "/olympos/" + A + "//x.bin"},
		{"leading slash", http.MethodPut, "/olympos//" + A + "/x.bin"},
		{"dot segment", http.MethodPut, "/olympos/" + A + "/./x.bin"},
		{"trailing slash", http.MethodPut, "/olympos/" + A + "/data/"},
		{"backslash", http.MethodPut, "/olympos/" + A + "/..%5C" + B + "%5Cx.bin"},
		{"control character", http.MethodPut, "/olympos/" + A + "/x%00.bin"},
		{"the prefix itself", http.MethodPut, "/olympos/" + A},
		{"read up and over", http.MethodGet, "/olympos/" + A + "/../" + B + "/.lock"},
		{"read from base up", http.MethodGet, "/olympos/" + baseID + "/../" + B + "/.lock"},
		{"delete b's lock up and over", http.MethodDelete, "/olympos/" + A + "/../" + B + "/.lock"},
		{"list without a prefix", http.MethodGet, "/olympos/"},
		{"list an empty prefix", http.MethodGet, "/olympos/?prefix="},
		{"list the bucket name", http.MethodGet, "/olympos/?prefix=olympos/"},
		{"list another run", http.MethodGet, "/olympos/?prefix=" + b.prefix},
		{"list the run id without its slash", http.MethodGet, "/olympos/?prefix=" + A},
		{"list a shorter run id", http.MethodGet, "/olympos/?prefix=" + A[:8]},
		{"list up and over", http.MethodGet, "/olympos/?prefix=" + a.prefix + "../" + b.prefix},
		{"list base up", http.MethodGet, "/olympos/?prefix=" + base + ".."},
		{"list with a leading slash", http.MethodGet, "/olympos/?prefix=/" + a.prefix},
		{"list a double slash", http.MethodGet, "/olympos/?prefix=" + a.prefix + "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantRefused(t, e.do(t, a.cred, tc.method, tc.target, "x-"+tc.name[:1]), http.StatusForbidden, "AccessDenied")
		})
	}
	// Bodies on a GET or a DELETE are refused too; the cases above refuse
	// them on the key first. Nothing got out.
	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("a's sink got %+v", p)
	}
	if p := b.sink.all(); len(p) != 0 {
		t.Errorf("b's sink got %+v", p)
	}
	if lock, ok := b.s.Lock(); !ok || string(lock) != "b-lock" {
		t.Errorf("b's lock %q %v", lock, ok)
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if len(src.asked) != 0 {
		t.Errorf("the source was asked for %q", src.asked)
	}
}

func TestHandlerMetricsAndLogs(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	const body = "a body that is never logged"
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/x.bin", body), http.StatusOK)
	wantRefused(t, e.do(t, a.cred, http.MethodDelete, "/olympos/"+a.prefix+"data/x.bin", ""), http.StatusForbidden, "AccessDenied")
	wantRefused(t, e.do(t, ingest.Credential{AccessKey: a.cred.AccessKey, Secret: "wrong"}, http.MethodGet, "/olympos/?prefix="+a.prefix, ""),
		http.StatusForbidden, "SignatureDoesNotMatch")

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(e.metrics)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	value := func(name string, labels map[string]string) float64 {
		for _, f := range families {
			if f.GetName() != name {
				continue
			}
		metric:
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if labels[l.GetName()] != l.GetValue() {
						continue metric
					}
				}
				if m.Counter != nil {
					return m.Counter.GetValue()
				}
				return m.Gauge.GetValue()
			}
		}
		return -1
	}
	checks := []struct {
		name   string
		labels map[string]string
		want   float64
	}{
		{"olympos_ingest_requests_total", map[string]string{"op": "PutObject", "code": "200"}, 1},
		{"olympos_ingest_requests_total", map[string]string{"op": "DeleteObject", "code": "403"}, 1},
		{"olympos_ingest_requests_total", map[string]string{"op": "ListObjects", "code": "403"}, 1},
		{"olympos_ingest_refused_total", map[string]string{"reason": "AccessDenied"}, 1},
		{"olympos_ingest_refused_total", map[string]string{"reason": "SignatureDoesNotMatch"}, 1},
		{"olympos_ingest_bytes_total", nil, float64(len(body))},
		{"olympos_ingest_runs", nil, 1},
	}
	for _, c := range checks {
		if got := value(c.name, c.labels); got != c.want {
			t.Errorf("%s%v = %v, want %v", c.name, c.labels, got, c.want)
		}
	}

	logs := e.logs.String()
	for _, secret := range []string{a.cred.Secret, "Authorization", "AWS4-HMAC-SHA256", "Signature=", body} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains %q", secret)
		}
	}
	if !strings.Contains(logs, a.s.RunID().String()) || !strings.Contains(logs, a.prefix+"data/x.bin") {
		t.Errorf("the log lacks the run or the key:\n%s", logs)
	}
}
