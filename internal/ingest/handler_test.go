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
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func newEnv(t *testing.T, opts ...ingest.HandlerOption) *env {
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
	dir := t.TempDir()
	h := ingest.NewHandler(reg, log, m, append([]ingest.HandlerOption{ingest.WithSpillDir(dir)}, opts...)...)
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
	r, err := e.tryDo(cred, method, target, body, mutate...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// tryDo is do for other goroutines than the test's: it returns the error.
func (e *env) tryDo(cred ingest.Credential, method, target, body string, mutate ...func(*http.Request)) (reply, error) {
	req, err := http.NewRequest(method, e.srv.URL+target, strings.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("X-Amz-Content-Sha256", hexSHA256(body))
	for _, m := range mutate {
		m(req)
	}
	return e.trySend(signer.SignV4(*req, cred.AccessKey, cred.Secret, "", testRegion))
}

func (e *env) send(t *testing.T, req *http.Request) reply {
	t.Helper()
	r, err := e.trySend(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) trySend(req *http.Request) (reply, error) {
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		return reply{}, fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, fmt.Errorf("read body: %w", err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}, nil
}

// metricValue is the value of the metric name with labels, or -1 when
// there is none.
func metricValue(t *testing.T, m *ingest.Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(m)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
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

// shaTag is the ETag the endpoint gives a body: the first 32 hex characters
// of its SHA-256, quoted.
func shaTag(body string) string { return `"` + hexSHA256(body)[:32] + `"` }

// fakeSink records every Put. With failAfter >= 0 it reads that many bytes
// and fails without draining the reader, as a sink with no destination left.
type fakeSink struct {
	failAfter int
	// first, when not nil, is closed once the first bytes arrived.
	first     chan struct{}
	firstOnce sync.Once
	// hold, when not nil, keeps a Put that read its body from returning
	// until it is closed.
	hold chan struct{}
	// stall, when not nil, stops the reading once stallAfter bytes arrived,
	// until it is closed; stalled is closed when it stops.
	stall, stalled chan struct{}
	stallAfter     int
	stallOnce      sync.Once

	mu      sync.Mutex
	puts    []sinkPut
	started int
}

type sinkPut struct {
	key  string
	body []byte
	err  error // the reader's error: the object was aborted
}

var errNoDestination = errors.New("fake sink: no destination left")

func newSink() *fakeSink { return &fakeSink{failAfter: -1} }

func (f *fakeSink) Put(ctx context.Context, key string, r io.Reader) (ingest.ObjectRecord, error) {
	f.mu.Lock()
	f.started++
	f.mu.Unlock()
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
		if f.stall != nil && buf.Len() >= f.stallAfter {
			f.stallOnce.Do(func() {
				close(f.stalled)
				<-f.stall
			})
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	if err == nil && f.hold != nil {
		<-f.hold
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

// startedPuts counts the Puts that began.
func (f *fakeSink) startedPuts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
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
		ETag string
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
		// A virtual-host request has no /olympos/ in its path; the path rule
		// refuses it.
		{"virtual host", "/" + a.prefix + "x", []func(*http.Request){func(r *http.Request) { r.Host = "olympos.example.test" }}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantRefused(t, e.do(t, a.cred, http.MethodPut, tc.target, "body", tc.mutate...), http.StatusForbidden, "AccessDenied")
		})
	}
	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("the sink got %d puts", len(p))
	}

	// The Host is not looked at: a server named olympos.<domain> serves path
	// style.
	for _, host := range []string{"olympos.example.test", "olympos.example.test:9444"} {
		key := a.prefix + "data/" + host + ".bin"
		wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+key, "body", func(r *http.Request) { r.Host = host }), http.StatusOK)
		if p := a.sink.all(); len(p) == 0 || p[len(p)-1].key != key {
			t.Errorf("Host %s: the sink did not get %s", host, key)
		}
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
	if got, want := r.header.Get("ETag"), shaTag(body); got != want {
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

// An object is written once (task 10 round 2). A client that did not see
// the answer to its PUT sends it again: the same body is answered as stored,
// nothing is written twice. Another body for a stored key stops the run as a
// client that broke the protocol, never as a failed destination.
func TestHandlerRepeatedPut(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	body := "a part's bytes"
	key := a.prefix + "data/all_1_1_0/data.bin"
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+key, body), http.StatusOK)
	r := e.do(t, a.cred, http.MethodPut, "/olympos/"+key, body, md5Header(body))
	wantStatus(t, r, http.StatusOK)
	if got := r.header.Get("ETag"); got != shaTag(body) {
		t.Errorf("ETag %s", got)
	}
	if puts := a.sink.all(); len(puts) != 1 {
		t.Fatalf("sink puts %d, want 1", len(puts))
	}
	if got := a.s.Objects(); len(got) != 1 {
		t.Fatalf("objects %+v", got)
	}
	notStopped(t, a.s)

	r = e.do(t, a.cred, http.MethodPut, "/olympos/"+key, "other bytes")
	wantStatus(t, r, http.StatusForbidden)
	if got := stopReason(t, a.s); got != ingest.ReasonRewrite {
		t.Fatalf("stop reason %q, want %q", got, ingest.ReasonRewrite)
	}
	if puts := a.sink.all(); len(puts) != 1 {
		t.Fatalf("sink puts %d, want 1", len(puts))
	}
}

// A PUT sent again while the first one is still being stored waits for it,
// then gets the stored object as its answer.
func TestHandlerRepeatedPutInFlight(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	a.sink.first, a.sink.hold = make(chan struct{}), make(chan struct{})
	body := "the body of a slow object"
	key := a.prefix + "data/all_1_1_0/data.bin"
	replies := make(chan reply, 2)
	send := func() {
		r, err := e.tryDo(a.cred, http.MethodPut, "/olympos/"+key, body)
		if err != nil {
			r.status = -1
		}
		replies <- r
	}
	go send()
	<-a.sink.first
	go send()
	time.Sleep(200 * time.Millisecond)
	a.sink.mu.Lock()
	started := a.sink.started
	a.sink.mu.Unlock()
	if started != 1 {
		t.Fatalf("the repeated PUT started a second write (%d)", started)
	}
	close(a.sink.hold)
	for range 2 {
		r := <-replies
		wantStatus(t, r, http.StatusOK)
		if got := r.header.Get("ETag"); got != shaTag(body) {
			t.Errorf("ETag %s", got)
		}
	}
	if got := a.s.Objects(); len(got) != 1 {
		t.Fatalf("objects %+v", got)
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
		wantRefused(t, e.do(t, ro.cred, http.MethodGet, "/olympos/"+other+"missing.bin", ""), http.StatusForbidden, "AccessDenied")
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
	if r := e.do(t, a.cred, http.MethodPut, lock, "the-backup-uuid", md5Header("the-backup-uuid")); r.status != http.StatusOK ||
		r.header.Get("ETag") != shaTag("the-backup-uuid") {
		t.Fatalf("PUT .lock: %s %s", r, r.header.Get("ETag"))
	}
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

// TestHandlerRate (R17): a burst over the rate is answered 503 SlowDown
// before its body is read, and the session keeps running; once under the
// rate again, requests succeed.
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
	for range 5 {
		wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/over.bin", "not read"),
			http.StatusServiceUnavailable, "SlowDown")
	}
	notStopped(t, a.s)
	if p := a.sink.all(); len(p) != 0 {
		t.Errorf("a refused PUT reached the sink: %d puts", len(p))
	}
	// A 503 SlowDown is back-pressure the client retries, not a refusal:
	// logged at Info, not Warn.
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		if strings.Contains(line, `"error":"SlowDown"`) && !strings.Contains(line, `"level":"INFO"`) {
			t.Fatalf("a 503 SlowDown is not logged at Info: %s", line)
		}
	}
	// The limit is per session.
	wantStatus(t, e.do(t, b.cred, http.MethodGet, "/olympos/?prefix="+b.prefix, ""), http.StatusOK)
	// Under the rate again, the run goes on.
	e.clock.add(time.Second)
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/later.bin", "stored"), http.StatusOK)
	notStopped(t, a.s)
	notStopped(t, b.s)
}

// TestHandlerRateStorm (R17): only a session over the rate for 30
// consecutive seconds is stopped, with "rate". A second without a refused
// request ends the streak.
func TestHandlerRateStorm(t *testing.T) {
	e := newEnv(t, ingest.WithRate(2))
	a := e.backup(t)
	get := func() reply { return e.do(t, a.cred, http.MethodGet, "/olympos/?prefix="+a.prefix, "") }
	// storm sends 4 requests a second (2 over the rate) for d.
	storm := func(d time.Duration) {
		t.Helper()
		for range int(d / (500 * time.Millisecond)) {
			e.clock.add(500 * time.Millisecond)
			wantStatus(t, get(), http.StatusOK)
			wantRefused(t, get(), http.StatusServiceUnavailable, "SlowDown")
		}
	}
	// atRate sends 2 requests a second, all taken, for d.
	atRate := func(d time.Duration) {
		t.Helper()
		for range int(d / time.Second) {
			e.clock.add(time.Second)
			wantStatus(t, get(), http.StatusOK)
			wantStatus(t, get(), http.StatusOK)
		}
	}
	atRate(time.Second)
	storm(20 * time.Second)
	notStopped(t, a.s)
	// Two seconds at the rate end the streak.
	atRate(2 * time.Second)
	// A new streak: its refusals run from t to t+29.5s, then t+30s.
	storm(30 * time.Second)
	notStopped(t, a.s)
	storm(500 * time.Millisecond)
	if got := stopReason(t, a.s); got != ingest.ReasonRate {
		t.Errorf("stop reason %q, want %q", got, ingest.ReasonRate)
	}
	wantRefused(t, get(), http.StatusForbidden, "InvalidAccessKeyId")
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
	l = e.list(t, a.cred, "prefix="+p)
	for _, c := range l.Contents {
		body := "body of " + strings.TrimPrefix(c.Key, p)
		if c.Key == p+".lock" {
			body = "lock"
		}
		if c.ETag != shaTag(body) {
			t.Errorf("%s: ETag %s, want %s", c.Key, c.ETag, shaTag(body))
		}
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

// multipartETag is the whole object's ETag with the part count.
func multipartETag(parts ...string) string {
	return fmt.Sprintf(`"%s-%d"`, hexSHA256(strings.Join(parts, ""))[:32], len(parts))
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

	t.Run("complete sent again", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		var tags []string
		for i, p := range parts {
			tags = append(tags, etagOf(t, m.part(t, i+1, p)))
		}
		first := m.complete(t, tags...)
		wantStatus(t, first, http.StatusOK)
		again := m.complete(t, tags...)
		wantStatus(t, again, http.StatusOK)
		if again.body != first.body {
			t.Errorf("repeated complete %q, want %q", again.body, first.body)
		}
		if puts := a.sink.all(); len(puts) != 1 || len(a.s.Objects()) != 1 {
			t.Fatalf("sink puts %d, objects %d", len(puts), len(a.s.Objects()))
		}
		notStopped(t, a.s)
		// Another part list for the completed upload: the run stops.
		wantStatus(t, m.complete(t, tags[0]), http.StatusForbidden)
		if got := stopReason(t, a.s); got != ingest.ReasonRewrite {
			t.Fatalf("stop reason %q", got)
		}
	})

	t.Run("in order", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		var tags []string
		for i, p := range parts {
			tag := etagOf(t, m.part(t, i+1, p))
			if tag != shaTag(p) {
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
	t.Run("spill over the budget", func(t *testing.T) {
		// R18: an early part that would take the spill over its budget is
		// refused 503 SlowDown before its body is read, and is taken once
		// the parts before it drained. The session never stops.
		e := newEnv(t, ingest.WithSpillLimit(10))
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		p := []string{"ab", "12345", "678901", "the last part, longer than the budget"}
		tags := make([]string, len(p))
		tags[1] = etagOf(t, m.part(t, 2, p[1]))
		wantRefused(t, m.part(t, 3, p[2]), http.StatusServiceUnavailable, "SlowDown")
		wantRefused(t, m.part(t, 4, p[3]), http.StatusServiceUnavailable, "SlowDown")
		notStopped(t, a.s)
		if n := spillFiles(t, e.spillDir); n != 1 {
			t.Errorf("%d spill files, want 1", n)
		}
		if n := ingest.Spilled(a.s); n != int64(len(p[1])) {
			t.Errorf("%d bytes counted as spilled, want %d", n, len(p[1]))
		}
		// The part in order is always taken; it drains part 2.
		tags[0] = etagOf(t, m.part(t, 1, p[0]))
		if n := ingest.Spilled(a.s); n != 0 {
			t.Errorf("%d bytes counted as spilled after the drain", n)
		}
		// Part 4 is still early, and over the budget on its own, until its turn.
		wantRefused(t, m.part(t, 4, p[3]), http.StatusServiceUnavailable, "SlowDown")
		tags[2] = etagOf(t, m.part(t, 3, p[2]))
		tags[3] = etagOf(t, m.part(t, 4, p[3]))
		wantStatus(t, m.complete(t, tags...), http.StatusOK)
		puts := a.sink.all()
		if len(puts) != 1 || puts[0].err != nil || string(puts[0].body) != strings.Join(p, "") {
			t.Fatalf("sink puts: %+v", puts)
		}
		if n := spillFiles(t, e.spillDir); n != 0 {
			t.Errorf("%d spill files left", n)
		}
		notStopped(t, a.s)
	})
	t.Run("a part without a length", func(t *testing.T) {
		a := e.backup(t)
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		chunked := func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("chunked part"))
			r.ContentLength = -1
		}
		for _, n := range []int{1, 2} {
			r := e.do(t, a.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=%d&uploadId=%s", m.key, n, m.id),
				"chunked part", chunked)
			wantRefused(t, r, http.StatusForbidden, "AccessDenied")
		}
		notStopped(t, a.s)
		tag := etagOf(t, m.part(t, 1, "with a length"))
		wantStatus(t, m.complete(t, tag), http.StatusOK)
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
		// The object is partly written and cannot be written again: the run
		// cannot succeed, so the session stops.
		if got := stopReason(t, a.s); got != ingest.ReasonUploadAborted {
			t.Errorf("stop reason %q", got)
		}
		wantRefused(t, m.part(t, 2, parts[1]), http.StatusForbidden, "InvalidAccessKeyId")
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
		// Out of scope is 403 whether the key exists or not; 404 is only for
		// keys in scope.
		{"read a missing key of b", http.MethodGet, "/olympos/" + b.prefix + "data/none.bin", "", "AccessDenied"},
		{"read a missing .lock of another run", http.MethodGet, "/olympos/" + uuid.NewString() + "/.lock", "", "AccessDenied"},
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
		if got := metricValue(t, e.metrics, c.name, c.labels); got != c.want {
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

// waitNoSpill waits until the spill directory is empty.
func waitNoSpill(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for spillFiles(t, dir) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := spillFiles(t, dir); n != 0 {
		t.Errorf("%d spill files left", n)
	}
}

// waitNoUploads waits until the handler has no open upload.
func waitNoUploads(t *testing.T, e *env) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for ingest.OpenUploads(e.handler) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := ingest.OpenUploads(e.handler); n != 0 {
		t.Errorf("%d uploads open", n)
	}
}

// TestHandlerExpiryEndsUploads: when a session expires no request can end
// its uploads, so expiry itself does. The session stops with "expired", the
// put of an open upload fails, its waiting parts leave the disk, and the
// handler forgets it.
func TestHandlerExpiryEndsUploads(t *testing.T) {
	check := func(t *testing.T, e *env, a *run) {
		t.Helper()
		if got := stopReason(t, a.s); got != ingest.ReasonExpired {
			t.Errorf("stop reason %q, want %q", got, ingest.ReasonExpired)
		}
		if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
			t.Error("the put of the open upload did not fail")
		}
		waitNoSpill(t, e.spillDir)
		waitNoUploads(t, e)
		if n := ingest.Spilled(a.s); n != 0 {
			t.Errorf("%d bytes counted as spilled", n)
		}
	}
	start := func(t *testing.T, e *env, ttl time.Duration) *run {
		t.Helper()
		a := e.backup(t, func(o *ingest.OpenOptions) { o.TTL = ttl })
		m := e.createUpload(t, a, a.prefix+"data/big.bin")
		etagOf(t, m.part(t, 1, "first"))
		etagOf(t, m.part(t, 3, "waits on disk"))
		if n := spillFiles(t, e.spillDir); n != 1 {
			t.Fatalf("%d spill files, want 1", n)
		}
		return a
	}

	t.Run("the TTL passes", func(t *testing.T) {
		e := newEnv(t)
		fire := ingest.ManualExpiry(e.reg)
		a := start(t, e, time.Hour)
		// The TTL passes with no request to notice it: the timer fires.
		e.clock.add(2 * time.Hour)
		fire()
		check(t, e, a)
	})
	t.Run("an Open drops the expired session", func(t *testing.T) {
		e := newEnv(t)
		a := start(t, e, time.Hour)
		e.clock.add(2 * time.Hour)
		e.backup(t) // reserve drops the expired session
		check(t, e, a)
	})
}

// TestHandlerConcurrentParts: ClickHouse uploads parts in parallel. Parts
// sent at once, in random order, become one put of the whole body, and leave
// nothing on disk.
func TestHandlerConcurrentParts(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	m := e.createUpload(t, a, a.prefix+"data/big.bin")
	const n = 10
	parts := make([]string, n)
	for i := range parts {
		parts[i] = strings.Repeat(string(rune('a'+i)), 40<<10+i*1000)
	}
	tags := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for _, i := range rand.Perm(n) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.tryDo(a.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=%d&uploadId=%s", m.key, i+1, m.id),
				parts[i], md5Header(parts[i]))
			switch {
			case err != nil:
				errs[i] = err
			case r.status != http.StatusOK:
				errs[i] = fmt.Errorf("reply %s", r)
			default:
				tags[i] = r.header.Get("ETag")
			}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("part %d: %v", i+1, err)
		}
	}
	if t.Failed() {
		return
	}
	r := m.complete(t, tags...)
	wantStatus(t, r, http.StatusOK)
	whole := strings.Join(parts, "")
	puts := a.sink.all()
	if len(puts) != 1 || puts[0].err != nil || string(puts[0].body) != whole {
		t.Fatalf("sink puts: %d", len(puts))
	}
	var res struct{ ETag string }
	if err := xml.Unmarshal([]byte(r.body), &res); err != nil || res.ETag != multipartETag(parts...) {
		t.Errorf("complete %s: %v", r.body, err)
	}
	if n := spillFiles(t, e.spillDir); n != 0 {
		t.Errorf("%d spill files left", n)
	}
	if n := ingest.Spilled(a.s); n != 0 {
		t.Errorf("%d bytes counted as spilled", n)
	}
	if n := ingest.OpenUploads(e.handler); n != 0 {
		t.Errorf("%d uploads open", n)
	}
	notStopped(t, a.s)
}

// TestHandlerPreAuthLogsDebug: a request refused before any session is
// found is counted, but logged at Debug only, so that unauthenticated
// clients cannot flood the log.
func TestHandlerPreAuthLogsDebug(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	wantRefused(t, e.send(t, mustRequest(t, http.MethodGet, e.srv.URL+"/olympos/?prefix="+a.prefix)), http.StatusForbidden, "AccessDenied")
	wantRefused(t, e.do(t, ingest.Credential{AccessKey: "OLYAAAAAAAAAAAAAAAAA", Secret: "x"}, http.MethodGet, "/olympos/?prefix="+a.prefix, ""),
		http.StatusForbidden, "InvalidAccessKeyId")
	wantRefused(t, e.do(t, a.cred, http.MethodGet, "/other/x", ""), http.StatusForbidden, "AccessDenied")
	if got := metricValue(t, e.metrics, "olympos_ingest_refused_total", map[string]string{"reason": "AccessDenied"}); got != 2 {
		t.Errorf("refused AccessDenied = %v, want 2", got)
	}
	if got := metricValue(t, e.metrics, "olympos_ingest_refused_total", map[string]string{"reason": "InvalidAccessKeyId"}); got != 1 {
		t.Errorf("refused InvalidAccessKeyId = %v, want 1", got)
	}
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		if strings.Contains(line, `"ingest request"`) && !strings.Contains(line, `"level":"DEBUG"`) {
			t.Errorf("a refusal without a session logged above Debug: %s", line)
		}
	}
	// A refusal of a known session still logs at Warn.
	wantRefused(t, e.do(t, a.cred, http.MethodDelete, "/olympos/"+a.prefix+"data/x.bin", ""), http.StatusForbidden, "AccessDenied")
	if !strings.Contains(e.logs.String(), `"level":"WARN","msg":"ingest request"`) {
		t.Errorf("a refusal of a session is not logged at Warn:\n%s", e.logs.String())
	}
}

func mustRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestHandlerRevokeCutsStalledBody: a client that stops sending in the middle
// of a body does not hold its handler once the session ends: Revoke cuts the
// read.
func TestHandlerRevokeCutsStalledBody(t *testing.T) {
	for name, end := range map[string]func(*ingest.Session){
		"revoke": func(s *ingest.Session) { s.Revoke("run ended") },
		"stop":   func(s *ingest.Session) { s.Stop("test stop") },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			a := e.backup(t)
			a.sink.first = make(chan struct{})
			body := strings.Repeat("s", 1<<20)
			pr, pw := io.Pipe()
			defer pw.Close()
			req, err := http.NewRequest(http.MethodPut, e.srv.URL+"/olympos/"+a.prefix+"data/stalled.bin", pr)
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = int64(len(body))
			req.Header.Set("X-Amz-Content-Sha256", hexSHA256(body))
			signed := signer.SignV4(*req, a.cred.AccessKey, a.cred.Secret, "", testRegion)
			done := make(chan int, 1)
			go func() {
				resp, err := e.srv.Client().Do(signed)
				if err != nil {
					done <- 0
					return
				}
				_ = resp.Body.Close()
				done <- resp.StatusCode
			}()
			if _, err := pw.Write([]byte(body[:4096])); err != nil {
				t.Fatal(err)
			}
			select {
			case <-a.sink.first:
			case <-time.After(5 * time.Second):
				t.Fatal("the body never reached the sink")
			}
			// The client sends nothing more and keeps the connection open.
			end(a.s)
			select {
			case code := <-done:
				if code == http.StatusOK {
					t.Error("the stalled PUT succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the handler is still blocked reading the stalled body")
			}
			if puts := a.sink.waitPuts(t, 1); puts[0].err == nil {
				t.Error("the object was stored")
			}
		})
	}
}

// TestHandlerUploadCapStartsNoPut: a CreateMultipartUpload over the run's
// open-upload cap is refused before it starts a Sink.Put.
func TestHandlerUploadCapStartsNoPut(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	const maxUploads = 256
	for i := range maxUploads {
		e.clock.add(10 * time.Millisecond) // under the rate
		e.createUpload(t, a, fmt.Sprintf("%sdata/f%d.bin", a.prefix, i))
	}
	if n := a.sink.startedPuts(); n != maxUploads {
		t.Fatalf("%d puts started, want %d", n, maxUploads)
	}
	r := e.do(t, a.cred, http.MethodPost, "/olympos/"+a.prefix+"data/one-more.bin?uploads", "")
	wantRefused(t, r, http.StatusForbidden, "AccessDenied")
	if n := a.sink.startedPuts(); n != maxUploads {
		t.Errorf("the refused upload started a put: %d puts started", n)
	}
	if n := ingest.OpenUploads(e.handler); n != maxUploads {
		t.Errorf("%d uploads open", n)
	}
}

// TestHandlerPercentKey: ClickHouse's escapeForFileName writes keys with a
// literal %, sent on the wire as %25. PUT, GET and List keep the exact key.
func TestHandlerPercentKey(t *testing.T) {
	e := newEnv(t)
	base := uuid.NewString() + "/"
	const dataKey = "data/db/t/all_1_1_0/n%2Ex.bin"
	const metaKey = "metadata/my%2Ddb/t%2E1.sql"
	src := &fakeSource{objects: map[string]string{base + dataKey: "base part"}}
	a := e.backup(t, func(o *ingest.OpenOptions) { o.Scope.Read = []string{base}; o.Source = src })
	wire := func(k string) string { return strings.ReplaceAll(k, "%", "%25") }

	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+wire(dataKey), "part data"), http.StatusOK)
	wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+wire(metaKey), "CREATE TABLE"), http.StatusOK)
	var keys []string
	for _, p := range a.sink.all() {
		keys = append(keys, p.key)
	}
	slices.Sort(keys)
	if want := []string{a.prefix + dataKey, a.prefix + metaKey}; !slices.Equal(keys, want) {
		t.Errorf("sink keys %q, want %q", keys, want)
	}
	if r := e.do(t, a.cred, http.MethodGet, "/olympos/"+a.prefix+wire(metaKey), ""); r.status != http.StatusOK || r.body != "CREATE TABLE" {
		t.Errorf("GET the kept body: %s", r)
	}
	if r := e.do(t, a.cred, http.MethodGet, "/olympos/"+base+wire(dataKey), ""); r.status != http.StatusOK || r.body != "base part" {
		t.Errorf("GET from the base: %s", r)
	}
	if l := e.list(t, a.cred, "prefix="+url.QueryEscape(a.prefix)); !slices.Equal(l.keys(), []string{a.prefix + dataKey, a.prefix + metaKey}) {
		t.Errorf("list own %q", l.keys())
	}
	if l := e.list(t, a.cred, "prefix="+url.QueryEscape(base+"data/db/t/")); !slices.Equal(l.keys(), []string{base + dataKey}) {
		t.Errorf("list base %q", l.keys())
	}
	notStopped(t, a.s)
}

// TestHandlerStopMetric: olympos_ingest_stops_total counts each session
// stop once, by its reason.
func TestHandlerStopMetric(t *testing.T) {
	e := newEnv(t)
	fire := ingest.ManualExpiry(e.reg)
	a := e.backup(t, func(o *ingest.OpenOptions) { o.MaxBytes = 4 })
	b := e.backup(t, func(o *ingest.OpenOptions) { o.MaxBytes = 4 })
	c := e.backup(t)
	wantRefused(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+a.prefix+"data/a.bin", "12345"), http.StatusForbidden, "AccessDenied")
	wantRefused(t, e.do(t, b.cred, http.MethodPut, "/olympos/"+b.prefix+"data/b.bin", "12345"), http.StatusForbidden, "AccessDenied")
	a.s.Stop("again") // only the first stop counts
	e.clock.add(2 * time.Hour)
	fire()
	c.s.Revoke("run ended") // a revoke is not a stop
	for reason, want := range map[string]float64{ingest.ReasonQuota: 2, ingest.ReasonExpired: 1, "again": -1} {
		if got := metricValue(t, e.metrics, "olympos_ingest_stops_total", map[string]string{"reason": reason}); got != want {
			t.Errorf("olympos_ingest_stops_total{reason=%q} = %v, want %v", reason, got, want)
		}
	}
}

// TestRemoveSpillFiles: the spill files a crash left behind are removed;
// nothing else in the directory is.
func TestRemoveSpillFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"olympos-ingest-1.part", "olympos-ingest-22.part", "other.part", "olympos-ingest-3.txt"} {
		if err := os.WriteFile(dir+"/"+name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	n, err := ingest.RemoveSpillFiles(dir)
	if err != nil || n != 2 {
		t.Fatalf("removed %d, %v; want 2", n, err)
	}
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if want := []string{"olympos-ingest-3.txt", "other.part"}; !slices.Equal(left, want) {
		t.Errorf("left %q, want %q", left, want)
	}
	if n, err := ingest.RemoveSpillFiles(dir + "/missing"); err != nil || n != 0 {
		t.Errorf("a missing directory: %d, %v", n, err)
	}
}

// completeXML is a CompleteMultipartUpload body listing etags.
func completeXML(etags ...string) string {
	var b strings.Builder
	b.WriteString(`<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for i, tag := range etags {
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", i+1, tag)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

// R35, R36: a Complete sent again while the first one still stores the
// object (a slow destination) waits for it and gets its answer, never
// NoSuchUpload.
func TestHandlerRepeatedCompleteInFlight(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	a.sink.hold = make(chan struct{})
	var release sync.Once
	unhold := func() { release.Do(func() { close(a.sink.hold) }) }
	defer unhold() // a failing test must not leave the server waiting on the sink
	parts := []string{strings.Repeat("a", 64<<10), "the last part"}
	m := e.createUpload(t, a, a.prefix+"data/big.bin")
	var tags []string
	for i, p := range parts {
		tags = append(tags, etagOf(t, m.part(t, i+1, p)))
	}
	replies := make(chan reply, 2)
	send := func() {
		r, err := e.tryDo(a.cred, http.MethodPost, "/olympos/"+m.key+"?uploadId="+m.id, completeXML(tags...))
		if err != nil {
			r.status = -1
		}
		replies <- r
	}
	go send()
	time.Sleep(100 * time.Millisecond)
	go send()
	select {
	case r := <-replies:
		t.Fatalf("a Complete returned while the object is being stored: %d %s", r.status, r.body)
	case <-time.After(200 * time.Millisecond):
	}
	unhold()
	first, second := <-replies, <-replies
	wantStatus(t, first, http.StatusOK)
	wantStatus(t, second, http.StatusOK)
	if first.body != second.body || !strings.Contains(first.body, strings.Trim(multipartETag(parts...), `"`)) {
		t.Fatalf("answers:\n%s\n%s", first.body, second.body)
	}
	if puts := a.sink.all(); len(puts) != 1 || len(a.s.Objects()) != 1 {
		t.Fatalf("sink puts %d, objects %d", len(puts), len(a.s.Objects()))
	}
	notStopped(t, a.s)
}

// A part sent again while the request that streamed it still writes the
// parts that waited on disk gets its answer at once. The Complete that
// follows waits for those parts to be written, instead of finding the
// part list short (seen on CI: ClickHouse sent a part again when the
// destination was slow, then the Complete, and the upload failed with
// InvalidPart).
func TestHandlerCompleteWaitsForWaitingParts(t *testing.T) {
	e := newEnv(t)
	a := e.backup(t)
	parts := []string{"the first part", strings.Repeat("b", 64<<10)}
	a.sink.stall, a.sink.stalled, a.sink.stallAfter = make(chan struct{}), make(chan struct{}), len(parts[0])+1
	var release sync.Once
	unstall := func() { release.Do(func() { close(a.sink.stall) }) }
	defer unstall() // a failing test must not leave the server waiting on the sink
	m := e.createUpload(t, a, a.prefix+"data/big.bin")
	tags := []string{shaTag(parts[0]), etagOf(t, m.part(t, 2, parts[1]))}

	first := make(chan reply, 1)
	go func() {
		r, err := e.tryDo(a.cred, http.MethodPut, fmt.Sprintf("/olympos/%s?partNumber=1&uploadId=%s", m.key, m.id),
			parts[0], md5Header(parts[0]))
		if err != nil {
			r.status = -1
		}
		first <- r
	}()
	select {
	case <-a.sink.stalled: // part 1 is written, part 2 is being written
	case <-time.After(10 * time.Second):
		t.Fatal("the sink got nothing of part 2")
	}
	if tag := etagOf(t, m.part(t, 1, parts[0])); tag != tags[0] {
		t.Fatalf("part 1 sent again: ETag %s, want %s", tag, tags[0])
	}
	completed := make(chan reply, 1)
	go func() {
		r, err := e.tryDo(a.cred, http.MethodPost, "/olympos/"+m.key+"?uploadId="+m.id, completeXML(tags...))
		if err != nil {
			r.status = -1
		}
		completed <- r
	}()
	select {
	case r := <-completed:
		t.Fatalf("the Complete returned while part 2 is being written: %d %s", r.status, r.body)
	case <-time.After(200 * time.Millisecond):
	}
	unstall()
	r := <-completed
	wantStatus(t, r, http.StatusOK)
	wantStatus(t, <-first, http.StatusOK)
	if !strings.Contains(r.body, strings.Trim(multipartETag(parts...), `"`)) {
		t.Fatalf("complete: %s", r.body)
	}
	if puts := a.sink.all(); len(puts) != 1 || puts[0].err != nil || string(puts[0].body) != strings.Join(parts, "") {
		t.Fatalf("sink puts: %d", len(puts))
	}
	notStopped(t, a.s)
}

// exclusiveSink refuses a second write of a key while one is in progress,
// and of a key it stored, as a filesystem destination does (O_EXCL on
// <file>.partial, link(2) on the file).
type exclusiveSink struct {
	mu       sync.Mutex
	writing  map[string]bool
	stored   map[string]string
	refused  int
	aborted  int
	inFlight chan struct{} // closed once a write is in progress
	once     sync.Once
}

func newExclusiveSink() *exclusiveSink {
	return &exclusiveSink{writing: map[string]bool{}, stored: map[string]string{}, inFlight: make(chan struct{})}
}

func (x *exclusiveSink) Put(_ context.Context, key string, r io.Reader) (ingest.ObjectRecord, error) {
	x.mu.Lock()
	if x.writing[key] || x.stored[key] != "" {
		x.refused++
		x.mu.Unlock()
		return ingest.ObjectRecord{}, errors.New("another upload in progress, or the file exists")
	}
	x.writing[key] = true
	x.mu.Unlock()
	x.once.Do(func() { close(x.inFlight) })
	b, err := io.ReadAll(r)
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.writing, key) // the partial file is removed either way
	if err != nil {
		x.aborted++
		return ingest.ObjectRecord{}, err
	}
	x.stored[key] = string(b)
	sum := sha256.Sum256(b)
	return ingest.ObjectRecord{Key: key, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}, nil
}

// R36: ClickHouse sends CreateMultipartUpload again when it did not see the
// answer. The earlier upload of the key is dropped, and its write ended,
// before the new one starts: no destination refuses it, the run goes on and
// stores the object once.
func TestHandlerRetriedCreate(t *testing.T) {
	e := newEnv(t)
	x := newExclusiveSink()
	a := e.backup(t, func(o *ingest.OpenOptions) { o.Sink = x })
	key := a.prefix + "data/big.bin"
	first := e.createUpload(t, a, key)
	wantStatus(t, first.part(t, 1, "a part of the lost upload"), http.StatusOK)
	<-x.inFlight
	parts := []string{strings.Repeat("b", 64<<10), "the last part"}
	second := e.createUpload(t, a, key)
	var tags []string
	for i, p := range parts {
		tags = append(tags, etagOf(t, second.part(t, i+1, p)))
	}
	wantStatus(t, second.complete(t, tags...), http.StatusOK)
	// The earlier upload is gone.
	for _, r := range []reply{first.part(t, 2, "late"), first.complete(t, "x")} {
		if r.code() != "NoSuchUpload" {
			t.Fatalf("the replaced upload: %d %s", r.status, r.code())
		}
	}
	x.mu.Lock()
	refused, aborted, stored := x.refused, x.aborted, x.stored[key]
	x.mu.Unlock()
	if refused != 0 || aborted != 1 || stored != strings.Join(parts, "") {
		t.Fatalf("sink: %d refused, %d aborted, stored %d bytes", refused, aborted, len(stored))
	}
	if got := a.s.Objects(); len(got) != 1 || got[0].Size != int64(len(stored)) {
		t.Fatalf("objects %+v", got)
	}
	notStopped(t, a.s)
}

// R36: one writer per key. A PutObject beside an open upload of its key, or
// an upload of a stored key that ends with another object, stops the run as
// "object rewritten"; nothing is overwritten. The same object again is a
// repeat, answered from the stored record.
func TestHandlerOneWriterPerKey(t *testing.T) {
	e := newEnv(t)
	t.Run("PutObject beside an open upload", func(t *testing.T) {
		a := e.backup(t)
		key := a.prefix + "data/big.bin"
		m := e.createUpload(t, a, key)
		wantStatus(t, m.part(t, 1, "part"), http.StatusOK)
		wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+key, "a whole object"), http.StatusForbidden)
		if got := stopReason(t, a.s); got != ingest.ReasonRewrite {
			t.Fatalf("stop reason %q", got)
		}
		for _, p := range a.sink.all() {
			if string(p.body) == "a whole object" {
				t.Fatal("the PutObject reached the sink")
			}
		}
	})
	upload := func(t *testing.T, a *run, key string, parts ...string) reply {
		t.Helper()
		m := e.createUpload(t, a, key)
		var tags []string
		for i, p := range parts {
			tags = append(tags, etagOf(t, m.part(t, i+1, p)))
		}
		return m.complete(t, tags...)
	}
	t.Run("a second upload of a stored key", func(t *testing.T) {
		a := e.backup(t)
		key := a.prefix + "data/big.bin"
		parts := []string{strings.Repeat("c", 64<<10), "end"}
		first := upload(t, a, key, parts...)
		wantStatus(t, first, http.StatusOK)
		// The same object again: answered, nothing written.
		again := upload(t, a, key, parts...)
		wantStatus(t, again, http.StatusOK)
		if !strings.Contains(again.body, strings.Trim(multipartETag(parts...), `"`)) {
			t.Fatalf("repeat: %s", again.body)
		}
		notStopped(t, a.s)
		// Another object for the stored key: the run stops.
		wantStatus(t, upload(t, a, key, "other", "bytes"), http.StatusForbidden)
		if got := stopReason(t, a.s); got != ingest.ReasonRewrite {
			t.Fatalf("stop reason %q", got)
		}
		if puts := a.sink.all(); len(puts) != 1 || string(puts[0].body) != strings.Join(parts, "") || len(a.s.Objects()) != 1 {
			t.Fatalf("sink puts %d, objects %d", len(puts), len(a.s.Objects()))
		}
	})
}

// R39: the bytes of a repeat are drained, not stored, and not charged to the
// run's quota: a PutObject or a multipart upload sent again whole is no
// second object.
func TestHandlerRepeatNotCharged(t *testing.T) {
	e := newEnv(t)
	parts := []string{strings.Repeat("c", 64<<10), "end"}
	size := int64(len(parts[0]) + len(parts[1]))
	a := e.backup(t, func(o *ingest.OpenOptions) { o.MaxBytes = 2*size + 10 })
	put := a.prefix + "data/small.bin"
	body := strings.Repeat("p", int(size))
	for range 3 {
		wantStatus(t, e.do(t, a.cred, http.MethodPut, "/olympos/"+put, body), http.StatusOK)
	}
	key := a.prefix + "data/big.bin"
	for range 3 {
		m := e.createUpload(t, a, key)
		var tags []string
		for i, p := range parts {
			tags = append(tags, etagOf(t, m.part(t, i+1, p)))
		}
		wantStatus(t, m.complete(t, tags...), http.StatusOK)
	}
	notStopped(t, a.s)
	if n := len(a.s.Objects()); n != 2 {
		t.Fatalf("%d objects", n)
	}
}
