package blob_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// readerPayload is deterministic and not periodic at small offsets, so a
// misplaced range shows up as a content mismatch.
func readerPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*131 + i/251) % 251)
	}
	return b
}

// checkObject runs the io.ReaderAt contract against an Object whose content
// is want.
func checkObject(t *testing.T, o blob.Object, want []byte) {
	t.Helper()
	if o.Size() != int64(len(want)) {
		t.Fatalf("size = %d, want %d", o.Size(), len(want))
	}
	for _, c := range []struct{ off, n int }{{0, 10}, {7, 100}, {len(want) - 10, 10}, {len(want) / 2, 4096}, {0, len(want)}} {
		p := make([]byte, c.n)
		n, err := o.ReadAt(p, int64(c.off))
		if err != nil && !(errors.Is(err, io.EOF) && c.off+c.n >= len(want)) {
			t.Fatalf("ReadAt(%d,%d): %v", c.off, c.n, err)
		}
		if n != c.n || !bytes.Equal(p, want[c.off:c.off+c.n]) {
			t.Fatalf("ReadAt(%d,%d): n=%d, content mismatch", c.off, c.n, n)
		}
	}
	// A read that crosses the end returns what is there plus io.EOF.
	p := make([]byte, 50)
	n, err := o.ReadAt(p, int64(len(want)-20))
	if n != 20 || !errors.Is(err, io.EOF) || !bytes.Equal(p[:n], want[len(want)-20:]) {
		t.Fatalf("ReadAt across end: n=%d err=%v", n, err)
	}
	// At and past the end: 0, io.EOF.
	for _, off := range []int64{int64(len(want)), int64(len(want)) + 1000} {
		if n, err := o.ReadAt(make([]byte, 8), off); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%d) past end: n=%d err=%v", off, n, err)
		}
	}
	if n, err := o.ReadAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("empty read: n=%d err=%v", n, err)
	}
	if _, err := o.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative offset must fail")
	}
}

func TestFSReader(t *testing.T) {
	root, _ := nfsRoot(t)
	ctx := context.Background()
	w, err := blob.OpenFS(blob.FSTarget{Name: "nas", Path: root + "/nas/olympos/backups", Prefix: "pfx"}, blob.StorageOptions{NFSRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	payload := readerPayload(300_000)
	p := blob.Join(w.Prefix(), "prod/db/orders/run1.zip")
	if _, err := w.Upload(ctx, p, bytes.NewReader(payload), "application/zip", nil); err != nil {
		t.Fatal(err)
	}
	var r blob.Reader = w
	o, err := r.Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	checkObject(t, o, payload)

	sum := sha256.Sum256(payload)
	got, err := blob.SequentialSHA256(ctx, o)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha: %q %v", got, err)
	}

	if _, err := r.Open(ctx, blob.Join(w.Prefix(), "nope.zip")); err == nil {
		t.Fatal("opening a missing file must fail")
	}
	if _, err := r.Open(ctx, "../escape"); err == nil {
		t.Fatal("path traversal must fail")
	}
	if _, err := r.Open(ctx, blob.Join(w.Prefix(), "prod")); err == nil {
		t.Fatal("opening a directory must fail")
	}
}

func TestFSReaderEmptyFile(t *testing.T) {
	root, _ := nfsRoot(t)
	w, err := blob.OpenFS(blob.FSTarget{Name: "nas", Path: root + "/nas/olympos/backups"}, blob.StorageOptions{NFSRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Upload(context.Background(), "empty.bin", bytes.NewReader(nil), "", nil); err != nil {
		t.Fatal(err)
	}
	o, err := w.Open(context.Background(), "empty.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if o.Size() != 0 {
		t.Fatal(o.Size())
	}
	got, err := blob.SequentialSHA256(context.Background(), o)
	sum := sha256.Sum256(nil)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha: %q %v", got, err)
	}
}

func TestSequentialSHA256HonoursContext(t *testing.T) {
	root, _ := nfsRoot(t)
	w, err := blob.OpenFS(blob.FSTarget{Name: "nas", Path: root + "/nas/olympos"}, blob.StorageOptions{NFSRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Upload(context.Background(), "x", bytes.NewReader(readerPayload(1<<20)), "", nil); err != nil {
		t.Fatal(err)
	}
	o, err := w.Open(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := blob.SequentialSHA256(ctx, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// fakeS3 answers HEAD and ranged GET of one object under /<bucket>/<key>
// and records every request.
type fakeS3 struct {
	mu       sync.Mutex
	data     []byte
	requests []string // "METHOD Range"
	srv      *httptest.Server
}

func newFakeS3(t *testing.T, bucket, key string, data []byte) *fakeS3 {
	f := &fakeS3{data: data}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.Header.Get("Range"))
		f.mu.Unlock()
		if r.URL.Path != "/"+bucket+"/"+key {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>no</Message></Error>`))
			return
		}
		w.Header().Set("ETag", `"abc"`)
		// ServeContent answers HEAD and Range (206 + Content-Range).
		http.ServeContent(w, r, "", time.Unix(1_700_000_000, 0), bytes.NewReader(f.data))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestS3Reader(t *testing.T) {
	ctx := context.Background()
	payload := readerPayload(200_000)
	f := newFakeS3(t, "bkt", "pfx/run1.zip", payload)
	s, err := blob.OpenS3(blob.S3Target{Name: "s3", Bucket: "bkt", Prefix: "pfx", EndpointOverride: f.srv.URL, PathStyle: true,
		AccessKeyID: "ak", SecretKey: "sk"}, blob.StorageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var r blob.Reader = s
	o, err := r.Open(ctx, "pfx/run1.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	checkObject(t, o, payload)

	// Every data read was a ranged GET; the object was never fetched whole.
	f.mu.Lock()
	for _, req := range f.requests {
		if strings.HasPrefix(req, "GET ") && !strings.HasPrefix(req, "GET bytes=") {
			t.Errorf("unranged request: %q", req)
		}
	}
	f.mu.Unlock()

	sum := sha256.Sum256(payload)
	got, err := blob.SequentialSHA256(ctx, o)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha: %q %v", got, err)
	}

	if _, err := r.Open(ctx, "pfx/missing.zip"); err == nil {
		t.Fatal("opening a missing object must fail")
	}
	if _, err := r.Open(ctx, "/abs"); err == nil {
		t.Fatal("invalid path must fail")
	}
}

func TestS3ReaderHonoursContext(t *testing.T) {
	f := newFakeS3(t, "bkt", "k", readerPayload(1000))
	s, err := blob.OpenS3(blob.S3Target{Name: "s3", Bucket: "bkt", EndpointOverride: f.srv.URL, PathStyle: true,
		AccessKeyID: "ak", SecretKey: "sk"}, blob.StorageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	o, err := s.Open(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	cancel()
	if _, err := o.ReadAt(make([]byte, 10), 0); err == nil {
		t.Fatal("ReadAt after cancel must fail")
	}
}
