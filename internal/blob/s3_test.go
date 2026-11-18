package blob_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testutil.StopMinIO()
	os.Exit(code)
}

// rootClient is a MinIO admin client (test setup only).
func rootClient(t *testing.T, s *testutil.MinIOServer) *minio.Client {
	t.Helper()
	c, err := minio.New(s.HostPort, &minio.Options{Creds: credentials.NewStaticV4(s.RootUser, s.RootPassword, ""), BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newBucket(t *testing.T, s *testutil.MinIOServer) string {
	t.Helper()
	name := "b-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if err := rootClient(t, s).MakeBucket(context.Background(), name, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return name
}

// slowReader returns small chunks so the uploader sees a real stream of
// unknown length.
type slowReader struct{ r io.Reader }

func (s slowReader) Read(p []byte) (int, error) {
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	return s.r.Read(p)
}

func TestS3Writer(t *testing.T) {
	srv := testutil.MinIO(t)
	ctx := context.Background()
	bucket := newBucket(t, srv)
	ak, sk := srv.MinIOUser(t, "writer-"+bucket[2:10], testutil.NoDeleteS3Policy(bucket))
	opts := blob.StorageOptions{S3PartSize: 5 << 20}
	w, err := blob.OpenS3(blob.S3Target{Name: "s3", Bucket: bucket, Prefix: "/pfx/", EndpointOverride: srv.Endpoint, PathStyle: true,
		AccessKeyID: ak, SecretKey: sk}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if w.Prefix() != "pfx" {
		t.Fatal(w.Prefix())
	}
	if err := w.CheckBucket(ctx); err != nil {
		t.Fatal(err)
	}

	// 21 MiB of random data through a pipe: multipart with 5 MiB parts.
	payload := make([]byte, 21<<20+12345)
	_, _ = rand.Read(payload)
	sum := sha256.Sum256(payload)
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, slowReader{bytes.NewReader(payload)})
		_ = pw.CloseWithError(err)
	}()
	key := blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/18/run.tar")
	res, err := w.Upload(ctx, key, pr, "application/x-tar", map[string]string{"olympos-tier": "weekly"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != int64(len(payload)) || res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("result %+v", res)
	}
	rc := rootClient(t, srv)
	obj, err := rc.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	n, err := io.Copy(h, obj)
	obj.Close()
	if err != nil || n != int64(len(payload)) || hex.EncodeToString(h.Sum(nil)) != res.SHA256 {
		t.Fatalf("stored object: %d %v", n, err)
	}
	st, err := rc.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if err != nil || st.ContentType != "application/x-tar" {
		t.Fatalf("stat: %+v %v", st.ContentType, err)
	}
	if !strings.Contains(st.ETag, "-") {
		t.Fatalf("expected a multipart ETag, got %q", st.ETag)
	}
	if tags, err := w.GetTags(ctx, key); err != nil || tags["olympos-tier"] != "weekly" {
		t.Fatalf("tags: %v %v", tags, err)
	}

	// Small upload (single PUT with If-None-Match) with tags.
	mkey := blob.Join(w.Prefix(), "prod/db/orders/clickhouse/2026/11/18/run.manifest.json")
	if _, err := w.Upload(ctx, mkey, strings.NewReader(`{"ok":true}`), "application/json", map[string]string{"olympos-tier": "weekly"}); err != nil {
		t.Fatal(err)
	}
	if b, err := w.Download(ctx, mkey, 100); err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("download: %q %v", b, err)
	}
	if tags, _ := w.GetTags(ctx, mkey); tags["olympos-tier"] != "weekly" {
		t.Fatal("manifest tags")
	}

	// Overwrite refused for small and large uploads; the object is intact.
	if _, err := w.Upload(ctx, mkey, strings.NewReader("evil"), "", nil); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("overwrite small: %v", err)
	}
	if _, err := w.Upload(ctx, key, bytes.NewReader(payload[:9<<20]), "", nil); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("overwrite large: %v", err)
	}
	if b, _ := w.Download(ctx, mkey, 100); string(b) != `{"ok":true}` {
		t.Fatal("object overwritten")
	}

	// Delete: only probe keys, refused by the policy for the writer user.
	if _, err := w.ProbeDeleteRefused(ctx, key); err == nil {
		t.Fatal("delete of a backup must be refused by the code")
	}
	probe := blob.Join(w.Prefix(), blob.ProbeDir, uuid.NewString())
	if _, err := w.Upload(ctx, probe, strings.NewReader("p"), "text/plain", nil); err != nil {
		t.Fatal(err)
	}
	if refused, err := w.ProbeDeleteRefused(ctx, probe); err != nil || !refused {
		t.Fatalf("writer delete: %v %v", refused, err)
	}
	root, err := blob.OpenS3(blob.S3Target{Bucket: bucket, EndpointOverride: srv.Endpoint, PathStyle: true,
		AccessKeyID: srv.RootUser, SecretKey: srv.RootPassword}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if refused, err := root.ProbeDeleteRefused(ctx, probe); err != nil || refused {
		t.Fatalf("root delete: %v %v", refused, err)
	}

	// Wrong secret / missing bucket: clear errors without the secret.
	bad, _ := blob.OpenS3(blob.S3Target{Bucket: bucket, EndpointOverride: srv.Endpoint, PathStyle: true, AccessKeyID: ak, SecretKey: "WRONG-SECRET-123"}, opts)
	if err := bad.CheckBucket(ctx); err == nil || strings.Contains(err.Error(), "WRONG-SECRET-123") {
		t.Fatalf("bad secret: %v", err)
	}
	missing, _ := blob.OpenS3(blob.S3Target{Bucket: "no-such-bucket-x", EndpointOverride: srv.Endpoint, PathStyle: true,
		AccessKeyID: srv.RootUser, SecretKey: srv.RootPassword}, opts)
	if err := missing.CheckBucket(ctx); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing bucket: %v", err)
	}
}

// recorder sends every request to MinIO and records Host and path.
type recorder struct {
	mu    sync.Mutex
	hosts []string
	paths []string
	rt    http.RoundTripper
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Host)
	r.paths = append(r.paths, req.URL.Path)
	r.mu.Unlock()
	return r.rt.RoundTrip(req)
}

func TestS3AddressingStyles(t *testing.T) {
	srv := testutil.MinIO(t)
	ctx := context.Background()
	bucket := newBucket(t, srv)
	_, port, _ := net.SplitHostPort(srv.HostPort)
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, srv.HostPort)
	}
	for _, pathStyle := range []bool{true, false} {
		rec := &recorder{rt: &http.Transport{DialContext: dial}}
		w, err := blob.OpenS3(blob.S3Target{Bucket: bucket, EndpointOverride: "http://" + testutil.MinIODomain + ":" + port, PathStyle: pathStyle,
			AccessKeyID: srv.RootUser, SecretKey: srv.RootPassword}, blob.StorageOptions{Transport: rec})
		if err != nil {
			t.Fatal(err)
		}
		key := "style/" + uuid.NewString()
		if _, err := w.Upload(ctx, key, strings.NewReader("x"), "", map[string]string{"a": "b"}); err != nil {
			t.Fatalf("path_style=%v: %v", pathStyle, err)
		}
		wantHost := testutil.MinIODomain + ":" + port
		wantPath := "/" + bucket + "/" + key
		if !pathStyle {
			wantHost = bucket + "." + testutil.MinIODomain + ":" + port
			wantPath = "/" + key
		}
		last := len(rec.hosts) - 1
		if rec.hosts[last] != wantHost || rec.paths[last] != wantPath {
			t.Fatalf("path_style=%v: request to %s%s, want %s%s", pathStyle, rec.hosts[last], rec.paths[last], wantHost, wantPath)
		}
	}
	// AWS default endpoint.
	if ep := (blob.S3Target{Region: "eu-central-1"}).S3Endpoint(); ep != "https://s3.eu-central-1.amazonaws.com" {
		t.Fatal(ep)
	}
	if ep := (blob.S3Target{}).S3Endpoint(); ep != "https://s3.us-east-1.amazonaws.com" {
		t.Fatal(ep)
	}
	if _, err := blob.OpenS3(blob.S3Target{Bucket: "b", EndpointOverride: "https://minio.example/sub", AccessKeyID: "a", SecretKey: "s"}, blob.StorageOptions{}); err == nil {
		t.Fatal("endpoint with a path")
	}
	if _, err := (blob.StorageOptions{CABundleFile: "/nonexistent.pem"}).S3Transport(); err == nil {
		t.Fatal("missing CA bundle")
	}
}
