package testutil

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// MinIO in Docker for S3 tests (container olympos-s3-minio-<package> on a
// random loopback port; one per test binary so that packages can run in
// parallel). Skipped when Docker is unavailable unless
// OLYMPOS_REQUIRE_DOCKER=1. Call StopMinIO from TestMain.
const (
	MinIOContainerPrefix = "olympos-s3-minio"
	MinIOImage           = "cgr.dev/chainguard/minio:latest"
	MinIOMCImage         = "cgr.dev/chainguard/minio-client:latest"
	MinIORootUser        = "olympos-root"
	// MinIODomain enables virtual-hosted-style requests (<bucket>.<domain>).
	MinIODomain = "minio.localhost"
)

// MinIOServer is a running MinIO.
type MinIOServer struct {
	HostPort     string // 127.0.0.1:<port>
	Endpoint     string // http://127.0.0.1:<port>
	RootUser     string
	RootPassword string
}

// MinIOContainer is this test binary's container name.
var MinIOContainer = func() string {
	wd, _ := os.Getwd()
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(filepath.Base(wd)))
	return MinIOContainerPrefix + "-" + name
}()

var (
	minioOnce    sync.Once
	minioSrv     *MinIOServer
	minioErr     error
	minioStarted bool
)

// MinIO starts (once per test binary) and returns the MinIO server.
func MinIO(t testing.TB) *MinIOServer {
	t.Helper()
	minioOnce.Do(func() { minioSrv, minioErr = startMinIO() })
	if minioErr != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("minio: %v", minioErr)
		}
		t.Skipf("minio unavailable: %v", minioErr)
	}
	return minioSrv
}

// StopMinIO removes the container if this binary started it.
func StopMinIO() {
	if minioStarted {
		_ = exec.Command("docker", "rm", "-f", "-v", MinIOContainer).Run()
	}
}

func startMinIO() (*MinIOServer, error) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		return nil, fmt.Errorf("docker not available: %w", err)
	}
	_ = exec.Command("docker", "rm", "-f", "-v", MinIOContainer).Run()
	pw := fmt.Sprintf("pw-%d-olympos", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--name", MinIOContainer, "-p", "127.0.0.1::9000",
		"-e", "MINIO_ROOT_USER="+MinIORootUser, "-e", "MINIO_ROOT_PASSWORD="+pw, "-e", "MINIO_DOMAIN="+MinIODomain,
		MinIOImage, "server", "/data").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run: %v: %s", err, out)
	}
	minioStarted = true
	out, err = exec.Command("docker", "port", MinIOContainer, "9000/tcp").Output()
	if err != nil {
		return nil, fmt.Errorf("docker port: %w", err)
	}
	hp := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
	s := &MinIOServer{HostPort: hp, Endpoint: "http://" + hp, RootUser: MinIORootUser, RootPassword: pw}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.Endpoint + "/minio/health/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", MinIOContainer).CombinedOutput()
	return nil, fmt.Errorf("minio did not become ready at %s: %s", s.Endpoint, logs)
}

// MC runs the MinIO client (in its own container sharing MinIO's network
// namespace) against alias "local" with root credentials. files are written
// to a temp dir mounted at /work.
func (s *MinIOServer) MC(t testing.TB, files map[string]string, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	full := append([]string{"run", "--rm", "--network", "container:" + MinIOContainer, "-v", dir + ":/work",
		"-e", "MC_HOST_local=http://" + s.RootUser + ":" + s.RootPassword + "@127.0.0.1:9000", MinIOMCImage}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("mc %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// MinIOUser creates a user whose only policy is policyJSON and returns its
// access key and secret key.
func (s *MinIOServer) MinIOUser(t testing.TB, name, policyJSON string) (string, string) {
	t.Helper()
	secret := fmt.Sprintf("sk-%s-%d", name, time.Now().UnixNano())
	s.MC(t, nil, "admin", "user", "add", "local", name, secret)
	s.MC(t, map[string]string{"p.json": policyJSON}, "admin", "policy", "create", "local", "pol-"+name, "/work/p.json")
	s.MC(t, nil, "admin", "policy", "attach", "local", "pol-"+name, "--user", name)
	return name, secret
}

// NoDeleteS3Policy is the policy Olympos needs on a bucket: write, read,
// tag, list (existence checks) and multipart — no s3:DeleteObject.
func NoDeleteS3Policy(bucket string) string {
	return `{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:ListBucket","s3:GetBucketLocation","s3:ListBucketMultipartUploads"],"Resource":["arn:aws:s3:::` + bucket + `"]},
 {"Effect":"Allow","Action":["s3:PutObject","s3:GetObject","s3:PutObjectTagging","s3:GetObjectTagging","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::` + bucket + `/*"]}]}`
}
