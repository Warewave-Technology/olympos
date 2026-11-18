package security

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestTrivyIntegration runs the real trivy binary against a tiny public
// image. Opt-in: OLYMPOS_TRIVY_IT=1 (needs network; downloads the trivy DB
// unless OLYMPOS_TRIVY_CACHE points at a warm cache).
func TestTrivyIntegration(t *testing.T) {
	if os.Getenv("OLYMPOS_TRIVY_IT") != "1" {
		t.Skip("set OLYMPOS_TRIVY_IT=1 to run")
	}
	bin, err := exec.LookPath("trivy")
	if err != nil {
		t.Skip("trivy not installed")
	}
	cache := os.Getenv("OLYMPOS_TRIVY_CACHE")
	if cache == "" {
		cache = t.TempDir()
	}
	r := &TrivyCLI{Bin: bin, CacheDir: cache, DBRepo: os.Getenv("OLYMPOS_TRIVY_DB_REPO"), Timeout: 10 * time.Minute}
	ctx := context.Background()
	if at, ok := r.DBUpdatedAt(); !ok || time.Since(at) > 24*time.Hour {
		if err := r.UpdateDB(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := r.DBUpdatedAt(); !ok {
		t.Fatal("no DB metadata after update")
	}
	// alpine:3.10 is end-of-life and has known vulnerabilities.
	out, err := r.Scan(ctx, "docker.io/library/alpine:3.10", nil)
	if err != nil {
		t.Fatal(err)
	}
	vulns, err := ParseTrivy(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities in alpine:3.10")
	}
	t.Logf("%d vulnerabilities, first %+v", len(vulns), vulns[0])

	// A private/nonexistent image without credentials fails with a ScanError.
	_, err = r.Scan(ctx, "ghcr.io/warewave-technology/olympos-does-not-exist@sha256:"+
		"0000000000000000000000000000000000000000000000000000000000000000", nil)
	var se *ScanError
	if !errors.As(err, &se) {
		t.Fatalf("want ScanError, got %v", err)
	}
	t.Logf("private image: auth=%v msg=%s", se.Auth, se.Msg)
}
