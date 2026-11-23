package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestNoKubernetesAPI fails when the probe binary, or the probe package,
// links anything from Kubernetes: the probe has no RBAC and must never
// talk to the Kubernetes API (docs/design/synthetic-monitoring.md §2.1,
// decision 1). Its identity comes from a mounted Secret instead.
func TestNoKubernetesAPI(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go command not found: %v", err)
	}
	cmd := exec.Command(goBin, "list", "-deps",
		"github.com/Warewave-Technology/olympos/cmd/olympos-probe",
		"github.com/Warewave-Technology/olympos/internal/probe")
	// The target the image ships, whatever the host is.
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 10 {
		t.Fatalf("go list returned too little: %q", out)
	}
	for _, d := range deps {
		if strings.HasPrefix(d, "k8s.io/") || strings.HasPrefix(d, "sigs.k8s.io/") {
			t.Errorf("olympos-probe depends on %s", d)
		}
	}
}

func TestHealth(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()
	if got := health(up.Listener.Addr().String()); got != 0 {
		t.Fatalf("health on a healthy endpoint = %d", got)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	if got := health(failing.Listener.Addr().String()); got != 1 {
		t.Fatalf("health on a failing endpoint = %d", got)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := lis.Addr().String()
	lis.Close()
	if got := health(down); got != 1 {
		t.Fatalf("health with nothing listening = %d", got)
	}
	for _, addr := range []string{"192.0.2.1:8082", "example.com:8082", "nonsense"} {
		if got := health(addr); got != 1 {
			t.Fatalf("health(%q) = %d: only localhost is checked", addr, got)
		}
	}
}

func TestHealthAddrDefault(t *testing.T) {
	t.Setenv("OLYMPOS_HEALTH_ADDR", "")
	if got := healthAddr(); got != "127.0.0.1:8082" {
		t.Fatalf("default health address = %q", got)
	}
	t.Setenv("OLYMPOS_HEALTH_ADDR", "127.0.0.1:9999")
	if got := healthAddr(); got != "127.0.0.1:9999" {
		t.Fatalf("health address = %q", got)
	}
}
