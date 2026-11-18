package audit

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestKubescapeInvocation(t *testing.T) {
	inv, err := KubescapeInvocation("/opt/kubescape", []string{"nsa", "cis", "mitre", "NSA"}, "azure", "/tmp/x/kubeconfig", "/tmp/x")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"scan", "framework", "nsa,cis-aks-t1.2.0,mitre", "--format", "json", "--format-version", "v2",
		"--output", "/tmp/x/kubescape.json", "--keep-local"}
	if inv.Bin != "/opt/kubescape" || !reflect.DeepEqual(inv.Args, want) {
		t.Fatalf("got %s %v", inv.Bin, inv.Args)
	}
	if inv.OutputFile != "/tmp/x/kubescape.json" {
		t.Errorf("output %s", inv.OutputFile)
	}
	if !contains(inv.Env, "KUBECONFIG=/tmp/x/kubeconfig") || !contains(inv.Env, "KS_SKIP_UPDATE_CHECK=true") {
		t.Errorf("env %v", inv.Env)
	}
	for _, a := range inv.Args {
		if strings.Contains(a, "submit") || strings.Contains(a, "account") || strings.Contains(a, "access-key") {
			t.Errorf("upload-related flag %q", a)
		}
	}
	inv, _ = KubescapeInvocation("kubescape", nil, "onprem", "k", "/w")
	if inv.Args[2] != "nsa,cis-v1.23-t1.0.1,mitre" {
		t.Errorf("default frameworks: %v", inv.Args[2])
	}
	inv, _ = KubescapeInvocation("kubescape", []string{"cis"}, "aws", "k", "/w")
	if inv.Args[2] != "cis-eks-t1.2.0" {
		t.Errorf("eks cis: %v", inv.Args[2])
	}
	if _, err := KubescapeInvocation("kubescape", []string{"allcontrols"}, "", "k", "/w"); err == nil {
		t.Error("unknown framework accepted")
	}
}

func TestPolarisInvocation(t *testing.T) {
	inv := PolarisInvocation("polaris", "/w/kubeconfig", "/w")
	want := []string{"audit", "--format", "json", "--output-file", "/w/polaris.json"}
	if !reflect.DeepEqual(inv.Args, want) || !contains(inv.Env, "KUBECONFIG=/w/kubeconfig") {
		t.Fatalf("got %v %v", inv.Args, inv.Env)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func script(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	p := filepath.Join(t.TempDir(), "tool.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecToolReadsOutputDespiteNonZeroExit(t *testing.T) {
	work := t.TempDir()
	bin := script(t, `out=""; while [ $# -gt 0 ]; do [ "$1" = "--output-file" ] && out="$2"; shift; done
test -n "$KUBECONFIG" || exit 9
echo '{"Results":[]}' > "$out"; exit 3`)
	inv := PolarisInvocation(bin, filepath.Join(work, "kubeconfig"), work)
	raw, err := ExecTool(context.Background(), inv, work)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != `{"Results":[]}` {
		t.Fatalf("raw = %q", raw)
	}
}

func TestExecToolFailureIsRedacted(t *testing.T) {
	work := t.TempDir()
	bin := script(t, `echo "error: Unauthorized: Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eXoifQ.c2lnbmF0dXJlc2ln token=s3cr3t-value" >&2; exit 1`)
	_, err := ExecTool(context.Background(), Invocation{Bin: bin, OutputFile: filepath.Join(work, "none.json")}, work)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cr3t-value") || strings.Contains(msg, "eyJzdWIiOiJ4eXoifQ") {
		t.Fatalf("secret leaked: %s", msg)
	}
	if !strings.Contains(msg, "Unauthorized") {
		t.Errorf("context lost: %s", msg)
	}
}

func TestExecToolTimeout(t *testing.T) {
	work := t.TempDir()
	bin := script(t, `exec sleep 30`)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ExecTool(ctx, Invocation{Bin: bin}, work)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestRedact(t *testing.T) {
	in := `Authorization: Bearer abc.def-ghi password=hunter2 "sig":"XYZ123" plain text`
	out := Redact(in)
	for _, s := range []string{"abc.def-ghi", "hunter2", "XYZ123"} {
		if strings.Contains(out, s) {
			t.Errorf("%q not redacted: %s", s, out)
		}
	}
	if !strings.Contains(out, "plain text") {
		t.Errorf("over-redacted: %s", out)
	}
}
