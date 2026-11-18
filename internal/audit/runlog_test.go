package audit

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// jwtCanary is the signature-bearing token in the kubescape fixture.
const jwtCanary = "eyJzdWIiOiJsb2ctY2FuYXJ5In0"

func kubescapeFailureLog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/kubescape-failure.log")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestShortReason(t *testing.T) {
	ks := kubescapeFailureLog(t)
	cases := []struct{ name, in, want string }{
		{"cobra Error line wins", ks, "framework 'cis-v1.23-t1.0.1' not found"},
		{"last error-level JSON line", strings.Replace(ks, "Error: framework 'cis-v1.23-t1.0.1' not found\n", "", 1),
			"failed to download framework: framework 'cis-v1.23-t1.0.1' not found"},
		{"logfmt (polaris/logrus)", `time="2026-11-18T19:20:01Z" level=info msg="Loading config"
time="2026-11-18T19:20:02Z" level=error msg="Error fetching Kubernetes resources: forbidden" kind=Pod
time="2026-11-18T19:20:02Z" level=info msg="exiting"`, "Error fetching Kubernetes resources: forbidden"},
		{"ANSI colors stripped", "\x1b[31mError: \x1b[0mboom\n", "boom"},
		{"plain last line", "starting\nsomething broke\n\n", "something broke"},
		{"empty", "  \n", ""},
		{"redacted", "Error: Unauthorized token=s3cr3t-value", "Unauthorized token=[REDACTED]"},
	}
	for _, c := range cases {
		if got := ShortReason(c.in); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if r := ShortReason("Error: " + strings.Repeat("x", 1000)); len([]rune(r)) > maxReasonRunes {
		t.Errorf("reason not capped: %d", len(r))
	}
}

func TestExecToolSplitsReasonAndLog(t *testing.T) {
	work := t.TempDir()
	fix, _ := filepath.Abs("testdata/kubescape-failure.log")
	// kubescape logs to stderr (and some lines to stdout) and exits 1.
	bin := script(t, `echo '{"level":"info","msg":"to stdout"}'; cat "`+fix+`" >&2; exit 1`)
	_, err := ExecTool(context.Background(), Invocation{Bin: bin, OutputFile: filepath.Join(work, "kubescape.json")}, work)
	var te *ToolError
	if !errors.As(err, &te) {
		t.Fatalf("err = %T %v", err, err)
	}
	if te.Reason != "tool.sh failed: framework 'cis-v1.23-t1.0.1' not found" {
		t.Errorf("reason = %q", te.Reason)
	}
	for _, s := range []string{"to stdout", "Kubescape scanner initializing", "failed to get cloud provider metadata", "Error: framework"} {
		if !strings.Contains(te.Log, s) {
			t.Errorf("log lacks %q", s)
		}
	}
	if red := RedactLog(te.Log); strings.Contains(red, jwtCanary) || !strings.Contains(red, "[REDACTED]") {
		t.Errorf("log not redacted: %s", red)
	}
	// The captured output is capped (the tail is kept).
	big := script(t, `i=0; while [ $i -lt 6000 ]; do echo "line $i ................................................"; i=$((i+1)); done >&2; echo "Error: last words" >&2; exit 2`)
	_, err = ExecTool(context.Background(), Invocation{Bin: big, OutputFile: filepath.Join(work, "x.json")}, work)
	if !errors.As(err, &te) || len(te.Log) > MaxLogBytes || !strings.HasSuffix(strings.TrimSpace(te.Log), "Error: last words") ||
		!strings.HasSuffix(te.Reason, "last words") {
		t.Fatalf("cap: len=%d reason=%q", len(te.Log), te.Reason)
	}
	if got := RedactLog("a\x00b\xffc"); got != "abc" {
		t.Errorf("RedactLog = %q", got)
	}
}

// A failed kubescape run stores a short error and the full (redacted) output
// in log; the log is returned by the run detail only.
func TestFailedRunErrorAndLog(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	gw := newFakeGW()
	c := addCluster(t, db, "prod-1", map[string]string{"env": "prod"}, "azure", "online", false)
	gw.connected[c] = true
	sched := addSchedule(t, db, ToolKubescape, "all", "0 3 * * *", nil)
	ks := kubescapeFailureLog(t)
	svc := &Service{DB: db, Log: quietLog(), Gateway: gw, KubescapeBin: "kubescape",
		Exec: func(context.Context, Invocation, string) ([]byte, error) {
			return nil, &ToolError{Reason: "kubescape failed: " + ShortReason(ks), Log: ks}
		}}
	svc.ksFws = []string{"nsa", "mitre"}
	r := addRunningRun(t, db, sched, ToolKubescape, c)
	if err := svc.Execute(ctx, r); err != nil {
		t.Fatal(err)
	}
	run, err := GetRun(ctx, db, r)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "failed" || run.Error != "kubescape failed: framework 'cis-v1.23-t1.0.1' not found" {
		t.Fatalf("run = %s %q", run.Status, run.Error)
	}
	if run.Log == nil || !strings.Contains(*run.Log, "Kubescape scanner initializing") || !strings.Contains(*run.Log, "Error: framework") ||
		strings.Contains(*run.Log, jwtCanary) {
		t.Fatalf("log = %v", run.Log)
	}

	// API: the list has no log, the detail has it.
	a := newAPIEnv(t)
	cl, other := a.prod, a.dev
	var id, devRun uuid.UUID
	if err := a.e.DB.QueryRow(ctx, `INSERT INTO audit_runs (tool, cluster_id, status, error, log) VALUES ('kubescape', $1, 'failed', 'short', 'full output') RETURNING id`, cl).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := a.e.DB.QueryRow(ctx, `INSERT INTO audit_runs (tool, cluster_id, status, log) VALUES ('polaris', $1, 'failed', 'dev output') RETURNING id`, other).Scan(&devRun); err != nil {
		t.Fatal(err)
	}
	viewer := a.e.Login(a.e.Principal("vic", "Member", "viewer@env=prod"))
	code, body := viewer.Raw("GET", "/api/v1/audit/runs", nil)
	if code != http.StatusOK || strings.Contains(string(body), "full output") || strings.Contains(string(body), `"log"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	var detail Run
	if code := viewer.Do("GET", "/api/v1/audit/runs/"+id.String(), nil, &detail); code != http.StatusOK || detail.Log == nil ||
		*detail.Log != "full output" || detail.Error != "short" {
		t.Fatalf("detail: %d %+v", code, detail)
	}
	if code, _ := viewer.Raw("GET", "/api/v1/audit/runs/"+devRun.String(), nil); code != http.StatusNotFound {
		t.Fatalf("out-of-scope run detail: %d", code)
	}
}
