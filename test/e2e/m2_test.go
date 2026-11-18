//go:build e2e

package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/inventory"
)

// Azurite's well-known development account.
const (
	azAccount   = "devstoreaccount1"
	azKey       = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	azInCluster = "http://azurite.olympos.svc:10000/devstoreaccount1"
)

// portForward forwards a local port to a Service in the lab.
func portForward(t *testing.T, ns, svc string, port int) int {
	t.Helper()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	local := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command("kubectl", "-n", ns, "port-forward", "svc/"+svc, fmt.Sprintf("%d:%d", local, port))
	cmd.Env = append(cmd.Environ(), "KUBECONFIG="+kubeconfig(t))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 30*time.Second, "port-forward "+svc, func() (bool, string) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", local), time.Second)
		if err != nil {
			return false, err.Error()
		}
		c.Close()
		return true, ""
	})
	return local
}

func labTarget(t *testing.T, c *client, service string) inventory.Target {
	t.Helper()
	var ts struct{ Items []inventory.Target }
	c.must("GET", "/targets", nil, &ts, 200)
	for _, tg := range ts.Items {
		if tg.Service == service && tg.ClusterID.String() == labClusterID && tg.Status != "gone" {
			return tg
		}
	}
	t.Fatalf("target %s not found", service)
	return inventory.Target{}
}

func waitRun(t *testing.T, c *client, jobID string, after time.Time, trigger string) backup.Run {
	t.Helper()
	var run backup.Run
	eventually(t, 5*time.Minute, trigger+" run of "+jobID, func() (bool, string) {
		var rs struct{ Items []backup.Run }
		c.must("GET", "/backup/runs?job_id="+jobID, nil, &rs, 200)
		for _, r := range rs.Items {
			if r.Trigger == trigger && r.CreatedAt.After(after.Add(-2*time.Minute)) && (r.Status == "succeeded" || r.Status == "failed") {
				run = r
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d runs", len(rs.Items))
	})
	if run.Status != "succeeded" {
		t.Fatalf("%s run failed: %s", trigger, run.Error)
	}
	return run
}

// TestM2BackupsPostgresAndClickHouse configures an Azurite destination with a
// container SAS (r c w t, no delete), then backs up the TLS PostgreSQL and the
// plaintext ClickHouse target through the real agent tunnel.
func TestM2BackupsPostgresAndClickHouse(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	ctx := context.Background()

	// Prepare the container and a container SAS from the host.
	azPort := portForward(t, "olympos", "azurite", 10000)
	cred, _ := azblob.NewSharedKeyCredential(azAccount, azKey)
	svcURL := fmt.Sprintf("http://127.0.0.1:%d/%s", azPort, azAccount)
	az, err := azblob.NewClientWithSharedKeyCredential(svcURL, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := az.CreateContainer(ctx, "backups", nil); err != nil && !strings.Contains(err.Error(), "ContainerAlreadyExists") {
		t.Fatalf("create container: %v", err)
	}
	q, err := sas.BlobSignatureValues{
		Protocol: sas.ProtocolHTTPSandHTTP, ExpiryTime: time.Now().Add(30 * 24 * time.Hour), ContainerName: "backups",
		Permissions: (&sas.ContainerPermissions{Read: true, Create: true, Write: true, Tag: true}).String(),
	}.SignWithSharedKey(cred)
	if err != nil {
		t.Fatal(err)
	}

	var dests struct {
		Items []map[string]any `json:"items"`
	}
	admin.must("GET", "/destinations", nil, &dests, 200)
	destID := ""
	for _, d := range dests.Items {
		if d["name"] == "lab-azurite" {
			destID = d["id"].(string)
		}
	}
	if destID == "" {
		var d map[string]any
		code, raw := admin.do("POST", "/destinations", map[string]any{
			"name": "lab-azurite", "account": azAccount, "container": "backups", "prefix": "olympos",
			"auth": "sas_token", "sas": map[string]any{"source": "stored", "value": q.Encode()}, "endpoint_override": azInCluster,
		}, &d)
		if code != 201 {
			t.Fatalf("create destination: %d %s", code, raw)
		}
		if strings.Contains(raw, q.Signature()) {
			t.Fatal("SAS signature returned by the API")
		}
		lt, _ := d["last_test"].(map[string]any)
		if lt["can_delete"] != false || lt["ok"] != true {
			t.Fatalf("destination test: %v", lt)
		}
		destID = d["id"].(string)
	}

	// --- PostgreSQL (TLS verify-full against the lab CA, via targetTLS) ---
	pg := labTarget(t, admin, "orders-pg")
	pgCred := map[string]any{"source": "stored", "username": "backup", "password": "CANARY-lab-pg-password"}
	var ct backup.ConnectionTest
	admin.must("POST", "/backup/test-connection", map[string]any{"target_id": pg.ID, "credential": pgCred}, &ct, 200)
	if !ct.OK || !ct.TLS || !strings.HasPrefix(ct.ServerVersion, "16") {
		t.Fatalf("pg test-connection: %+v", ct)
	}
	pgJob := ensureJob(t, admin, pg.ID, destID, pgCred, map[string]any{"databases": []string{"orders"}})

	start := time.Now()
	admin.must("POST", "/backup/jobs/"+pgJob+"/run", map[string]any{"trigger": "test"}, nil, 202)
	dry := waitRun(t, admin, pgJob, start, "test")
	if dry.Tier != "test" {
		t.Errorf("dry run tier %q", dry.Tier)
	}
	admin.must("PATCH", "/backup/jobs/"+pgJob, map[string]any{"enabled": true}, nil, 200)
	start = time.Now()
	admin.must("POST", "/backup/jobs/"+pgJob+"/run", map[string]any{"trigger": "manual"}, nil, 202)
	pgRun := waitRun(t, admin, pgJob, start, "manual")
	if pgRun.WireBytes == 0 || pgRun.Bytes == 0 || len(pgRun.SHA256) != 64 {
		t.Fatalf("run accounting: %+v", pgRun)
	}
	wantPrefix := "olympos/lab/lab/orders-pg/postgresql/"
	if !strings.HasPrefix(pgRun.BlobPath, wantPrefix) || !strings.HasSuffix(pgRun.BlobPath, pgRun.ID.String()+".zip") {
		t.Fatalf("blob path %q", pgRun.BlobPath)
	}
	body := download(t, az, pgRun.BlobPath)
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["globals.sql"] || !names["orders.dump"] {
		t.Fatalf("zip entries: %v", names)
	}
	var man map[string]any
	if err := json.Unmarshal(download(t, az, strings.TrimSuffix(pgRun.BlobPath, ".zip")+".manifest.json"), &man); err != nil {
		t.Fatal(err)
	}
	if mb, _ := man["blob"].(map[string]any); mb["sha256"] != pgRun.SHA256 || man["engine"] != "postgresql" {
		t.Fatalf("manifest %v does not match run sha256 %s", man, pgRun.SHA256)
	}
	tags, err := az.ServiceClient().NewContainerClient("backups").NewBlobClient(pgRun.BlobPath).GetTags(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	tier := ""
	for _, tg := range tags.BlobTagSet {
		if *tg.Key == "olympos-tier" {
			tier = *tg.Value
		}
	}
	if tier != pgRun.Tier || tier == "" {
		t.Fatalf("olympos-tier tag %q, run tier %q", tier, pgRun.Tier)
	}

	// --- ClickHouse (no TLS on the target: allowed, tls.missing finding) ---
	ch := labTarget(t, admin, "metrics-ch")
	chCred := map[string]any{"source": "stored", "username": "backup", "password": "CANARY-lab-ch-password"}
	runSQL(t, "metrics-ch", "CREATE DATABASE IF NOT EXISTS metrics")
	runSQL(t, "metrics-ch", "CREATE TABLE IF NOT EXISTS metrics.events (d Date, v UInt64) ENGINE = MergeTree PARTITION BY toYYYYMM(d) ORDER BY d")
	runSQL(t, "metrics-ch", "INSERT INTO metrics.events SELECT toDate('2026-10-01') + number % 60, number FROM numbers(10000)")
	chJob := ensureJob(t, admin, ch.ID, destID, chCred, map[string]any{"databases": []string{"metrics"}})
	start = time.Now()
	admin.must("POST", "/backup/jobs/"+chJob+"/run", map[string]any{"trigger": "manual"}, nil, 202)
	chRun := waitRun(t, admin, chJob, start, "manual")
	chZip := download(t, az, chRun.BlobPath)
	zr, err = zip.NewReader(bytes.NewReader(chZip), int64(len(chZip)))
	if err != nil {
		t.Fatal(err)
	}
	natives := 0
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "data/metrics/events/") && strings.HasSuffix(f.Name, ".native") {
			natives++
		}
	}
	if natives < 2 {
		t.Fatalf("expected one Native entry per partition, got %d", natives)
	}
	var fs struct{ Items []map[string]any }
	admin.must("GET", "/findings?source=tls&status=open", nil, &fs, 200)
	found := false
	for _, f := range fs.Items {
		if strings.Contains(fmt.Sprint(f["resource_ref"]), "metrics-ch") || strings.Contains(fmt.Sprint(f["title"]), "metrics-ch") {
			found = true
		}
	}
	if !found {
		t.Errorf("tls.missing finding for metrics-ch not found: %v", fs.Items)
	}

	// Credentials never appear in API output or server logs.
	var j map[string]any
	_, raw := admin.do("GET", "/backup/jobs/"+pgJob, nil, &j)
	if strings.Contains(raw, "CANARY") {
		t.Fatal("password in job response")
	}
	logs := run(t, "kubectl", "-n", "olympos", "logs", "deploy/olympos", "--tail=-1")
	for _, canary := range []string{"CANARY-lab-pg-password", "CANARY-lab-ch-password", q.Signature()} {
		if strings.Contains(logs, canary) {
			t.Fatalf("secret %q found in server logs", canary[:12])
		}
	}
}

func ensureJob(t *testing.T, c *client, targetID, destID string, cred, opts map[string]any) string {
	t.Helper()
	var jobs struct{ Items []backup.Job }
	c.must("GET", "/backup/jobs", nil, &jobs, 200)
	for _, j := range jobs.Items {
		if j.Target.ID == targetID {
			return j.ID.String()
		}
	}
	var j backup.Job
	c.must("POST", "/backup/jobs", map[string]any{
		"target_id": targetID, "credential": cred, "destination_id": destID, "engine_options": opts,
		"cron": "0 2 * * *", "timezone": "Europe/Istanbul", "enabled": false,
	}, &j, 201)
	return j.ID.String()
}

func download(t *testing.T, az *azblob.Client, path string) []byte {
	t.Helper()
	r, err := az.DownloadStream(context.Background(), "backups", path, nil)
	if err != nil {
		t.Fatalf("download %s: %v", path, err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return b
}

func runSQL(t *testing.T, deploy, sql string) {
	t.Helper()
	run(t, "kubectl", "-n", "lab", "exec", "deploy/"+deploy, "--", "clickhouse-client", "--user", "backup",
		"--password", "CANARY-lab-ch-password", "--query", sql)
}
