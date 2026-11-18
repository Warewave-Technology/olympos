//go:build e2e

package e2e

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// TestM6SelfBackupRestore (F17) runs on the chart's bundled PostgreSQL: the
// built-in olympos-self job is configured, dumps the Olympos database to
// Azurite, and docs/restore-olympos.md is followed: restore the dump into a
// new database, point the server at it with the same key vault, sign in and
// find the data as of the dump. Runs last: it restarts the server.
func TestM6SelfBackupRestore(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")

	// The chart runs the bundled PostgreSQL, reachable only by the server.
	run(t, "kubectl", "-n", "olympos", "get", "statefulset/olympos-postgresql", "networkpolicy/olympos-postgresql", "secret/olympos-postgresql")

	var dash struct {
		Attention []struct{ Kind string } `json:"attention"`
	}
	var self backup.SelfView
	admin.must("GET", "/backup/self", nil, &self, 200)
	if !self.Configured {
		admin.must("GET", "/dashboard", nil, &dash, 200)
		if !hasKind(dash.Attention, "self_backup_unset") {
			t.Fatalf("Needs attention must ask for the self-backup destination: %+v", dash.Attention)
		}
	}
	var dests struct {
		Items []map[string]any `json:"items"`
	}
	admin.must("GET", "/destinations", nil, &dests, 200)
	destID := ""
	for _, d := range dests.Items {
		if d["name"] == "lab-azurite" {
			destID, _ = d["id"].(string)
		}
	}
	if destID == "" {
		t.Skip("needs the lab-azurite destination (TestM2BackupsPostgresAndClickHouse)")
	}
	admin.must("PUT", "/backup/self", map[string]any{"destination_id": destID}, &self, 200)
	if !self.Configured || self.Job == nil || self.Job.DestinationName != "lab-azurite" {
		t.Fatalf("self job: %+v", self)
	}
	admin.must("GET", "/dashboard", nil, &dash, 200)
	if hasKind(dash.Attention, "self_backup_unset") {
		t.Fatal("still needs attention after the destination was set")
	}
	// The job is built in: the generic job API neither lists nor deletes it.
	if code, _ := admin.do("DELETE", "/backup/jobs/"+self.Job.ID.String(), nil, nil); code != 404 {
		t.Fatalf("delete olympos-self: %d", code)
	}

	// Marker before the dump, then the dump, then a marker after it.
	setMarker(t, admin, "before")
	admin.must("POST", "/backup/self/run", nil, nil, 202)
	var done *backup.Run
	eventually(t, 3*time.Minute, "olympos-self run", func() (bool, string) {
		admin.must("GET", "/backup/self", nil, &self, 200)
		if len(self.Runs) > 0 && (self.Runs[0].Status == "succeeded" || self.Runs[0].Status == "failed") {
			done = self.Runs[0]
			return true, ""
		}
		return false, fmt.Sprintf("%d runs", len(self.Runs))
	})
	if done.Status != "succeeded" {
		t.Fatalf("olympos-self failed: %s", done.Error)
	}
	setMarker(t, admin, "after")

	// docs/restore-olympos.md §1: download and verify the dump.
	azPort := portForward(t, "olympos", "azurite", 10000)
	cred, _ := azblob.NewSharedKeyCredential(azAccount, azKey)
	az, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("http://127.0.0.1:%d/%s", azPort, azAccount), cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(done.BlobPath, "/olympos/olympos/olympos-db/postgresql/") {
		t.Fatalf("blob path: %s", done.BlobPath)
	}
	zb := download(t, az, done.BlobPath)
	if sum := sha256.Sum256(zb); hex.EncodeToString(sum[:]) != done.SHA256 {
		t.Fatal("sha256 of the dump does not match the run")
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "olympos.dump" {
		t.Fatalf("dump zip: %v", err)
	}
	rc, _ := zr.File[0].Open()
	dump, _ := io.ReadAll(rc)
	rc.Close()

	// §2–3: restore into a new database and point the server at it.
	run(t, "kubectl", "-n", "olympos", "scale", "deploy/olympos", "--replicas=0")
	run(t, "kubectl", "-n", "olympos", "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/name=olympos-server", "--timeout=120s")
	psql := func(sql string) {
		run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--", "psql", "-U", "olympos", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql)
	}
	psql("DROP DATABASE IF EXISTS olympos_restored")
	psql("DROP DATABASE IF EXISTS olympos_before_restore")
	psql("CREATE DATABASE olympos_restored")
	restore := exec.Command("kubectl", "-n", "olympos", "exec", "-i", "statefulset/olympos-postgresql", "--",
		"pg_restore", "-U", "olympos", "-d", "olympos_restored", "--no-owner", "--exit-on-error")
	restore.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig(t))
	restore.Stdin = bytes.NewReader(dump)
	if out, err := restore.CombinedOutput(); err != nil {
		t.Fatalf("pg_restore: %v\n%s", err, out)
	}
	psql("ALTER DATABASE olympos RENAME TO olympos_before_restore")
	psql("ALTER DATABASE olympos_restored RENAME TO olympos")
	run(t, "kubectl", "-n", "olympos", "scale", "deploy/olympos", "--replicas=1")
	run(t, "kubectl", "-n", "olympos", "rollout", "status", "deploy/olympos", "--timeout=180s")

	// §4: sign in, data as of the dump (same key vault: the CA opens).
	admin = login(t, devAdminOID, "Lab Admin")
	if got := marker(t, admin); got != "before" {
		t.Fatalf("restored marker %q, want the value at dump time", got)
	}
	admin.must("GET", "/backup/self", nil, &self, 200)
	if !self.Configured {
		t.Fatal("self job missing after restore")
	}
	eventually(t, 2*time.Minute, "lab agent reconnects to the restored server", func() (bool, string) {
		var c map[string]any
		admin.must("GET", "/clusters/"+labClusterID, nil, &c, 200)
		return c["status"] == "online", fmt.Sprint(c["status"])
	})
	psql("DROP DATABASE olympos_before_restore")
	setMarker(t, admin, "")
}

func hasKind(items []struct{ Kind string }, kind string) bool {
	for _, a := range items {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// The marker is a label on the lab cluster ("" removes it).
func setMarker(t *testing.T, c *client, v string) {
	t.Helper()
	var cl map[string]any
	c.must("GET", "/clusters/"+labClusterID, nil, &cl, 200)
	labels := map[string]string{}
	if m, ok := cl["labels"].(map[string]any); ok {
		for k, x := range m {
			if !strings.HasPrefix(k, "olympos.io/") {
				labels[k] = fmt.Sprint(x)
			}
		}
	}
	if v == "" {
		delete(labels, "f17-marker")
	} else {
		labels["f17-marker"] = v
	}
	c.must("PATCH", "/clusters/"+labClusterID, map[string]any{"labels": labels}, nil, 200)
}

func marker(t *testing.T, c *client) string {
	t.Helper()
	var cl map[string]any
	c.must("GET", "/clusters/"+labClusterID, nil, &cl, 200)
	m, _ := cl["labels"].(map[string]any)
	return fmt.Sprint(m["f17-marker"])
}
