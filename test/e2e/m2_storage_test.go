//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// ensureDestination creates a destination by name unless it exists.
func ensureDestination(t *testing.T, c *client, body map[string]any) map[string]any {
	t.Helper()
	var ds struct {
		Items []map[string]any `json:"items"`
	}
	c.must("GET", "/destinations", nil, &ds, 200)
	for _, d := range ds.Items {
		if d["name"] == body["name"] {
			return d
		}
	}
	var d map[string]any
	code, raw := c.do("POST", "/destinations", body, &d)
	if code != 201 {
		t.Fatalf("create destination %v: %d %s", body["name"], code, raw)
	}
	return d
}

func ensureJobTo(t *testing.T, c *client, targetID, destID string, cred map[string]any) string {
	t.Helper()
	var jobs struct{ Items []backup.JobView }
	c.must("GET", "/backup/jobs", nil, &jobs, 200)
	for _, j := range jobs.Items {
		if j.Target.ID == targetID && j.Destination.ID.String() == destID {
			return j.ID.String()
		}
	}
	var j backup.JobView
	c.must("POST", "/backup/jobs", map[string]any{"target_id": targetID, "credential": cred, "destination_id": destID,
		"engine_options": map[string]any{"databases": []string{"orders"}}, "cron": "0 3 * * *", "timezone": "UTC", "enabled": true}, &j, 201)
	return j.ID.String()
}

// TestM2StorageS3AndNFS backs the TLS PostgreSQL up to an S3-compatible
// endpoint (MinIO, writer user without delete) and to an NFS-style mount.
func TestM2StorageS3AndNFS(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	pg := labTarget(t, admin, "orders-pg")
	cred := map[string]any{"source": "stored", "username": "backup", "password": "CANARY-lab-pg-password"}

	s3 := ensureDestination(t, admin, map[string]any{
		"name": "lab-minio", "kind": "s3", "endpoint_override": "http://minio.olympos.svc:9000", "region": "us-east-1",
		"bucket": "backups", "prefix": "olympos", "path_style": true, "auth": "access_key",
		"access_key_id": "olympos-backup", "secret_key": map[string]any{"source": "stored", "value": "lab-backup-secret-key"},
	})
	if lt, _ := s3["last_test"].(map[string]any); lt != nil && lt["can_delete"] == true {
		t.Fatalf("MinIO writer user must not be able to delete: %v", lt)
	}

	var mounts struct {
		Items []struct {
			Name     string `json:"name"`
			Path     string `json:"path"`
			Writable bool   `json:"writable"`
		} `json:"items"`
	}
	admin.must("GET", "/destinations/mounts", nil, &mounts, 200)
	mountPath := ""
	for _, m := range mounts.Items {
		if m.Name == "lab" && m.Writable {
			mountPath = m.Path
		}
	}
	if mountPath == "" {
		t.Fatalf("lab NFS mount not listed: %+v", mounts.Items)
	}
	nfs := ensureDestination(t, admin, map[string]any{"name": "lab-nfs", "kind": "nfs", "auth": "none", "path": mountPath + "/olympos"})

	for _, d := range []map[string]any{s3, nfs} {
		job := ensureJobTo(t, admin, pg.ID, d["id"].(string), cred)
		r := runAndWait(t, admin, job, "manual")
		if !strings.Contains(r.BlobPath, "/orders-pg/postgresql/") || len(r.SHA256) != 64 || r.Bytes == 0 {
			t.Fatalf("%v run: %+v", d["kind"], r)
		}
	}
	// The object really is in MinIO (listed with the writer user).
	_, _ = runOK(t, "kubectl", "-n", "olympos", "delete", "pod", "mc-e2e-ls", "--ignore-not-found", "--now")
	run(t, "kubectl", "-n", "olympos", "run", "mc-e2e-ls", "--restart=Never",
		"--image=cgr.dev/chainguard/minio-client:latest", "--image-pull-policy=IfNotPresent",
		"--env=MC_HOST_u=http://olympos-backup:lab-backup-secret-key@minio.olympos.svc:9000", "--", "ls", "--recursive", "u/backups/olympos/")
	defer func() { _, _ = runOK(t, "kubectl", "-n", "olympos", "delete", "pod", "mc-e2e-ls", "--now") }()
	run(t, "kubectl", "-n", "olympos", "wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/mc-e2e-ls", "--timeout=90s")
	out := run(t, "kubectl", "-n", "olympos", "logs", "mc-e2e-ls")
	if !strings.Contains(out, ".manifest.json") || !strings.Contains(out, ".zip") {
		t.Fatalf("objects not in MinIO:\n%s", out)
	}
}
