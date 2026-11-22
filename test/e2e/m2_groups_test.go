//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// azuriteSelector points the lab's Azurite Service at its pod, or at nothing:
// without endpoints new connections are refused, and Azurite keeps its data
// (it holds it in memory, so stopping the pod would lose the container).
func azuriteSelector(t *testing.T, app string) {
	t.Helper()
	run(t, "kubectl", "-n", "olympos", "patch", "service", "azurite", "--type", "merge",
		"-p", fmt.Sprintf(`{"spec":{"selector":{"app":%q}}}`, app))
}

// TestM2GroupPartialAndRepair backs the TLS PostgreSQL up to a destination
// group of Azurite and MinIO, makes Azurite unreachable for one run (partial,
// a repair queued, the attention item), puts it back and sees the repair
// write only the missing copy, which the original run's restore guide offers.
func TestM2GroupPartialAndRepair(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")

	azPort := portForward(t, "olympos", "azurite", 10000)
	cred, _ := azblob.NewSharedKeyCredential(azAccount, azKey)
	az, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("http://127.0.0.1:%d/%s", azPort, azAccount), cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := az.CreateContainer(context.Background(), "backups", nil); err != nil && !strings.Contains(err.Error(), "ContainerAlreadyExists") {
		t.Fatalf("create container: %v", err)
	}
	q, err := sas.BlobSignatureValues{
		Protocol: sas.ProtocolHTTPSandHTTP, ExpiryTime: time.Now().Add(30 * 24 * time.Hour), ContainerName: "backups",
		Permissions: (&sas.ContainerPermissions{Read: true, Create: true, Write: true, Tag: true}).String(),
	}.SignWithSharedKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	azDest := ensureDestination(t, admin, map[string]any{
		"name": "e2e-copies-azurite", "account": azAccount, "container": "backups", "prefix": "groups",
		"auth": "sas_token", "sas": map[string]any{"source": "stored", "value": q.Encode()}, "endpoint_override": azInCluster,
	})
	s3Dest := ensureDestination(t, admin, map[string]any{
		"name": "e2e-copies-minio", "kind": "s3", "endpoint_override": "http://minio.olympos.svc:9000", "region": "us-east-1",
		"bucket": "backups", "prefix": "groups", "path_style": true, "auth": "access_key",
		"access_key_id": "olympos-backup", "secret_key": map[string]any{"source": "stored", "value": "lab-backup-secret-key"},
	})
	azID, s3ID := azDest["id"].(string), s3Dest["id"].(string)

	// The same location under another name is not a second copy.
	twin := ensureDestination(t, admin, map[string]any{
		"name": "e2e-copies-azurite-twin", "account": azAccount, "container": "backups", "prefix": "groups",
		"auth": "sas_token", "sas": map[string]any{"source": "stored", "value": q.Encode()}, "endpoint_override": azInCluster,
	})
	code, raw := admin.do("POST", "/destination-groups", map[string]any{"name": "e2e-same", "member_ids": []string{azID, twin["id"].(string)}}, nil)
	if code != 422 || !strings.Contains(raw, "write to the same location") {
		t.Fatalf("same location: %d %s", code, raw)
	}

	var groups struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	admin.must("GET", "/destination-groups", nil, &groups, 200)
	groupID := ""
	for _, g := range groups.Items {
		if g.Name == "e2e-copies" {
			groupID = g.ID
		}
	}
	if groupID == "" {
		var g struct {
			ID string `json:"id"`
		}
		admin.must("POST", "/destination-groups", map[string]any{"name": "e2e-copies", "member_ids": []string{s3ID, azID}}, &g, 201)
		groupID = g.ID
	}

	pg := labTarget(t, admin, "orders-pg")
	var j backup.JobView
	admin.must("POST", "/backup/jobs", map[string]any{"target_id": pg.ID,
		"credential":           map[string]any{"source": "stored", "username": "backup", "password": "CANARY-lab-pg-password"},
		"destination_group_id": groupID, "engine_options": map[string]any{"databases": []string{"orders"}},
		"cron": "0 4 * * *", "timezone": "UTC", "enabled": true}, &j, 201)
	job := j.ID.String()

	// Both copies, same bytes.
	ok := runAndWait(t, admin, job, "manual")
	if len(ok.Copies) != 2 || ok.Copies[0].DestinationID.String() != s3ID || ok.Copies[0].SHA256 != ok.Copies[1].SHA256 ||
		ok.Copies[0].Status != "succeeded" || ok.Copies[1].Status != "succeeded" {
		t.Fatalf("group run copies: %+v", ok.Copies)
	}

	// Azurite unreachable. The server's idle connections to it close after
	// 90 s; only then are new ones refused.
	azuriteSelector(t, "azurite-e2e-off")
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "-n", "olympos", "patch", "service", "azurite", "--type", "merge", "-p", `{"spec":{"selector":{"app":"azurite"}}}`)
	})
	time.Sleep(100 * time.Second)

	var queued backup.Run
	admin.must("POST", "/backup/jobs/"+job+"/run", map[string]any{"trigger": "manual"}, &queued, 202)
	var partial backup.Run
	eventually(t, 5*time.Minute, "partial run", func() (bool, string) {
		admin.must("GET", "/backup/runs/"+queued.ID.String(), nil, &partial, 200)
		return partial.Status != "queued" && partial.Status != "running", partial.Status
	})
	var dash struct {
		Attention []struct{ Kind, Detail string } `json:"attention"`
	}
	admin.must("GET", "/dashboard", nil, &dash, 200)
	azuriteSelector(t, "azurite")
	if partial.Status != "partial" || len(partial.Copies) != 2 || partial.Copies[0].Status != "succeeded" || partial.Copies[1].Status != "failed" ||
		!strings.HasPrefix(partial.Error, "e2e-copies-azurite: ") {
		t.Fatalf("expected partial with a failed Azurite copy: %s %q %+v", partial.Status, partial.Error, partial.Copies)
	}
	found := false
	for _, a := range dash.Attention {
		found = found || a.Kind == "backup_partial" && strings.Contains(a.Detail, "missing e2e-copies-azurite")
	}
	if !found {
		t.Errorf("no backup_partial attention item: %+v", dash.Attention)
	}

	// The repair writes only the missing copy, from a fresh dump.
	var repair backup.Run
	eventually(t, 5*time.Minute, "repair run", func() (bool, string) {
		var runs struct{ Items []backup.Run }
		admin.must("GET", "/backup/runs?job_id="+job, nil, &runs, 200)
		for _, r := range runs.Items {
			if r.RepairOf != nil && *r.RepairOf == partial.ID && r.Status == "succeeded" {
				repair = r
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d runs", len(runs.Items))
	})
	if len(repair.Copies) != 1 || repair.Copies[0].DestinationID.String() != azID || repair.Copies[0].SHA256 == partial.Copies[0].SHA256 ||
		repair.Trigger != "manual" {
		t.Fatalf("repair: %+v", repair)
	}

	// The original run's guide offers both copies; ?copy= picks the repaired one.
	var detail struct {
		Status  string `json:"status"`
		Restore struct {
			Copies []struct {
				DestinationID string `json:"destination_id"`
				RunID         string `json:"run_id"`
				Selected      bool   `json:"selected"`
			} `json:"copies"`
			Steps []struct{ Commands string } `json:"steps"`
		} `json:"restore"`
	}
	admin.must("GET", "/backup/runs/"+partial.ID.String()+"?copy="+azID, nil, &detail, 200)
	cs := detail.Restore.Copies
	if detail.Status != "partial" || len(cs) != 2 || cs[0].DestinationID != s3ID || cs[1].DestinationID != azID ||
		cs[1].RunID != repair.ID.String() || !cs[1].Selected || cs[0].Selected {
		t.Fatalf("restore copies: %+v", detail)
	}
	if len(detail.Restore.Steps) == 0 || !strings.Contains(detail.Restore.Steps[0].Commands, repair.ID.String()) {
		t.Fatalf("restore steps do not use the repair's blob: %+v", detail.Restore.Steps)
	}
	admin.must("GET", "/dashboard", nil, &dash, 200)
	for _, a := range dash.Attention {
		if a.Kind == "backup_partial" && strings.Contains(a.Detail, "e2e-copies-azurite") {
			t.Errorf("attention item still there after the repair: %+v", a)
		}
	}
}
