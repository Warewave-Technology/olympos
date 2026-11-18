//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

func vaultRootToken(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(work(), "vault-init.json"))
	if err != nil {
		t.Skipf("lab vault not initialized: %v", err)
	}
	var v struct {
		RootToken string `json:"root_token"`
	}
	_ = json.Unmarshal(b, &v)
	return v.RootToken
}

// vaultCLI runs the vault CLI inside the lab Vault pod with the root token
// (the test plays the out-of-band admin; Olympos never gets this token twice).
func vaultCLI(t *testing.T, root string, args ...string) string {
	t.Helper()
	return run(t, "kubectl", append([]string{"-n", "lab", "exec", "deploy/vault", "--", "env", "VAULT_TOKEN=" + root, "vault"}, args...)...)
}

// grantedUser signs a person in once (creating the principal), grants roles
// as admin and returns a session for them.
func grantedUser(t *testing.T, admin *client, name string, roles ...string) *client {
	t.Helper()
	oid := uuid.NewSHA1(uuid.NameSpaceOID, []byte("olympos-e2e-"+name)).String()
	// The first dev-login is denied (no grants yet) but creates the principal.
	if r, err := http.Get(baseURL() + "/auth/dev-login?oid=" + oid + "&name=" + name); err == nil {
		r.Body.Close()
	}
	code, raw := admin.do("POST", "/grants", map[string]any{"object_id": oid, "roles": roles, "scope": "env=lab"}, nil)
	if code != 201 && !strings.Contains(raw, "already") {
		// Re-runs: the grant may already exist (duplicate grants are harmless).
		if code != 201 {
			t.Logf("grant %s: %d %s", name, code, raw)
		}
	}
	return login(t, oid, name)
}

// TestM3VaultMakerChecker configures the lab Vault (TLS verified against the
// lab CA), browses keys, runs a change request through maker/checker, detects
// drift and takes a raft snapshot backup.
func TestM3VaultMakerChecker(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	root := vaultRootToken(t)
	admin := login(t, devAdminOID, "Lab Admin")

	var vs struct {
		Items []struct {
			ID       string `json:"id"`
			Provider string `json:"provider"`
			Status   string `json:"status"`
			Target   struct {
				Service string `json:"service"`
			} `json:"target"`
		} `json:"items"`
	}
	vaultID := ""
	eventually(t, time.Minute, "lab vault listed", func() (bool, string) {
		admin.must("GET", "/vaults", nil, &vs, 200)
		for _, v := range vs.Items {
			if v.Target.Service == "vault" && v.Provider == "hashicorp" {
				vaultID = v.ID
				return true, v.Status
			}
		}
		return false, fmt.Sprintf("%+v", vs.Items)
	})

	// A secret that exists before Olympos manages the mount (baseline, not drift).
	path := "app/orders-" + uuid.NewString()[:8]
	vaultCLI(t, root, "kv", "put", "secret/"+path, "password=CANARY-old-value", "user=orders")

	var insp struct {
		Version string `json:"version"`
		Mounts  []struct {
			Path    string `json:"path"`
			Version int    `json:"version"`
		} `json:"mounts"`
	}
	admin.must("POST", "/vaults/"+vaultID+"/inspect", map[string]any{"root_token": root}, &insp, 200)
	kv := map[string]int{}
	for _, m := range insp.Mounts {
		kv[m.Path] = m.Version
	}
	if kv["secret/"] != 2 || kv["legacy/"] != 1 {
		t.Fatalf("mounts: %+v", insp.Mounts)
	}
	code, raw := admin.do("POST", "/vaults/"+vaultID+"/configure", map[string]any{"root_token": root, "mounts": []string{"secret/"}}, nil)
	if code != 200 {
		t.Fatalf("configure: %d %s", code, raw)
	}
	pol := vaultCLI(t, root, "policy", "read", "olympos")
	if strings.Contains(pol, `"secret/data/*"`) && strings.Contains(strings.SplitN(pol[strings.Index(pol, `"secret/data/*"`):], "}", 2)[0], "read") {
		t.Fatalf("olympos policy grants read on data:\n%s", pol)
	}

	admin.must("POST", "/vaults/"+vaultID+"/refresh", nil, nil, 202)
	var sec struct {
		Keys           []string `json:"keys"`
		CurrentVersion int      `json:"current_version"`
	}
	eventually(t, time.Minute, "secret indexed", func() (bool, string) {
		code, raw := admin.do("GET", "/vaults/"+vaultID+"/secrets/"+path+"?mount=secret/", nil, &sec)
		return code == 200 && len(sec.Keys) == 2, raw
	})
	if _, raw := admin.do("GET", "/vaults/"+vaultID+"/secrets/"+path+"?mount=secret/", nil, nil); strings.Contains(raw, "CANARY") {
		t.Fatal("secret value returned by the API")
	}

	maker := grantedUser(t, admin, "maker", "vault-maker")
	checker := grantedUser(t, admin, "checker", "vault-approver")

	var cr struct {
		ID                    string `json:"id"`
		Status                string `json:"status"`
		CanApprove            bool   `json:"can_approve"`
		ApproveDisabledReason string `json:"approve_disabled_reason"`
		Items                 []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"items"`
	}
	maker.must("POST", "/change-requests", map[string]any{
		"vault_id": vaultID, "justification": "Rotate orders DB password (e2e)",
		"items": []map[string]any{{"mount": "secret/", "path": path, "key": "password", "op": "replace",
			"value": "CANARY-new-value", "base_version": sec.CurrentVersion}},
	}, &cr, 201)
	maker.must("GET", "/change-requests/"+cr.ID, nil, &cr, 200)
	if cr.CanApprove || cr.ApproveDisabledReason == "" {
		t.Fatalf("maker can approve own request: %+v", cr)
	}
	if code, _ := maker.do("POST", "/change-requests/"+cr.ID+"/approve", map[string]any{"comment": "self"}, nil); code != 403 {
		t.Fatalf("maker self-approve: %d", code)
	}
	_, raw = checker.do("GET", "/change-requests/"+cr.ID, nil, nil)
	if strings.Contains(raw, "CANARY") || !strings.Contains(raw, "hm:") {
		t.Fatalf("checker view must show a fingerprint and never the value: %s", raw)
	}
	checker.must("POST", "/change-requests/"+cr.ID+"/approve", map[string]any{"comment": "LGTM"}, &cr, 200)
	if cr.Status != "applied" {
		t.Fatalf("change request status %s", cr.Status)
	}
	got := vaultCLI(t, root, "kv", "get", "-format=json", "secret/"+path)
	if !strings.Contains(got, "CANARY-new-value") || !strings.Contains(got, `"user": "orders"`) {
		t.Fatalf("vault after apply: %s", got)
	}

	// Out-of-band write → drift finding.
	vaultCLI(t, root, "kv", "patch", "secret/"+path, "user=someone-else")
	admin.must("POST", "/vaults/"+vaultID+"/refresh", nil, nil, 202)
	eventually(t, 2*time.Minute, "vault-drift finding", func() (bool, string) {
		var fs struct{ Items []map[string]any }
		admin.must("GET", "/findings?source=vault-drift&status=open", nil, &fs, 200)
		for _, f := range fs.Items {
			if strings.Contains(fmt.Sprint(f["resource_ref"]), path) {
				return true, ""
			}
		}
		return false, fmt.Sprint(len(fs.Items))
	})

	// Raft snapshot backup via the Olympos AppRole.
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
		t.Skip("destination from TestM2 missing")
	}
	vt := labTarget(t, admin, "vault")
	var jobs struct{ Items []backup.Job }
	admin.must("GET", "/backup/jobs", nil, &jobs, 200)
	jobID := ""
	for _, j := range jobs.Items {
		if j.Target.ID == vt.ID {
			jobID = j.ID.String()
		}
	}
	if jobID == "" {
		var j backup.Job
		admin.must("POST", "/backup/jobs", map[string]any{"target_id": vt.ID, "destination_id": destID,
			"cron": "0 4 * * *", "timezone": "UTC", "enabled": true}, &j, 201)
		jobID = j.ID.String()
	}
	start := time.Now()
	admin.must("POST", "/backup/jobs/"+jobID+"/run", map[string]any{"trigger": "manual"}, nil, 202)
	snap := waitRun(t, admin, jobID, start, "manual")
	if !strings.HasSuffix(snap.BlobPath, ".snap") || snap.Bytes < 1000 {
		t.Fatalf("snapshot run: %+v", snap)
	}

	logs := run(t, "kubectl", "-n", "olympos", "logs", "deploy/olympos", "--tail=-1")
	for _, s := range []string{root, "CANARY-new-value", "CANARY-old-value"} {
		if strings.Contains(logs, s) {
			t.Fatal("vault secret material in server logs")
		}
	}
}

// TestM3OpenBaoOverTLS: OpenBao (raft, TLS from the lab CA) is inspected
// through the tunnel like HashiCorp Vault.
func TestM3OpenBaoOverTLS(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	b, err := os.ReadFile(filepath.Join(work(), "openbao-init.json"))
	if err != nil {
		t.Skipf("lab openbao not initialized: %v", err)
	}
	var init struct {
		RootToken string `json:"root_token"`
	}
	_ = json.Unmarshal(b, &init)
	admin := login(t, devAdminOID, "Lab Admin")
	var vs struct {
		Items []struct {
			ID       string `json:"id"`
			Provider string `json:"provider"`
		} `json:"items"`
	}
	admin.must("GET", "/vaults", nil, &vs, 200)
	id := ""
	for _, v := range vs.Items {
		if v.Provider == "openbao" {
			id = v.ID
		}
	}
	if id == "" {
		t.Fatal("openbao not listed")
	}
	var insp struct {
		Version string `json:"version"`
		Mounts  []struct {
			Path    string `json:"path"`
			Version int    `json:"version"`
		} `json:"mounts"`
	}
	admin.must("POST", "/vaults/"+id+"/inspect", map[string]any{"root_token": init.RootToken}, &insp, 200)
	found := false
	for _, m := range insp.Mounts {
		found = found || (m.Path == "secret/" && m.Version == 2)
	}
	if !found || insp.Version == "" {
		t.Fatalf("openbao inspect: %+v", insp)
	}
	// The vault target is a backup candidate even when the vault is configured.
	var ts struct {
		Items []struct {
			Service string `json:"service"`
			Engine  string `json:"engine"`
			Status  string `json:"status"`
		} `json:"items"`
	}
	admin.must("GET", "/targets?engine=vault", nil, &ts, 200)
	svcs := map[string]string{}
	for _, x := range ts.Items {
		svcs[x.Service] = x.Status
	}
	if _, ok := svcs["openbao"]; !ok {
		t.Fatalf("openbao not a vault backup target: %+v", ts.Items)
	}
}
