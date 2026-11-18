//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const ksCanary = "CANARY-k8s-secret-value-5c1e"

// TestM5SecretInventory (F3): off by default (no RBAC on secrets); once
// enabled the agent reports Secrets with key names, references and the
// managing operator; SA tokens and unmanaged Secrets become findings; no
// value reaches the server's database or any log.
func TestM5SecretInventory(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	sa := "system:serviceaccount:olympos-system:olympos-agent"
	if out, _ := runOK(t, "kubectl", "auth", "can-i", "--as", sa, "list", "secrets", "-n", "lab"); strings.TrimSpace(out) != "no" {
		t.Fatalf("agent can list secrets with the inventory off: %q", out)
	}

	run(t, "kubectl", "-n", "lab", "create", "secret", "generic", "e2e-used", "--from-literal=password="+ksCanary, "--from-literal=username=svc")
	run(t, "kubectl", "-n", "lab", "create", "secret", "generic", "e2e-lonely", "--from-literal=api_key="+ksCanary)
	run(t, "kubectl", "-n", "lab", "create", "secret", "generic", "e2e-from-eso", "--from-literal=DB_URL="+ksCanary)
	run(t, "kubectl", "-n", "lab", "label", "secret", "e2e-from-eso", "reconcile.external-secrets.io/managed=true")
	applyStdin(t, `apiVersion: v1
kind: Secret
metadata:
  name: e2e-legacy-token
  namespace: lab
  annotations: {kubernetes.io/service-account.name: default}
type: kubernetes.io/service-account-token
---
apiVersion: v1
kind: Pod
metadata: {name: e2e-secret-user, namespace: lab}
spec:
  containers:
  - name: c
    image: busybox:1.36
    command: [sleep, "3600"]
    env:
    - name: PW
      valueFrom: {secretKeyRef: {name: e2e-used, key: password}}
`)
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "-n", "lab", "delete", "pod/e2e-secret-user", "secret/e2e-used", "secret/e2e-lonely", "secret/e2e-from-eso",
			"secret/e2e-legacy-token", "--ignore-not-found", "--wait=false")
		_, _ = runOK(t, "helm", "upgrade", "olympos-agent", "deploy/helm/olympos-agent", "-n", "olympos-system", "--reuse-values",
			"--set", "secretsInventory.enabled=false", "--wait", "--timeout", "3m")
	})

	run(t, "helm", "upgrade", "olympos-agent", "deploy/helm/olympos-agent", "-n", "olympos-system", "--reuse-values",
		"--set", "secretsInventory.enabled=true", "--wait", "--timeout", "3m")
	if out, _ := runOK(t, "kubectl", "auth", "can-i", "--as", sa, "get", "secrets", "-n", "lab"); strings.TrimSpace(out) != "no" {
		t.Fatalf("inventory must not grant get on secrets: %q", out)
	}

	type row struct {
		Namespace    string   `json:"namespace"`
		Name         string   `json:"name"`
		Type         string   `json:"type"`
		Keys         []string `json:"keys"`
		ReferencedBy []string `json:"referenced_by"`
		ManagedBy    string   `json:"managed_by"`
		Findings     []string `json:"findings"`
	}
	var inv struct {
		Clusters []struct {
			ClusterID string `json:"cluster_id"`
			Enabled   bool   `json:"enabled"`
		} `json:"clusters"`
		Items []row `json:"items"`
	}
	byName := map[string]row{}
	eventually(t, 3*time.Minute, "secret inventory with findings", func() (bool, string) {
		admin.must("GET", "/security/secrets?cluster="+labClusterID, nil, &inv, 200)
		byName = map[string]row{}
		for _, r := range inv.Items {
			if r.Namespace == "lab" && strings.HasPrefix(r.Name, "e2e-") {
				byName[r.Name] = r
			}
		}
		ok := len(inv.Clusters) == 1 && inv.Clusters[0].Enabled && len(byName) == 4 &&
			len(byName["e2e-used"].ReferencedBy) > 0 && len(byName["e2e-legacy-token"].Findings) > 0
		return ok, fmt.Sprintf("%+v", byName)
	})
	if r := byName["e2e-used"]; strings.Join(r.Keys, ",") != "password,username" || strings.Join(r.ReferencedBy, ",") != "Pod/e2e-secret-user" {
		t.Errorf("e2e-used: %+v", r)
	}
	if r := byName["e2e-from-eso"]; r.ManagedBy != "External Secrets Operator" || len(r.Findings) != 0 {
		t.Errorf("e2e-from-eso: %+v", r)
	}
	if r := byName["e2e-legacy-token"]; r.Type != "kubernetes.io/service-account-token" || !contains(r.Findings, "secret.legacy_sa_token") {
		t.Errorf("e2e-legacy-token: %+v", r)
	}
	if r := byName["e2e-lonely"]; !contains(r.Findings, "secret.unmanaged") {
		t.Errorf("e2e-lonely: %+v", r)
	}

	dump := run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--", "pg_dump", "-U", "olympos", "--data-only", "olympos")
	logs := run(t, "kubectl", "-n", "olympos", "logs", "deploy/olympos", "--tail=-1")
	agent := run(t, "kubectl", "-n", "olympos-system", "logs", "deploy/olympos-agent", "--tail=-1")
	for where, text := range map[string]string{"database": dump, "server logs": logs, "agent logs": agent} {
		if strings.Contains(text, ksCanary) {
			t.Errorf("a Secret value reached the %s", where)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
