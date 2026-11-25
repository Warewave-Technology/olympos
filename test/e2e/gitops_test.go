//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/inventory"
)

const (
	gitopsName    = "lab-gitops"
	gitopsNS      = "olympos-gitops"
	gitopsRelease = "olympos-agent-g"
)

// TestGitOpsSync installs an agent and its probe the way a GitOps tool does
// (#59, docs/install.md "Install with Argo CD or Flux"): the identity
// Secrets from the GitOps tab of Add cluster, then the chart rendered with
// helm template (no lookup) and applied, like a sync. Two more syncs, one
// client-side and one server-side, change nothing: the same certificates,
// no bootstrap token written back, both online, no enroll attempt after the
// first. It runs in its own namespace of the lab cluster, like M9's lab-b;
// the commands name olympos-system, which the lab's own agent uses, so the
// test swaps the namespace.
func TestGitOpsSync(t *testing.T) {
	admin := login(t, devAdminOID, "Lab Admin")
	var created inventory.InstallResponse
	admin.must("POST", "/clusters", map[string]any{"name": gitopsName + "-" + time.Now().UTC().Format("150405"),
		"labels": map[string]string{"env": "lab"}}, &created, 201)
	id := created.Cluster.ID.String()
	if created.GitOps == nil {
		t.Fatal("install response without the GitOps variant")
	}
	manifest := filepath.Join(t.TempDir(), "agent.yaml")
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "delete", "-f", manifest, "--ignore-not-found", "--wait=false")
		_, _ = runOK(t, "kubectl", "delete", "namespace", gitopsNS, "--ignore-not-found", "--wait=false")
		admin.do("DELETE", "/clusters/"+id, nil, nil)
	})
	token := helmSets(created.Command)["bootstrapToken"]
	if token == "" || strings.Contains(created.GitOps.Values, token) || !strings.Contains(created.GitOps.Secrets, token) {
		t.Fatalf("the token must be in the Secret commands only:\n%s\n%s", created.GitOps.Secrets, created.GitOps.Values)
	}

	// Once, on the cluster: the Secrets with the token.
	run(t, "sh", "-c", strings.ReplaceAll(created.GitOps.Secrets, "olympos-system", gitopsNS))

	// The values for Git, rendered without lookup; the lab's images.
	values := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(values, []byte(created.GitOps.Values), 0o600); err != nil {
		t.Fatal(err)
	}
	out := run(t, "helm", "template", gitopsRelease, "deploy/helm/olympos-agent", "--namespace", gitopsNS, "-f", values,
		"--set", "providerOverride=onprem",
		"--set", "image.repository=olympos-agent", "--set", "image.tag=e2e", "--set", "image.pullPolicy=Never",
		"--set", "probe.image.repository=olympos-probe", "--set", "probe.image.tag=e2e", "--set", "probe.image.pullPolicy=Never")
	if strings.Contains(out, "kind: Secret\n") || strings.Contains(out, "bootstrap-token") {
		t.Fatalf("the rendered chart must hold no Secret and no token:\n%s", out)
	}
	if err := os.WriteFile(manifest, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, "kubectl", "apply", "-n", gitopsNS, "-f", manifest)
	waitProbesOnline(t, admin, id)

	certs := func() map[string]string {
		t.Helper()
		got := map[string]string{}
		for _, s := range []string{"olympos-agent-identity", "olympos-probe-identity"} {
			data := run(t, "kubectl", "-n", gitopsNS, "get", "secret", s, "-o", `jsonpath={.data.tls\.crt}|{.data.bootstrap-token}`)
			crt, tok, _ := strings.Cut(data, "|")
			if tok != "" {
				t.Errorf("%s still holds a bootstrap token", s)
			}
			b, _ := base64.StdEncoding.DecodeString(crt)
			if len(b) == 0 {
				t.Errorf("%s holds no certificate", s)
			}
			sum := sha256.Sum256(b)
			got[s] = hex.EncodeToString(sum[:8])
		}
		return got
	}
	before := certs()
	enrolls := func() int {
		logs := run(t, "kubectl", "-n", gitopsNS, "logs", "deploy/olympos-agent", "--tail=-1")
		return strings.Count(logs, "probe identity: the bootstrap token was refused") + strings.Count(logs, "probe identity: enrollment failed")
	}

	// Two more syncs: client-side, then server-side as Argo CD does with
	// ServerSideApply=true.
	run(t, "kubectl", "apply", "-n", gitopsNS, "-f", manifest)
	run(t, "kubectl", "apply", "-n", gitopsNS, "--server-side", "--force-conflicts", "--field-manager=argocd-controller", "-f", manifest)
	time.Sleep(20 * time.Second)
	waitProbesOnline(t, admin, id)
	after := certs()
	for s, sum := range before {
		if after[s] != sum {
			t.Errorf("%s: certificate %s before the syncs, %s after", s, sum, after[s])
		}
	}
	if n := enrolls(); n != 0 {
		t.Errorf("the agent retried a spent token %d times after the syncs", n)
	}
}
