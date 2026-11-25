package inventory

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/Warewave-Technology/olympos/internal/pki"
)

// P21: Install probe carries the server's OLYMPOS_AGENT_INSTALL_SETS (an
// image mirror, probe.image.*) like the Add cluster command; the probe's own
// sets come last and the token ends the command.
func TestProbeInstallCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		api  API
		want string
	}{
		{"defaults", API{},
			"helm upgrade olympos-agent oci://ghcr.io/warewave-technology/charts/olympos-agent -n olympos-system --reuse-values --set probe.enabled=true --set probe.bootstrapToken=olyb_t"},
		{"install sets", API{AgentChart: "./deploy/helm/olympos-agent", AgentSets: []string{"image.repository=mirror/olympos-agent", "probe.image.repository=mirror/olympos-probe"}},
			"helm upgrade olympos-agent ./deploy/helm/olympos-agent -n olympos-system --reuse-values --set image.repository=mirror/olympos-agent --set probe.image.repository=mirror/olympos-probe --set probe.enabled=true --set probe.bootstrapToken=olyb_t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.api.probeInstallCommand("olyb_t"); got != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// #59: the GitOps variant of Add cluster. The token goes only into the
// kubectl commands that create both identity Secrets (one token enrolls the
// agent and the probe); the chart values hold everything else the helm
// command sets, typed like --set, plus identity.manageSecrets=false.
func TestGitOpsInstall(t *testing.T) {
	a := API{GatewayURL: "gw.example:8443", CA: pki.NewForTest(),
		AgentSets: []string{"image.repository=mirror/olympos-agent", "probe.replicas=2"}}
	g := a.gitopsInstall(&Cluster{Name: "oke-fra-mes", BenchEnabled: true}, "olyb_t")
	for _, s := range []string{"olympos-agent-identity", "olympos-probe-identity"} {
		want := "kubectl -n olympos-system create secret generic " + s + " \\\n  --from-literal=bootstrap-token=olyb_t --dry-run=client -o yaml | kubectl apply -f -"
		if !strings.Contains(g.Secrets, want) {
			t.Errorf("secrets: no %s line:\n%s", s, g.Secrets)
		}
	}
	if !strings.HasPrefix(g.Secrets, "kubectl create namespace olympos-system --dry-run=client -o yaml | kubectl apply -f -\n") {
		t.Errorf("secrets: the namespace first:\n%s", g.Secrets)
	}
	if strings.Contains(g.Values, "olyb_t") {
		t.Fatalf("values must not hold the token:\n%s", g.Values)
	}
	var v map[string]any
	if err := yaml.Unmarshal([]byte(g.Values), &v); err != nil {
		t.Fatalf("values are not YAML: %v\n%s", err, g.Values)
	}
	ca, _ := v["serverCA"].(string)
	if v["server"] != "gw.example:8443" || v["clusterName"] != "oke-fra-mes" || !strings.HasPrefix(ca, "LS0t") ||
		v["identity"].(map[string]any)["manageSecrets"] != false || v["bench"].(map[string]any)["enabled"] != true ||
		v["image"].(map[string]any)["repository"] != "mirror/olympos-agent" || v["probe"].(map[string]any)["replicas"] != float64(2) {
		t.Fatalf("values:\n%s", g.Values)
	}
	if _, ok := v["bootstrapToken"]; ok {
		t.Fatalf("values: no bootstrapToken key:\n%s", g.Values)
	}
	if !strings.HasPrefix(g.Values, "# oci://ghcr.io/warewave-technology/charts/olympos-agent, namespace olympos-system\n") {
		t.Errorf("values: the chart and namespace first:\n%s", g.Values)
	}
}

// Install probe in GitOps: the probe's Secret only, and probe.enabled for
// the values in Git.
func TestGitOpsProbeInstall(t *testing.T) {
	g := (&API{}).gitopsProbeInstall("olyb_p")
	if strings.Contains(g.Secrets, "olympos-agent-identity") || !strings.Contains(g.Secrets, "create secret generic olympos-probe-identity \\\n  --from-literal=bootstrap-token=olyb_p") {
		t.Fatalf("secrets:\n%s", g.Secrets)
	}
	var v map[string]any
	if err := yaml.Unmarshal([]byte(g.Values), &v); err != nil || v["probe"].(map[string]any)["enabled"] != true || strings.Contains(g.Values, "olyb_p") {
		t.Fatalf("values (%v):\n%s", err, g.Values)
	}
}
