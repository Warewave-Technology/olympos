package inventory

import (
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

// GitOpsInstall is the install command for Argo CD, Flux and other tools that
// render the agent chart with helm template (#59, docs/install.md "Install
// with Argo CD or Flux"). The one-time token goes only into Secrets, which
// are created once on the cluster and never rendered (identity.manageSecrets
// false): a sync cannot write a spent token or replace an enrolled
// certificate. Values holds the rest of what the helm command sets, for Git.
type GitOpsInstall struct {
	Secrets string `json:"secrets"`
	Values  string `json:"values"`
}

const agentNamespace = "olympos-system"

// gitopsInstall is the GitOps form of installCommand: the token in both
// identity Secrets (it enrolls the agent, then the probe), the values without it.
func (a *API) gitopsInstall(c *Cluster, token string) *GitOpsInstall {
	sets := []string{"server=" + a.GatewayURL, "clusterName=" + c.Name, "serverCA=" + a.caBase64()}
	if c.BenchEnabled {
		sets = append(sets, "bench.enabled=true")
	}
	sets = append(sets, a.AgentSets...)
	sets = append(sets, "identity.manageSecrets=false")
	return &GitOpsInstall{
		Secrets: "kubectl create namespace " + agentNamespace + " --dry-run=client -o yaml | kubectl apply -f -\n" +
			identitySecretCommand("olympos-agent-identity", token) + "\n" +
			identitySecretCommand("olympos-probe-identity", token),
		Values: "# " + a.chart() + ", namespace " + agentNamespace + "\n" + setsYAML(sets),
	}
}

// gitopsProbeInstall is the GitOps form of probeInstallCommand: the probe's
// Secret only (it may exist: a revoked probe), and probe.enabled for Git.
func (a *API) gitopsProbeInstall(token string) *GitOpsInstall {
	sets := append(append([]string{}, a.AgentSets...), "probe.enabled=true")
	return &GitOpsInstall{
		Secrets: identitySecretCommand("olympos-probe-identity", token),
		Values:  "# add to the values of the olympos-agent application\n" + setsYAML(sets),
	}
}

// identitySecretCommand creates the Secret, or adds the token to it when it
// exists (apply keeps the keys it did not write: an enrolled certificate).
func identitySecretCommand(name, token string) string {
	return "kubectl -n " + agentNamespace + " create secret generic " + name + " \\\n" +
		"  --from-literal=bootstrap-token=" + token + " --dry-run=client -o yaml | kubectl apply -f -"
}

// setsYAML turns helm --set pairs (a.b=v) into the values YAML they mean,
// typed the way --set types them: true and false are booleans, whole numbers
// integers, everything else a string.
func setsYAML(sets []string) string {
	root := map[string]any{}
	for _, kv := range sets {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		node := root
		parts := strings.Split(k, ".")
		for _, p := range parts[:len(parts)-1] {
			next, ok := node[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				node[p] = next
			}
			node = next
		}
		node[parts[len(parts)-1]] = setValue(v)
	}
	out, _ := yaml.Marshal(root)
	return string(out)
}

func setValue(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	return v
}
