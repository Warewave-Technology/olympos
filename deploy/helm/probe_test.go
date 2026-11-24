package helm

import (
	"bytes"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
)

// olympos-probe in the agent chart (docs/design/synthetic-monitoring.md §2.1,
// §9 "Probe isolation", decisions 1 and 4).

func decode[T any](t *testing.T, doc map[string]any) T {
	t.Helper()
	var v T
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.UnmarshalStrict(b, &v); err != nil {
		t.Fatalf("decode %v: %v", doc["kind"], err)
	}
	return v
}

func probeDeployment(t *testing.T, docs []map[string]any) appsv1.Deployment {
	t.Helper()
	d := find(docs, "Deployment", "olympos-probe")
	if d == nil {
		t.Fatal("probe Deployment missing")
	}
	return decode[appsv1.Deployment](t, d)
}

// §9: the probe ServiceAccount has no RoleBinding or ClusterRoleBinding and
// no token automount, whatever else is enabled.
func TestProbeServiceAccountHasNoRBAC(t *testing.T) {
	docs := render(t, "--set", "bench.enabled=true", "--set", "secretsInventory.enabled=true",
		"--set", "probe.networkPolicy.egressCIDRs[0]=10.0.0.0/8")
	sa := find(docs, "ServiceAccount", "olympos-probe")
	if sa == nil {
		t.Fatal("probe ServiceAccount missing")
	}
	if v, ok := sa["automountServiceAccountToken"].(bool); !ok || v {
		t.Fatalf("probe ServiceAccount automountServiceAccountToken: %v", sa["automountServiceAccountToken"])
	}
	bindings := 0
	for _, d := range docs {
		if d["kind"] != "RoleBinding" && d["kind"] != "ClusterRoleBinding" {
			continue
		}
		bindings++
		subjects, _ := d["subjects"].([]any)
		for _, s := range subjects {
			if m, _ := s.(map[string]any); m["name"] == "olympos-probe" {
				t.Errorf("%s %v binds the probe ServiceAccount", d["kind"], d["metadata"].(map[string]any)["name"])
			}
		}
	}
	if bindings < 3 {
		t.Fatalf("expected the agent and bench bindings in the render, got %d", bindings)
	}
}

// The probe pod: no token, no service links, the agent's hardening, no
// ports, exec liveness, and exactly one volume, the projected identity
// mounted read-only.
func TestProbePodHardening(t *testing.T) {
	dep := probeDeployment(t, render(t))
	pod := dep.Spec.Template.Spec
	if pod.ServiceAccountName != "olympos-probe" {
		t.Errorf("serviceAccountName %q", pod.ServiceAccountName)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Error("pod must set automountServiceAccountToken: false")
	}
	if pod.EnableServiceLinks == nil || *pod.EnableServiceLinks {
		t.Error("pod must set enableServiceLinks: false")
	}
	psc := pod.SecurityContext
	if psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.RunAsUser == nil || *psc.RunAsUser != 65532 ||
		psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("pod securityContext: %+v", psc)
	}
	// The projected files are root's: fsGroup and 0440 keep tls.key
	// readable by the probe only, not world-readable.
	if psc == nil || psc.FSGroup == nil || *psc.FSGroup != 65532 {
		t.Errorf("pod securityContext.fsGroup must be 65532: %+v", psc)
	}
	if len(pod.Containers) != 1 || len(pod.InitContainers) != 0 {
		t.Fatalf("containers: %d, init containers: %d", len(pod.Containers), len(pod.InitContainers))
	}
	c := pod.Containers[0]
	sc := c.SecurityContext
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil ||
		!*sc.ReadOnlyRootFilesystem || sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" ||
		len(sc.Capabilities.Add) != 0 || sc.Privileged != nil {
		t.Errorf("container securityContext: %+v", sc)
	}
	if len(c.Ports) != 0 {
		t.Error("probe must not expose ports")
	}
	if c.LivenessProbe == nil || c.LivenessProbe.Exec == nil || strings.Join(c.LivenessProbe.Exec.Command, " ") != "/olympos-probe health" {
		t.Errorf("liveness: %+v", c.LivenessProbe)
	}
	if len(pod.Volumes) != 1 || pod.Volumes[0].Projected == nil {
		t.Fatalf("the projected identity must be the only volume: %+v", pod.Volumes)
	}
	if m := pod.Volumes[0].Projected.DefaultMode; m == nil || *m != 0o440 {
		t.Errorf("projected defaultMode must be 0440, got %v", m)
	}
	src := pod.Volumes[0].Projected.Sources
	if len(src) != 2 || src[0].Secret == nil || src[1].ConfigMap == nil {
		t.Fatalf("projected sources: %+v", src)
	}
	sec := src[0].Secret
	if sec.Name != "olympos-probe-identity" || sec.Optional == nil || !*sec.Optional ||
		len(sec.Items) != 2 || sec.Items[0].Key != "tls.crt" || sec.Items[1].Key != "tls.key" {
		t.Errorf("probe Secret source (tls.crt and tls.key only, optional): %+v", sec)
	}
	if cm := src[1].ConfigMap; cm.Name != "olympos-agent-ca" || len(cm.Items) != 1 || cm.Items[0].Key != "ca.crt" {
		t.Errorf("CA source: %+v", cm)
	}
	if len(c.VolumeMounts) != 1 || !c.VolumeMounts[0].ReadOnly || c.VolumeMounts[0].MountPath != "/etc/olympos-probe" || c.VolumeMounts[0].SubPath != "" {
		t.Errorf("volume mounts: %+v", c.VolumeMounts)
	}
	env := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		env[e.Name] = e
	}
	if env["OLYMPOS_PROBE_IDENTITY_DIR"].Value != "/etc/olympos-probe" || env["OLYMPOS_HEALTH_ADDR"].Value != "127.0.0.1:8082" ||
		env["OLYMPOS_SERVER"].Value != "gw.example:8443" || env["OLYMPOS_PROBE_MAX_CONCURRENCY"].Value != "20" {
		t.Errorf("env: %+v", c.Env)
	}
	if f := env["GOMEMLIMIT"].ValueFrom; f == nil || f.ResourceFieldRef == nil || f.ResourceFieldRef.Resource != "limits.memory" ||
		f.ResourceFieldRef.ContainerName != "probe" {
		t.Errorf("GOMEMLIMIT must follow the memory limit: %+v", env["GOMEMLIMIT"])
	}
	for _, e := range c.Env {
		if strings.Contains(e.Name, "TOKEN") || (e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil) {
			t.Errorf("env %s: the probe gets no token and no Secret through the environment", e.Name)
		}
	}
}

func TestProbeDeploymentGolden(t *testing.T) {
	got, err := yaml.Marshal(find(render(t), "Deployment", "olympos-probe"))
	if err != nil {
		t.Fatal(err)
	}
	golden := "testdata/probe-deployment.golden.yaml"
	if *update {
		_ = os.WriteFile(golden, got, 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("probe Deployment differs from golden (go test ./deploy/helm/ -update). Got:\n%s", got)
	}
}

func TestProbeDisabledRendersNothing(t *testing.T) {
	docs := render(t, "--set", "probe.enabled=false", "--set", "probe.networkPolicy.egressCIDRs[0]=10.0.0.0/8")
	for _, d := range docs {
		md, _ := d["metadata"].(map[string]any)
		labels, _ := md["labels"].(map[string]any)
		if name, _ := md["name"].(string); strings.Contains(name, "probe") || labels["app.kubernetes.io/name"] == "olympos-probe" {
			t.Errorf("probe.enabled=false renders %s %s", d["kind"], name)
		}
	}
	agent := decode[appsv1.Deployment](t, find(docs, "Deployment", "olympos-agent"))
	for _, e := range agent.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "OLYMPOS_PROBE_ENABLED" && e.Value != "false" {
			t.Errorf("OLYMPOS_PROBE_ENABLED=%q with the probe disabled", e.Value)
		}
	}
}

func TestAgentProbeEnv(t *testing.T) {
	agent := decode[appsv1.Deployment](t, find(render(t), "Deployment", "olympos-agent"))
	env := map[string]string{}
	for _, e := range agent.Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env["OLYMPOS_PROBE_ENABLED"] != "true" || env["OLYMPOS_PROBE_IDENTITY_SECRET"] != "olympos-probe-identity" {
		t.Fatalf("agent probe env: %v", env)
	}
}

func TestProbeNetworkPolicyOptIn(t *testing.T) {
	if find(render(t), "NetworkPolicy", "olympos-probe") != nil {
		t.Fatal("NetworkPolicy rendered without probe.networkPolicy.egressCIDRs")
	}
	docs := render(t, "--set", "probe.networkPolicy.egressCIDRs={10.20.0.0/16,192.0.2.10/32}")
	np := find(docs, "NetworkPolicy", "olympos-probe")
	if np == nil {
		t.Fatal("NetworkPolicy missing with egressCIDRs")
	}
	p := decode[networkingv1.NetworkPolicy](t, np)
	if p.Spec.PodSelector.MatchLabels["app.kubernetes.io/name"] != "olympos-probe" {
		t.Errorf("podSelector: %+v", p.Spec.PodSelector)
	}
	if len(p.Spec.PolicyTypes) != 1 || p.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress || len(p.Spec.Ingress) != 0 {
		t.Errorf("policyTypes: %v", p.Spec.PolicyTypes)
	}
	if len(p.Spec.Egress) != 2 {
		t.Fatalf("egress rules: %+v", p.Spec.Egress)
	}
	var cidrs []string
	for _, peer := range p.Spec.Egress[0].To {
		if peer.IPBlock == nil || len(peer.IPBlock.Except) != 0 || peer.PodSelector != nil || peer.NamespaceSelector != nil {
			t.Errorf("CIDR peer: %+v", peer)
			continue
		}
		cidrs = append(cidrs, peer.IPBlock.CIDR)
	}
	if strings.Join(cidrs, ",") != "10.20.0.0/16,192.0.2.10/32" || len(p.Spec.Egress[0].Ports) != 0 {
		t.Errorf("CIDR rule: %+v", p.Spec.Egress[0])
	}
	dns := p.Spec.Egress[1]
	if len(dns.To) != 1 || dns.To[0].IPBlock != nil || dns.To[0].NamespaceSelector == nil ||
		dns.To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "kube-system" ||
		dns.To[0].PodSelector == nil || dns.To[0].PodSelector.MatchLabels["k8s-app"] != "kube-dns" || len(dns.Ports) != 2 {
		t.Errorf("DNS rule must allow only kube-dns: %+v", dns)
	}
	for _, port := range dns.Ports {
		if port.Port == nil || port.Port.IntValue() != 53 {
			t.Errorf("DNS port: %+v", port)
		}
	}
}

// probe.networkPolicy.dns replaces each default it sets as a whole (OpenShift
// DNS here); unset fields keep the kube-dns defaults.
func TestProbeNetworkPolicyDNSOverride(t *testing.T) {
	values := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(values, []byte(`probe:
  networkPolicy:
    egressCIDRs: [10.20.0.0/16]
    dns:
      namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: openshift-dns}}
      podSelector: {matchLabels: {dns.operator.openshift.io/daemonset-dns: default}}
      ports: [{protocol: UDP, port: 5353}, {protocol: TCP, port: 5353}]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	dns := decode[networkingv1.NetworkPolicy](t, find(render(t, "-f", values), "NetworkPolicy", "olympos-probe")).Spec.Egress[1]
	if ns := dns.To[0].NamespaceSelector.MatchLabels; len(ns) != 1 || ns["kubernetes.io/metadata.name"] != "openshift-dns" {
		t.Errorf("namespaceSelector: %v", ns)
	}
	if pod := dns.To[0].PodSelector.MatchLabels; len(pod) != 1 || pod["dns.operator.openshift.io/daemonset-dns"] != "default" {
		t.Errorf("podSelector must replace k8s-app=kube-dns, not add to it: %v", pod)
	}
	if len(dns.Ports) != 2 || dns.Ports[0].Port.IntValue() != 5353 || dns.Ports[1].Port.IntValue() != 5353 {
		t.Errorf("ports: %+v", dns.Ports)
	}

	dns = decode[networkingv1.NetworkPolicy](t, find(render(t, "--set", "probe.networkPolicy.egressCIDRs[0]=10.0.0.0/8",
		"--set", "probe.networkPolicy.dns.ports[0].port=1053", "--set", "probe.networkPolicy.dns.ports[0].protocol=UDP"),
		"NetworkPolicy", "olympos-probe")).Spec.Egress[1]
	if dns.To[0].PodSelector.MatchLabels["k8s-app"] != "kube-dns" || dns.To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "kube-system" ||
		len(dns.Ports) != 1 || dns.Ports[0].Port.IntValue() != 1053 {
		t.Errorf("only ports set: %+v", dns)
	}
}

// The probe Secret in template mode (lookup finds nothing): a new cluster's
// bootstrapToken enrolls the probe too; an Install probe token wins. With a
// live Secret the chart keeps its keys (checked in the lab, see the task
// report: helm template cannot look up).
func TestProbeIdentitySecret(t *testing.T) {
	token := func(docs []map[string]any) string {
		t.Helper()
		s := find(docs, "Secret", "olympos-probe-identity")
		if s == nil {
			t.Fatal("probe identity Secret missing")
		}
		if s["metadata"].(map[string]any)["annotations"].(map[string]any)["helm.sh/resource-policy"] != "keep" {
			t.Fatal("probe identity Secret must be kept on uninstall")
		}
		if _, ok := s["stringData"]; ok {
			t.Fatal("probe identity Secret: data only")
		}
		data, _ := s["data"].(map[string]any)
		if len(data) != 1 {
			t.Fatalf("data keys: %v", data)
		}
		b, err := base64.StdEncoding.DecodeString(data["bootstrap-token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := token(render(t)); got != "olyb_x" {
		t.Errorf("new cluster: bootstrap-token %q, want the cluster's bootstrapToken", got)
	}
	if got := token(render(t, "--set", "probe.bootstrapToken=olyb_probe")); got != "olyb_probe" {
		t.Errorf("Install probe: bootstrap-token %q, want probe.bootstrapToken", got)
	}
}

// helm upgrade --reuse-values from a release older than the probe renders
// with that release's values, which have no probe section at all (Helm uses
// the old chart's values then). The probe is on and renders exactly as with
// the defaults; the Install probe command (--set probe.enabled=true --set
// probe.bootstrapToken=…) works too.
func TestProbeToleratesOldValues(t *testing.T) {
	old := oldValuesChart(t)
	want, _ := yaml.Marshal(find(render(t), "Deployment", "olympos-probe"))
	got, _ := yaml.Marshal(find(renderChart(t, old), "Deployment", "olympos-probe"))
	if !bytes.Equal(got, want) {
		t.Fatalf("probe Deployment without probe values differs from the defaults (the template fallbacks and values.yaml disagree):\n%s", got)
	}
	docs := renderChart(t, old, "--set", "probe.enabled=true", "--set", "probe.bootstrapToken=olyb_probe")
	if got, _ := yaml.Marshal(find(docs, "Deployment", "olympos-probe")); !bytes.Equal(got, want) {
		t.Fatalf("Install probe on old values:\n%s", got)
	}
	if find(docs, "Role", "olympos-agent-identity") == nil || find(docs, "ServiceAccount", "olympos-probe") == nil {
		t.Fatal("Install probe on old values: probe objects missing")
	}
	np := "probe.networkPolicy.egressCIDRs[0]=10.0.0.0/8"
	wantNP, _ := yaml.Marshal(find(render(t, "--set", np), "NetworkPolicy", "olympos-probe"))
	if got, _ := yaml.Marshal(find(renderChart(t, old, "--set", np), "NetworkPolicy", "olympos-probe")); !bytes.Equal(got, wantNP) {
		t.Fatalf("NetworkPolicy on old values differs from the defaults:\n%s", got)
	}
	if find(renderChart(t, old, "--set", "probe.enabled=false"), "Deployment", "olympos-probe") != nil {
		t.Fatal("probe.enabled=false on old values still renders the probe")
	}
}

// oldValuesChart copies the agent chart with the probe section removed
// from values.yaml.
func oldValuesChart(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "olympos-agent")
	err := filepath.WalkDir("olympos-agent", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("olympos-agent", p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if rel == "values.yaml" {
			var v map[string]any
			if err := yaml.Unmarshal(b, &v); err != nil {
				return err
			}
			if _, ok := v["probe"]; !ok {
				t.Fatal("values.yaml has no probe section")
			}
			delete(v, "probe")
			if b, err = yaml.Marshal(v); err != nil {
				return err
			}
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}
