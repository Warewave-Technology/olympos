// Package helm tests the rendered Helm charts (SPEC §18: agent RBAC matches
// §4.2 exactly — golden file; bench RBAC only when enabled).
package helm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/Warewave-Technology/olympos/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

func render(t *testing.T, extra ...string) []map[string]any {
	t.Helper()
	return renderChart(t, "olympos-agent", extra...)
}

// renderChart renders an agent chart directory (a copy, for old values).
func renderChart(t *testing.T, chart string, extra ...string) []map[string]any {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	args := append([]string{"template", "a", chart, "--namespace", "olympos-system",
		"--set", "server=gw.example:8443", "--set", "bootstrapToken=olyb_x",
		"--set", "serverCA=" + base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))}, extra...)
	cmd := exec.Command("helm", args...)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template: %v\n%s", err, stderr.String())
	}
	var docs []map[string]any
	dec := utilyaml.NewYAMLOrJSONDecoder(&out, 4096)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}
		if m != nil {
			docs = append(docs, m)
		}
	}
	return docs
}

func find(docs []map[string]any, kind, name string) map[string]any {
	for _, d := range docs {
		md, _ := d["metadata"].(map[string]any)
		if d["kind"] == kind && md["name"] == name {
			return d
		}
	}
	return nil
}

func rules(t *testing.T, doc map[string]any) []rbacv1.PolicyRule {
	t.Helper()
	b, _ := yaml.Marshal(doc)
	var r rbacv1.ClusterRole
	if err := yaml.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.Rules
}

func TestAgentClusterRoleGolden(t *testing.T) {
	docs := render(t)
	cr := find(docs, "ClusterRole", "olympos-agent-olympos-system")
	if cr == nil {
		t.Fatal("ClusterRole missing")
	}
	got, _ := yaml.Marshal(map[string]any{"rules": cr["rules"]})
	golden := "testdata/agent-clusterrole.golden.yaml"
	if *update {
		_ = os.WriteFile(golden, got, 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("agent ClusterRole differs from golden (SPEC §4.2). Got:\n%s", got)
	}
	for _, r := range rules(t, cr) {
		for _, res := range r.Resources {
			if res == "secrets" || strings.Contains(res, "/exec") || strings.Contains(res, "/attach") || strings.Contains(res, "/portforward") {
				t.Errorf("forbidden resource %q in ClusterRole", res)
			}
		}
		for _, v := range r.Verbs {
			if v != "get" && v != "list" && v != "watch" {
				t.Errorf("write verb %q in ClusterRole", v)
			}
		}
	}
}

// F3: the opt-in Secret inventory adds exactly secrets list/watch (no get)
// and nothing else; off by default (the default golden has no secrets).
func TestAgentSecretsInventoryRBAC(t *testing.T) {
	cr := find(render(t, "--set", "secretsInventory.enabled=true"), "ClusterRole", "olympos-agent-olympos-system")
	got, _ := yaml.Marshal(map[string]any{"rules": cr["rules"]})
	golden := "testdata/agent-clusterrole-secrets.golden.yaml"
	if *update {
		_ = os.WriteFile(golden, got, 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("agent ClusterRole (secretsInventory) differs from golden. Got:\n%s", got)
	}
	n := 0
	for _, r := range rules(t, cr) {
		for _, res := range r.Resources {
			if res == "secrets" {
				n++
				if strings.Join(r.Verbs, ",") != "list,watch" || len(r.ResourceNames) != 0 {
					t.Fatalf("secrets rule must be list/watch only: %+v", r)
				}
			}
		}
	}
	if n != 1 {
		t.Fatalf("secrets rules: %d", n)
	}
}

// The agent's Role names its own identity Secret and, with the probe
// enabled (the default), the probe's, which it keeps (synthetic monitoring
// decision 1): nothing else, and no list/watch/create/delete.
func TestAgentIdentitySecretOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		want  []string
	}{
		{"probe enabled", nil, []string{"olympos-agent-identity", "olympos-probe-identity"}},
		{"probe disabled", []string{"--set", "probe.enabled=false"}, []string{"olympos-agent-identity"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role := find(render(t, tc.extra...), "Role", "olympos-agent-identity")
			if role == nil {
				t.Fatal("identity Role missing")
			}
			rs := rules(t, role)
			if len(rs) != 1 || strings.Join(rs[0].ResourceNames, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("identity Role must name exactly %v: %+v", tc.want, rs)
			}
			if strings.Join(rs[0].Resources, ",") != "secrets" || len(rs[0].APIGroups) != 1 || rs[0].APIGroups[0] != "" {
				t.Fatalf("identity Role must be for core secrets only: %+v", rs[0])
			}
			for _, v := range rs[0].Verbs {
				if v == "list" || v == "watch" || v == "create" || v == "delete" {
					t.Fatalf("identity Role verb %q not allowed", v)
				}
			}
		})
	}
}

func TestBenchRBACOnlyWhenEnabled(t *testing.T) {
	if find(render(t), "Role", "olympos-agent-bench") != nil {
		t.Fatal("bench RBAC rendered while bench.enabled=false")
	}
	docs := render(t, "--set", "bench.enabled=true")
	role := find(docs, "Role", "olympos-agent-bench")
	if role == nil {
		t.Fatal("bench Role missing when enabled")
	}
	md := role["metadata"].(map[string]any)
	if md["namespace"] != "olympos-bench" {
		t.Fatalf("bench Role namespace %v", md["namespace"])
	}
	ns := find(docs, "Namespace", "olympos-bench")
	if ns == nil || ns["metadata"].(map[string]any)["labels"].(map[string]any)["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Fatal("olympos-bench namespace must be PSA privileged")
	}
}

func TestAgentPodHardening(t *testing.T) {
	d := find(render(t), "Deployment", "olympos-agent")
	b, _ := yaml.Marshal(d)
	s := string(b)
	for _, want := range []string{"runAsNonRoot: true", "readOnlyRootFilesystem: true", "allowPrivilegeEscalation: false", "type: RuntimeDefault", "- ALL"} {
		if !strings.Contains(s, want) {
			t.Errorf("agent Deployment missing %q", want)
		}
	}
	if strings.Contains(s, "containerPort") {
		t.Error("agent must not expose ports")
	}
}

func TestAgentBindingSubject(t *testing.T) {
	b := find(render(t), "ClusterRoleBinding", "olympos-agent-olympos-system")
	if b == nil {
		t.Fatal("binding missing")
	}
	s := b["subjects"].([]any)[0].(map[string]any)
	if s["name"] != "olympos-agent" || s["namespace"] != "olympos-system" {
		t.Fatalf("binding subject %v", s)
	}
}

func TestBenchKyvernoExceptionsOptIn(t *testing.T) {
	docs := render(t, "--set", "bench.enabled=true")
	for _, d := range docs {
		if d["kind"] == "PolicyException" {
			t.Fatalf("PolicyException rendered without opt-in: %v", d["apiVersion"])
		}
	}
	docs = render(t, "--set", "bench.enabled=true", "--set", "bench.kyverno.policyRefs[0].name=p", "--set", "bench.kyverno.policyRefs[0].kind=ValidatingPolicy")
	found := false
	for _, d := range docs {
		if d["kind"] == "PolicyException" && d["apiVersion"] == "policies.kyverno.io/v1" {
			found = true
		}
	}
	if !found {
		t.Fatal("policies.kyverno.io/v1 PolicyException missing")
	}
}

// Values from an older release (helm upgrade --reuse-values) lack newer keys.
func TestBenchToleratesOldValues(t *testing.T) {
	render(t, "--set", "bench.enabled=true", "--set", "bench.kyverno=null")
}

func renderServer(t *testing.T, extra ...string) ([]map[string]any, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	cmd := exec.Command("helm", append([]string{"template", "o", "olympos-server", "--namespace", "olympos"}, extra...)...)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.New(stderr.String())
	}
	var docs []map[string]any
	dec := utilyaml.NewYAMLOrJSONDecoder(&out, 4096)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}
		if m != nil {
			docs = append(docs, m)
		}
	}
	return docs, nil
}

// F5: single replica by default, a second one only when explicitly enabled.
func TestServerSingleReplica(t *testing.T) {
	docs, err := renderServer(t)
	if err != nil {
		t.Fatal(err)
	}
	dep := find(docs, "Deployment", "o")
	spec, _ := dep["spec"].(map[string]any)
	if spec["replicas"] != float64(1) && spec["replicas"] != int64(1) && spec["replicas"] != 1 {
		t.Fatalf("replicas: %v", spec["replicas"])
	}
	if st, _ := spec["strategy"].(map[string]any); st["type"] != "Recreate" {
		t.Fatalf("strategy: %v", spec["strategy"])
	}
	cm := find(docs, "ConfigMap", "o-config")
	if data, _ := cm["data"].(map[string]any); !strings.Contains(data["config.yaml"].(string), "multiReplica: false") {
		t.Fatalf("config: %v", data["config.yaml"])
	}
	if _, err := renderServer(t, "--set", "replicas=2"); err == nil || !strings.Contains(err.Error(), "single replica") {
		t.Fatalf("replicas=2 must fail: %v", err)
	}
	docs, err = renderServer(t, "--set", "replicas=2", "--set", "experimental.multiReplica=true")
	if err != nil {
		t.Fatal(err)
	}
	if spec, _ := find(docs, "Deployment", "o")["spec"].(map[string]any); spec["strategy"] != nil {
		t.Fatalf("multiReplica keeps the rolling update: %v", spec["strategy"])
	}
}

// F17: the bundled PostgreSQL by default; only the server may reach it.
func TestServerBundledPostgreSQL(t *testing.T) {
	docs, err := renderServer(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range [][2]string{{"StatefulSet", "o-postgresql"}, {"Service", "o-postgresql"}, {"Secret", "o-postgresql"}, {"NetworkPolicy", "o-postgresql"}} {
		if find(docs, k[0], k[1]) == nil {
			t.Fatalf("%s %s missing", k[0], k[1])
		}
	}
	sts, _ := yaml.Marshal(find(docs, "StatefulSet", "o-postgresql"))
	if !strings.Contains(string(sts), "@sha256:") || !strings.Contains(string(sts), "scram-sha-256") {
		t.Fatalf("postgres image must be pinned by digest and use SCRAM:\n%s", sts)
	}
	np, _ := yaml.Marshal(find(docs, "NetworkPolicy", "o-postgresql"))
	if !strings.Contains(string(np), "app.kubernetes.io/name: olympos-server") {
		t.Fatalf("network policy must admit only the server:\n%s", np)
	}
	cfg := find(docs, "ConfigMap", "o-config")["data"].(map[string]any)["config.yaml"].(string)
	if !strings.Contains(cfg, "dsn: postgres://olympos@o-postgresql.olympos.svc:5432/olympos") || !strings.Contains(cfg, "passwordFile: /etc/olympos/db/password") {
		t.Fatalf("config: %s", cfg)
	}
	docs, err = renderServer(t, "--set", "postgresql.bundled=false", "--set", "olympos.database.dsnRef=kv://kv/dsn")
	if err != nil {
		t.Fatal(err)
	}
	if find(docs, "StatefulSet", "o-postgresql") != nil {
		t.Fatal("external database: no bundled PostgreSQL")
	}
	if _, err := renderServer(t, "--set", "olympos.database.dsnRef=kv://kv/dsn"); err == nil {
		t.Fatal("bundled + dsnRef must fail")
	}
}

// The chart owns listen ports, experimental and (with gatewayTLSSecret) the
// gateway certificate files, and merges them with what the user sets: a
// section written twice is a duplicate key and the server does not start.
func TestServerConfigMergesUserSections(t *testing.T) {
	values := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(values, []byte(`gatewayTLSSecret: gw
olympos:
  listen: {http: ":9999", tlsCertFile: /etc/olympos/ui/tls.crt, tlsKeyFile: /etc/olympos/ui/tls.key}
  gateway: {extraSANs: [gw.example]}
  experimental: {multiReplica: false}
  entra: {tenantID: 00000000-0000-0000-0000-0000000000aa, clientID: app, clientSecretRef: "kv://kv-test/oidc"}
  keyVault: {name: kv-test}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	docs, err := renderServer(t, "-f", values)
	if err != nil {
		t.Fatal(err)
	}
	cm := find(docs, "ConfigMap", "o-config")
	if cm == nil {
		t.Fatal("no config ConfigMap")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cm["data"].(map[string]any)["config.yaml"].(string)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path) // fails on a duplicate key
	if err != nil {
		t.Fatalf("server cannot load the rendered config: %v", err)
	}
	if cfg.Listen.HTTP != ":8080" || cfg.Listen.Metrics != ":9090" {
		t.Errorf("listen ports must match the container ports: %+v", cfg.Listen)
	}
	if cfg.Listen.TLSCertFile != "/etc/olympos/ui/tls.crt" || cfg.Listen.TLSKeyFile != "/etc/olympos/ui/tls.key" {
		t.Errorf("UI TLS files dropped: %+v", cfg.Listen)
	}
	if cfg.Gateway.TLSCertFile != "/etc/olympos/gateway-tls/tls.crt" || len(cfg.Gateway.ExtraSANs) != 1 {
		t.Errorf("gateway: %+v", cfg.Gateway)
	}
}

func TestServerExternalDatabaseNeedsDSN(t *testing.T) {
	if _, err := renderServer(t, "--set", "postgresql.bundled=false"); err == nil || !strings.Contains(err.Error(), "needs olympos.database.dsnRef") {
		t.Fatalf("external database without a DSN must fail to render: %v", err)
	}
	if _, err := renderServer(t, "--set", "postgresql.bundled=false", "--set", "olympos.database.dsnRef=kv://v/dsn"); err != nil {
		t.Fatal(err)
	}
}
