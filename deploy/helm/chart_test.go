// Package helm tests the rendered Helm charts (SPEC §18: agent RBAC matches
// §4.2 exactly — golden file; bench RBAC only when enabled).
package helm

import (
	"bytes"
	"encoding/base64"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

var update = flag.Bool("update", false, "rewrite golden files")

func render(t *testing.T, extra ...string) []map[string]any {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	args := append([]string{"template", "a", "olympos-agent", "--namespace", "olympos-system",
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
			if res == "secrets" || res == "configmaps" || strings.Contains(res, "/exec") || strings.Contains(res, "/attach") || strings.Contains(res, "/portforward") {
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

func TestAgentIdentitySecretOnly(t *testing.T) {
	docs := render(t)
	role := find(docs, "Role", "olympos-agent-identity")
	if role == nil {
		t.Fatal("identity Role missing")
	}
	rs := rules(t, role)
	if len(rs) != 1 || len(rs[0].ResourceNames) != 1 || rs[0].ResourceNames[0] != "olympos-agent-identity" {
		t.Fatalf("identity Role must be resourceNames-restricted: %+v", rs)
	}
	for _, v := range rs[0].Verbs {
		if v == "list" || v == "watch" || v == "create" || v == "delete" {
			t.Fatalf("identity Role verb %q not allowed", v)
		}
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
