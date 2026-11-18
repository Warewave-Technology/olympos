package audit

import (
	"os"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/findings"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fkey struct{ control, ref, sev string }

func keys(fs []findings.Finding) map[fkey]bool {
	m := map[fkey]bool{}
	for _, f := range fs {
		m[fkey{f.ControlID, f.ResourceRef, f.Severity}] = true
	}
	return m
}

func TestNormalizeKubescape(t *testing.T) {
	n, err := NormalizeKubescape(fixture(t, "kubescape-run1.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[fkey]bool{
		{"C-0016", "default/Deployment/web", "medium"}:               true,
		{"C-0057", "default/Deployment/web", "high"}:                 true,
		{"C-0035", "ClusterRoleBinding/ops-admin", "medium"}:         true,
		{"C-0262", "kube-system/Pod/kube-apiserver-cp1", "critical"}: true,
	}
	got := keys(n.Findings)
	if len(got) != len(want) {
		t.Fatalf("findings = %v", got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %v in %v", k, got)
		}
	}
	if n.Score == nil || *n.Score != 77.1 {
		t.Fatalf("score = %v", n.Score)
	}
	for _, f := range n.Findings {
		if f.Title == "" {
			t.Errorf("empty title: %+v", f)
		}
	}
	if fw := n.Summary["frameworks"].(map[string]float64); fw["NSA"] != 74.5 {
		t.Errorf("frameworks = %v", fw)
	}
}

func TestKubescapeSeverityMapping(t *testing.T) {
	for sf, want := range map[float64]string{10: "critical", 9: "critical", 8: "high", 7: "high", 6: "medium", 4: "medium", 3: "low", 1: "low", 0: "info"} {
		if got := kubescapeSeverity(sf); got != want {
			t.Errorf("scoreFactor %v: %s want %s", sf, got, want)
		}
	}
}

func TestNormalizePolaris(t *testing.T) {
	n, err := NormalizePolaris(fixture(t, "polaris.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[fkey]bool{
		{"deploymentMissingReplicas", "default/Deployment/web", "medium"}:      true,
		{"hostNetworkSet", "default/Deployment/web", "high"}:                   true,
		{"runAsRootAllowed", "default/Deployment/web/container:nginx", "high"}: true,
	}
	got := keys(n.Findings)
	if len(got) != len(want) {
		t.Fatalf("findings = %v", got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %v", k)
		}
	}
	// successes 3 (hostIPC, cpuLimits, clusterrole), warnings 1, dangers 2 →
	// 6 / (6 + 1 + 4) = 54.5
	if n.Score == nil || *n.Score != 54.5 {
		t.Fatalf("score = %v", n.Score)
	}
}

func TestNormalizeKubeBenchManaged(t *testing.T) {
	bn, err := NormalizeKubeBench(fixture(t, "kube-bench-aks.json"), "aks-n1", "aks-1.8/node", true)
	if err != nil {
		t.Fatal(err)
	}
	// The control plane section (a FAIL) is N/A on managed: not counted.
	if bn.Pass != 3 || bn.Fail != 1 || bn.Warn != 1 || bn.Info != 0 || !bn.ControlPlaneNA {
		t.Fatalf("got %+v", bn)
	}
	if len(bn.Findings) != 1 || bn.Findings[0].ControlID != "aks-1.8:3.1.3" || bn.Findings[0].ResourceRef != "node/aks-n1" ||
		bn.Findings[0].Severity != "high" {
		t.Fatalf("findings = %+v", bn.Findings)
	}
	// Every counted result is kept as a check for the node detail view.
	if len(bn.Checks) != bn.Pass+bn.Fail+bn.Warn+bn.Info {
		t.Fatalf("checks = %d", len(bn.Checks))
	}
	var fail *BenchCheck
	for i := range bn.Checks {
		if bn.Checks[i].Status == "FAIL" {
			fail = &bn.Checks[i]
		}
	}
	if fail == nil || fail.ID != "3.1.3" || fail.Description == "" || fail.Section == "" || fail.NodeType == "" {
		t.Fatalf("fail check = %+v", fail)
	}
}

func TestNormalizeKubeBenchOnPremMaster(t *testing.T) {
	raw := fixture(t, "kube-bench-master.json")
	bn, err := NormalizeKubeBench(raw, "cp1", "cis-1.12/master", false)
	if err != nil {
		t.Fatal(err)
	}
	if bn.Pass != 2 || bn.Fail != 2 || bn.Warn != 1 || bn.Info != 1 || bn.ControlPlaneNA {
		t.Fatalf("got %+v", bn)
	}
	got := keys(bn.Findings)
	if !got[fkey{"cis-1.12:1.1.12", "node/cp1", "high"}] || !got[fkey{"cis-1.12:4.2.6", "node/cp1", "medium"}] || len(got) != 2 {
		t.Fatalf("findings = %v", got)
	}
	// Same output treated as managed: master section dropped.
	bn, _ = NormalizeKubeBench(raw, "cp1", "cis-1.12/master", true)
	if bn.Pass != 1 || bn.Fail != 1 || len(bn.Findings) != 1 || !bn.ControlPlaneNA {
		t.Fatalf("managed: %+v", bn)
	}
}

func TestNormalizeRejectsGarbage(t *testing.T) {
	if _, err := NormalizeKubescape([]byte("not json")); err == nil {
		t.Error("kubescape")
	}
	if _, err := NormalizePolaris([]byte("{")); err == nil {
		t.Error("polaris")
	}
	if _, err := NormalizeKubeBench([]byte("fake logs"), "n", "cis-1.12/node", false); err == nil {
		t.Error("kube-bench")
	}
}
