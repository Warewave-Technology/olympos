//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type auditRun struct {
	ID            string  `json:"id"`
	Tool          string  `json:"tool"`
	ClusterID     string  `json:"cluster_id"`
	Status        string  `json:"status"`
	Score         *float64 `json:"score"`
	NewFindings   int     `json:"new_findings"`
	Error         string  `json:"error"`
	BenchNodes    []struct {
		NodeName       string `json:"node_name"`
		Benchmark      string `json:"benchmark"`
		State          string `json:"state"`
		Pass           int    `json:"pass"`
		Fail           int    `json:"fail"`
		ControlPlaneNA bool   `json:"control_plane_na"`
	} `json:"bench_nodes"`
}

func auditSchedule(t *testing.T, c *client, tool string, frameworks []string) string {
	t.Helper()
	var s struct {
		Items []struct {
			ID   string `json:"id"`
			Tool string `json:"tool"`
		} `json:"items"`
	}
	c.must("GET", "/audit/schedules", nil, &s, 200)
	for _, x := range s.Items {
		if x.Tool == tool {
			return x.ID
		}
	}
	var created struct{ ID string `json:"id"` }
	body := map[string]any{"tool": tool, "scope_selector": "env=lab", "cron": "0 3 * * *", "timezone": "UTC", "enabled": true}
	if frameworks != nil {
		body["frameworks"] = frameworks
	}
	c.must("POST", "/audit/schedules", body, &created, 201)
	return created.ID
}

func runAudit(t *testing.T, c *client, scheduleID string, timeout time.Duration) auditRun {
	t.Helper()
	var queued struct{ Items []auditRun }
	c.must("POST", "/audit/schedules/"+scheduleID+"/run", map[string]any{"cluster_id": labClusterID}, &queued, 202)
	if len(queued.Items) != 1 {
		t.Fatalf("queued runs: %+v", queued.Items)
	}
	var r auditRun
	eventually(t, timeout, "audit run "+queued.Items[0].ID, func() (bool, string) {
		c.must("GET", "/audit/runs/"+queued.Items[0].ID, nil, &r, 200)
		return r.Status == "succeeded" || r.Status == "failed", r.Status
	})
	if r.Status != "succeeded" {
		t.Fatalf("%s run failed: %s", r.Tool, r.Error)
	}
	return r
}

// TestM4Audit runs polaris and kubescape through the read-only API proxy,
// then kube-bench as per-node Jobs after enabling the exception.
func TestM4Audit(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")

	t.Run("polaris", func(t *testing.T) {
		r := runAudit(t, admin, auditSchedule(t, admin, "polaris", nil), 10*time.Minute)
		var fs struct{ Items []map[string]any }
		admin.must("GET", "/findings?source=polaris&status=open&cluster="+labClusterID, nil, &fs, 200)
		if len(fs.Items) == 0 {
			t.Fatalf("polaris produced no findings (run %+v)", r)
		}
	})

	t.Run("kubescape", func(t *testing.T) {
		r := runAudit(t, admin, auditSchedule(t, admin, "kubescape", []string{"nsa"}), 20*time.Minute)
		if r.Score == nil {
			t.Errorf("kubescape run has no score")
		}
		var fs struct{ Items []map[string]any }
		admin.must("GET", "/findings?source=kubescape&status=open&cluster="+labClusterID, nil, &fs, 200)
		if len(fs.Items) == 0 {
			t.Fatal("kubescape produced no findings")
		}
	})

	t.Run("kube-bench", func(t *testing.T) {
		// Enable the exception on the agent; RBAC + namespace appear only now.
		sa := "system:serviceaccount:olympos-system:olympos-agent"
		run(t, "helm", "upgrade", "olympos-agent", "deploy/helm/olympos-agent", "-n", "olympos-system", "--reuse-values",
			"--set", "bench.enabled=true", "--wait", "--timeout", "3m")
		out, _ := runOK(t, "kubectl", "auth", "can-i", "--as", sa, "create", "jobs", "-n", "olympos-bench")
		if strings.TrimSpace(out) != "yes" {
			t.Fatalf("bench RBAC not rendered: %q", out)
		}
		out, _ = runOK(t, "kubectl", "auth", "can-i", "--as", sa, "create", "jobs", "-n", "lab")
		if strings.TrimSpace(out) != "no" {
			t.Fatalf("bench RBAC leaks outside olympos-bench: %q", out)
		}
		eventually(t, 2*time.Minute, "bench capability advertised", func() (bool, string) {
			var c struct {
				BenchEnabled bool   `json:"bench_enabled"`
				Status       string `json:"status"`
			}
			admin.must("GET", "/clusters/"+labClusterID, nil, &c, 200)
			return c.BenchEnabled && c.Status == "online", fmt.Sprintf("%+v", c)
		})
		r := runAudit(t, admin, auditSchedule(t, admin, "kube-bench", nil), 15*time.Minute)
		if len(r.BenchNodes) != 2 {
			t.Fatalf("bench nodes: %+v", r.BenchNodes)
		}
		for _, n := range r.BenchNodes {
			if n.State != "succeeded" || n.Pass+n.Fail == 0 {
				t.Errorf("node %s: %+v", n.NodeName, n)
			}
			if n.ControlPlaneNA {
				t.Errorf("on-prem cluster must not be control_plane_na: %s", n.NodeName)
			}
			if strings.Contains(n.NodeName, "control-plane") != strings.HasSuffix(n.Benchmark, "/master") {
				t.Errorf("benchmark %s on node %s", n.Benchmark, n.NodeName)
			}
		}
		// Jobs are cleaned up by the agent.
		eventually(t, time.Minute, "bench jobs deleted", func() (bool, string) {
			out := run(t, "kubectl", "-n", "olympos-bench", "get", "jobs", "-o", "name")
			return strings.TrimSpace(out) == "", out
		})
	})
}
