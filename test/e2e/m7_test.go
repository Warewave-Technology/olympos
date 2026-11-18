//go:build e2e

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestM7AgentNetworkCut (F18) cuts the lab agent's network to the server
// (NetworkPolicy + conntrack flush on its node; the kube API stays
// reachable) while a kube-bench run is in flight, starts a backup during
// the outage and restores the network. Expected: the backup is retried
// after the reconnect and succeeds, kube-bench results buffered by the
// agent arrive exactly once, nothing is resolved while offline, and the
// outage produces exactly one agent.offline and one agent.online message.
func TestM7AgentNetworkCut(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	var cl struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	admin.must("GET", "/clusters/"+labClusterID, nil, &cl, 200)
	if cl.Status != "online" {
		t.Fatalf("lab agent not online: %s", cl.Status)
	}
	psql := func(sql string) string {
		return strings.TrimSpace(run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--",
			"psql", "-U", "olympos", "-d", "olympos", "-At", "-c", sql))
	}
	events := func(typ string) int {
		n, _ := strconv.Atoi(psql(fmt.Sprintf(`SELECT count(*) FROM outbox WHERE event_type = '%s' AND payload->'fields'->>'cluster' = '%s'`, typ, cl.Name)))
		return n
	}
	openFindings := func() int {
		var fs struct{ Items []map[string]any }
		admin.must("GET", "/findings?status=open&cluster="+labClusterID+"&limit=1000", nil, &fs, 200)
		return len(fs.Items)
	}
	offline0, online0 := events("agent.offline"), events("agent.online")
	open0 := openFindings()

	// A kube-bench run is in flight: its Jobs run while the network is cut.
	var queued struct{ Items []auditRun }
	admin.must("POST", "/audit/schedules/"+auditSchedule(t, admin, "kube-bench", nil)+"/run", map[string]any{"cluster_id": labClusterID}, &queued, 202)
	benchID := queued.Items[0].ID
	eventually(t, 2*time.Minute, "kube-bench jobs started", func() (bool, string) {
		out := run(t, "kubectl", "-n", "olympos-bench", "get", "jobs", "-o", "name")
		return strings.TrimSpace(out) != "", out
	})

	// Cut: no traffic from the agent to the server pod; flushing conntrack
	// breaks the established gRPC stream too.
	serverIP := strings.TrimSpace(run(t, "kubectl", "-n", "olympos", "get", "pod", "-l", "app.kubernetes.io/name=olympos-server",
		"-o", "jsonpath={.items[0].status.podIP}"))
	node := strings.TrimSpace(run(t, "kubectl", "-n", "olympos-system", "get", "pod", "-l", "app.kubernetes.io/name=olympos-agent",
		"-o", "jsonpath={.items[0].spec.nodeName}"))
	policy := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: e2e-cut-agent, namespace: olympos-system}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
  - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [%s/32]}}]
`, serverIP)
	applyStdin(t, policy)
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "-n", "olympos-system", "delete", "networkpolicy", "e2e-cut-agent", "--ignore-not-found")
	})
	run(t, "docker", "exec", node, "conntrack", "-F")

	eventually(t, 3*time.Minute, "server marks the agent offline", func() (bool, string) {
		admin.must("GET", "/clusters/"+labClusterID, nil, &cl, 200)
		return cl.Status == "offline", cl.Status
	})
	// A backup during the outage fails quietly and waits for the reconnect.
	pg := labTarget(t, admin, "orders-pg")
	var jobs struct {
		Items []struct {
			ID     string `json:"id"`
			Target struct {
				ID string `json:"id"`
			} `json:"target"`
		} `json:"items"`
	}
	admin.must("GET", "/backup/jobs", nil, &jobs, 200)
	jobID := ""
	for _, j := range jobs.Items {
		if j.Target.ID == pg.ID {
			jobID = j.ID
		}
	}
	if jobID == "" {
		t.Skip("needs the orders-pg backup job (TestM2BackupsPostgresAndClickHouse)")
	}
	start := time.Now()
	admin.must("POST", "/backup/jobs/"+jobID+"/run", map[string]any{"trigger": "manual"}, nil, 202)
	eventually(t, time.Minute, "backup attempt fails and a retry is queued", func() (bool, string) {
		out := psql(fmt.Sprintf(`SELECT string_agg(status || ':' || attempt, ',' ORDER BY attempt) FROM backup_runs WHERE job_id = '%s' AND created_at > '%s'`,
			jobID, start.Add(-5*time.Second).UTC().Format(time.RFC3339)))
		return out == "failed:1,queued:2", out
	})
	// agent.offline after the (e2e: 20 s) debounce, exactly once.
	eventually(t, time.Minute, "agent.offline", func() (bool, string) {
		n := events("agent.offline") - offline0
		return n == 1, fmt.Sprint(n)
	})
	time.Sleep(15 * time.Second)
	if n := events("agent.offline") - offline0; n != 1 {
		t.Fatalf("agent.offline messages: %d, want 1", n)
	}
	if n := openFindings(); n < open0 {
		t.Fatalf("findings resolved while the agent was offline: %d → %d", open0, n)
	}

	// Restore the network: reconnect, one agent.online, retry succeeds.
	run(t, "kubectl", "-n", "olympos-system", "delete", "networkpolicy", "e2e-cut-agent")
	eventually(t, 3*time.Minute, "agent reconnects", func() (bool, string) {
		admin.must("GET", "/clusters/"+labClusterID, nil, &cl, 200)
		return cl.Status == "online", cl.Status
	})
	eventually(t, 3*time.Minute, "backup retry succeeds", func() (bool, string) {
		out := psql(fmt.Sprintf(`SELECT string_agg(status || ':' || attempt, ',' ORDER BY attempt) FROM backup_runs WHERE job_id = '%s' AND created_at > '%s'`,
			jobID, start.Add(-5*time.Second).UTC().Format(time.RFC3339)))
		return out == "failed:1,succeeded:2", out
	})
	if n := events("agent.online") - online0; n != 1 {
		t.Fatalf("agent.online messages: %d, want 1", n)
	}

	// kube-bench: buffered results arrived once per node (no duplicates).
	var r auditRun
	eventually(t, 15*time.Minute, "kube-bench run "+benchID, func() (bool, string) {
		admin.must("GET", "/audit/runs/"+benchID, nil, &r, 200)
		return r.Status == "succeeded" || r.Status == "failed" || r.Status == "missed", r.Status
	})
	if r.Status != "succeeded" || len(r.BenchNodes) != 2 {
		t.Fatalf("kube-bench after the cut: %s %s %+v", r.Status, r.Error, r.BenchNodes)
	}
	for _, n := range r.BenchNodes {
		if n.State != "succeeded" || len(n.Checks) < n.Pass+n.Fail || n.Pass+n.Fail == 0 {
			t.Errorf("node %s: %+v (%d checks)", n.NodeName, n.State, len(n.Checks))
		}
		// A duplicated chunk would corrupt the JSON or double the counts.
		if len(n.Checks) != n.Pass+n.Fail+n.Warn+n.Info {
			t.Errorf("node %s: %d checks for %d results", n.NodeName, len(n.Checks), n.Pass+n.Fail+n.Warn+n.Info)
		}
	}
}

func applyStdin(t *testing.T, manifest string) {
	t.Helper()
	out, err := runStdin(t, manifest, "kubectl", "apply", "-f", "-")
	if err != nil {
		t.Fatalf("kubectl apply: %v\n%s", err, out)
	}
}
