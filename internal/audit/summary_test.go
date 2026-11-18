//go:build dev

package audit

import (
	"context"
	"net/http"
	"testing"
)

func TestAuditClusterSummaries(t *testing.T) {
	a := newAPIEnv(t)
	ctx, db := context.Background(), a.e.DB
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// prod: two kubescape runs (the newer one counts) and one polaris run.
	exec(`INSERT INTO audit_runs (tool, cluster_id, status, score, new_findings, finished_at, created_at) VALUES
		('kubescape', $1, 'succeeded', 71.5, 4, now() - interval '2 days', now() - interval '2 days'),
		('kubescape', $1, 'failed', NULL, 0, now() - interval '1 hour', now() - interval '1 hour'),
		('polaris', $1, 'succeeded', 88, 2, now() - interval '3 hours', now() - interval '3 hours')`, a.prod)
	exec(`INSERT INTO audit_runs (tool, cluster_id, status, created_at) VALUES ('kube-bench', $1, 'running', now())`, a.devBench)
	// Open audit findings count; resolved ones and non-audit sources do not.
	exec(`INSERT INTO findings (source, cluster_id, control_id, severity, resource_ref, title, status) VALUES
		('kubescape', $1, 'C-0016', 'critical', 'a', 't', 'open'),
		('kubescape', $1, 'C-0017', 'high', 'a', 't', 'open'),
		('polaris', $1, 'runAsRoot', 'high', 'b', 't', 'open'),
		('polaris', $1, 'cpuLimits', 'medium', 'c', 't', 'open'),
		('kube-bench', $1, 'cis:4.2.6', 'low', 'node/n1', 't', 'open'),
		('kubescape', $1, 'C-0018', 'critical', 'z', 't', 'resolved'),
		('kyverno', $1, 'p/r', 'critical', 'k', 't', 'open'),
		('netpol', $1, 'netpol.no_default_deny', 'medium', 'web', 't', 'open')`, a.prod)

	all := a.e.Login(a.e.Principal("all", "Member", "viewer"))
	var resp struct{ Items []ClusterSummary }
	if code := all.Do("GET", "/api/v1/audit/clusters", nil, &resp); code != http.StatusOK {
		t.Fatalf("GET /audit/clusters = %d", code)
	}
	if len(resp.Items) != 3 || resp.Items[0].ClusterName != "dev-1" || resp.Items[1].ClusterName != "dev-bench" || resp.Items[2].ClusterName != "prod-1" {
		t.Fatalf("items = %+v", resp.Items)
	}
	dev, bench, prod := resp.Items[0], resp.Items[1], resp.Items[2]
	if len(dev.LastRuns) != 0 || dev.OpenFindings != (SeverityCounts{}) || dev.Provider != "onprem" || dev.BenchEnabled {
		t.Errorf("empty cluster = %+v", dev)
	}
	if !bench.BenchEnabled || len(bench.LastRuns) != 1 || bench.LastRuns[0].Status != "running" || bench.LastRuns[0].FinishedAt != nil {
		t.Errorf("bench cluster = %+v", bench)
	}
	runs := map[string]LastRun{}
	for _, r := range prod.LastRuns {
		runs[r.Tool] = r
	}
	if len(runs) != 2 || runs["kubescape"].Status != "failed" || runs["kubescape"].Score != nil ||
		runs["polaris"].Score == nil || *runs["polaris"].Score != 88 || runs["polaris"].NewFindings != 2 || prod.Provider != "azure" {
		t.Errorf("prod last runs = %+v", prod.LastRuns)
	}
	if prod.OpenFindings != (SeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1}) {
		t.Errorf("prod open findings = %+v", prod.OpenFindings)
	}

	// Scope: only readable clusters.
	viewer := a.e.Login(a.e.Principal("vic", "Member", "viewer@env=prod"))
	if code := viewer.Do("GET", "/api/v1/audit/clusters", nil, &resp); code != http.StatusOK {
		t.Fatalf("viewer = %d", code)
	}
	if len(resp.Items) != 1 || resp.Items[0].ClusterID != a.prod {
		t.Errorf("viewer items = %+v", resp.Items)
	}
}
