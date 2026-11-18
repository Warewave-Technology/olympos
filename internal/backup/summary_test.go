//go:build dev

package backup_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

func TestClusterSummariesAPI(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	db := e.DB
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// A prod cluster with nothing in it still gets a row.
	var empty uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, labels, status) VALUES ('prod-empty', '{"env":"prod"}', 'online') RETURNING id`).Scan(&empty); err != nil {
		t.Fatal(err)
	}
	// prod: the seeded target has an enabled job; one more candidate; a gone
	// target and a Vault-only target (no olympos.io/backup) do not count.
	exec(`INSERT INTO targets (id, cluster_id, namespace, service, port, engine, status) VALUES
		('t-prod-2', $1, 'db', 'second', 5432, 'postgresql', 'candidate'),
		('t-prod-gone', $1, 'db', 'old', 5432, 'postgresql', 'gone'),
		('t-prod-vault', $1, 'vault', 'vault', 8200, '', 'candidate')`, a.prod.ClusterID)
	job := addJob(t, db, a.prod, jobOpts{enabled: true})
	disabled := addJob(t, db, fixtureWithTarget(a.prod, "t-prod-2"), jobOpts{})
	exec(`UPDATE backup_jobs SET deleted_at = now() WHERE id = $1`, disabled) // deleted: t-prod-2 is a candidate again
	now := time.Now()
	run := func(status, trigger string, created time.Time, finished *time.Time, bytes int64) {
		t.Helper()
		exec(`INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, created_at, started_at, finished_at, bytes)
			VALUES ($1, $2, $3, $4, $4, $4, $5, $6)`, job, trigger, status, created, finished, bytes)
	}
	at := func(d time.Duration) *time.Time { x := now.Add(-d); return &x }
	run("succeeded", "schedule", now.Add(-40*24*time.Hour), at(40*24*time.Hour-time.Minute), 999) // outside 30 days
	run("succeeded", "schedule", now.Add(-26*time.Hour), at(25*time.Hour), 50)                    // in 30d, not in 24h
	run("succeeded", "schedule", now.Add(-3*time.Hour), at(2*time.Hour), 100)
	run("failed", "schedule", now.Add(-90*time.Minute), at(80*time.Minute), 0)
	run("missed", "schedule", now.Add(-4*time.Hour), nil, 0)
	run("succeeded", "test", now.Add(-time.Minute), at(30*time.Second), 7) // connection test: ignored

	all := e.Login(e.Principal("root", "Member", "viewer")) // scope "all"
	var resp struct{ Items []backup.ClusterSummary }
	if code := all.Do("GET", "/api/v1/backup/clusters", nil, &resp); code != 200 {
		t.Fatalf("GET /backup/clusters = %d", code)
	}
	rows := map[string]backup.ClusterSummary{}
	for _, s := range resp.Items {
		rows[s.ClusterName] = s
	}
	if len(resp.Items) != 3 || resp.Items[0].ClusterName != "dev-kind" {
		t.Fatalf("items = %+v", resp.Items)
	}
	p := rows["prod-aks"]
	if p.Targets != 2 || p.Candidates != 1 || p.Jobs != 1 || p.JobsEnabled != 1 {
		t.Errorf("prod counts = %+v", p)
	}
	if p.Last24h != (backup.RunCounts{Succeeded: 1, Failed: 1, Missed: 1}) || p.Bytes30d != 150 {
		t.Errorf("prod runs = %+v bytes=%d", p.Last24h, p.Bytes30d)
	}
	if p.LastSuccessAt == nil || p.LastSuccessAt.Sub(*at(2 * time.Hour)).Abs() > time.Second {
		t.Errorf("last success = %v", p.LastSuccessAt)
	}
	if d := rows["dev-kind"]; d.Targets != 1 || d.Candidates != 1 || d.Jobs != 0 || d.LastSuccessAt != nil {
		t.Errorf("dev = %+v", d)
	}
	if z := rows["prod-empty"]; z.ClusterID != empty || z.Targets != 0 || z.Jobs != 0 || z.Bytes30d != 0 || z.LastSuccessAt != nil {
		t.Errorf("empty = %+v", z)
	}

	// Scope: a prod viewer sees prod clusters only.
	viewer := e.Login(e.Principal("vic", "Member", "viewer@env=prod"))
	if code := viewer.Do("GET", "/api/v1/backup/clusters", nil, &resp); code != 200 {
		t.Fatalf("viewer = %d", code)
	}
	if len(resp.Items) != 2 || resp.Items[0].ClusterName != "prod-aks" || resp.Items[1].ClusterName != "prod-empty" {
		t.Errorf("viewer items = %+v", resp.Items)
	}
}

func fixtureWithTarget(f fixture, target string) fixture {
	f.TargetID = target
	return f
}
