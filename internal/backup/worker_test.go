package backup_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

type finishedRun struct {
	Status, Error, BlobPath, SHA, Tier string
	Bytes, Wire                        int64
	StartedAt, FinishedAt              *time.Time
}

func loadRun(t *testing.T, db *store.DB, id uuid.UUID) finishedRun {
	t.Helper()
	var r finishedRun
	if err := db.QueryRow(context.Background(), `SELECT status, error, blob_path, sha256, tier, bytes, wire_bytes, started_at, finished_at
		FROM backup_runs WHERE id = $1`, id).Scan(&r.Status, &r.Error, &r.BlobPath, &r.SHA, &r.Tier, &r.Bytes, &r.Wire, &r.StartedAt, &r.FinishedAt); err != nil {
		t.Fatal(err)
	}
	return r
}

func queue(t *testing.T, db *store.DB, job uuid.UUID, trigger string, at *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for) VALUES ($1,$2,'queued',$3) RETURNING id`,
		job, trigger, at).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func newWorker(t *testing.T, db *store.DB, d *fakeDialer, b *fakeBlobs) *backup.Worker {
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	return &backup.Worker{DB: db, Log: quietLog(), Dialer: d, Blobs: b, Creds: &backup.Credentials{KV: kv, Envelope: &secrets.Envelope{KV: kv}},
		Global: 4, PerCluster: 1}
}

func claimAndRun(t *testing.T, w *backup.Worker, want uuid.UUID) {
	t.Helper()
	id, err := w.Claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != want {
		t.Fatalf("claimed %s, want %s", id, want)
	}
	w.Execute(context.Background(), id)
}

func TestWorkerSuccessManifestAndTier(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod-aks", nil, "online")
	ch := addChannel(t, db)
	job := addJob(t, db, f, jobOpts{cron: "0 2 * * *", tz: "Europe/Istanbul", enabled: true, channel: &ch, options: `{"databases":["a"]}`})
	d, b := newDialer(f.ClusterID), newBlobs("olympos/")
	w := newWorker(t, db, d, b)

	// First scheduled run of November (Istanbul time) → monthly.
	first := time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC) // 2026-11-01 02:00 +03
	run1 := queue(t, db, job, "schedule", &first)
	claimAndRun(t, w, run1)
	r := loadRun(t, db, run1)
	if r.Status != "succeeded" || r.Tier != "monthly" || r.Error != "" {
		t.Fatalf("run: %+v", r)
	}
	sum := sha256.Sum256(fakePayload)
	if r.SHA != hex.EncodeToString(sum[:]) || r.Bytes != int64(len(fakePayload)) || r.Wire != 2*wirePerConn {
		t.Fatalf("sha/bytes/wire: %+v", r)
	}
	day := r.StartedAt.UTC().Format("2006/01/02")
	wantPath := "olympos/prod-aks/db/orders/clickhouse/" + day + "/" + run1.String() + ".tar"
	if r.BlobPath != wantPath {
		t.Fatalf("blob path %s, want %s", r.BlobPath, wantPath)
	}
	if string(b.blobs[wantPath]) != string(fakePayload) || b.tags[wantPath][backup.TierTag] != "monthly" {
		t.Fatalf("blob/tags: %v", b.tags[wantPath])
	}
	mPath := "olympos/prod-aks/db/orders/clickhouse/" + day + "/" + run1.String() + ".manifest.json"
	var m backup.Manifest
	if err := json.Unmarshal(b.blobs[mPath], &m); err != nil {
		t.Fatalf("manifest %s: %v (%v)", mPath, err, keysOf(b.blobs))
	}
	if m.Format != backup.ManifestFormat || m.RunID != run1 || m.JobID != job || m.Blob.SHA256 != r.SHA || m.Blob.Size != r.Bytes ||
		m.WireBytes != 2*wirePerConn || m.Engine != fakeEngineName || m.ServerVersion != "fake 1.0" || m.ToolVersion != "fakedump 2" ||
		m.Tier != "monthly" || m.Cluster.Name != "prod-aks" || m.Target.Namespace != "db" || m.Target.Service != "orders" ||
		m.Target.TLSServerName != "orders.db.svc" || m.TransferMode != "e2e-tls" || m.TLS == nil || !*m.TLS ||
		!strings.Contains(string(m.EngineOptions), `"databases"`) || m.Details["restore"] != "cat" || m.ScheduledFor == nil {
		t.Fatalf("manifest: %+v", m)
	}
	if b.tags[mPath][backup.TierTag] != "monthly" {
		t.Fatal("manifest not tagged")
	}
	ev := events(t, db, "backup.succeeded")
	if len(ev) != 1 || ev[0].Channel == nil || *ev[0].Channel != ch {
		t.Fatalf("succeeded event: %+v", ev)
	}
	var tlsOK *bool
	_ = db.QueryRow(ctx, `SELECT tls_ok FROM targets WHERE id = $1`, f.TargetID).Scan(&tlsOK)
	if tlsOK == nil || !*tlsOK {
		t.Fatal("tls_ok not recorded")
	}

	// Finished rows are immutable.
	if _, err := db.Exec(ctx, `UPDATE backup_runs SET status = 'failed' WHERE id = $1`, run1); err == nil {
		t.Fatal("finished run updated")
	}
	if _, err := db.Exec(ctx, `DELETE FROM backup_runs WHERE id = $1`, run1); err == nil {
		t.Fatal("run deleted")
	}

	// Next day, same ISO week (Mon 2 Nov is a new week: Nov 1 2026 is a Sunday).
	second := time.Date(2026, 11, 1, 23, 0, 0, 0, time.UTC) // Mon 2 Nov 02:00 +03 → new ISO week
	run2 := queue(t, db, job, "schedule", &second)
	claimAndRun(t, w, run2)
	if tr := loadRun(t, db, run2).Tier; tr != "weekly" {
		t.Fatalf("tier %s, want weekly", tr)
	}
	third := time.Date(2026, 11, 2, 23, 0, 0, 0, time.UTC) // Tue 3 Nov
	run3 := queue(t, db, job, "schedule", &third)
	claimAndRun(t, w, run3)
	if tr := loadRun(t, db, run3).Tier; tr != "daily" {
		t.Fatalf("tier %s, want daily", tr)
	}
	// Manual → daily; test → test (and no notification).
	run4 := queue(t, db, job, "manual", nil)
	claimAndRun(t, w, run4)
	if tr := loadRun(t, db, run4).Tier; tr != "daily" {
		t.Fatalf("manual tier %s", tr)
	}
	run5 := queue(t, db, job, "test", nil)
	claimAndRun(t, w, run5)
	r5 := loadRun(t, db, run5)
	if r5.Tier != "test" || r5.Status != "succeeded" || b.tags[r5.BlobPath][backup.TierTag] != "test" {
		t.Fatalf("test run: %+v", r5)
	}
	if n := len(events(t, db, "backup.succeeded")); n != 4 {
		t.Fatalf("succeeded events: %d (test runs must not notify)", n)
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestWorkerFailureScrubsSecrets(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod", nil, "online")
	w := newWorker(t, db, newDialer(f.ClusterID), newBlobs(""))
	const canary = "Canary-Pw-91af3c"
	credID, err := w.Creds.Insert(ctx, db, backup.CredentialInput{Source: backup.SourceStored, Username: "backup", Password: canary})
	if err != nil {
		t.Fatal(err)
	}
	job := addJob(t, db, f, jobOpts{enabled: true, credential: &credID, options: `{"fail":true,"leak_secret":true}`})
	run := queue(t, db, job, "manual", nil)
	claimAndRun(t, w, run)
	r := loadRun(t, db, run)
	if r.Status != "failed" || r.FinishedAt == nil || strings.Contains(r.Error, canary) || !strings.Contains(r.Error, "dump failed") {
		t.Fatalf("run: %+v", r)
	}
	ev := events(t, db, "backup.failed")
	if len(ev) != 1 {
		t.Fatalf("failed events: %+v", ev)
	}
	raw, _ := json.Marshal(ev[0].Payload)
	if strings.Contains(string(raw), canary) {
		t.Fatal("secret in event")
	}

	// Upload failure.
	job2 := addJob(t, db, f, jobOpts{enabled: true, credential: &credID})
	w.Blobs.(*fakeBlobs).fail = errors.New("403 AuthorizationPermissionMismatch")
	run2 := queue(t, db, job2, "manual", nil)
	claimAndRun(t, w, run2)
	r2 := loadRun(t, db, run2)
	if r2.Status != "failed" || !strings.Contains(r2.Error, "AuthorizationPermissionMismatch") || r2.BlobPath != "" {
		t.Fatalf("upload failure: %+v", r2)
	}
}

func TestWorkerAgentOffline(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	off := seed(t, db, "offline-cluster", nil, "offline")
	other := seed(t, db, "elsewhere", nil, "online") // connected to another replica
	w := newWorker(t, db, newDialer(), newBlobs(""))
	jOff := addJob(t, db, off, jobOpts{enabled: true})
	jOther := addJob(t, db, other, jobOpts{enabled: true})
	rOff := queue(t, db, jOff, "manual", nil)
	rOther := queue(t, db, jOther, "manual", nil)
	id, err := w.Claim(ctx)
	if err != nil || id != uuid.Nil {
		t.Fatalf("claim: %v %v", id, err)
	}
	if r := loadRun(t, db, rOff); r.Status != "failed" || r.Error != "agent_offline" {
		t.Fatalf("offline run: %+v", r)
	}
	if r := loadRun(t, db, rOther); r.Status != "queued" {
		t.Fatalf("run of a cluster connected elsewhere must stay queued: %+v", r)
	}
	ev := events(t, db, "backup.failed")
	if len(ev) != 1 || ev[0].Payload["reason"] != "agent_offline" {
		t.Fatalf("events: %+v", ev)
	}
}

func TestWorkerPerClusterConcurrency(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	a := seed(t, db, "a", nil, "online")
	b := seed(t, db, "b", nil, "online")
	w := newWorker(t, db, newDialer(a.ClusterID, b.ClusterID), newBlobs(""))
	w.PerCluster = 1
	a1 := queue(t, db, addJob(t, db, a, jobOpts{}), "manual", nil)
	a2 := queue(t, db, addJob(t, db, a, jobOpts{}), "manual", nil)
	b1 := queue(t, db, addJob(t, db, b, jobOpts{}), "manual", nil)
	got := map[uuid.UUID]bool{}
	for i := 0; i < 3; i++ {
		id, err := w.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id != uuid.Nil {
			got[id] = true
		}
	}
	if len(got) != 2 || !got[a1] || !got[b1] || got[a2] {
		t.Fatalf("claimed %v (a1=%s a2=%s b1=%s)", got, a1, a2, b1)
	}
	// Once a1 finishes, a2 becomes claimable.
	w.Execute(ctx, a1)
	if id, _ := w.Claim(ctx); id != a2 {
		t.Fatalf("expected a2, got %s", id)
	}

	// Run loop end-to-end with global=1: everything completes.
	w.Execute(ctx, b1)
	w.Execute(ctx, a2)
	a3 := queue(t, db, addJob(t, db, a, jobOpts{}), "manual", nil)
	a4 := queue(t, db, addJob(t, db, a, jobOpts{}), "manual", nil)
	w.Global, w.Poll = 1, 20*time.Millisecond
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(rctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (loadRun(t, db, a3).Status != "succeeded" || loadRun(t, db, a4).Status != "succeeded") {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if loadRun(t, db, a3).Status != "succeeded" || loadRun(t, db, a4).Status != "succeeded" {
		t.Fatal("run loop did not finish runs")
	}
}

func TestWorkerReapsStaleRuns(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod", nil, "online")
	w := newWorker(t, db, newDialer(f.ClusterID), newBlobs(""))
	w.StaleAfter = time.Second
	run := queue(t, db, addJob(t, db, f, jobOpts{}), "manual", nil)
	if id, _ := w.Claim(ctx); id != run {
		t.Fatal("not claimed")
	}
	time.Sleep(1500 * time.Millisecond)
	if err := w.ReapStale(ctx); err != nil {
		t.Fatal(err)
	}
	if r := loadRun(t, db, run); r.Status != "failed" || !strings.Contains(r.Error, "interrupted") {
		t.Fatalf("stale run: %+v", r)
	}
}

func TestTargetGonePausesJobs(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod", nil, "online")
	job := addJob(t, db, f, jobOpts{enabled: true, last: ptr(time.Now().Add(-48 * time.Hour))})
	err := store.Tx(ctx, db, func(tx pgxTx) error { return backup.OnTargetGone(ctx, tx, f.ClusterID, f.TargetID) })
	if err != nil {
		t.Fatal(err)
	}
	var reason string
	_ = db.QueryRow(ctx, `SELECT paused_reason FROM backup_jobs WHERE id = $1`, job).Scan(&reason)
	if reason != backup.PausedTargetGone {
		t.Fatalf("paused_reason %q", reason)
	}
	ev := events(t, db, "backup.failed")
	if len(ev) != 1 || ev[0].Payload["reason"] != "target_gone" {
		t.Fatalf("events: %+v", ev)
	}
	err = store.Tx(ctx, db, func(tx pgxTx) error {
		return backup.OnTargetUpsert(ctx, tx, f.ClusterID, pbTarget(f.TargetID))
	})
	if err != nil {
		t.Fatal(err)
	}
	var last time.Time
	_ = db.QueryRow(ctx, `SELECT paused_reason, last_scheduled_for FROM backup_jobs WHERE id = $1`, job).Scan(&reason, &last)
	if reason != "" || time.Since(last) > time.Minute {
		t.Fatalf("not resumed: %q %v", reason, last)
	}
}
