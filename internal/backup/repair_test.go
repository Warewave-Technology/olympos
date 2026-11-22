//go:build dev

package backup_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// yearly gives a retry window of weeks: half the time to the next 1 January.
const yearly = "0 0 1 1 *"

type repairRow struct {
	ID           uuid.UUID
	Trigger      string
	Status       string
	ScheduledFor *time.Time
	Attempt      int
	RetryUntil   *time.Time
	RepairOf     *uuid.UUID
	Dests        []uuid.UUID
}

// queuedRuns returns the job's queued runs, oldest first.
func queuedRuns(t *testing.T, db *store.DB, job uuid.UUID) []repairRow {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id, trigger, status, scheduled_for, attempt, retry_until, repair_of, destination_ids
		FROM backup_runs WHERE job_id = $1 AND status = 'queued' ORDER BY created_at`, job)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []repairRow
	for rows.Next() {
		var r repairRow
		if err := rows.Scan(&r.ID, &r.Trigger, &r.Status, &r.ScheduledFor, &r.Attempt, &r.RetryUntil, &r.RepairOf, &r.Dests); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// onlyRepair asserts exactly one queued run, a repair of orig for dests.
func onlyRepair(t *testing.T, db *store.DB, job, orig uuid.UUID, attempt int, dests ...uuid.UUID) repairRow {
	t.Helper()
	q := queuedRuns(t, db, job)
	if len(q) != 1 {
		t.Fatalf("queued runs: %+v", q)
	}
	r := q[0]
	if r.RepairOf == nil || *r.RepairOf != orig || r.Attempt != attempt || len(r.Dests) != len(dests) {
		t.Fatalf("repair: %+v", r)
	}
	for i := range dests {
		if r.Dests[i] != dests[i] {
			t.Fatalf("repair destinations %v, want %v", r.Dests, dests)
		}
	}
	return r
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// partialRun queues a scheduled run on the group job and runs it with
// member 2 failing.
func partialRun(t *testing.T, db *store.DB, g groupFixture) (uuid.UUID, time.Time) {
	t.Helper()
	g.B2.fail, g.B2.failAfter = errors.New("503 ServerBusy"), 100
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	run := queue(t, db, g.Job, "schedule", &at)
	claimAndRun(t, g.W, run)
	if r := loadRun(t, db, run); r.Status != "partial" {
		t.Fatalf("run: %+v", r)
	}
	return run, at
}

func TestRepairQueuedAfterPartial(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{cron: yearly})
	orig, at := partialRun(t, db, g)

	rep := onlyRepair(t, db, g.Job, orig, 2, g.Dest2)
	want := backup.RetryWindow(yearly, "UTC", at)
	if rep.Trigger != "schedule" || rep.ScheduledFor == nil || !rep.ScheduledFor.Equal(at) || rep.RetryUntil == nil || !rep.RetryUntil.Equal(want) {
		t.Fatalf("repair keeps trigger, scheduled_for and window: %+v (window %s)", rep, want)
	}
	ev := events(t, db, "backup.%")
	if len(ev) != 1 || ev[0].Type != "backup.partial" {
		t.Fatalf("events: %+v", ev)
	}
	p := ev[0].Payload
	f, _ := p["fields"].(map[string]any)
	if p["run_id"] != orig.String() || p["job_id"] != g.Job.String() || p["repair_queued"] != true ||
		len(strs(p["missing_destinations"])) != 1 || strs(p["missing_destinations"])[0] != "dest-b" ||
		f["missing"] != "dest-b" || f["error"] != "dest-b: upload: 503 ServerBusy" || f["trigger"] != "schedule" ||
		f["cluster"] != "prod" || f["target"] != "db/orders" {
		t.Fatalf("backup.partial payload: %+v", p)
	}
}

func TestRepairSucceeds(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		t.Run(map[bool]string{false: "quiet", true: "opt-in"}[optIn], func(t *testing.T) {
			db := testutil.DB(t)
			g := seedGroup(t, db, jobOpts{cron: yearly})
			if _, err := db.Exec(context.Background(), `UPDATE backup_jobs SET notify_on_success = $2 WHERE id = $1`, g.Job, optIn); err != nil {
				t.Fatal(err)
			}
			orig, at := partialRun(t, db, g)
			rep := onlyRepair(t, db, g.Job, orig, 2, g.Dest2)
			g.B2.fail, g.B2.failAfter = nil, 0
			b1 := len(g.B1.blobs)
			claimAndRun(t, g.W, rep.ID)

			if r := loadRun(t, db, rep.ID); r.Status != "succeeded" {
				t.Fatalf("repair: %+v", r)
			}
			cs := loadCopies(t, db, rep.ID)
			if len(cs) != 1 || cs[0].Dest != g.Dest2 || cs[0].Status != "succeeded" || len(g.B1.blobs) != b1 {
				t.Fatalf("repair copies: %+v", cs)
			}
			// The tier is what the copy would have had in the original run.
			if cs[0].Tier != "monthly" {
				t.Fatalf("repair tier %s (scheduled %s)", cs[0].Tier, at)
			}
			if q := queuedRuns(t, db, g.Job); len(q) != 0 {
				t.Fatalf("nothing left to repair: %+v", q)
			}
			ev := events(t, db, "backup.succeeded")
			if !optIn {
				if len(ev) != 0 {
					t.Fatalf("backup.succeeded is opt-in: %+v", ev)
				}
			} else if len(ev) != 1 || ev[0].Payload["repair_of"] != orig.String() || ev[0].Payload["run_id"] != rep.ID.String() {
				t.Fatalf("backup.succeeded: %+v", ev)
			}
			if ev := events(t, db, "backup.failed"); len(ev) != 0 {
				t.Fatalf("failed events: %+v", ev)
			}
		})
	}
}

func TestRepairGivesUp(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{cron: yearly})
	orig, _ := partialRun(t, db, g)
	r2 := onlyRepair(t, db, g.Job, orig, 2, g.Dest2)
	claimAndRun(t, g.W, r2.ID)
	if r := loadRun(t, db, r2.ID); r.Status != "failed" {
		t.Fatalf("repair 2: %+v", r)
	}
	if ev := events(t, db, "backup.failed"); len(ev) != 0 {
		t.Fatalf("a repair with another one queued is quiet: %+v", ev)
	}
	r3 := onlyRepair(t, db, g.Job, orig, 3, g.Dest2) // repair_of: the original, not repair 2
	claimAndRun(t, g.W, r3.ID)
	if r := loadRun(t, db, r3.ID); r.Status != "failed" {
		t.Fatalf("repair 3: %+v", r)
	}
	if q := queuedRuns(t, db, g.Job); len(q) != 0 {
		t.Fatalf("attempt 3 is the last: %+v", q)
	}
	ev := events(t, db, "backup.failed")
	if len(ev) != 1 || ev[0].Payload["run_id"] != r3.ID.String() || ev[0].Payload["repair_of"] != orig.String() ||
		len(strs(ev[0].Payload["missing_destinations"])) != 1 || strs(ev[0].Payload["missing_destinations"])[0] != "dest-b" {
		t.Fatalf("backup.failed: %+v", ev)
	}
	if ev := events(t, db, "backup.partial"); len(ev) != 1 {
		t.Fatalf("only the original run is partial: %+v", ev)
	}
}

// A repair that writes some of the missing copies is partial and queues
// another repair for the rest.
func TestRepairPartial(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{cron: yearly})
	d3 := addDest(t, db, "dest-c")
	if _, err := db.Exec(ctx, `INSERT INTO destination_group_members (group_id, destination_id, position) VALUES ($1, $2, 2)`, g.Group, d3); err != nil {
		t.Fatal(err)
	}
	b3 := g.Blobs.dest(d3, "c")
	b3.fail = errors.New("403 Forbidden")
	orig, _ := partialRun(t, db, g)
	r2 := onlyRepair(t, db, g.Job, orig, 2, g.Dest2, d3)
	g.B2.fail, g.B2.failAfter = nil, 0
	claimAndRun(t, g.W, r2.ID)
	if r := loadRun(t, db, r2.ID); r.Status != "partial" {
		t.Fatalf("repair 2: %+v", r)
	}
	onlyRepair(t, db, g.Job, orig, 3, d3)
	if ev := events(t, db, "backup.partial"); len(ev) != 1 || ev[0].Payload["run_id"] != orig.String() ||
		len(strs(ev[0].Payload["missing_destinations"])) != 2 {
		t.Fatalf("only the original run alerts: %+v", ev)
	}
}

func TestRepairNotQueued(t *testing.T) {
	cases := map[string]string{
		"outside the window": `UPDATE backup_runs SET retry_until = now() - interval '1 minute' WHERE id = $1`,
		"attempt limit":      `UPDATE backup_runs SET attempt = 3 WHERE id = $1`,
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			db := testutil.DB(t)
			g := seedGroup(t, db, jobOpts{cron: yearly})
			g.B2.fail, g.B2.failAfter = errors.New("503 ServerBusy"), 100
			at := time.Now().Add(-time.Minute)
			run := queue(t, db, g.Job, "schedule", &at)
			if _, err := db.Exec(context.Background(), setup, run); err != nil {
				t.Fatal(err)
			}
			claimAndRun(t, g.W, run)
			if r := loadRun(t, db, run); r.Status != "partial" {
				t.Fatalf("run: %+v", r)
			}
			if q := queuedRuns(t, db, g.Job); len(q) != 0 {
				t.Fatalf("no repair: %+v", q)
			}
			ev := events(t, db, "backup.%")
			if len(ev) != 1 || ev[0].Type != "backup.partial" || ev[0].Payload["repair_queued"] != false {
				t.Fatalf("events: %+v", ev)
			}
		})
	}
}

func TestRepairTestRunNever(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{cron: yearly})
	g.B2.fail, g.B2.failAfter = errors.New("503 ServerBusy"), 100
	run := queue(t, db, g.Job, "test", nil)
	claimAndRun(t, g.W, run)
	if r := loadRun(t, db, run); r.Status != "partial" {
		t.Fatalf("run: %+v", r)
	}
	if q := queuedRuns(t, db, g.Job); len(q) != 0 {
		t.Fatalf("test runs are never repaired: %+v", q)
	}
	if ev := events(t, db, "backup.%"); len(ev) != 0 {
		t.Fatalf("test runs never notify: %+v", ev)
	}
}

// Review Focus 3: the missing member left the group before the repair ran:
// the repair fails, quietly, and nothing more is queued.
func TestRepairMemberRemoved(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{cron: yearly})
	orig, _ := partialRun(t, db, g)
	rep := onlyRepair(t, db, g.Job, orig, 2, g.Dest2)
	if _, err := db.Exec(context.Background(), `DELETE FROM destination_group_members WHERE group_id = $1 AND destination_id = $2`, g.Group, g.Dest2); err != nil {
		t.Fatal(err)
	}
	claimAndRun(t, g.W, rep.ID)
	if r := loadRun(t, db, rep.ID); r.Status != "failed" || r.Error != "nothing left to repair: the missing destinations are no longer used by this job" {
		t.Fatalf("repair: %+v", r)
	}
	if q := queuedRuns(t, db, g.Job); len(q) != 0 {
		t.Fatalf("queued: %+v", q)
	}
	if ev := events(t, db, "backup.failed"); len(ev) != 0 {
		t.Fatalf("quiet: %+v", ev)
	}
}

// The retry of a repair interrupted by an agent disconnect keeps the
// repair's original run and destinations.
func TestRepairDisconnectedKeepsSubset(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{cron: yearly})
	orig, at := partialRun(t, db, g)
	rep := onlyRepair(t, db, g.Job, orig, 2, g.Dest2)
	id, err := g.W.Claim(ctx)
	if err != nil || id != rep.ID {
		t.Fatalf("claim: %s %v", id, err)
	}
	d := g.W.Dialer.(*fakeDialer)
	d.mu.Lock()
	d.connected[g.ClusterID] = false
	d.mu.Unlock()
	g.W.Execute(ctx, id)
	if r := loadRun(t, db, rep.ID); r.Status != "failed" {
		t.Fatalf("disconnected repair: %+v", r)
	}
	retry := onlyRepair(t, db, g.Job, orig, 3, g.Dest2)
	if retry.Trigger != "schedule" || retry.ScheduledFor == nil || !retry.ScheduledFor.Equal(at) {
		t.Fatalf("retry: %+v", retry)
	}
	if ev := events(t, db, "backup.failed"); len(ev) != 0 {
		t.Fatalf("quiet: %+v", ev)
	}
}

// A plain run interrupted by a disconnect is retried as a plain run: its
// retry resolves the job's destinations again.
func TestDisconnectedPlainRunRetry(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{cron: yearly})
	at := time.Now().Add(-time.Minute)
	run := queue(t, db, g.Job, "schedule", &at)
	id, err := g.W.Claim(ctx)
	if err != nil || id != run {
		t.Fatalf("claim: %s %v", id, err)
	}
	d := g.W.Dialer.(*fakeDialer)
	d.mu.Lock()
	d.connected[g.ClusterID] = false
	d.mu.Unlock()
	g.W.Execute(ctx, id)
	q := queuedRuns(t, db, g.Job)
	if len(q) != 1 || q[0].RepairOf != nil || q[0].Dests != nil || q[0].Attempt != 2 {
		t.Fatalf("retry: %+v", q)
	}
}

func TestCopyMetrics(t *testing.T) {
	db := testutil.DB(t)
	ok := metrics.BackupCopies.WithLabelValues("dest", "succeeded")
	failed := metrics.BackupCopies.WithLabelValues("dest-b", "failed")
	ok0, failed0 := promtest.ToFloat64(ok), promtest.ToFloat64(failed)
	g := seedGroup(t, db, jobOpts{cron: yearly})
	partialRun(t, db, g)
	if d := promtest.ToFloat64(ok) - ok0; d != 1 {
		t.Fatalf("succeeded copies on dest: +%v", d)
	}
	if d := promtest.ToFloat64(failed) - failed0; d != 1 {
		t.Fatalf("failed copies on dest-b: +%v", d)
	}
}

// The self-backup's restore guide is built from its latest restorable run,
// partial included.
func TestSelfViewRestoresPartial(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	f := seed(t, db, "prod", nil, "online")
	d2 := addDest(t, db, "dest-b")
	// The self runner moves to groups later; copy rows are what counts here.
	var job, run uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (system, destination_id, cron) VALUES ('olympos-self', $1, '30 2 * * *') RETURNING id`,
		f.DestID).Scan(&job); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, destination_ids)
		VALUES ($1, 'schedule', 'partial', now(), now(), $2) RETURNING id`, job, []uuid.UUID{f.DestID, d2}).Scan(&run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, blob_path, sha256) VALUES
		($1, $2, 'failed', '', ''), ($1, $3, 'succeeded', 'olympos/self.zip', 'abc')`, run, f.DestID, d2); err != nil {
		t.Fatal(err)
	}
	v, err := backup.LoadSelfView(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if v.Restore == nil || len(v.Restore.Copies) != 1 || v.Restore.Copies[0].DestinationID != d2 {
		t.Fatalf("restore: %+v", v.Restore)
	}
}
