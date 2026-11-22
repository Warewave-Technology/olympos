//go:build dev

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
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

type copyRow struct {
	Dest                        uuid.UUID
	Status, BlobPath, SHA, Tier string
	Error                       string
	Bytes                       int64
	StartedAt                   *time.Time
}

// loadCopies returns a run's copies in the order of its destination_ids.
func loadCopies(t *testing.T, db *store.DB, run uuid.UUID) []copyRow {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT c.destination_id, c.status, c.blob_path, c.sha256, c.tier, c.error, c.bytes, c.started_at
		FROM backup_run_copies c JOIN backup_runs r ON r.id = c.run_id WHERE c.run_id = $1
		ORDER BY array_position(r.destination_ids, c.destination_id)`, run)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []copyRow
	for rows.Next() {
		var c copyRow
		if err := rows.Scan(&c.Dest, &c.Status, &c.BlobPath, &c.SHA, &c.Tier, &c.Error, &c.Bytes, &c.StartedAt); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func runDestIDs(t *testing.T, db *store.DB, run uuid.UUID) []uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	if err := db.QueryRow(context.Background(), `SELECT destination_ids FROM backup_runs WHERE id = $1`, run).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	return ids
}

func payloadSHA() string {
	sum := sha256.Sum256(fakePayload)
	return hex.EncodeToString(sum[:])
}

// groupFixture is a job on a group of two destinations, each with its own
// fake writer.
type groupFixture struct {
	fixture
	Dest2  uuid.UUID
	Group  uuid.UUID
	Job    uuid.UUID
	Blobs  *fakeBlobs
	B1, B2 *fakeBlobs
	W      *backup.Worker
}

func seedGroup(t *testing.T, db *store.DB, o jobOpts) groupFixture {
	t.Helper()
	g := groupFixture{fixture: seed(t, db, "prod", nil, "online")}
	g.Dest2 = addDest(t, db, "dest-b")
	g.Group = addGroup(t, db, "pair", g.DestID, g.Dest2)
	o.group = &g.Group
	o.enabled = true
	g.Job = addJob(t, db, g.fixture, o)
	g.Blobs = newBlobs("unused/")
	g.B1, g.B2 = g.Blobs.dest(g.DestID, "a"), g.Blobs.dest(g.Dest2, "b")
	g.W = newWorker(t, db, newDialer(g.ClusterID), g.Blobs)
	return g
}

func readManifest(t *testing.T, b *fakeBlobs, blobPath string, run uuid.UUID) backup.Manifest {
	t.Helper()
	var m backup.Manifest
	if err := json.Unmarshal(b.blobs[backup.ManifestPath(blobPath, run)], &m); err != nil {
		t.Fatalf("manifest for %s: %v", blobPath, err)
	}
	return m
}

func TestWorkerGroupAllCopies(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{})
	_, _ = db.Exec(ctx, `UPDATE backup_jobs SET notify_on_success = true WHERE id = $1`, g.Job)
	run := queue(t, db, g.Job, "manual", nil)
	claimAndRun(t, g.W, run)

	r := loadRun(t, db, run)
	if r.Status != "succeeded" || r.Error != "" || r.SHA != payloadSHA() || r.Bytes != int64(len(fakePayload)) {
		t.Fatalf("run: %+v", r)
	}
	if ids := runDestIDs(t, db, run); len(ids) != 2 || ids[0] != g.DestID || ids[1] != g.Dest2 {
		t.Fatalf("destination_ids: %v", ids)
	}
	cs := loadCopies(t, db, run)
	if len(cs) != 2 {
		t.Fatalf("copies: %+v", cs)
	}
	for i, b := range []*fakeBlobs{g.B1, g.B2} {
		c := cs[i]
		if c.Status != "succeeded" || c.SHA != payloadSHA() || c.Bytes != int64(len(fakePayload)) || c.Tier != "daily" || c.Error != "" || c.StartedAt == nil {
			t.Fatalf("copy %d: %+v", i, c)
		}
		if string(b.blobs[c.BlobPath]) != string(fakePayload) || b.tags[c.BlobPath][backup.TierTag] != "daily" {
			t.Fatalf("copy %d blob %s: %v", i, c.BlobPath, keysOf(b.blobs))
		}
		m := readManifest(t, b, c.BlobPath, run)
		if m.Blob.Path != c.BlobPath || m.Blob.SHA256 != c.SHA || m.Tier != "daily" || m.Destination == nil ||
			m.Group == nil || m.Group.Name != "pair" || strings.Join(m.Group.Members, ",") != "dest,dest-b" {
			t.Fatalf("copy %d manifest: %+v", i, m)
		}
	}
	if !strings.HasPrefix(cs[0].BlobPath, "a/") || !strings.HasPrefix(cs[1].BlobPath, "b/") || r.BlobPath != cs[0].BlobPath {
		t.Fatalf("paths: run %s, copies %s %s", r.BlobPath, cs[0].BlobPath, cs[1].BlobPath)
	}
	if m := readManifest(t, g.B2, cs[1].BlobPath, run); m.Destination.Name != "dest-b" || m.Destination.Kind != "azure_blob" {
		t.Fatalf("destination in manifest: %+v", m.Destination)
	}
	if len(g.Blobs.blobs) != 0 {
		t.Fatalf("nothing goes to the default writer: %v", keysOf(g.Blobs.blobs))
	}
	if ev := events(t, db, "backup.succeeded"); len(ev) != 1 {
		t.Fatalf("succeeded events: %+v", ev)
	}
}

func TestWorkerGroupPartial(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{})
	_, _ = db.Exec(ctx, `UPDATE backup_jobs SET notify_on_success = true WHERE id = $1`, g.Job)
	g.B2.fail, g.B2.failAfter = errors.New("503 ServerBusy"), 100
	run := queue(t, db, g.Job, "manual", nil)
	claimAndRun(t, g.W, run)

	r := loadRun(t, db, run)
	if r.Status != "partial" || r.Error != "dest-b: upload: 503 ServerBusy" || r.SHA != payloadSHA() {
		t.Fatalf("run: %+v", r)
	}
	cs := loadCopies(t, db, run)
	if len(cs) != 2 || cs[0].Status != "succeeded" || cs[1].Status != "failed" || cs[1].Error != "upload: 503 ServerBusy" ||
		cs[1].BlobPath != "" || cs[1].SHA != "" {
		t.Fatalf("copies: %+v", cs)
	}
	if r.BlobPath != cs[0].BlobPath || string(g.B1.blobs[cs[0].BlobPath]) != string(fakePayload) {
		t.Fatalf("run blob path %s, copy 1 %s", r.BlobPath, cs[0].BlobPath)
	}
	_ = readManifest(t, g.B1, cs[0].BlobPath, run)
	if len(g.B2.blobs) != 0 {
		t.Fatalf("failed copy wrote: %v", keysOf(g.B2.blobs))
	}
	if ev := events(t, db, "backup.%"); len(ev) != 0 {
		t.Fatalf("partial emits neither succeeded nor failed: %+v", ev)
	}
}

// Review Focus 1: a destination that cannot be opened is a failed copy, not
// a failed run.
func TestWorkerGroupOpenFails(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{})
	g.B2.openErr = errors.New("no credential for dest-b")
	run := queue(t, db, g.Job, "manual", nil)
	claimAndRun(t, g.W, run)

	r := loadRun(t, db, run)
	if r.Status != "partial" || r.Error != "dest-b: open destination: no credential for dest-b" {
		t.Fatalf("run: %+v", r)
	}
	cs := loadCopies(t, db, run)
	if len(cs) != 2 || cs[0].Status != "succeeded" || cs[1].Status != "failed" || cs[1].Error != "open destination: no credential for dest-b" {
		t.Fatalf("copies: %+v", cs)
	}
}

func TestWorkerGroupAllFail(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{})
	g.B1.fail = errors.New("403 AuthorizationPermissionMismatch")
	g.B2.fail, g.B2.failAfter = errors.New("503 ServerBusy"), 10
	run := queue(t, db, g.Job, "manual", nil)
	claimAndRun(t, g.W, run)

	r := loadRun(t, db, run)
	if r.Status != "failed" || r.Error != "upload: 403 AuthorizationPermissionMismatch" || r.BlobPath != "" || r.SHA != "" {
		t.Fatalf("run: %+v", r)
	}
	cs := loadCopies(t, db, run)
	if len(cs) != 2 || cs[0].Status != "failed" || cs[1].Status != "failed" || cs[1].Error != "upload: 503 ServerBusy" {
		t.Fatalf("copies: %+v", cs)
	}
	if ev := events(t, db, "backup.failed"); len(ev) != 1 {
		t.Fatalf("failed events: %+v", ev)
	}
}

// An engine that fails before writing anything leaves no copies.
func TestWorkerGroupEngineFails(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{options: `{"fail":true}`})
	run := queue(t, db, g.Job, "manual", nil)
	claimAndRun(t, g.W, run)
	if r := loadRun(t, db, run); r.Status != "failed" || r.Error != "dump failed" {
		t.Fatalf("run: %+v", r)
	}
	if cs := loadCopies(t, db, run); len(cs) != 0 {
		t.Fatalf("copies: %+v", cs)
	}
}

func TestWorkerSingleDestinationCopyRow(t *testing.T) {
	db := testutil.DB(t)
	f := seed(t, db, "prod", nil, "online")
	b := newBlobs("olympos")
	w := newWorker(t, db, newDialer(f.ClusterID), b)
	job := addJob(t, db, f, jobOpts{enabled: true})
	run := queue(t, db, job, "manual", nil)
	claimAndRun(t, w, run)

	r := loadRun(t, db, run)
	if r.Status != "succeeded" || r.Tier != "daily" || r.SHA != payloadSHA() || !strings.HasPrefix(r.BlobPath, "olympos/prod/db/orders/") {
		t.Fatalf("run: %+v", r)
	}
	if ids := runDestIDs(t, db, run); len(ids) != 1 || ids[0] != f.DestID {
		t.Fatalf("destination_ids: %v", ids)
	}
	cs := loadCopies(t, db, run)
	if len(cs) != 1 || cs[0].Dest != f.DestID || cs[0].Status != "succeeded" || cs[0].BlobPath != r.BlobPath || cs[0].SHA != r.SHA ||
		cs[0].Bytes != r.Bytes || cs[0].Tier != "daily" {
		t.Fatalf("copies: %+v (run %+v)", cs, r)
	}
	m := readManifest(t, b, r.BlobPath, run)
	if m.Destination == nil || m.Destination.Name != "dest" || m.Group != nil {
		t.Fatalf("manifest destination/group: %+v %+v", m.Destination, m.Group)
	}
}

// insertFinishedRun records a scheduled run that finished earlier, with
// succeeded copies on dests.
func insertFinishedRun(t *testing.T, db *store.DB, job uuid.UUID, status string, at time.Time, dests ...uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, scheduled_for, started_at, finished_at, destination_ids)
		VALUES ($1, 'schedule', $2, $3, $3, $3, $4) RETURNING id`, job, status, at, dests).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, d := range dests {
		if _, err := db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, tier, finished_at) VALUES ($1,$2,'succeeded','monthly',$3)`,
			id, d, at); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// Tiers are decided per destination: member 1 already has its monthly and
// weekly copy, member 2 (down last time) has none.
func TestTierPerDestination(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{})
	insertFinishedRun(t, db, g.Job, "partial", time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC), g.DestID) // Mon 2 Nov
	at := time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC)                                                 // Tue 3 Nov
	run := queue(t, db, g.Job, "schedule", &at)
	claimAndRun(t, g.W, run)

	cs := loadCopies(t, db, run)
	if len(cs) != 2 || cs[0].Tier != "daily" || cs[1].Tier != "monthly" {
		t.Fatalf("copies: %+v", cs)
	}
	if g.B1.tags[cs[0].BlobPath][backup.TierTag] != "daily" || g.B2.tags[cs[1].BlobPath][backup.TierTag] != "monthly" {
		t.Fatal("blob tags do not follow the copy tiers")
	}
	if m := readManifest(t, g.B2, cs[1].BlobPath, run); m.Tier != "monthly" {
		t.Fatalf("manifest tier %s", m.Tier)
	}
	if r := loadRun(t, db, run); r.Tier != "daily" {
		t.Fatalf("run tier %s, want the first copy's", r.Tier)
	}
	if tier, err := backup.TierForDestination(context.Background(), db, g.Job, run, g.Dest2, at, time.UTC); err != nil || tier != "monthly" {
		t.Fatalf("TierForDestination: %s %v", tier, err)
	}
}

// Runs from before the upgrade have no copy rows: they count for every
// destination, so no extra monthly copy is tagged.
func TestTierPreUpgradeRuns(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{})
	insertFinishedRun(t, db, g.Job, "succeeded", time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC)) // Tue 3 Nov, no copies
	insertFinishedRun(t, db, g.Job, "failed", time.Date(2026, 11, 10, 1, 0, 0, 0, time.UTC))   // failed: does not count
	at := time.Date(2026, 11, 10, 2, 0, 0, 0, time.UTC)                                        // Tue 10 Nov, next ISO week
	run := queue(t, db, g.Job, "schedule", &at)
	claimAndRun(t, g.W, run)

	cs := loadCopies(t, db, run)
	if len(cs) != 2 || cs[0].Tier != "weekly" || cs[1].Tier != "weekly" {
		t.Fatalf("copies: %+v", cs)
	}
}

func TestDryRunStepsPerDestination(t *testing.T) {
	db := testutil.DB(t)
	g := seedGroup(t, db, jobOpts{})
	g.B2.fail, g.B2.failAfter = errors.New("503 ServerBusy"), 100
	run := queue(t, db, g.Job, "test", nil)
	claimAndRun(t, g.W, run)

	var status string
	var raw []byte
	if err := db.QueryRow(context.Background(), `SELECT status, steps FROM backup_runs WHERE id = $1`, run).Scan(&status, &raw); err != nil {
		t.Fatal(err)
	}
	var steps []backup.Step
	if err := json.Unmarshal(raw, &steps); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range steps {
		sign := "+"
		if !s.OK {
			sign = "-"
		}
		names = append(names, sign+s.Name)
	}
	if status != "partial" || strings.Join(names, " ") != "+agent +credential +engine +upload -upload +manifest" {
		t.Fatalf("%s: %v", status, names)
	}
	if !strings.Contains(steps[3].Detail, "to dest") || !strings.Contains(steps[4].Detail, "dest-b") ||
		!strings.Contains(steps[4].Detail, "503 ServerBusy") || !strings.Contains(steps[5].Detail, "dest") {
		t.Fatalf("details: %+v", steps)
	}
	if cs := loadCopies(t, db, run); len(cs) != 2 || cs[0].Tier != "test" {
		t.Fatalf("test run copies: %+v", cs)
	}
}

// Ruling 2: a repair run writes only to its destinations that the job
// still uses; with none left it fails at start.
func TestWorkerRepairDestinations(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	g := seedGroup(t, db, jobOpts{})
	orig := insertFinishedRun(t, db, g.Job, "partial", time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC), g.DestID)
	queueRepair := func(dests ...uuid.UUID) uuid.UUID {
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, repair_of, destination_ids) VALUES ($1, 'manual', 'queued', $2, $3)
			RETURNING id`, g.Job, orig, dests).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	gone := addDest(t, db, "dest-gone")
	rep := queueRepair(g.Dest2, gone)
	claimAndRun(t, g.W, rep)
	if r := loadRun(t, db, rep); r.Status != "succeeded" {
		t.Fatalf("repair: %+v", r)
	}
	cs := loadCopies(t, db, rep)
	if len(cs) != 1 || cs[0].Dest != g.Dest2 || cs[0].Status != "succeeded" || len(g.B1.blobs) != 0 {
		t.Fatalf("repair copies: %+v (member 1 blobs %v)", cs, keysOf(g.B1.blobs))
	}

	rep2 := queueRepair(gone)
	claimAndRun(t, g.W, rep2)
	if r := loadRun(t, db, rep2); r.Status != "failed" || r.Error != "nothing left to repair: the missing destinations are no longer used by this job" {
		t.Fatalf("empty repair: %+v", r)
	}
	if cs := loadCopies(t, db, rep2); len(cs) != 0 {
		t.Fatalf("empty repair copies: %+v", cs)
	}
}
