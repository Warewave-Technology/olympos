package backup_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/postgres"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// pgDumpDir lays out <major>/bin/pg_dump for the local pg_dump, or skips.
func pgDumpDir(t *testing.T) string {
	t.Helper()
	bin := ""
	for _, d := range []string{os.Getenv("OLYMPOS_PG_BIN"), "/opt/homebrew/opt/libpq/bin", "/usr/lib/postgresql/17/bin", "/usr/lib/postgresql/16/bin"} {
		if d != "" {
			if _, err := os.Stat(filepath.Join(d, "pg_dump")); err == nil {
				bin = d
				break
			}
		}
	}
	if bin == "" {
		if p, err := exec.LookPath("pg_dump"); err == nil {
			bin = filepath.Dir(p)
		}
	}
	if bin == "" {
		t.Skip("pg_dump not found")
	}
	out, err := exec.Command(filepath.Join(bin, "pg_dump"), "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	var major int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)[strings.Index(string(out), ")")+1:]), "%d", &major); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, fmt.Sprint(major), "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"pg_dump", "pg_dumpall"} {
		_ = os.Symlink(filepath.Join(bin, tool), filepath.Join(dir, fmt.Sprint(major), "bin", tool))
	}
	return dir
}

// F17: the built-in olympos-self job dumps Olympos' own database with the
// server's login, writes the same manifest/tags as any job, cannot be
// deleted and is invisible to the agent-backed job queries.
func TestSelfBackup(t *testing.T) {
	db := testutil.DB(t)
	postgres.SetDumpDir(pgDumpDir(t))
	ctx := context.Background()
	f := seed(t, db, "c1", nil, "online")
	cc := db.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cc.User, cc.Host, cc.Port, cc.Database)

	if v := selfView(t, db); v.Configured {
		t.Fatal("not configured before an admin chose a destination")
	}
	var jobID uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (system, destination_id, cron, timezone, enabled, last_scheduled_for)
		VALUES ('olympos-self', $1, '30 2 * * *', 'UTC', true, now()) RETURNING id`, f.DestID).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO backup_jobs (system, destination_id, cron) VALUES ('olympos-self', $1, '* * * * *')`, f.DestID); err == nil {
		t.Fatal("a second olympos-self job must be refused")
	}
	if _, err := db.Exec(ctx, `UPDATE backup_jobs SET deleted_at = now() WHERE id = $1`, jobID); err == nil {
		t.Fatal("olympos-self must not be deletable")
	}
	if _, err := backup.LoadJob(ctx, db, jobID); err == nil {
		t.Fatal("olympos-self must not appear as an agent-backed job")
	}
	runID, err := backup.QueueSelfRun(ctx, db, jobID)
	if err != nil {
		t.Fatal(err)
	}
	blobs := newBlobs("olympos")
	s := &backup.SelfBackup{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Blobs: blobs, DSN: dsn, Password: cc.Password, Tick: 50 * time.Millisecond}
	rctx, cancel := context.WithCancel(ctx)
	go s.Run(rctx)
	var status, errMsg, path, tier string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_ = db.QueryRow(ctx, `SELECT status, error, blob_path, tier FROM backup_runs WHERE id = $1`, runID).Scan(&status, &errMsg, &path, &tier)
		if status == "succeeded" || status == "failed" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if status != "succeeded" {
		t.Fatalf("self run: %s %s", status, errMsg)
	}
	if !strings.HasPrefix(path, "olympos/olympos/olympos/olympos-db/postgresql/") || tier != "daily" || blobs.tags[path]["olympos-tier"] != "daily" {
		t.Fatalf("path %q tier %q tags %v", path, tier, blobs.tags[path])
	}
	zr, err := zip.NewReader(bytes.NewReader(blobs.blobs[path]), int64(len(blobs.blobs[path])))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, zf := range zr.File {
		names = append(names, zf.Name)
	}
	if strings.Join(names, ",") != cc.Database+".dump" {
		t.Fatalf("zip entries: %v", names)
	}
	var m backup.Manifest
	if err := json.Unmarshal(blobs.blobs[backup.ManifestPath(path, runID)], &m); err != nil {
		t.Fatal(err)
	}
	if m.Target.ID != backup.SelfSystem || m.JobID != jobID || m.Details["system"] != backup.SelfSystem {
		t.Fatalf("manifest: %+v", m)
	}
	for p, b := range blobs.blobs {
		if len(cc.Password) >= 12 && bytes.Contains(b, []byte(cc.Password)) && !strings.HasSuffix(p, ".zip") {
			t.Fatalf("password in %s", p)
		}
	}
	if v := selfView(t, db); !v.Configured || len(v.Runs) != 1 || v.Runs[0].Status != "succeeded" {
		t.Fatalf("view: %+v", v)
	}
}

// selfEnv is an olympos-self job writing to a group of two destinations,
// each with its own fake writer, and a runner for it.
type selfEnv struct {
	db      *store.DB
	job     uuid.UUID
	d1, d2  uuid.UUID
	b1, b2  *fakeBlobs
	runner  *backup.SelfBackup
	channel uuid.UUID
}

func newSelfGroup(t *testing.T) *selfEnv {
	t.Helper()
	db := testutil.DB(t)
	postgres.SetDumpDir(pgDumpDir(t))
	ctx := context.Background()
	f := seed(t, db, "c1", nil, "online")
	e := &selfEnv{db: db, d1: f.DestID, d2: addDest(t, db, "dest2"), channel: addChannel(t, db)}
	g := addGroup(t, db, "self-pair", e.d1, e.d2)
	// Yearly: a retry window of weeks, so every spaced repair fits whatever
	// the time of day.
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (system, destination_group_id, cron, timezone, enabled, last_scheduled_for, notify_channel_id)
		VALUES ('olympos-self', $1, $3, 'UTC', true, now(), $2) RETURNING id`, g, e.channel, yearly).Scan(&e.job); err != nil {
		t.Fatal(err)
	}
	blobs := newBlobs("olympos")
	e.b1, e.b2 = blobs.dest(e.d1, "p1"), blobs.dest(e.d2, "p2")
	cc := db.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cc.User, cc.Host, cc.Port, cc.Database)
	e.runner = &backup.SelfBackup{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Blobs: blobs, DSN: dsn, Password: cc.Password,
		Tick: 50 * time.Millisecond}
	return e
}

type selfRun struct {
	ID        uuid.UUID
	Status    string
	Error     string
	Attempt   int
	RepairOf  *uuid.UUID
	Dests     []uuid.UUID
	BlobPath  string
	Tier      string
	NotBefore *time.Time
}

// runSelf queues a manual run and runs the self loop until n runs of the
// job have finished and none is queued or running. Queued repairs are made
// due at once (their not_before set in the past).
func (e *selfEnv) runSelf(t *testing.T, n int) []selfRun {
	t.Helper()
	ctx := context.Background()
	if _, err := backup.QueueSelfRun(ctx, e.db, e.job); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.runner.Run(rctx)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := e.db.Exec(ctx, `UPDATE backup_runs SET not_before = now() - interval '1 second'
			WHERE job_id = $1 AND status = 'queued' AND not_before > now()`, e.job); err != nil {
			t.Fatal(err)
		}
		var done, open int
		_ = e.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE finished_at IS NOT NULL), count(*) FILTER (WHERE status IN ('queued','running'))
			FROM backup_runs WHERE job_id = $1`, e.job).Scan(&done, &open)
		if done >= n && open == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	out := e.selfRuns(t)
	if len(out) != n {
		t.Fatalf("want %d runs, got %+v", n, out)
	}
	return out
}

// selfRuns returns the job's runs, oldest first.
func (e *selfEnv) selfRuns(t *testing.T) []selfRun {
	t.Helper()
	rows, err := e.db.Query(context.Background(), `SELECT id, status, error, attempt, repair_of, destination_ids, blob_path, tier, not_before
		FROM backup_runs WHERE job_id = $1 ORDER BY created_at`, e.job)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []selfRun
	for rows.Next() {
		var r selfRun
		if err := rows.Scan(&r.ID, &r.Status, &r.Error, &r.Attempt, &r.RepairOf, &r.Dests, &r.BlobPath, &r.Tier, &r.NotBefore); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Design "Self-backup": olympos-self writes one dump to every member of
// its group, with copy rows, manifests per copy and identical blobs.
func TestSelfBackupGroup(t *testing.T) {
	e := newSelfGroup(t)
	runs := e.runSelf(t, 1)
	r := runs[0]
	if r.Status != "succeeded" || len(r.Dests) != 2 || r.Dests[0] != e.d1 || r.Dests[1] != e.d2 {
		t.Fatalf("run: %+v", r)
	}
	if !strings.HasPrefix(r.BlobPath, "p1/olympos/olympos/olympos-db/postgresql/") || r.Tier != "daily" {
		t.Fatalf("run columns from the first copy: %+v", r)
	}
	p2 := "p2" + strings.TrimPrefix(r.BlobPath, "p1")
	if len(e.b1.blobs[r.BlobPath]) == 0 || !bytes.Equal(e.b1.blobs[r.BlobPath], e.b2.blobs[p2]) {
		t.Fatalf("copies differ: %d vs %d bytes", len(e.b1.blobs[r.BlobPath]), len(e.b2.blobs[p2]))
	}
	for _, c := range []struct {
		b    *fakeBlobs
		path string
		name string
	}{{e.b1, r.BlobPath, "dest"}, {e.b2, p2, "dest2"}} {
		var m backup.Manifest
		if err := json.Unmarshal(c.b.blobs[backup.ManifestPath(c.path, r.ID)], &m); err != nil {
			t.Fatalf("manifest on %s: %v", c.name, err)
		}
		if m.Target.ID != backup.SelfSystem || m.Details["system"] != backup.SelfSystem || m.Destination == nil || m.Destination.Name != c.name ||
			m.Group == nil || m.Group.Name != "self-pair" || strings.Join(m.Group.Members, ",") != "dest,dest2" || m.Blob.Path != c.path {
			t.Fatalf("manifest on %s: %+v", c.name, m)
		}
		if c.b.tags[c.path]["olympos-tier"] != "daily" {
			t.Fatalf("tags on %s: %v", c.name, c.b.tags[c.path])
		}
	}
	v := selfView(t, e.db)
	if v.Job == nil || v.Job.DestinationID != nil || v.Job.DestinationGroupID == nil || v.Job.DestinationName != "self-pair" {
		t.Fatalf("self job: %+v", v.Job)
	}
	if len(v.Runs) != 1 || len(v.Runs[0].Copies) != 2 || v.Runs[0].Copies[0].DestinationName != "dest" || v.Runs[0].Copies[1].Status != "succeeded" ||
		v.Runs[0].DestinationName != "self-pair" {
		t.Fatalf("self view runs: %+v", v.Runs)
	}
	if v.Restore == nil || len(v.Restore.Copies) != 2 || !v.Restore.Copies[0].Selected {
		t.Fatalf("restore guide: %+v", v.Restore)
	}
	if ev := events(t, e.db, "backup.%"); len(ev) != 0 {
		t.Fatalf("events: %+v", ev)
	}
}

// One member failing: the run is partial, backup.partial goes out with the
// olympos-self title, and the self loop runs the repair, which completes
// the missing copy. The restore guide stays on the original run.
func TestSelfBackupPartialRepair(t *testing.T) {
	e := newSelfGroup(t)
	e.b2.fail, e.b2.failOnly = errors.New("disk full"), 1
	runs := e.runSelf(t, 2)
	orig, rep := runs[0], runs[1]
	if orig.Status != "partial" || orig.Error != "dest2: upload: disk full" {
		t.Fatalf("original: %+v", orig)
	}
	if rep.Status != "succeeded" || rep.RepairOf == nil || *rep.RepairOf != orig.ID || rep.Attempt != 2 || len(rep.Dests) != 1 || rep.Dests[0] != e.d2 {
		t.Fatalf("repair: %+v", rep)
	}
	if len(e.b2.blobs[rep.BlobPath]) == 0 || !strings.HasPrefix(rep.BlobPath, "p2/") {
		t.Fatalf("repaired copy %q not on dest2", rep.BlobPath)
	}
	ev := events(t, e.db, "backup.%")
	if len(ev) != 1 || ev[0].Type != "backup.partial" || ev[0].Channel == nil || *ev[0].Channel != e.channel {
		t.Fatalf("events: %+v", ev)
	}
	p := ev[0].Payload
	fields, _ := p["fields"].(map[string]any)
	if p["title"] != "Backup incomplete: Olympos database (olympos-self)" || p["link"] != "/backups?self=1&run="+orig.ID.String() ||
		fields["target"] != backup.SelfSystem || fields["missing"] != "dest2" || p["repair_queued"] != true ||
		fmt.Sprint(p["missing_destinations"]) != "[dest2]" {
		t.Fatalf("backup.partial: %+v", p)
	}
	v := selfView(t, e.db)
	if len(v.Runs) != 2 || v.Runs[0].RepairOf == nil || len(v.Runs[1].Copies) != 2 || v.Runs[1].Copies[1].Status != "failed" {
		t.Fatalf("self view runs: %+v", v.Runs)
	}
	// The guide is built from the original run and also offers the copy
	// the repair completed.
	c := v.Restore.Copies
	if len(c) != 2 || c[0].DestinationID != e.d1 || c[0].RunID != orig.ID || !c[0].Selected ||
		c[1].DestinationID != e.d2 || c[1].RunID != rep.ID || c[1].TakenAt == nil {
		t.Fatalf("restore guide copies: %+v", c)
	}
	mustContain(t, guideText(v.Restore), backup.ManifestPath(orig.BlobPath, orig.ID))
	v2, err := backup.LoadSelfView(context.Background(), e.db, &e.d2)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.Restore.Copies) != 2 || !v2.Restore.Copies[1].Selected {
		t.Fatalf("copy on dest2 not selected: %+v", v2.Restore.Copies)
	}
	mustContain(t, guideText(v2.Restore), rep.BlobPath)
	mustContain(t, guideText(v2.Restore), backup.ManifestPath(rep.BlobPath, rep.ID))
}

// The self loop leaves a repair in the queue until its not_before.
func TestSelfBackupRepairWaits(t *testing.T) {
	e := newSelfGroup(t)
	e.b2.fail, e.b2.failOnly = errors.New("disk full"), 1
	ctx := context.Background()
	if _, err := backup.QueueSelfRun(ctx, e.db, e.job); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	before := time.Now()
	go e.runner.Run(rctx)
	var runs []selfRun
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if runs = e.selfRuns(t); len(runs) == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	after := time.Now()
	time.Sleep(500 * time.Millisecond) // ten ticks of the loop
	cancel()
	runs = e.selfRuns(t)
	if len(runs) != 2 || runs[0].Status != "partial" || runs[1].Status != "queued" || runs[1].RepairOf == nil {
		t.Fatalf("runs: %+v", runs)
	}
	nb := runs[1].NotBefore
	if nb == nil || nb.Before(before.Add(backup.RepairDelays[0]-time.Second)) || nb.After(after.Add(backup.RepairDelays[0]+time.Second)) {
		t.Fatalf("repair not_before %v, want 5 minutes after the partial run", nb)
	}
}

// A repair that keeps failing gives up with backup.failed (self title)
// after MaxRepairs repairs.
func TestSelfBackupRepairGivesUp(t *testing.T) {
	e := newSelfGroup(t)
	e.b2.fail = errors.New("disk full")
	runs := e.runSelf(t, 1+backup.MaxRepairs)
	last := runs[backup.MaxRepairs]
	if runs[0].Status != "partial" || runs[1].Status != "failed" || runs[2].Status != "failed" || last.Status != "failed" || last.Attempt != 1+backup.MaxRepairs {
		t.Fatalf("runs: %+v", runs)
	}
	ev := events(t, e.db, "backup.%")
	if len(ev) != 2 || ev[0].Type != "backup.partial" || ev[1].Type != "backup.failed" {
		t.Fatalf("events: %+v", ev)
	}
	p := ev[1].Payload
	fields, _ := p["fields"].(map[string]any)
	if p["title"] != "Backup failed: Olympos database (olympos-self)" || p["link"] != "/backups?self=1&run="+last.ID.String() ||
		fields["target"] != backup.SelfSystem || fields["missing"] != "dest2" || p["repair_of"] != runs[0].ID.String() {
		t.Fatalf("backup.failed: %+v", p)
	}
}

// A failed self run on one destination still sends today's backup.failed:
// self title, self link, target olympos-self and the whole error.
func TestSelfBackupFailedEvent(t *testing.T) {
	e := newSelfGroup(t)
	if _, err := e.db.Exec(context.Background(), `UPDATE backup_jobs SET destination_id = $2, destination_group_id = NULL WHERE id = $1`,
		e.job, e.d1); err != nil {
		t.Fatal(err)
	}
	e.b1.openErr = errors.New("container not found")
	runs := e.runSelf(t, 1)
	if runs[0].Status != "failed" || runs[0].Error != "open destination: container not found" {
		t.Fatalf("run: %+v", runs[0])
	}
	ev := events(t, e.db, "backup.%")
	if len(ev) != 1 || ev[0].Type != "backup.failed" {
		t.Fatalf("events: %+v", ev)
	}
	p := ev[0].Payload
	fields, _ := p["fields"].(map[string]any)
	if p["title"] != "Backup failed: Olympos database (olympos-self)" || p["link"] != "/backups?self=1&run="+runs[0].ID.String() ||
		fields["target"] != backup.SelfSystem || fields["trigger"] != "manual" || fields["error"] != runs[0].Error || fields["cluster"] != nil {
		t.Fatalf("backup.failed: %+v", p)
	}
}

func guideText(g *backup.RestoreGuide) string {
	var b strings.Builder
	for _, s := range g.Steps {
		b.WriteString(s.Commands + "\n")
	}
	return b.String()
}

func selfView(t *testing.T, db *store.DB) backup.SelfView {
	t.Helper()
	v, err := backup.LoadSelfView(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	return *v
}

// A self run left running by a server that stopped is finished like any
// run: an interrupted repair continues the repair chain (the next spaced
// repair is queued, quietly), and an interrupted plain run sends
// backup.failed.
func TestSelfBackupInterruptedRun(t *testing.T) {
	e := newSelfGroup(t)
	ctx := context.Background()
	var partial, repair, plain uuid.UUID
	if err := e.db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, destination_ids)
		VALUES ($1, 'manual', 'partial', now() - interval '20 minutes', now() - interval '19 minutes', $2) RETURNING id`, e.job, []uuid.UUID{e.d1, e.d2}).Scan(&partial); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status) VALUES ($1, $2, 'succeeded'), ($1, $3, 'failed')`, partial, e.d1, e.d2); err != nil {
		t.Fatal(err)
	}
	if err := e.db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, attempt, repair_of, destination_ids, not_before, started_at, updated_at)
		VALUES ($1, 'manual', 'running', 2, $2, $3, now() - interval '14 minutes', now() - interval '13 minutes', now() - interval '10 minutes') RETURNING id`,
		e.job, partial, []uuid.UUID{e.d2}).Scan(&repair); err != nil {
		t.Fatal(err)
	}
	if err := e.db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, updated_at)
		VALUES ($1, 'manual', 'running', now() - interval '12 minutes', now() - interval '10 minutes') RETURNING id`, e.job).Scan(&plain); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.runner.Run(rctx)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var open int
		_ = e.db.QueryRow(ctx, `SELECT count(*) FROM backup_runs WHERE job_id = $1 AND status = 'running'`, e.job).Scan(&open)
		if open == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	runs := e.selfRuns(t)
	byID := map[uuid.UUID]selfRun{}
	var next *selfRun
	for i, r := range runs {
		byID[r.ID] = r
		if r.Status == "queued" {
			next = &runs[i]
		}
	}
	const interrupted = "interrupted: server stopped during the run"
	if r := byID[repair]; r.Status != "failed" || r.Error != interrupted {
		t.Fatalf("repair: %+v", r)
	}
	if r := byID[plain]; r.Status != "failed" || r.Error != interrupted {
		t.Fatalf("plain run: %+v", r)
	}
	if next == nil || next.RepairOf == nil || *next.RepairOf != partial || next.Attempt != 3 || next.NotBefore == nil ||
		len(next.Dests) != 1 || next.Dests[0] != e.d2 {
		t.Fatalf("next repair: %+v (runs %+v)", next, runs)
	}
	ev := events(t, e.db, "backup.%")
	if len(ev) != 1 || ev[0].Type != "backup.failed" || ev[0].Payload["link"] != "/backups?self=1&run="+plain.String() {
		t.Fatalf("events: %+v", ev)
	}
}
