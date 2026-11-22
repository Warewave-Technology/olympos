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
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (system, destination_group_id, cron, timezone, enabled, last_scheduled_for, notify_channel_id)
		VALUES ('olympos-self', $1, '30 2 * * *', 'UTC', true, now(), $2) RETURNING id`, g, e.channel).Scan(&e.job); err != nil {
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
	ID       uuid.UUID
	Status   string
	Error    string
	Attempt  int
	RepairOf *uuid.UUID
	Dests    []uuid.UUID
	BlobPath string
	Tier     string
}

// runSelf queues a manual run and runs the self loop until n runs of the
// job have finished and none is queued or running.
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
		var done, open int
		_ = e.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE finished_at IS NOT NULL), count(*) FILTER (WHERE status IN ('queued','running'))
			FROM backup_runs WHERE job_id = $1`, e.job).Scan(&done, &open)
		if done >= n && open == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	rows, err := e.db.Query(ctx, `SELECT id, status, error, attempt, repair_of, destination_ids, blob_path, tier FROM backup_runs
		WHERE job_id = $1 ORDER BY created_at`, e.job)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []selfRun
	for rows.Next() {
		var r selfRun
		if err := rows.Scan(&r.ID, &r.Status, &r.Error, &r.Attempt, &r.RepairOf, &r.Dests, &r.BlobPath, &r.Tier); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if len(out) != n {
		t.Fatalf("want %d runs, got %+v", n, out)
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
	// A succeeded repair only holds the repaired copy: the guide is built
	// from the original run.
	if v.Restore == nil || len(v.Restore.Copies) != 1 || v.Restore.Copies[0].DestinationID != e.d1 {
		t.Fatalf("restore guide: %+v", v.Restore)
	}
	var cmds strings.Builder
	for _, st := range v.Restore.Steps {
		cmds.WriteString(st.Commands)
	}
	mustContain(t, cmds.String(), orig.ID.String())
}

// A repair that keeps failing gives up with backup.failed (self title)
// after MaxAttempts.
func TestSelfBackupRepairGivesUp(t *testing.T) {
	e := newSelfGroup(t)
	e.b2.fail = errors.New("disk full")
	runs := e.runSelf(t, backup.MaxAttempts)
	if runs[0].Status != "partial" || runs[1].Status != "failed" || runs[2].Status != "failed" || runs[2].Attempt != backup.MaxAttempts {
		t.Fatalf("runs: %+v", runs)
	}
	ev := events(t, e.db, "backup.%")
	if len(ev) != 2 || ev[0].Type != "backup.partial" || ev[1].Type != "backup.failed" {
		t.Fatalf("events: %+v", ev)
	}
	p := ev[1].Payload
	fields, _ := p["fields"].(map[string]any)
	if p["title"] != "Backup failed: Olympos database (olympos-self)" || p["link"] != "/backups?self=1&run="+runs[2].ID.String() ||
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

func selfView(t *testing.T, db *store.DB) backup.SelfView {
	t.Helper()
	v, err := backup.LoadSelfView(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	return *v
}
