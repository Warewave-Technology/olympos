package backup_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
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

func selfView(t *testing.T, db *store.DB) backup.SelfView {
	t.Helper()
	v, err := backup.LoadSelfView(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return *v
}
