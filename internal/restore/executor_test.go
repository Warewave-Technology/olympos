//go:build dev

package restore_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
)

// ---------------------------------------------------------------- fakes

// restoreCall is what the fake restorer was given.
type restoreCall struct {
	databases []string
	superuser bool
	secret    string
	snapshot  []byte
	options   restore.Options
	requestID string
}

// fakeRestorer restores every selected database from a zip entry of the
// same name (read to the end, so archive/zip checks its CRC), or reads the
// Vault snapshot. It reports each database as created before reading it.
type fakeRestorer struct {
	mu    sync.Mutex
	calls []restoreCall
	// block, when set, holds the restore after the first database was
	// created until it is closed; started is closed at that point.
	block, started chan struct{}
}

func (f *fakeRestorer) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.block, f.started = nil, nil, nil
}

func (f *fakeRestorer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeRestorer) last() restoreCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakeRestorer) Restore(ctx context.Context, rc backup.RestoreContext) (*backup.RestoreResult, error) {
	c, err := rc.Credential(ctx)
	if err != nil {
		return nil, err
	}
	call := restoreCall{databases: rc.Databases, superuser: rc.Superuser, secret: string(c.Secret), requestID: rc.RequestID}
	_ = json.Unmarshal(rc.Options, &call.options)
	if rc.Snapshot != nil {
		if call.snapshot, err = io.ReadAll(rc.Snapshot); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	block, started := f.block, f.started
	f.mu.Unlock()

	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
	if rc.Archive == nil {
		res.Items = append(res.Items, backup.RestoreItem{Name: "snapshot", Status: "succeeded", Bytes: int64(len(call.snapshot))})
		return res, nil
	}
	zr, err := zip.NewReader(rc.Archive, rc.Archive.Size())
	if err != nil {
		return res, err
	}
	for i, db := range rc.Databases {
		res.Created = append(res.Created, db)
		rc.Progress(backup.Progress{Phase: "restore", Database: db, Created: append([]string{}, res.Created...)})
		if i == 0 && block != nil {
			close(started)
			select {
			case <-block:
			case <-ctx.Done():
				return res, ctx.Err()
			}
		}
		r, err := zr.Open(db)
		if err != nil {
			return res, err
		}
		n, err := io.Copy(io.Discard, r)
		r.Close()
		if err != nil {
			res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "failed", Bytes: n, Error: err.Error()})
			return res, fmt.Errorf("%s: %w", db, err)
		}
		res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "succeeded", Bytes: n, Tables: 1})
	}
	return res, nil
}

var (
	pgRestorer    = &fakeRestorer{}
	vaultRestorer = &fakeRestorer{}
)

func init() {
	backup.RegisterRestorer("postgresql", pgRestorer)
	backup.RegisterRestorer("vault", vaultRestorer)
}

// ---------------------------------------------------------------- fixture

type xenv struct {
	*env
	ex             *restore.Executor
	maker, checker *apitest.Client
}

func newXEnv(t *testing.T) *xenv {
	e := newEnv(t)
	pgRestorer.reset()
	vaultRestorer.reset()
	x := &xenv{env: e,
		maker:   e.login("ada", "viewer@env=prod", "operator@env=stage"),
		checker: e.login("bob", "operator@env=prod", "operator@env=stage"),
	}
	x.ex = &restore.Executor{DB: e.DB, Log: e.Log, Dialer: e.dialer, Blobs: e.blobs,
		Creds: &backup.Credentials{KV: e.KV, Envelope: e.Envelope}, Envelope: e.Envelope,
		PerCluster: 2, Heartbeat: 20 * time.Millisecond, StaleAfter: time.Minute, ProgressEvery: time.Millisecond}
	x.pgRun = x.pgRunWith(zipOf(t, "shop", []byte("shop-dump-data"), "billing", []byte("billing-dump-data")), "")
	return x
}

// pgRunWith replaces the PostgreSQL run of the fixture with one whose copy
// is b, recorded with digest sum (default: b's).
func (x *xenv) pgRunWith(b []byte, sum string) uuid.UUID {
	x.T.Helper()
	if sum == "" {
		sum = digest(b)
	}
	run := x.runSum(x.pgSource, "succeeded", "manual", "zip", map[string]any{"databases": []string{"postgres", "shop", "billing"}}, sum)
	x.put(run, b)
	x.pgRun = run
	return run
}

// zipOf builds a zip archive of stored (uncompressed) entries name, data, ...
func zipOf(t *testing.T, kv ...any) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < len(kv); i += 2 {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: kv[i].(string), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(kv[i+1].([]byte)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// put stores b as the run's copy.
func (x *xenv) put(run uuid.UUID, b []byte) {
	x.T.Helper()
	var path string
	x.scan(&path, `SELECT blob_path FROM backup_run_copies WHERE run_id = $1`, run)
	x.blobs.put(path, b)
}

// approved opens a PostgreSQL request into target and has it approved.
func (x *xenv) approved(target string) uuid.UUID {
	x.T.Helper()
	rq := x.open(x.maker, x.pgInput(target))
	if code := x.do(x.checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", map[string]string{"comment": "go"}, nil); code != 200 {
		x.T.Fatalf("approve: %d %s", code, x.bodies[len(x.bodies)-1])
	}
	return rq.ID
}

// claim expects the executor to claim want (uuid.Nil: nothing).
func (x *xenv) claim(want uuid.UUID) {
	x.T.Helper()
	got, err := x.ex.Claim(context.Background())
	if err != nil {
		x.T.Fatalf("claim: %v", err)
	}
	if got != want {
		x.T.Fatalf("claimed %s, want %s", got, want)
	}
}

type stored struct {
	Status     restore.Status
	Error      string
	Result     backup.RestoreResult
	Progress   backup.Progress
	StartedAt  *time.Time
	FinishedAt *time.Time
}

func (x *xenv) stored(id uuid.UUID) stored {
	x.T.Helper()
	var s stored
	var st string
	var res, prog []byte
	if err := x.DB.QueryRow(context.Background(), `SELECT status, error, result, progress, started_at, finished_at FROM restore_requests WHERE id = $1`, id).
		Scan(&st, &s.Error, &res, &prog, &s.StartedAt, &s.FinishedAt); err != nil {
		x.T.Fatal(err)
	}
	s.Status = restore.Status(st)
	_ = json.Unmarshal(res, &s.Result)
	_ = json.Unmarshal(prog, &s.Progress)
	return s
}

func (x *xenv) wiped(id uuid.UUID) {
	x.T.Helper()
	if tok, cred := x.secretsOf(id); tok || cred {
		x.T.Fatalf("secrets kept after the end: token %v, credential %v", tok, cred)
	}
}

// eventTypes lists the restore events of a request.
func (x *xenv) eventTypes(id uuid.UUID) []string {
	var out []string
	for _, ev := range x.events("restore.%") {
		if ev.Payload["restore_id"] == id.String() {
			out = append(out, ev.Type)
		}
	}
	return out
}

// ---------------------------------------------------------------- tests

func TestExecuteSucceeds(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	x.claim(id)
	if s := x.stored(id); s.Status != restore.StatusRunning || s.StartedAt == nil {
		t.Fatalf("claimed: %+v", s)
	}
	// One at a time per request: nothing else to claim.
	x.claim(uuid.Nil)
	x.ex.Execute(context.Background(), id)

	s := x.stored(id)
	if s.Status != restore.StatusSucceeded || s.Error != "" || s.FinishedAt == nil {
		t.Fatalf("finished: %+v", s)
	}
	if len(s.Result.Items) != 2 || s.Result.Items[0].Name != "shop" || s.Result.Items[0].Status != "succeeded" ||
		s.Result.Items[1].Name != "billing" || s.Result.Items[1].Bytes != int64(len("billing-dump-data")) ||
		strings.Join(s.Result.Created, ",") != "shop,billing" {
		t.Fatalf("result: %+v", s.Result)
	}
	if strings.Join(s.Progress.Created, ",") != "shop,billing" {
		t.Fatalf("progress: %+v", s.Progress)
	}
	c := pgRestorer.last()
	if pgRestorer.callCount() != 1 || c.secret != canaryPassword || !c.superuser || strings.Join(c.databases, ",") != "shop,billing" ||
		c.options.Globals == nil || !*c.options.Globals || c.requestID != id.String() {
		t.Fatalf("restorer got: %+v", c)
	}
	x.wiped(id)
	if ev := x.eventTypes(id); strings.Join(ev, ",") != "restore.requested,restore.approved,restore.started,restore.succeeded" {
		t.Fatalf("events: %v", ev)
	}
	if a := x.actions(id); strings.Join(a, ",") != "restore.approved,restore.requested,restore.started,restore.succeeded" {
		t.Fatalf("audit: %v", a)
	}
	// The target is free again.
	x.approved(x.pgTarget)
	x.noCanary()
}

func TestExecuteVault(t *testing.T) {
	x := newXEnv(t)
	src := x.target(x.prod, "vault", "vault", "hashicorp")
	snap := bytes.Repeat([]byte("raft-snapshot-"), 1000)
	run := x.runSum(src, "succeeded", "manual", "snap", nil, digest(snap))
	x.put(run, snap)
	tgt := x.target(x.stage, "vault-new", "vault", "hashicorp")
	rq := x.open(x.maker, map[string]any{"run_id": run, "target_id": tgt, "vault_token": canaryToken, "justification": "Restore the vault after the outage"})
	if code := x.do(x.checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", nil, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	x.claim(rq.ID)
	x.ex.Execute(context.Background(), rq.ID)
	s := x.stored(rq.ID)
	if s.Status != restore.StatusSucceeded || len(s.Result.Items) != 1 || s.Result.Items[0].Name != "snapshot" {
		t.Fatalf("vault restore: %+v", s)
	}
	c := vaultRestorer.last()
	if c.secret != canaryToken || !bytes.Equal(c.snapshot, snap) || len(c.databases) != 0 {
		t.Fatalf("vault restorer got secret %v, %d snapshot bytes", c.secret == canaryToken, len(c.snapshot))
	}
	x.wiped(rq.ID)
	x.noCanary()
}

// Review Focus 1: the target gets data between approval and start. The
// start-time re-check refuses, names the database, and nothing is written.
func TestExecuteTargetGotData(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	pgInspector.set(restore.TargetReport{Superuser: true, Existing: map[string]bool{"billing": true, "shop": false}}, nil, false)
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	s := x.stored(id)
	if s.Status != restore.StatusFailed || !strings.Contains(s.Error, "billing") || !strings.Contains(s.Error, "with data in them") {
		t.Fatalf("not refused: %+v", s)
	}
	if pgRestorer.callCount() != 0 {
		t.Fatal("the restorer ran")
	}
	x.wiped(id)
	if ev := x.eventTypes(id); ev[len(ev)-1] != "restore.failed" {
		t.Fatalf("events: %v", ev)
	}
	x.noCanary()
}

// The other start-time rules: the target went away.
func TestExecuteTargetGone(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	x.claim(id)
	x.exec(`UPDATE targets SET status = 'gone' WHERE id = $1`, x.pgTarget)
	calls := pgInspector.calls
	x.ex.Execute(context.Background(), id)
	if s := x.stored(id); s.Status != restore.StatusFailed || !strings.Contains(s.Error, "the target is gone") {
		t.Fatalf("gone target: %+v", s)
	}
	if pgRestorer.callCount() != 0 || pgInspector.calls != calls || x.dialer.dialCount() != 0 {
		t.Fatal("the target was contacted")
	}
	x.wiped(id)
}

// Review Focus 3: a copy changed after it was written fails the SHA-256
// pass before anything connects to the target.
func TestExecuteTamperedCopy(t *testing.T) {
	x := newXEnv(t)
	good := zipOf(t, "shop", []byte("shop-dump-data"), "billing", []byte("billing-dump-data"))
	bad := bytes.Replace(good, []byte("shop-dump-data"), []byte("shop-dump-DATA"), 1)
	x.pgRunWith(bad, digest(good))
	id := x.approved(x.pgTarget)
	calls := pgInspector.calls
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	s := x.stored(id)
	if s.Status != restore.StatusFailed || !strings.Contains(s.Error, "SHA-256") || !strings.Contains(s.Error, digest(bad)) {
		t.Fatalf("tampered copy: %+v", s)
	}
	if pgRestorer.callCount() != 0 || pgInspector.calls != calls || x.dialer.dialCount() != 0 {
		t.Fatalf("the target was contacted: restorer %d, inspector %d→%d, dials %d", pgRestorer.callCount(), calls, pgInspector.calls, x.dialer.dialCount())
	}
	x.wiped(id)
	x.noCanary()
}

// Review Focus 3: an archive written corrupt (its checksum matches the copy
// row) fails on the entry's CRC-32; the database is named and the databases
// created so far are listed and left in place.
func TestExecuteCRCError(t *testing.T) {
	x := newXEnv(t)
	good := zipOf(t, "shop", []byte("shop-dump-data"), "billing", []byte("billing-dump-data"))
	bad := bytes.Replace(good, []byte("billing-dump-data"), []byte("billing-dump-DATA"), 1)
	x.pgRunWith(bad, "")
	id := x.approved(x.pgTarget)
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	s := x.stored(id)
	if s.Status != restore.StatusFailed || !strings.Contains(s.Error, "billing") || !strings.Contains(s.Error, zip.ErrChecksum.Error()) ||
		!strings.Contains(s.Error, "left in place: shop, billing") {
		t.Fatalf("CRC error: %+v", s)
	}
	if len(s.Result.Items) != 2 || s.Result.Items[0].Status != "succeeded" || s.Result.Items[1].Status != "failed" ||
		!strings.Contains(s.Result.Items[1].Error, "checksum") || strings.Join(s.Result.Created, ",") != "shop,billing" {
		t.Fatalf("result: %+v", s.Result)
	}
	x.wiped(id)
	if ev := x.events("restore.failed"); len(ev) != 1 || !strings.Contains(ev[0].Payload["fields"].(map[string]any)["Error"].(string), "billing") {
		t.Fatalf("restore.failed: %+v", ev)
	}
}

// Review Focus 4: a request left running by a stopped server is failed by
// the reaper with the databases created so far, and the target is free.
func TestReapStale(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	x.claim(id)
	// The stopped server's last heartbeat.
	x.exec(`UPDATE restore_requests SET progress = '{"phase":"restore","database":"billing","created":["shop","billing"]}' WHERE id = $1`, id)
	x.ex.StaleAfter = 100 * time.Millisecond
	time.Sleep(250 * time.Millisecond)
	if err := x.ex.ReapStale(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := x.stored(id)
	if s.Status != restore.StatusFailed || !strings.HasPrefix(s.Error, "interrupted: server stopped during the restore") ||
		!strings.Contains(s.Error, "shop, billing") || strings.Join(s.Result.Created, ",") != "shop,billing" || s.FinishedAt == nil {
		t.Fatalf("reaped: %+v", s)
	}
	x.wiped(id)
	if ev := x.eventTypes(id); ev[len(ev)-1] != "restore.failed" {
		t.Fatalf("events: %v", ev)
	}
	if a := x.actions(id); !strings.Contains(strings.Join(a, ","), "restore.failed") {
		t.Fatalf("audit: %v", a)
	}
	// A late Execute of the reaped request changes nothing.
	x.ex.Execute(context.Background(), id)
	if s2 := x.stored(id); s2.Status != restore.StatusFailed || s2.Error != s.Error || pgRestorer.callCount() != 0 {
		t.Fatalf("after a late execute: %+v", s2)
	}
	// The target is free: a new request is approved and claimed.
	next := x.approved(x.pgTarget)
	x.claim(next)
}

// A running restore heartbeats: the reaper leaves it alone.
func TestHeartbeatKeepsRunning(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	pgRestorer.mu.Lock()
	pgRestorer.block, pgRestorer.started = make(chan struct{}), make(chan struct{})
	block, started := pgRestorer.block, pgRestorer.started
	pgRestorer.mu.Unlock()
	x.ex.StaleAfter = 300 * time.Millisecond
	x.claim(id)
	done := make(chan struct{})
	go func() { x.ex.Execute(context.Background(), id); close(done) }()
	<-started
	time.Sleep(600 * time.Millisecond)
	if err := x.ex.ReapStale(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := x.stored(id)
	if s.Status != restore.StatusRunning || s.Progress.Database != "shop" || strings.Join(s.Progress.Created, ",") != "shop" ||
		s.Progress.Phase != "restore" {
		t.Fatalf("while running: %+v", s)
	}
	close(block)
	<-done
	if s := x.stored(id); s.Status != restore.StatusSucceeded {
		t.Fatalf("after: %+v", s)
	}
}

// A restore interrupted by the server's shutdown fails at once.
func TestExecuteInterrupted(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	pgRestorer.mu.Lock()
	pgRestorer.block, pgRestorer.started = make(chan struct{}), make(chan struct{})
	started := pgRestorer.started
	pgRestorer.mu.Unlock()
	x.claim(id)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { x.ex.Execute(ctx, id); close(done) }()
	<-started
	cancel()
	<-done
	s := x.stored(id)
	if s.Status != restore.StatusFailed || !strings.HasPrefix(s.Error, "interrupted: server stopped during the restore") ||
		strings.Join(s.Result.Created, ",") != "shop" {
		t.Fatalf("interrupted: %+v", s)
	}
	x.wiped(id)
}

// Restores and backup runs share the per-cluster running limit, both ways.
func TestClaimSharesClusterLimit(t *testing.T) {
	x := newXEnv(t)
	x.ex.PerCluster = 1
	ctx := context.Background()
	// A backup running in the target's cluster holds the only slot.
	stageSrc := x.target(x.stage, "other-pg", "postgresql", "")
	var job uuid.UUID
	x.scan(&job, `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone) VALUES ($1, $2, '0 2 * * *', 'UTC') RETURNING id`, stageSrc, x.dest)
	var backupRun uuid.UUID
	x.scan(&backupRun, `INSERT INTO backup_runs (job_id, trigger, status, started_at, destination_ids) VALUES ($1, 'manual', 'running', now(), ARRAY[$2::uuid]) RETURNING id`, job, x.dest)
	id := x.approved(x.pgTarget)
	x.claim(uuid.Nil)
	x.exec(`UPDATE backup_runs SET status = 'succeeded', finished_at = now() WHERE id = $1`, backupRun)
	x.claim(id)

	// The running restore holds the slot for backups.
	var queued uuid.UUID
	x.scan(&queued, `INSERT INTO backup_runs (job_id, trigger, status, destination_ids) VALUES ($1, 'manual', 'queued', ARRAY[$2::uuid]) RETURNING id`, job, x.dest)
	w := &backup.Worker{DB: x.DB, Log: x.Log, Dialer: x.dialer, PerCluster: 1}
	if got, err := w.Claim(ctx); err != nil || got != uuid.Nil {
		t.Fatalf("backup claimed %s (%v) while a restore holds the slot", got, err)
	}
	w.PerCluster = 2
	if got, err := w.Claim(ctx); err != nil || got != queued {
		t.Fatalf("backup claim with a free slot: %s %v", got, err)
	}
	// Now the cluster has a restore and a backup running: another restore
	// waits at a limit of 2.
	x.ex.PerCluster = 2
	other := x.approved(x.pgTarget2)
	x.claim(uuid.Nil)
	x.exec(`UPDATE backup_runs SET status = 'succeeded', finished_at = now() WHERE id = $1`, queued)
	x.claim(other)
}

// No claim while the target's agent is not connected to this replica, and
// none once the approval is older than ApprovedTTL.
func TestClaimNeedsAgentAndFreshApproval(t *testing.T) {
	x := newXEnv(t)
	id := x.approved(x.pgTarget)
	x.dialer.setConnected(x.stage, false)
	x.claim(uuid.Nil)
	if s := x.stored(id); s.Status != restore.StatusApproved {
		t.Fatalf("not connected: %+v", s)
	}
	x.dialer.setConnected(x.stage, true)
	x.exec(`UPDATE restore_requests SET approved_expires_at = now() - interval '1 minute' WHERE id = $1`, id)
	x.claim(uuid.Nil)
	if s := x.stored(id); s.Status != restore.StatusApproved {
		t.Fatalf("expired approval: %+v", s)
	}
}

// Ruling 7: every audit row and event of a restore carries the backup's
// cluster, so a reader of the target's cluster only sees none of them in
// the activity feed (they would name the source's run and databases).
func TestRestoreAuditOnSourceCluster(t *testing.T) {
	x := newXEnv(t)
	ctx := context.Background()
	// requested, approved, started, succeeded
	ok := x.approved(x.pgTarget)
	x.claim(ok)
	x.ex.Execute(ctx, ok)
	// checked (dialog), requested, rejected
	if code := x.do(x.maker, "POST", "/api/v1/restores/check", x.pgInput(x.pgTarget2), nil); code != 200 {
		t.Fatalf("check: %d", code)
	}
	rej := x.open(x.maker, x.pgInput(x.pgTarget2))
	if code := x.do(x.checker, "POST", "/api/v1/restores/"+rej.ID.String()+"/reject", map[string]string{"comment": "no"}, nil); code != 200 {
		t.Fatalf("reject: %d", code)
	}
	// cancelled
	can := x.open(x.maker, x.pgInput(x.pgTarget2))
	if code := x.do(x.maker, "POST", "/api/v1/restores/"+can.ID.String()+"/cancel", nil, nil); code != 200 {
		t.Fatalf("cancel: %d", code)
	}
	// expired
	exp := x.open(x.maker, x.pgInput(x.pgTarget2))
	x.exec(`UPDATE restore_requests SET expires_at = now() - interval '1 hour' WHERE id = $1`, exp.ID)
	if n, err := x.api.ExpireDue(ctx); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	// break-glass, then failed at start (target got data)
	in := x.pgInput(x.pgTarget2)
	in["break_glass"] = true
	bg := x.open(x.login("root", "admin"), in)
	pgInspector.set(restore.TargetReport{Superuser: true, Existing: map[string]bool{"shop": true}}, nil, false)
	x.claim(bg.ID)
	x.ex.Execute(ctx, bg.ID)

	want := []string{"restore.approved", "restore.break_glass", "restore.cancelled", "restore.checked", "restore.expired", "restore.failed",
		"restore.rejected", "restore.requested", "restore.started", "restore.succeeded"}
	rows, err := x.DB.Query(ctx, `SELECT DISTINCT action FROM activity_log WHERE action LIKE 'restore.%' ORDER BY action`)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		seen = append(seen, a)
	}
	rows.Close()
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("actions: %v", seen)
	}
	var off int
	x.scan(&off, `SELECT count(*) FROM activity_log WHERE action LIKE 'restore.%' AND cluster_id IS DISTINCT FROM $1`, x.prod)
	if off != 0 {
		t.Fatalf("%d restore audit rows not on the backup's cluster", off)
	}
	for _, ev := range x.events("restore.%") {
		if ev.Payload["cluster_id"] != x.prod.String() {
			t.Fatalf("%s carries cluster %v", ev.Type, ev.Payload["cluster_id"])
		}
	}

	type feed struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	count := func(c *apitest.Client) int {
		var f feed
		if code := x.do(c, "GET", "/api/v1/activity?limit=500", nil, &f); code != http.StatusOK {
			t.Fatalf("activity: %d", code)
		}
		n := 0
		for _, it := range f.Items {
			if strings.HasPrefix(it.Action, "restore.") {
				n++
			}
		}
		return n
	}
	for _, c := range []*apitest.Client{x.login("stage-reader", "viewer@env=stage"), x.login("stage-admin", "admin@env=stage")} {
		if n := count(c); n != 0 {
			t.Fatalf("a target-only reader sees %d restore audit rows", n)
		}
	}
	if n := count(x.login("prod-reader", "viewer@env=prod")); n == 0 {
		t.Fatal("a reader of the backup's cluster sees no restore audit rows")
	}
	x.noCanary()
}

var _ = errors.New

// The copy row and the sidecar manifest must agree too: a manifest that
// records another digest fails the request before the target is contacted.
func TestExecuteManifestMismatch(t *testing.T) {
	x := newXEnv(t)
	var path string
	x.scan(&path, `SELECT blob_path FROM backup_run_copies WHERE run_id = $1`, x.pgRun)
	other := strings.Repeat("0", 64)
	m, _ := json.Marshal(map[string]any{"run_id": x.pgRun, "details": map[string]any{"databases": []string{"postgres", "shop", "billing"}},
		"blob": map[string]any{"sha256": other}})
	x.blobs.put(backup.ManifestPath(path, x.pgRun), m)
	id := x.approved(x.pgTarget)
	calls := pgInspector.calls
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	if s := x.stored(id); s.Status != restore.StatusFailed || !strings.Contains(s.Error, "does not match its manifest") || !strings.Contains(s.Error, other) {
		t.Fatalf("manifest mismatch: %+v", s)
	}
	if pgRestorer.callCount() != 0 || pgInspector.calls != calls || x.dialer.dialCount() != 0 {
		t.Fatal("the target was contacted")
	}
	x.wiped(id)
}
