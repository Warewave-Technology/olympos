//go:build dev

package restore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/clickhouse"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/restore"
)

// Native ClickHouse runs as a restore source (task 16): the check verifies
// the copy's signed manifest and lists every object of the selected
// databases with the allowlist's decision.

const (
	nativeKeyName   = "olympos-manifest"
	nativeIngestURL = "https://ingest.olympos.test:9444"
)

// nativeObj is one object of a native fixture run.
type nativeObj struct{ db, name, kind, ddl string }

var nativeSchema = []nativeObj{
	{"shop", "orders", clickhouse.KindTable, "CREATE TABLE shop.orders (`id` UInt64) ENGINE = MergeTree ORDER BY id"},
	{"shop", "ext", clickhouse.KindTable, "CREATE TABLE shop.ext (`id` UInt64) ENGINE = URL('http://example.invalid/x', 'CSV')"},
	{"shop", "report", clickhouse.KindView, "CREATE VIEW shop.report (`id` UInt64) AS SELECT id FROM stats.daily"},
	{"stats", "daily", clickhouse.KindTable, "CREATE TABLE stats.daily (`id` UInt64) ENGINE = Log"},
}

// nativeRun inserts a succeeded full native run of a native job on target,
// with one copy in dest: its objects, the metadata of objs, and its sidecar
// with the signed manifest. It returns the run and the sidecar's path.
func (e *env) nativeRun(target string, objs []nativeObj) (uuid.UUID, string) {
	e.T.Helper()
	ctx := context.Background()
	var job uuid.UUID
	e.scan(&job, `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone, engine_options) VALUES ($1, $2, '0 2 * * *', 'UTC',
		'{"method":"native"}') RETURNING id`, target, e.dest)
	run := uuid.New()
	dir := "p/c/shop/" + run.String()
	m := &clickhouse.NativeManifest{Format: clickhouse.NativeManifestFormat, RunID: run.String(), ServerVersion: "25.8.1.1",
		Settings: map[string]string{"async": "1", "id": run.String()}, PartRows: map[string]uint64{}}
	put := func(rel string, body []byte) string {
		h := sha256.Sum256(body)
		key := run.String() + "/" + rel
		m.Objects = append(m.Objects, ingest.ObjectRecord{Key: key, Size: int64(len(body)), SHA256: hex.EncodeToString(h[:])})
		e.blobs.put(dir+"/"+rel, body)
		return key
	}
	put(".backup", []byte("<config/>"))
	at := map[string]int{}
	for _, o := range objs {
		key := put("metadata/"+o.db+"/"+o.name+".sql", []byte(o.ddl))
		i, ok := at[o.db]
		if !ok {
			i = len(m.Databases)
			at[o.db] = i
			m.Databases = append(m.Databases, clickhouse.NativeDatabase{Name: o.db})
		}
		m.Databases[i].Objects = append(m.Databases[i].Objects, clickhouse.NativeObject{Name: o.name, Kind: o.kind, DDLKey: key})
	}
	s, err := clickhouse.Sign(ctx, e.KV, nativeKeyName, m)
	if err != nil {
		e.T.Fatal(err)
	}
	signed, err := json.Marshal(s)
	if err != nil {
		e.T.Fatal(err)
	}
	side, _ := json.Marshal(map[string]any{"run_id": run, "details": map[string]json.RawMessage{backup.NativeManifestDetail: signed}})
	sidecar := backup.ManifestPath(dir, run)
	e.blobs.put(sidecar, side)
	e.exec(`INSERT INTO backup_runs (id, job_id, trigger, status, blob_path, sha256, started_at, finished_at, destination_ids, objects)
		VALUES ($1, $2, 'manual', 'succeeded', $3, $4, now(), now(), ARRAY[$5::uuid], $6)`, run, job, dir, m.SHA256(), e.dest, len(m.Objects))
	e.exec(`INSERT INTO backup_run_copies (run_id, destination_id, status, blob_path, sha256) VALUES ($1, $2, 'succeeded', $3, $4)`,
		run, e.dest, dir, m.SHA256())
	e.exec(`INSERT INTO ingest_credentials (access_key, run_id, kind, scope, fingerprint, expires_at, revoked_at, reason)
		VALUES ($1, $2, 'backup', $3, 'hm:test', now(), now(), 'run ended')`, "OLY"+run.String()[:8], run, `{"write": "`+run.String()+`/"}`)
	return run, sidecar
}

// R38 is lifted: a native run's copy is checked and opened like any other,
// and the check lists the decisions for the selected databases: every
// object, those left out with their reason.
func TestNativeCheckAndOpen(t *testing.T) {
	e := newEnv(t)
	src := e.target(e.prod, "events-ch", "clickhouse", "")
	tgt := e.target(e.stage, "events-ch-new", "clickhouse", "")
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	run, _ := e.nativeRun(src, nativeSchema)
	in := map[string]any{"run_id": run, "target_id": tgt, "credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}

	var res restore.CheckResult
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || !res.OK || res.Native == nil {
		t.Fatalf("check: %d %+v", code, res)
	}
	if !reflect.DeepEqual(res.DatabasesInBackup, []string{"shop", "stats"}) || !reflect.DeepEqual(res.Databases, []string{"shop", "stats"}) {
		t.Fatalf("databases: %+v", res)
	}
	want := []backup.NativeDecision{
		{Database: "shop", Name: "ext", Kind: "table", Reason: "the URL engine is not on the restore allowlist"},
		{Database: "shop", Name: "orders", Kind: "table", Allowed: true},
		{Database: "shop", Name: "report", Kind: "view", Allowed: true},
		{Database: "stats", Name: "daily", Kind: "table", Allowed: true},
	}
	if !reflect.DeepEqual(res.Native.Objects, want) {
		t.Fatalf("decisions:\n got %+v\nwant %+v", res.Native.Objects, want)
	}

	// The decisions are for the selection: a view that reads a database
	// left unselected is not restored.
	in["databases"] = []string{"shop"}
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || !res.OK {
		t.Fatalf("check shop: %d %+v", code, res)
	}
	want = []backup.NativeDecision{
		{Database: "shop", Name: "ext", Kind: "table", Reason: "the URL engine is not on the restore allowlist"},
		{Database: "shop", Name: "orders", Kind: "table", Allowed: true},
		{Database: "shop", Name: "report", Kind: "view", Reason: "it reads stats.daily, which is not restored"},
	}
	if !reflect.DeepEqual(res.Native.Objects, want) || !reflect.DeepEqual(res.Databases, []string{"shop"}) {
		t.Fatalf("decisions for shop:\n got %+v\nwant %+v", res.Native.Objects, want)
	}

	// Opening it works now (R38 lifted).
	in["justification"] = "INC-1: restore the shop database into events-ch-new"
	rq := e.open(maker, in)
	if rq.Engine != "clickhouse" || !reflect.DeepEqual(rq.Databases, []string{"shop"}) || rq.Source.RunID != run {
		t.Fatalf("request: %+v", rq)
	}
	e.noCanary()
}

// TestNativeCheckDoesNotVerify: a copy whose manifest does not verify is
// refused with "the backup's manifest does not verify" on the copy, the
// target is not contacted, and the decisions are listed from what the copy
// holds, every object left out with that reason; the cause is logged, not
// shown.
func TestNativeCheckDoesNotVerify(t *testing.T) {
	e := newEnv(t)
	src := e.target(e.prod, "events-ch", "clickhouse", "")
	tgt := e.target(e.stage, "events-ch-new", "clickhouse", "")
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	run, sidecar := e.nativeRun(src, nativeSchema[:2])
	in := map[string]any{"run_id": run, "target_id": tgt, "credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}

	// The run's DDL changed in storage: its manifest still verifies, the
	// object does not.
	e.blobs.put("p/c/shop/"+run.String()+"/metadata/shop/orders.sql", []byte("CREATE TABLE shop.orders (`id` UInt64) ENGINE = URL('http://x', 'CSV')"))
	var res restore.CheckResult
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || res.OK ||
		res.Fields["copy_destination_id"] != "the backup's manifest does not verify" {
		t.Fatalf("a changed definition: %d %+v", code, res)
	}

	raw := e.blobs.blobs[sidecar]
	e.blobs.put(sidecar, bytes.Replace(raw, []byte(`"server_version":"25.8.1.1"`), []byte(`"server_version":"25.8.1.2"`), 1))
	calls := chInspector.calls
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || res.OK ||
		res.Fields["copy_destination_id"] != "the backup's manifest does not verify" || res.Native == nil || len(res.Native.Objects) != 0 {
		t.Fatalf("a manifest that does not verify: %d %+v", code, res)
	}
	if chInspector.calls != calls {
		t.Fatal("the target was contacted for a backup that does not verify")
	}
	if !strings.Contains(e.LogBuf.String(), "verify native manifest") {
		t.Fatalf("the cause is not logged: %s", e.LogBuf.String())
	}
	in["justification"] = "INC-1: restore the shop database into events-ch-new"
	var eb errBody
	if code := e.do(maker, "POST", "/api/v1/restores", in, &eb); code != http.StatusUnprocessableEntity ||
		eb.Fields["copy_destination_id"] != "the backup's manifest does not verify" {
		t.Fatalf("open: %d %+v", code, eb)
	}
	e.noCanary()
}

// TestNativeCheckIngestOff: without the ingest endpoint a native copy cannot
// be restored (its ClickHouse reads the backup through it), and the check
// says so.
func TestNativeCheckIngestOff(t *testing.T) {
	e := newEnv(t)
	e.api.Native = nil
	src := e.target(e.prod, "events-ch", "clickhouse", "")
	tgt := e.target(e.stage, "events-ch-new", "clickhouse", "")
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	run, _ := e.nativeRun(src, nativeSchema[:1])
	in := map[string]any{"run_id": run, "target_id": tgt, "credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}
	var res restore.CheckResult
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || res.OK ||
		res.Fields["run_id"] != "a native backup is restored through the ingest endpoint, which is off on this server (ingest.url)" {
		t.Fatalf("check: %d %+v", code, res)
	}
}

// TestNativeExecuteNotYet: an approved native request ends at its start,
// failed, before anything is read from the copy or sent to the target, its
// secrets wiped: the native RESTORE is task 17's.
func TestNativeExecuteNotYet(t *testing.T) {
	x := newXEnv(t)
	src := x.target(x.prod, "events-ch", "clickhouse", "")
	tgt := x.target(x.stage, "events-ch-new", "clickhouse", "")
	run, _ := x.nativeRun(src, nativeSchema[:1])
	rq := x.open(x.maker, map[string]any{"run_id": run, "target_id": tgt, "justification": "INC-1: restore the shop database",
		"credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}})
	if code := x.do(x.checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", map[string]string{"comment": "go"}, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	x.claim(rq.ID)
	calls := chInspector.calls
	x.ex.Execute(context.Background(), rq.ID)
	if s := x.stored(rq.ID); s.Status != restore.StatusFailed || s.Error != "this server does not run native restores yet; nothing was read or written" {
		t.Fatalf("native request: %+v", s)
	}
	if chInspector.calls != calls || x.dialer.dialCount() != 0 {
		t.Fatal("the target was contacted")
	}
	x.wiped(rq.ID)
	x.noCanary()
}

// TestNativeCheckClientGone: a request that goes away while its chain is
// read ends quietly: no "does not verify" warning, no internal error, the
// target not contacted.
func TestNativeCheckClientGone(t *testing.T) {
	e := newEnv(t)
	src := e.target(e.prod, "events-ch", "clickhouse", "")
	tgt := e.target(e.stage, "events-ch-new", "clickhouse", "")
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	run, sidecar := e.nativeRun(src, nativeSchema[:1])
	reached, done := make(chan struct{}), make(chan struct{})
	e.blobs.mu.Lock()
	e.blobs.hold = func(ctx context.Context, path string) error {
		if path != sidecar {
			return nil
		}
		close(reached)
		<-ctx.Done() // the client is gone
		defer close(done)
		return ctx.Err()
	}
	e.blobs.mu.Unlock()
	t.Cleanup(func() {
		e.blobs.mu.Lock()
		e.blobs.hold = nil
		e.blobs.mu.Unlock()
	})
	in := map[string]any{"run_id": run, "target_id": tgt, "credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}
	ctx, cancel := context.WithCancel(context.Background())
	b, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, "POST", e.Srv.URL+"/api/v1/restores/check", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", maker.CSRF)
	sent := make(chan error, 1)
	go func() {
		resp, err := maker.HTTP.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		sent <- err
	}()
	<-reached
	calls := chInspector.calls
	cancel()
	if err := <-sent; err == nil {
		t.Fatal("the request was answered")
	}
	<-done
	// The handler ends right after the read; give its log lines time to land.
	time.Sleep(300 * time.Millisecond)
	for _, s := range []string{"does not verify", "request failed"} {
		if strings.Contains(e.LogBuf.String(), s) {
			t.Fatalf("a request that went away logged %q: %s", s, e.LogBuf.String())
		}
	}
	if chInspector.calls != calls {
		t.Fatal("the target was contacted")
	}
}
