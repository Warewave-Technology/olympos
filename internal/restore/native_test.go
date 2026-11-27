//go:build dev

package restore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/clickhouse"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/restore"
	"github.com/Warewave-Technology/olympos/internal/secrets"
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
	// .backup lists every file put, with the first half of its SHA-256 as
	// its checksum: what the restore reads is resolved from it.
	var files strings.Builder
	put := func(rel string, body []byte) string {
		h := sha256.Sum256(body)
		key := run.String() + "/" + rel
		m.Objects = append(m.Objects, ingest.ObjectRecord{Key: key, Size: int64(len(body)), SHA256: hex.EncodeToString(h[:])})
		e.blobs.put(dir+"/"+rel, body)
		fmt.Fprintf(&files, "<file><name>%s</name><size>%d</size><checksum>%s</checksum></file>", rel, len(body), hex.EncodeToString(h[:16]))
		return key
	}
	at := map[string]int{}
	for _, o := range objs {
		if _, ok := at[o.db]; !ok {
			engine := e.dbEngines[o.db]
			if engine == "" {
				engine = "Atomic"
			}
			put("metadata/"+o.db+".sql", []byte("CREATE DATABASE "+o.db+" ENGINE = "+engine))
		}
		key := put("metadata/"+o.db+"/"+o.name+".sql", []byte(o.ddl))
		if o.kind == clickhouse.KindTable {
			put("data/"+o.db+"/"+o.name+"/all_1_1_0/data.bin", []byte("the rows of "+o.db+"."+o.name))
		}
		i, ok := at[o.db]
		if !ok {
			i = len(m.Databases)
			at[o.db] = i
			m.Databases = append(m.Databases, clickhouse.NativeDatabase{Name: o.db})
		}
		m.Databases[i].Objects = append(m.Databases[i].Objects, clickhouse.NativeObject{Name: o.name, Kind: o.kind, DDLKey: key})
	}
	put(".backup", []byte("<config><version>1</version><uuid>"+uuid.NewString()+"</uuid><contents>"+files.String()+"</contents></config>"))
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

// TestNativeCheckDatabaseEngine (R52): a selected database whose engine in
// the backup is not Atomic is refused at the check, with the reason; left
// unselected, the others restore.
func TestNativeCheckDatabaseEngine(t *testing.T) {
	e := newEnv(t)
	e.dbEngines = map[string]string{"stats": "Lazy(60)"}
	src := e.target(e.prod, "events-ch", "clickhouse", "")
	tgt := e.target(e.stage, "events-ch-new", "clickhouse", "")
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	run, _ := e.nativeRun(src, nativeSchema)
	in := map[string]any{"run_id": run, "target_id": tgt, "credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}
	var res restore.CheckResult
	want := "a native restore cannot create these databases (leave them out): stats: it has the Lazy database engine; a native restore " +
		"creates Atomic databases only, and RESTORE refuses a database of another engine (restore it with the logical method)"
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || res.OK || res.Fields["databases"] != want {
		t.Fatalf("check: %d %+v", code, res)
	}
	in["databases"] = []string{"shop"}
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != http.StatusOK || !res.OK {
		t.Fatalf("check shop: %d %+v", code, res)
	}
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

// nativeRunner is the native restorer of the executor tests, in place of
// ClickHouse's (its RESTORE is the engine's Docker test's): it records the
// run and what its ingest session serves, and reads what read names
// through the session's source, as the target's RESTORE would.
type nativeRunner struct {
	reg   *ingest.Registry
	read  []string
	block bool // hold until the restore's context ends
	// silent sends no request: a target that cannot reach the endpoint,
	// whose RESTORE retries until the session stops and it is KILLed.
	// slowStart is the work before the RESTORE (CREATE DATABASE, Replicated
	// tables), which does not count against FirstRequest.
	silent    bool
	slowStart time.Duration
	err       error

	mu       sync.Mutex
	calls    []backup.NativeRestoreRun
	rc       backup.RestoreContext
	sess     *ingest.Session
	readErrs []error
	stopped  bool
}

func (*nativeRunner) Restore(context.Context, backup.RestoreContext) (*backup.RestoreResult, error) {
	return nil, errors.New("a native copy is not restored as one blob")
}

func (f *nativeRunner) RestoreNativeBackup(ctx context.Context, rc backup.RestoreContext, run backup.NativeRestoreRun) (*backup.RestoreResult, error) {
	s, secret, ok := f.reg.Lookup(run.AccessKey)
	f.mu.Lock()
	f.calls, f.rc, f.sess = append(f.calls, run), rc, s
	f.mu.Unlock()
	if !ok || secret != run.Secret {
		return nil, errors.New("the credential is not a live session")
	}
	time.Sleep(f.slowStart)
	if run.Sent != nil {
		run.Sent() // the RESTORE goes to the target
	}
	for _, key := range f.read {
		rc, _, err := s.Source().Open(ctx, key)
		if err == nil {
			_, err = io.ReadAll(rc)
			rc.Close()
		}
		f.mu.Lock()
		f.readErrs = append(f.readErrs, err)
		f.mu.Unlock()
		if err != nil {
			return &backup.RestoreResult{Created: []string{"shop"}}, errors.New("clickhouse: native restore RESTORE_FAILED: S3 error")
		}
	}
	if f.silent {
		reason := <-run.Stop
		return &backup.RestoreResult{}, errors.New("clickhouse: native restore ended (the ingest session stopped: " + reason + "): KILL QUERY made it RESTORE_FAILED")
	}
	if f.block {
		<-ctx.Done()
		f.mu.Lock()
		f.stopped = true
		f.mu.Unlock()
		return &backup.RestoreResult{Created: []string{"shop"}}, errors.New("clickhouse: native restore ended (" + ctx.Err().Error() + "): KILL QUERY made it RESTORE_CANCELLED")
	}
	if f.err != nil {
		return nil, f.err
	}
	res := &backup.RestoreResult{Created: []string{"shop"}, Notes: []string{}}
	for _, db := range rc.Databases {
		res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "succeeded", Tables: 1, Rows: 3})
	}
	return res, nil
}

func (f *nativeRunner) last() (backup.NativeRestoreRun, backup.RestoreContext, *ingest.Session, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return backup.NativeRestoreRun{}, backup.RestoreContext{}, nil, 0
	}
	return f.calls[len(f.calls)-1], f.rc, f.sess, len(f.calls)
}

// nativeExec is an executor test of a native request: the runner in place
// of ClickHouse's restorer, and an ingest registry for the credentials.
func nativeExec(t *testing.T) (*xenv, *nativeRunner) {
	x := newXEnv(t)
	fp, err := secrets.NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg := ingest.NewRegistry(x.DB, fp, 8, nil)
	x.ex.Native = &backup.NativeRestoreConfig{KV: x.KV, ManifestKeyName: nativeKeyName, URL: nativeIngestURL, Registry: reg}
	f := &nativeRunner{reg: reg}
	backup.RegisterRestorer("clickhouse", f)
	t.Cleanup(func() { backup.RegisterRestorer("clickhouse", clickhouse.Engine{}) })
	return x, f
}

// approvedNative opens a native request of objs for databases and has it
// approved; it returns the request and the run.
func (x *xenv) approvedNative(objs []nativeObj, databases ...string) (uuid.UUID, uuid.UUID) {
	x.T.Helper()
	src := x.target(x.prod, "events-ch", "clickhouse", "")
	tgt := x.target(x.stage, "events-ch-new", "clickhouse", "")
	run, _ := x.nativeRun(src, objs)
	in := map[string]any{"run_id": run, "target_id": tgt, "justification": "INC-1: restore the shop database",
		"credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}
	if len(databases) > 0 {
		in["databases"] = databases
	}
	rq := x.open(x.maker, in)
	if code := x.do(x.checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", map[string]string{"comment": "go"}, nil); code != 200 {
		x.T.Fatalf("approve: %d", code)
	}
	return rq.ID, run
}

// R50: a native request records, when it is opened, the databases and
// every object the restore leaves out with its reason; the request shows
// them to the checker.
func TestNativeOpenRecordsDecisions(t *testing.T) {
	x := newXEnv(t)
	id, _ := x.approvedNative(nativeSchema, "shop")
	var rq restore.Request
	if code := x.do(x.checker, "GET", "/api/v1/restores/"+id.String(), nil, &rq); code != http.StatusOK {
		t.Fatalf("get: %d", code)
	}
	want := &restore.NativeOptions{Databases: []string{"shop"}, Excluded: []backup.NativeDecision{
		{Database: "shop", Name: "ext", Kind: "table", Reason: "the URL engine is not on the restore allowlist"},
		{Database: "shop", Name: "report", Kind: "view", Reason: "it reads stats.daily, which is not restored"},
	}}
	if !reflect.DeepEqual(rq.Options.Native, want) {
		t.Fatalf("options.native:\n got %+v\nwant %+v", rq.Options.Native, want)
	}
	// Every database selected (none given): the record names them all.
	y := newXEnv(t)
	id2, _ := y.approvedNative(nativeSchema)
	var rq2 restore.Request
	y.do(y.checker, "GET", "/api/v1/restores/"+id2.String(), nil, &rq2)
	if rq2.Options.Native == nil || !reflect.DeepEqual(rq2.Options.Native.Databases, []string{"shop", "stats"}) ||
		len(rq2.Options.Native.Excluded) != 1 {
		t.Fatalf("every database: %+v", rq2.Options.Native)
	}
	x.noCanary()
}

// TestNativeExecute: an approved native request is checked again, its
// target too, and restored by the engine with a read-only credential over
// the chain, minted at start and revoked at the end, whose session serves
// only the chain's signed objects.
func TestNativeExecute(t *testing.T) {
	x, f := nativeExec(t)
	id, run := x.approvedNative(nativeSchema, "shop")
	key := run.String() + "/metadata/shop/orders.sql"
	f.read = []string{key}
	x.claim(id)
	calls := chInspector.calls
	x.ex.Execute(context.Background(), id)
	s := x.stored(id)
	if s.Status != restore.StatusSucceeded || s.Error != "" || len(s.Result.Items) != 1 || strings.Join(s.Result.Created, ",") != "shop" {
		t.Fatalf("native request: %+v", s)
	}
	if chInspector.calls != calls+1 {
		t.Fatal("the target was not checked again at start")
	}
	nr, rc, sess, n := f.last()
	if n != 1 || nr.RunID != run.String() || nr.URL != nativeIngestURL+"/olympos/"+run.String()+"/" || rc.RequestID != id.String() ||
		!reflect.DeepEqual(rc.Databases, []string{"shop"}) || len(nr.Decisions) != 3 || nr.Rows == nil {
		t.Fatalf("the engine got %v, %+v", nr, rc)
	}
	if sess.Kind() != ingest.KindRestore || !reflect.DeepEqual(sess.Scope(), ingest.Scope{Read: []string{run.String() + "/"}}) {
		t.Fatalf("the session: %v %+v", sess.Kind(), sess.Scope())
	}
	if f.readErrs[0] != nil {
		t.Fatalf("a signed object: %v", f.readErrs[0])
	}
	// A key the manifest does not list is refused, and the run goes on.
	if _, _, err := sess.Source().Open(context.Background(), run.String()+"/data/shop/x.bin"); !errors.Is(err, ingest.ErrNotServed) {
		t.Fatalf("a key the manifest does not list: %v", err)
	}
	// So is what the restore does not read (security review v0.4, finding
	// 5): the database left unselected, the data of an object left out.
	// Nor the definition of an object left out (fix round 1, B).
	for _, rel := range []string{"metadata/stats.sql", "metadata/stats/daily.sql", "data/stats/daily/all_1_1_0/data.bin", "data/shop/ext/all_1_1_0/data.bin",
		"metadata/shop/ext.sql", "metadata/shop/report.sql"} {
		if _, _, err := sess.Source().Open(context.Background(), run.String()+"/"+rel); !errors.Is(err, ingest.ErrNotServed) {
			t.Errorf("%s, which the restore does not read: %v", rel, err)
		}
	}
	for _, rel := range []string{".backup", "metadata/shop.sql", "metadata/shop/orders.sql", "data/shop/orders/all_1_1_0/data.bin"} {
		rc, _, err := sess.Source().Open(context.Background(), run.String()+"/"+rel)
		if err != nil {
			t.Errorf("%s, which the restore reads: %v", rel, err)
			continue
		}
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
	// The credential is revoked at the end.
	if _, _, ok := f.reg.Lookup(nr.AccessKey); ok {
		t.Fatal("the credential lives on after the restore")
	}
	var revoked bool
	x.scan(&revoked, `SELECT revoked_at IS NOT NULL FROM ingest_credentials WHERE run_id = $1 AND kind = 'restore'`, id)
	if !revoked {
		t.Fatal("the credential's row is not revoked")
	}
	x.wiped(id)
	x.noCanary()
}

// TestNativeExecuteChanged (R50): when the check at start does not decide
// what the request was approved with, the request fails before the target
// is contacted or a credential minted; a request with no record is refused
// too.
func TestNativeExecuteChanged(t *testing.T) {
	for name, set := range map[string]string{
		"changed":    `jsonb_set(options, '{native,excluded}', '[]')`,
		"unrecorded": `options - 'native'`,
	} {
		t.Run(name, func(t *testing.T) {
			x, f := nativeExec(t)
			id, _ := x.approvedNative(nativeSchema, "shop")
			x.exec(`UPDATE restore_requests SET options = `+set+` WHERE id = $1`, id)
			x.claim(id)
			calls := chInspector.calls
			x.ex.Execute(context.Background(), id)
			want := "the backup or Olympos's restore rules changed since the request was approved: the objects the restore would leave out are not the ones approved; " +
				"nothing was written to the target; open a new request"
			if name == "unrecorded" {
				want = "the request does not record the objects the restore leaves out, so they were not approved; nothing was written to the target; " +
					"open a new request"
			}
			if s := x.stored(id); s.Status != restore.StatusFailed || s.Error != want {
				t.Fatalf("request: %+v", s)
			}
			if _, _, _, n := f.last(); n != 0 || chInspector.calls != calls {
				t.Fatal("the target was contacted")
			}
			var minted int
			x.scan(&minted, `SELECT count(*) FROM ingest_credentials WHERE run_id = $1`, id)
			if minted != 0 {
				t.Fatal("a credential was minted")
			}
			x.wiped(id)
		})
	}
}

// TestNativeExecuteObjectChanged: an object changed in storage after the
// approval is never served whole: its read fails, and the request fails
// naming it.
func TestNativeExecuteObjectChanged(t *testing.T) {
	x, f := nativeExec(t)
	id, run := x.approvedNative(nativeSchema, "shop")
	// A data file: the check reads the definitions and the .backup, not it.
	key := run.String() + "/data/shop/orders/all_1_1_0/data.bin"
	f.read = []string{key}
	x.blobs.put("p/c/shop/"+run.String()+"/data/shop/orders/all_1_1_0/data.bin", []byte("the rows of shop.orderX"))
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	s := x.stored(id)
	want := "the restore failed: the backup's object " + key + " does not match its signed manifest; its read was aborted; " +
		"databases created and left in place: shop"
	if s.Status != restore.StatusFailed || s.Error != want {
		t.Fatalf("request: %+v", s)
	}
	x.noCanary()
}

// Found in the lab test of v0.4.0-rc.1: a restore whose target sends no
// request to the endpoint within FirstRequest of the RESTORE is KILLed and
// fails saying what to check; nothing was created. The work before the
// RESTORE does not count (review of v0.4.0-rc.2).
func TestNativeExecuteNoRequest(t *testing.T) {
	x, f := nativeExec(t)
	f.silent = true
	x.ex.Native.FirstRequest = 200 * time.Millisecond
	id, _ := x.approvedNative(nativeSchema, "shop")
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	s := x.stored(id)
	want := "the restore failed: no request from the target reached the ingest endpoint " + nativeIngestURL + " within 200ms: check the egress " +
		"of the ClickHouse pods to its host and port, and that ClickHouse trusts its certificate: clickhouse: native restore ended " +
		"(the ingest session stopped: no request): KILL QUERY made it RESTORE_FAILED"
	if s.Status != restore.StatusFailed || s.Error != want {
		t.Fatalf("request: %q %q\nwant %q", s.Status, s.Error, want)
	}
	x.noCanary()
}

// TestNativeExecuteSlowStart: work before the RESTORE (CREATE DATABASE,
// Replicated tables) that takes longer than FirstRequest does not count: the
// window starts when the RESTORE is sent (review of v0.4.0-rc.2).
func TestNativeExecuteSlowStart(t *testing.T) {
	x, f := nativeExec(t)
	f.slowStart = 500 * time.Millisecond
	x.ex.Native.FirstRequest = 200 * time.Millisecond
	id, _ := x.approvedNative(nativeSchema, "shop")
	x.claim(id)
	x.ex.Execute(context.Background(), id)
	if s := x.stored(id); s.Status != restore.StatusSucceeded {
		t.Fatalf("a restore with a slow start: %q %q", s.Status, s.Error)
	}
}

// TestNativeExecuteStopped: a native restore whose request ended elsewhere
// is stopped (its context ends, which KILLs the RESTORE on the target), and
// its credential is revoked.
func TestNativeExecuteStopped(t *testing.T) {
	x, f := nativeExec(t)
	f.block = true
	id, _ := x.approvedNative(nativeSchema, "shop")
	x.claim(id)
	done := make(chan struct{})
	go func() { x.ex.Execute(context.Background(), id); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, _, n := f.last(); n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the restore did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	x.exec(`UPDATE restore_requests SET status = 'failed', error = 'reaped elsewhere', finished_at = now() WHERE id = $1`, id)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the restore kept running after its request ended elsewhere")
	}
	f.mu.Lock()
	stopped := f.stopped
	f.mu.Unlock()
	nr, _, _, _ := f.last()
	if _, _, ok := f.reg.Lookup(nr.AccessKey); !stopped || ok {
		t.Fatalf("stopped %v, credential live %v", stopped, ok)
	}
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
	// The server logs each request once its handler has returned: wait for
	// that line, so the handler's own log lines are in.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(e.LogBuf.String(), "/api/v1/restores/check") {
		if time.Now().After(deadline) {
			t.Fatalf("the check's handler did not return:\n%s", e.LogBuf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, s := range []string{`"msg":"restore: the native backup does not verify"`, "request failed"} {
		if strings.Contains(e.LogBuf.String(), s) {
			t.Fatalf("a request that went away logged %q: %s", s, e.LogBuf.String())
		}
	}
	// What it cut is at Debug, for whoever looks.
	if !strings.Contains(e.LogBuf.String(), "the check ended with its request") {
		t.Fatalf("the cut cause is not logged at Debug: %s", e.LogBuf.String())
	}
	if chInspector.calls != calls {
		t.Fatal("the target was contacted")
	}
}
