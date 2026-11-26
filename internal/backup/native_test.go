//go:build dev

package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/signer"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/clickhouse"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// The worker's native path (task 10) against a real ingest endpoint: the
// fake engine plays ClickHouse, PUTting a small backup with signed requests
// as ClickHouse does, and the real ClickHouse code builds and signs the
// manifest.

const nativeKey = "olympos-manifest"

// nativeObject is one object of the fake backup, keyed relative to the run.
type nativeObject struct {
	rel  string
	body []byte
}

// nativeBackup is what the fake ClickHouse writes: two parts of shop.orders
// (40 and 2 rows), the metadata, and .backup last, which lists the rest.
func nativeBackup() []nativeObject { return nativeBackupOf(false) }

// nativeBackupOf is nativeBackup, or with structureOnly what a BACKUP with
// structure_only = 1 writes: the metadata and .backup.
func nativeBackupOf(structureOnly bool) []nativeObject {
	objs := []nativeObject{
		{"data/shop/orders/all_1_1_0/data.bin", bytes.Repeat([]byte("part-one-"), 40_000)},
		{"data/shop/orders/all_1_1_0/count.txt", []byte("40")},
		{"data/shop/orders/all_2_2_0/data.bin", []byte("part-two")},
		{"data/shop/orders/all_2_2_0/count.txt", []byte("2")},
		{"metadata/shop.sql", []byte("CREATE DATABASE shop UUID 'a1485f28-bfdd-4ac8-8373-2de920367b6a' ENGINE = Atomic")},
		{"metadata/shop/orders.sql", []byte("CREATE TABLE shop.orders UUID 'aa757254-1568-44ed-857d-b236f30e79cd' (`id` UInt64) " +
			"ENGINE = MergeTree ORDER BY id")},
	}
	if structureOnly {
		objs = objs[4:]
	}
	var files strings.Builder
	for _, o := range objs {
		sum := sha256.Sum256(o.body)
		fmt.Fprintf(&files, "<file><name>%s</name><size>%d</size><checksum>%s</checksum></file>", o.rel, len(o.body), hex.EncodeToString(sum[:16]))
	}
	meta := "<config><version>1</version><deduplicate_files>1</deduplicate_files><timestamp>2026-11-26 02:00:00</timestamp>" +
		"<uuid>b72cb88e-d879-4426-b595-748adff8e17e</uuid><contents>" + files.String() + "</contents></config>"
	return append(objs, nativeObject{".backup", []byte(meta)})
}

// nativeCall is what the fake ClickHouse saw of one run.
type nativeCall struct {
	run    backup.NativeRun
	killed string // the stop reason it was KILLed for
	// quota is the session's byte limit after run.Before (R39), kill what
	// run.Before said to end of the native backups running (R41).
	quota int64
	kill  []string
	// An incremental's reads of its base chain (run.Base): the status of
	// the GET of the base's .backup, the keys a LIST of each prefix of the
	// chain returned, and the statuses of a GET of an object no manifest
	// lists and of a key outside the run's scope.
	baseGet  int
	listed   map[string][]string
	unlisted int
	outside  int
}

// nativeRegistry is the ingest registry of the test's endpoint, in which
// the fake ClickHouse looks up its run's session.
var nativeRegistry *ingest.Registry

var nativeCalls = struct {
	mu   sync.Mutex
	runs map[string]*nativeCall
}{runs: map[string]*nativeCall{}}

func nativeCallOf(t *testing.T, run uuid.UUID) nativeCall {
	t.Helper()
	nativeCalls.mu.Lock()
	defer nativeCalls.mu.Unlock()
	c := nativeCalls.runs[run.String()]
	if c == nil {
		t.Fatalf("the engine never ran %s", run)
	}
	return *c
}

func (fakeEngine) NativeJob(raw json.RawMessage) (backup.NativeJob, error) {
	var o struct {
		Method      string   `json:"method"`
		Databases   []string `json:"databases"`
		Incremental string   `json:"incremental"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return backup.NativeJob{}, err
	}
	return backup.NativeJob{Native: o.Method == "native", Incremental: o.Incremental != "", Databases: o.Databases}, nil
}

// BackupNative plays ClickHouse: it takes the .lock, PUTs every object of
// nativeBackup, signed with the run's credential, and drops the .lock. A
// refused request is retried by ClickHouse until the run KILLs it: here,
// it waits for the stop and is KILLed.
func (fakeEngine) BackupNative(ctx context.Context, ec backup.EngineContext, run backup.NativeRun) (string, error) {
	call := &nativeCall{run: run}
	nativeCalls.mu.Lock()
	nativeCalls.runs[run.RunID] = call
	nativeCalls.mu.Unlock()
	kill := func(reason string) error {
		nativeCalls.mu.Lock()
		call.killed = reason
		nativeCalls.mu.Unlock()
		return fmt.Errorf("clickhouse: native backup ended (the ingest session stopped: %s): KILL QUERY made it BACKUP_FAILED", reason)
	}
	do := func(method, rel string, body []byte) (int, error) {
		req, err := http.NewRequestWithContext(ctx, method, run.URL+rel, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		sum := sha256.Sum256(body)
		req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))
		resp, err := http.DefaultClient.Do(signer.SignV4(*req, run.AccessKey, run.Secret, "", "us-east-1"))
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	var o struct {
		fakeOpts
		// Repeat sends the first object again: "same" body or "other".
		Repeat string `json:"native_repeat"`
		// TargetBytes is what the databases hold on disk, Running the runs
		// whose native backups run on the target (run.Before).
		TargetBytes int64    `json:"native_target_bytes"`
		Running     []string `json:"native_running"`
		// Extra stores an object the .backup does not list.
		Extra bool `json:"native_extra"`
	}
	_ = json.Unmarshal(ec.Options, &o)
	if o.LeakSecret {
		return "", errors.New("clickhouse: BACKUP: S3 secret " + run.Secret + " refused")
	}
	if run.Before != nil {
		kill, err := run.Before(ctx, backup.NativeTarget{Bytes: o.TargetBytes, Running: o.Running})
		if err != nil {
			return "", err
		}
		nativeCalls.mu.Lock()
		call.kill = kill
		nativeCalls.mu.Unlock()
	}
	if s, _, ok := nativeRegistry.Lookup(run.AccessKey); ok {
		nativeCalls.mu.Lock()
		call.quota = s.MaxBytes()
		nativeCalls.mu.Unlock()
	}
	steps := []nativeObject{{".lock", []byte("lock")}}
	if o.Extra {
		steps = append(steps, nativeObject{"data/shop/orders/extra.bin", []byte("not in .backup")})
	}
	if run.Base != nil {
		incr, err := nativeIncrementalOf(ctx, run, call)
		if err != nil {
			return "", err
		}
		steps = append(steps, incr...)
	} else {
		steps = append(steps, nativeBackupOf(run.StructureOnly)...)
	}
	for _, obj := range steps {
		select {
		case reason := <-run.Stop:
			return "", kill(reason)
		default:
		}
		status, err := do(http.MethodPut, obj.rel, obj.body)
		if err == nil && status == http.StatusOK && o.Repeat != "" && strings.HasSuffix(obj.rel, "all_1_1_0/data.bin") {
			// Its S3 client did not see the answer and sends the PUT again.
			body := obj.body
			if o.Repeat == "other" {
				body = append(bytes.Clone(body), '!')
			}
			status, err = do(http.MethodPut, obj.rel, body)
		}
		if err == nil && status != http.StatusOK {
			err = fmt.Errorf("PUT %s: %d", obj.rel, status)
		}
		if err != nil {
			select {
			case reason := <-run.Stop:
				return "", kill(reason)
			case <-time.After(10 * time.Second):
				return "", fmt.Errorf("clickhouse: %v, and the run did not stop", err)
			}
		}
	}
	if status, err := do(http.MethodDelete, ".lock", nil); err != nil || status != http.StatusNoContent {
		return "", fmt.Errorf("DELETE .lock: %d %v", status, err)
	}
	return "fake 25.8", nil
}

// nativeGet is a GET signed with the run's credential: its status and body.
func nativeGet(ctx context.Context, run backup.NativeRun, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	sum := sha256.Sum256(nil)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))
	resp, err := http.DefaultClient.Do(signer.SignV4(*req, run.AccessKey, run.Secret, "", "us-east-1"))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// nativeIncrementalOf plays an incremental BACKUP on run.Base: it reads the
// base's .backup and lists the run's read prefixes, as ClickHouse does, and
// returns what it writes: one new part of shop.orders (5 rows) and a
// .backup that takes every file of the base from the base.
func nativeIncrementalOf(ctx context.Context, run backup.NativeRun, call *nativeCall) ([]nativeObject, error) {
	bucket := strings.TrimSuffix(run.URL, run.RunID+"/")
	status, raw, err := nativeGet(ctx, run, run.Base.URL+".backup")
	nativeCalls.mu.Lock()
	call.baseGet = status
	nativeCalls.mu.Unlock()
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("clickhouse: read the base's .backup: %d %v", status, err)
	}
	base, err := clickhouse.ParseBackupMeta(raw)
	if err != nil {
		return nil, err
	}
	listed := map[string][]string{}
	s, _, _ := nativeRegistry.Lookup(run.AccessKey)
	for _, prefix := range s.Scope().Read {
		_, body, err := nativeGet(ctx, run, strings.TrimSuffix(bucket, "/")+"?prefix="+prefix)
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents []struct{ Key string } `xml:"Contents"`
		}
		if err := xml.Unmarshal(body, &res); err != nil {
			return nil, fmt.Errorf("list %s: %v: %s", prefix, err, body)
		}
		for _, c := range res.Contents {
			listed[prefix] = append(listed[prefix], c.Key)
		}
	}
	unlisted, _, _ := nativeGet(ctx, run, run.Base.URL+"data/shop/orders/not-in-the-manifest.bin")
	outside, _, _ := nativeGet(ctx, run, bucket+uuid.NewString()+"/.backup")
	nativeCalls.mu.Lock()
	call.listed, call.unlisted, call.outside = listed, unlisted, outside
	nativeCalls.mu.Unlock()

	part := "data/shop/orders/inc_" + run.RunID[:8] + "/"
	objs := []nativeObject{{part + "data.bin", []byte("incremental part")}, {part + "count.txt", []byte("5")}}
	var files strings.Builder
	for _, f := range base.Files {
		fmt.Fprintf(&files, "<file><name>%s</name><size>%d</size><checksum>%s</checksum><use_base>true</use_base></file>", f.Name, f.Size, f.Checksum)
	}
	for _, o := range objs {
		sum := sha256.Sum256(o.body)
		fmt.Fprintf(&files, "<file><name>%s</name><size>%d</size><checksum>%s</checksum></file>", o.rel, len(o.body), hex.EncodeToString(sum[:16]))
	}
	meta := "<config><version>1</version><deduplicate_files>1</deduplicate_files><timestamp>2026-11-26 02:00:00</timestamp>" +
		"<uuid>" + uuid.NewString() + "</uuid><base_backup>S3('" + run.Base.URL + "')</base_backup><base_backup_uuid>" + base.UUID +
		"</base_backup_uuid><contents>" + files.String() + "</contents></config>"
	return append(objs, nativeObject{".backup", []byte(meta)}), nil
}

// SignNativeManifest is the real engine's.
func (fakeEngine) SignNativeManifest(ctx context.Context, in backup.NativeManifestInput) (*backup.NativeManifestResult, error) {
	return clickhouse.Engine{}.SignNativeManifest(ctx, in)
}

// nativeEnv is a group of two destinations, a native job on it and an
// ingest endpoint on httptest.
type nativeEnv struct {
	groupFixture
	reg *ingest.Registry
	srv *httptest.Server
	kv  *secrets.LocalKeyVault
}

func seedNative(t *testing.T, db *store.DB) nativeEnv {
	t.Helper()
	g := seedGroup(t, db, jobOpts{options: `{"method":"native","databases":["shop"]}`})
	fp, err := secrets.NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg := ingest.NewRegistry(db, fp, 4, nil)
	srv := httptest.NewServer(ingest.NewHandler(reg, quietLog(), ingest.NewMetrics(), ingest.WithSpillDir(t.TempDir())))
	t.Cleanup(srv.Close)
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	g.W.Native = &backup.NativeConfig{Registry: reg, URL: srv.URL, KV: kv, ManifestKeyName: nativeKey}
	nativeRegistry = reg
	return nativeEnv{groupFixture: g, reg: reg, srv: srv, kv: kv}
}

// runDir is the run's directory on a destination of prefix.
func runDir(t *testing.T, db *store.DB, prefix string, run uuid.UUID) string {
	t.Helper()
	var started time.Time
	if err := db.QueryRow(context.Background(), `SELECT started_at FROM backup_runs WHERE id = $1`, run).Scan(&started); err != nil {
		t.Fatal(err)
	}
	return backup.RunDir(prefix, "prod", "db", "orders", "clickhouse", started, run)
}

// readSidecar reads a native copy's sidecar and verifies its manifest from
// the bytes in Details, as a restore does.
func readSidecar(t *testing.T, b *fakeBlobs, kv secrets.KeyVault, dir string, run uuid.UUID) (backup.Manifest, *clickhouse.NativeManifest) {
	t.Helper()
	raw := b.blobs[backup.ManifestPath(dir, run)]
	var side struct {
		backup.Manifest
		Details map[string]json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(raw, &side); err != nil {
		t.Fatalf("sidecar %s: %v (%v)", backup.ManifestPath(dir, run), err, keysOf(b.blobs))
	}
	signed := side.Details[backup.NativeManifestDetail]
	if !bytes.HasPrefix(signed, []byte(`{"key_id":"`+nativeKey+`/1","manifest":{`)) {
		t.Fatalf("the signed manifest is not in Details as it was signed: %.80s", signed)
	}
	m, err := clickhouse.VerifySigned(context.Background(), kv, nativeKey, run.String(), signed)
	if err != nil {
		t.Fatal(err)
	}
	return side.Manifest, m
}

type credRow struct {
	Scope   string
	Reason  *string
	Revoked *time.Time
	TTL     time.Duration
}

func credentialOf(t *testing.T, db *store.DB, run uuid.UUID) credRow {
	t.Helper()
	var c credRow
	var created, expires time.Time
	if err := db.QueryRow(context.Background(), `SELECT scope::text, reason, revoked_at, created_at, expires_at FROM ingest_credentials
		WHERE run_id = $1 AND kind = 'backup'`, run).Scan(&c.Scope, &c.Reason, &c.Revoked, &created, &expires); err != nil {
		t.Fatal(err)
	}
	c.TTL = expires.Sub(created)
	return c
}

// TestNativeRunSucceeds: every object reaches every destination tagged
// incomplete, then one signed manifest per destination, every object
// re-tagged complete, both copies succeeded, the credential revoked.
func TestNativeRunSucceeds(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)

	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "succeeded" || r.Error != "" || len(cs) != 2 {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	call := nativeCallOf(t, run)
	if call.run.URL != e.srv.URL+"/olympos/"+run.String()+"/" || call.run.RunID != run.String() || call.killed != "" ||
		strings.Join(call.run.Databases, ",") != "shop" || !strings.HasPrefix(call.run.AccessKey, "OLY") {
		t.Fatalf("engine call: %v, killed %q", call.run, call.killed)
	}
	var total int64
	for _, o := range nativeBackup() {
		total += int64(len(o.body))
	}
	for i, b := range []*fakeBlobs{e.B1, e.B2} {
		dir := runDir(t, db, []string{"a", "b"}[i], run)
		c := cs[i]
		env, m := readSidecar(t, b, e.kv, dir, run)
		if c.Status != "succeeded" || c.BlobPath != dir || c.SHA != m.SHA256() || c.Bytes != total || c.Tier != "daily" {
			t.Fatalf("copy %d: %+v (dir %s, manifest %s)", i, c, dir, m.SHA256())
		}
		for _, o := range nativeBackup() {
			p := dir + "/" + o.rel
			if !bytes.Equal(b.blobs[p], o.body) {
				t.Fatalf("copy %d: %s not stored (%v)", i, p, keysOf(b.blobs))
			}
			if tg := b.tags[p]; tg[backup.StateTag] != backup.StateComplete || tg[backup.TierTag] != "daily" {
				t.Fatalf("copy %d: %s tagged %v", i, p, tg)
			}
		}
		if tg := b.tags[backup.ManifestPath(dir, run)]; tg[backup.StateTag] != backup.StateComplete || tg[backup.TierTag] != "daily" {
			t.Fatalf("copy %d: manifest tagged %v", i, tg)
		}
		if _, ok := b.blobs[dir+"/.lock"]; ok {
			t.Fatal("the .lock reached a destination")
		}
		// The sidecar is the run's, its blob the run's directory.
		if env.Format != backup.ManifestFormat || env.RunID != run || env.Engine != "clickhouse" || env.Blob.Path != dir ||
			env.Blob.SHA256 != m.SHA256() || env.Blob.Size != total || env.ServerVersion != "fake 25.8" || env.Tier != "daily" ||
			env.Group == nil || env.Destination == nil {
			t.Fatalf("copy %d sidecar: %+v", i, env)
		}
		// Rows per table: the sum of its parts' count.txt.
		if len(m.Databases) != 1 || m.Databases[0].Objects[0].Name != "orders" || m.Databases[0].Objects[0].Rows != 42 ||
			m.PartRows["data/shop/orders/all_1_1_0/count.txt"] != 40 || len(m.Objects) != len(nativeBackup()) ||
			m.ServerVersion != "fake 25.8" || m.Settings["id"] != run.String() {
			t.Fatalf("manifest: %+v", m)
		}
	}
	if r.BlobPath != cs[0].BlobPath || r.SHA != cs[0].SHA || r.Bytes != total {
		t.Fatalf("run columns: %+v", r)
	}
	cred := credentialOf(t, db, run)
	if cred.Revoked == nil || cred.Reason == nil || *cred.Reason != "run ended" || cred.Scope != `{"write": "`+run.String()+`/"}` ||
		cred.TTL != 6*time.Hour {
		t.Fatalf("credential: %+v", cred)
	}
}

// Review Focus 4: one destination fails in the middle of an object. Its copy
// fails with that object, its objects stay incomplete, the run is partial,
// and the other copy is complete. A native run queues no repair.
func TestNativeRunOneDestinationFails(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	e.B2.fail, e.B2.failAfter, e.B2.failOn = errors.New("503 ServerBusy"), 100_000, "all_1_1_0/data.bin"
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)

	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	const failed = "upload data/shop/orders/all_1_1_0/data.bin: 503 ServerBusy"
	if r.Status != "partial" || r.Error != "dest-b: "+failed || len(cs) != 2 || cs[0].Status != "succeeded" ||
		cs[1].Status != "failed" || cs[1].Error != failed {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	dir1, dir2 := runDir(t, db, "a", run), runDir(t, db, "b", run)
	_, m := readSidecar(t, e.B1, e.kv, dir1, run)
	if cs[0].SHA != m.SHA256() || m.Databases[0].Objects[0].Rows != 42 {
		t.Fatalf("the complete copy: %+v", cs[0])
	}
	for _, o := range nativeBackup() {
		if tg := e.B1.tags[dir1+"/"+o.rel]; tg[backup.StateTag] != backup.StateComplete {
			t.Fatalf("copy 1: %s tagged %v", o.rel, tg)
		}
	}
	// What reached member 2 before it failed stays incomplete; nothing after.
	if _, ok := e.B2.blobs[backup.ManifestPath(dir2, run)]; ok {
		t.Fatal("a manifest on the failed copy")
	}
	for p, tg := range e.B2.tags {
		if tg[backup.StateTag] != backup.StateIncomplete {
			t.Fatalf("copy 2: %s tagged %v", p, tg)
		}
	}
	if _, ok := e.B2.blobs[dir2+"/data/shop/orders/all_2_2_0/data.bin"]; ok {
		t.Fatal("the failed destination took objects after its failure")
	}
	if ev := events(t, db, "backup.partial"); len(ev) != 1 || ev[0].Payload["repair_queued"] != false {
		t.Fatalf("partial event: %+v", ev)
	}
	var repairs int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM backup_runs WHERE repair_of = $1`, run).Scan(&repairs); err != nil || repairs != 0 {
		t.Fatalf("repairs queued for a native run: %d %v", repairs, err)
	}
	if cred := credentialOf(t, db, run); cred.Revoked == nil {
		t.Fatal("credential not revoked")
	}
}

// When no destination takes an object, the session stops, the backup is
// KILLed, the run fails with each copy's own error and the credential is
// revoked.
func TestNativeRunAllDestinationsFail(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	e.B1.fail, e.B1.failOn = errors.New("403 AuthorizationPermissionMismatch"), "count.txt"
	e.B2.fail, e.B2.failAfter, e.B2.failOn = errors.New("503 ServerBusy"), 100_000, "all_1_1_0/data.bin"
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)

	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "failed" || r.Error != "upload data/shop/orders/all_1_1_0/count.txt: 403 AuthorizationPermissionMismatch" || len(cs) != 2 ||
		cs[0].Status != "failed" || cs[1].Status != "failed" || cs[1].Error != "upload data/shop/orders/all_1_1_0/data.bin: 503 ServerBusy" {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	if call := nativeCallOf(t, run); call.killed != ingest.ReasonDestination {
		t.Fatalf("killed for %q, want %q", call.killed, ingest.ReasonDestination)
	}
	if cred := credentialOf(t, db, run); cred.Revoked == nil {
		t.Fatal("credential not revoked")
	}
	if ev := events(t, db, "backup.failed"); len(ev) != 1 {
		t.Fatalf("failed events: %+v", ev)
	}
}

// A destination that cannot change tags never completes a native copy. Its
// manifest is tagged complete only after every object: a copy left half
// tagged has an incomplete manifest, like the objects the lifecycle rule
// removes.
func TestNativeRunTagsFail(t *testing.T) {
	for name, tc := range map[string]struct {
		after   int
		errText string
	}{
		"half way through the objects": {3, "tag the objects complete: "},
		"on the manifest":              {len(nativeBackup()), "tag the manifest complete: "},
	} {
		t.Run(name, func(t *testing.T) {
			db := testutil.DB(t)
			e := seedNative(t, db)
			e.B2.failTags, e.B2.failTagsAfter = errors.New("409 Conflict"), tc.after
			run := queue(t, db, e.Job, "manual", nil)
			claimAndRun(t, e.W, run)
			cs := loadCopies(t, db, run)
			dir := runDir(t, db, "b", run)
			if r := loadRun(t, db, run); r.Status != "partial" || len(cs) != 2 || cs[0].Status != "succeeded" || cs[1].Status != "failed" ||
				!strings.HasPrefix(cs[1].Error, tc.errText) || !strings.HasSuffix(cs[1].Error, "409 Conflict") || cs[1].BlobPath != dir {
				t.Fatalf("run: %+v copies %+v", r, cs)
			}
			if tg := e.B2.tags[backup.ManifestPath(dir, run)]; tg[backup.StateTag] != backup.StateIncomplete {
				t.Fatalf("the failed copy's manifest is tagged %v", tg)
			}
			complete := 0
			for _, o := range nativeBackup() {
				if e.B2.tags[dir+"/"+o.rel][backup.StateTag] == backup.StateComplete {
					complete++
				}
			}
			if complete != tc.after {
				t.Fatalf("%d objects tagged complete, want %d", complete, tc.after)
			}
			if tg := e.B1.tags[backup.ManifestPath(runDir(t, db, "a", run), run)]; tg[backup.StateTag] != backup.StateComplete {
				t.Fatalf("the complete copy's manifest is tagged %v", tg)
			}
		})
	}
}

// R14: with the endpoint off, a native job's run fails with the reason; it
// writes nothing and opens no session.
func TestNativeRunIngestOff(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	e.W.Native = nil
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)
	if r := loadRun(t, db, run); r.Status != "failed" || r.Error != "the ingest endpoint is off: set ingest.url" {
		t.Fatalf("run: %+v", r)
	}
	if len(e.B1.blobs)+len(e.B2.blobs) != 0 || len(loadCopies(t, db, run)) != 0 {
		t.Fatal("wrote with the endpoint off")
	}
}

// Repairs are off for native runs: a repair queued for the job, from before
// it was native, is refused.
func TestNativeRunNotRepaired(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedNative(t, db)
	orig := insertFinishedRun(t, db, e.Job, "partial", time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC), e.DestID)
	var rep uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, repair_of, destination_ids) VALUES ($1, 'manual', 'queued', $2, $3)
		RETURNING id`, e.Job, orig, []uuid.UUID{e.Dest2}).Scan(&rep); err != nil {
		t.Fatal(err)
	}
	claimAndRun(t, e.W, rep)
	if r := loadRun(t, db, rep); r.Status != "failed" || r.Error != "a native run is not repaired; the next run is a full backup" {
		t.Fatalf("repair: %+v", r)
	}
	if len(e.B2.blobs) != 0 {
		t.Fatal("the repair wrote")
	}
}

// Review Focus 2: after a restart a native run left running has its ingest
// credential revoked ("server restart") by start-up recovery; the worker
// fails it at once, not after the stale-heartbeat delay. Its objects stay
// incomplete. A running run of this process is left alone.
func TestNativeRunServerRestart(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedNative(t, db)
	running := func() uuid.UUID {
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at) VALUES ($1, 'manual', 'running', now()) RETURNING id`,
			e.Job).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.reg.Open(ctx, ingest.OpenOptions{RunID: id, Kind: ingest.KindBackup, Scope: ingest.Scope{Write: id.String() + "/"},
			TTL: time.Hour, Sink: discardSink{}, MaxBytes: 1 << 20}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	before := running()
	if err := ingest.MarkInterrupted(ctx, db, time.Now()); err != nil {
		t.Fatal(err)
	}
	after := running() // opened after the restart: its credential is live
	if err := e.W.ReapStale(ctx); err != nil {
		t.Fatal(err)
	}
	if r := loadRun(t, db, before); r.Status != "failed" || !strings.HasPrefix(r.Error, "interrupted: the server restarted during the native backup") ||
		!strings.Contains(r.Error, "KILL QUERY WHERE query_id = 'olympos-backup-"+before.String()+"' SYNC") {
		t.Fatalf("run before the restart: %+v", r)
	}
	if r := loadRun(t, db, after); r.Status != "running" {
		t.Fatalf("run after the restart: %+v", r)
	}
	if ev := events(t, db, "backup.failed"); len(ev) != 1 {
		t.Fatalf("failed events: %+v", ev)
	}
}

type discardSink struct{}

func (discardSink) Put(_ context.Context, key string, r io.Reader) (ingest.ObjectRecord, error) {
	n, err := io.Copy(io.Discard, r)
	return ingest.ObjectRecord{Key: key, Size: n}, err
}

// The ingest secret never reaches the run's records, even when the engine
// lets it through.
func TestNativeRunScrubsSecret(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	if _, err := db.Exec(context.Background(), `UPDATE backup_jobs SET engine_options = '{"method":"native","leak_secret":true}' WHERE id = $1`, e.Job); err != nil {
		t.Fatal(err)
	}
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)
	secret := nativeCallOf(t, run).run.Secret
	r := loadRun(t, db, run)
	if r.Status != "failed" || secret == "" || strings.Contains(r.Error, secret) || r.Error != "clickhouse: BACKUP: S3 secret [HIDDEN] refused" {
		t.Fatalf("run: %+v", r)
	}
	if cs := loadCopies(t, db, run); len(cs) != 0 {
		t.Fatalf("copies of a run that wrote nothing: %+v", cs)
	}
	if cred := credentialOf(t, db, run); cred.Revoked == nil {
		t.Fatal("credential not revoked")
	}
}

// A PUT sent again with the same body (ClickHouse did not see the answer)
// is answered as stored: nothing is written twice, which every destination
// would refuse, and the run succeeds.
func TestNativeRunRepeatedPut(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	setOptions(t, db, e.Job, `{"method":"native","native_repeat":"same"}`)
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)
	if r := loadRun(t, db, run); r.Status != "succeeded" {
		t.Fatalf("run: %+v copies %+v", r, loadCopies(t, db, run))
	}
	// Each destination: every object once, and the manifest.
	for _, b := range []*fakeBlobs{e.B1, e.B2} {
		if b.uploads != len(nativeBackup())+1 {
			t.Fatalf("%d uploads, want %d", b.uploads, len(nativeBackup())+1)
		}
	}
}

// Another body for a stored object stops the run as a client that broke the
// protocol: the copies are not blamed on their destinations.
func TestNativeRunRewrittenObject(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	setOptions(t, db, e.Job, `{"method":"native","native_repeat":"other"}`)
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)
	if call := nativeCallOf(t, run); call.killed != ingest.ReasonRewrite {
		t.Fatalf("killed for %q, want %q", call.killed, ingest.ReasonRewrite)
	}
	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "failed" || !strings.Contains(r.Error, ingest.ReasonRewrite) || len(cs) != 2 {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	for _, c := range cs {
		if c.Status != "failed" || strings.HasPrefix(c.Error, "upload") || !strings.Contains(c.Error, ingest.ReasonRewrite) {
			t.Fatalf("copy: %+v", c)
		}
	}
}

// Minor 4: the server shutting down in the middle of an object stops the
// session; the uploads are not cut by the worker's context, so no copy is
// taken for a failed destination.
func TestNativeRunShutdownMidObject(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	e.B1.holdOn, e.B1.held = "all_2_2_0/data.bin", make(chan struct{})
	run := queue(t, db, e.Job, "manual", nil)
	id, err := e.W.Claim(context.Background())
	if err != nil || id != run {
		t.Fatalf("claimed %s %v", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-e.B1.held; cancel() }()
	e.W.Execute(ctx, run)

	if call := nativeCallOf(t, run); call.killed != "server shutting down" {
		t.Fatalf("killed for %q", call.killed)
	}
	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "failed" || len(cs) != 2 {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	for _, c := range cs {
		if c.Status != "failed" || strings.HasPrefix(c.Error, "upload") || !strings.Contains(c.Error, "server shutting down") {
			t.Fatalf("copy: %+v", c)
		}
	}
	if cred := credentialOf(t, db, run); cred.Revoked == nil {
		t.Fatal("credential not revoked")
	}
}

func setOptions(t *testing.T, db *store.DB, job uuid.UUID, opts string) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `UPDATE backup_jobs SET engine_options = $2 WHERE id = $1`, job, opts); err != nil {
		t.Fatal(err)
	}
}

// runMethod is what the run API says of a run: its method and its objects
// as JSON (null for a logical run).
func runMethod(t *testing.T, db *store.DB, id uuid.UUID) (string, string) {
	t.Helper()
	r, err := backup.LoadRun(context.Background(), db, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Method  string          `json:"method"`
		Objects json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v.Method, string(v.Objects)
}

// The run API tells a native run (method, the objects it stored) from a
// logical one: the run page shows the Native badge and the object count,
// and no logical restore commands.
func TestNativeRunMethodAndObjects(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedNative(t, db)
	check := func(what string, id uuid.UUID, method, objects string) {
		t.Helper()
		if m, o := runMethod(t, db, id); m != method || o != objects {
			t.Fatalf("%s: method %q objects %s, want %q %s", what, m, o, method, objects)
		}
	}

	run := queue(t, db, e.Job, "manual", nil)
	check("queued, by the job's method", run, "native", "null")
	claimAndRun(t, e.W, run)
	check("succeeded", run, "native", fmt.Sprint(len(nativeBackup())))

	// Failed before ClickHouse stored anything.
	e.W.Native = nil
	off := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, off)
	check("endpoint off", off, "native", "0")

	// A worker that stopped in the middle of a native run: reaped by its
	// heartbeat, still a native run.
	var stale uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, updated_at)
		VALUES ($1, 'manual', 'running', now() - interval '1 hour', now() - interval '1 hour') RETURNING id`, e.Job).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.reg.Open(ctx, ingest.OpenOptions{RunID: stale, Kind: ingest.KindBackup, Scope: ingest.Scope{Write: stale.String() + "/"},
		TTL: time.Hour, Sink: discardSink{}, MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if err := e.W.ReapStale(ctx); err != nil {
		t.Fatal(err)
	}
	if r := loadRun(t, db, stale); r.Status != "failed" {
		t.Fatalf("stale run: %+v", r)
	}
	check("reaped", stale, "native", "0")

	// The job is logical now: its earlier runs keep their method.
	if _, err := db.Exec(ctx, `UPDATE backup_jobs SET engine_options = '{"databases":["shop"]}' WHERE id = $1`, e.Job); err != nil {
		t.Fatal(err)
	}
	check("after the job changed", run, "native", fmt.Sprint(len(nativeBackup())))
	check("queued logical", queue(t, db, e.Job, "manual", nil), "logical", "null")
	// A finished run of a logical job.
	check("logical", insertFinishedRun(t, db, e.Job, "succeeded", time.Now().Add(-time.Hour), e.DestID), "logical", "null")
}

// R39: the byte limit of a native run is the largest of twice the last full
// native run, 1.5 times the databases' size on disk, read before the BACKUP,
// and 1 GiB; ingest.maxRunBytes replaces it. A run over its limit is KILLed
// and fails with an error that names the limit and the way out.
func TestNativeRunQuota(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)

	// No full yet, a large database: 1.5 times its size, not a fixed cap.
	setOptions(t, db, e.Job, `{"method":"native","native_target_bytes":214748364800}`)
	big := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, big)
	if r := loadRun(t, db, big); r.Status != "succeeded" {
		t.Fatalf("run: %+v", r)
	}
	if q := nativeCallOf(t, big).quota; q != 300<<30 {
		t.Fatalf("quota %d, want 1.5 x 200 GiB", q)
	}
	if nativeCallOf(t, big).run.SkipSize {
		t.Fatal("the automatic limit needs the databases' size")
	}

	// After that full, a small database: twice the full.
	var full int64
	if err := db.QueryRow(context.Background(), `SELECT bytes FROM backup_runs WHERE id = $1`, big).Scan(&full); err != nil {
		t.Fatal(err)
	}
	setOptions(t, db, e.Job, `{"method":"native","native_target_bytes":1024}`)
	small := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, small)
	if q := nativeCallOf(t, small).quota; q != max(2*full, 1<<30) {
		t.Fatalf("quota %d, want max(2 x %d, 1 GiB)", q, full)
	}

	// ingest.maxRunBytes under what the run writes: KILLed for the quota.
	e.W.Native.MaxRunBytes = 1000
	over := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, over)
	call := nativeCallOf(t, over)
	// A configured limit needs no size: the engine does not read it.
	if call.quota != 1000 || call.killed != ingest.ReasonQuota || !call.run.SkipSize {
		t.Fatalf("quota %d, killed for %q", call.quota, call.killed)
	}
	r := loadRun(t, db, over)
	if r.Status != "failed" || !strings.HasPrefix(r.Error, "native byte limit: the run wrote more than 1000 B (ingest.maxRunBytes)") ||
		!strings.Contains(r.Error, "raise ingest.maxRunBytes") {
		t.Fatalf("run: %+v", r)
	}
}

// R40: a dry run of a native job backs up the structure only. It goes the
// whole way (credential, upload, signed manifest, tags) with no data, and is
// not the last full the byte limit counts from.
func TestNativeRunDryRun(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	run := queue(t, db, e.Job, "test", nil)
	claimAndRun(t, e.W, run)
	if call := nativeCallOf(t, run); !call.run.StructureOnly {
		t.Fatal("a dry run's BACKUP is not structure only")
	}
	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "succeeded" || len(cs) != 2 {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	for i, b := range []*fakeBlobs{e.B1, e.B2} {
		dir := runDir(t, db, []string{"a", "b"}[i], run)
		_, m := readSidecar(t, b, e.kv, dir, run)
		if m.Settings["structure_only"] != "1" || len(m.PartRows) != 0 || len(m.Objects) != len(nativeBackupOf(true)) ||
			m.Databases[0].Objects[0].Rows != 0 || cs[i].Tier != "test" {
			t.Fatalf("copy %d: %+v, manifest %+v", i, cs[i], m)
		}
		if tg := b.tags[backup.ManifestPath(dir, run)]; tg[backup.StateTag] != backup.StateComplete || tg[backup.TierTag] != "test" {
			t.Fatalf("copy %d: manifest tagged %v", i, tg)
		}
	}
	// The next scheduled run is a full one: its BACKUP has the data.
	full := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, full)
	if call := nativeCallOf(t, full); call.run.StructureOnly || call.quota != 1<<30 {
		t.Fatalf("after a dry run: structure only %v, quota %d", call.run.StructureOnly, call.quota)
	}
}

// R41: before its BACKUP a native run ends the native backups on the target
// whose runs are over (a server that crashed, an agent lost mid-run): only
// those. The BACKUP of a run still running, another job's on the same
// target, is never ended, nor one of a run this server does not know.
func TestNativeRunEndsOrphans(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedNative(t, db)
	// Another job on the same target, whose runs these are.
	var other uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO backup_jobs (target_id, destination_id, destination_group_id, cron, timezone, engine_options)
		SELECT target_id, destination_id, destination_group_id, cron, timezone, engine_options FROM backup_jobs WHERE id = $1 RETURNING id`,
		e.Job).Scan(&other); err != nil {
		t.Fatal(err)
	}
	run := func(status string) uuid.UUID {
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at) VALUES ($1, 'manual', $2, now()) RETURNING id`,
			other, status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	live, failed, done := run("running"), run("failed"), run("succeeded")
	e.W.PerCluster = 2 // the live run holds one of the cluster's slots
	unknown := uuid.New()
	setOptions(t, db, e.Job, fmt.Sprintf(`{"method":"native","native_running":["%s","%s","%s","%s"]}`, live, failed, done, unknown))
	r := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, r)
	call := nativeCallOf(t, r)
	if strings.Join(call.kill, ",") != failed.String()+","+done.String() {
		t.Fatalf("ended %v; want only the finished runs %s and %s", call.kill, failed, done)
	}
	if got := loadRun(t, db, r); got.Status != "succeeded" {
		t.Fatalf("run: %+v", got)
	}
}

// R43: an object the client stored that .backup does not list is left out
// of the signed manifest and stays incomplete on every destination, so the
// lifecycle rule removes it; the run still succeeds.
func TestNativeRunUnlistedObject(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	setOptions(t, db, e.Job, `{"method":"native","native_extra":true}`)
	run := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, run)
	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "succeeded" || len(cs) != 2 {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	var total int64
	for _, o := range nativeBackup() {
		total += int64(len(o.body))
	}
	for i, b := range []*fakeBlobs{e.B1, e.B2} {
		dir := runDir(t, db, []string{"a", "b"}[i], run)
		_, m := readSidecar(t, b, e.kv, dir, run)
		if len(m.Objects) != len(nativeBackup()) || cs[i].Bytes != total {
			t.Fatalf("copy %d: %d objects in the manifest, %d bytes", i, len(m.Objects), cs[i].Bytes)
		}
		extra := dir + "/data/shop/orders/extra.bin"
		if _, ok := b.blobs[extra]; !ok {
			t.Fatalf("copy %d: the extra object was not stored", i)
		}
		if tg := b.tags[extra]; tg[backup.StateTag] != backup.StateIncomplete {
			t.Fatalf("copy %d: the unlisted object is tagged %v", i, tg)
		}
	}
	if _, objects := runMethod(t, db, run); objects != fmt.Sprint(len(nativeBackup())) {
		t.Fatalf("objects %s", objects)
	}
}

// A native job's run that fails before the native path starts (the agent
// gone, at claim or when it runs) is still a native run: method native, 0
// objects, as the API documents.
func TestNativeRunEarlyFailures(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	e := seedNative(t, db)
	cluster := func(status string) {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE clusters SET status = $2 WHERE id = (SELECT t.cluster_id FROM backup_jobs j
			JOIN targets t ON t.id = j.target_id WHERE j.id = $1)`, e.Job, status); err != nil {
			t.Fatal(err)
		}
	}
	// Revoked while it was queued: failed at claim.
	cluster("revoked")
	atClaim := queue(t, db, e.Job, "manual", nil)
	if id, err := e.W.Claim(ctx); err != nil || id != uuid.Nil {
		t.Fatalf("claimed %s %v", id, err)
	}
	// Revoked once claimed: failed when it runs.
	cluster("online")
	atRun := queue(t, db, e.Job, "manual", nil)
	id, err := e.W.Claim(ctx)
	if err != nil || id != atRun {
		t.Fatalf("claimed %s %v", id, err)
	}
	cluster("revoked")
	e.W.Execute(ctx, atRun)
	for name, id := range map[string]uuid.UUID{"at claim": atClaim, "at run": atRun} {
		if r := loadRun(t, db, id); r.Status != "failed" {
			t.Fatalf("%s: %+v", name, r)
		}
		if m, o := runMethod(t, db, id); m != "native" || o != "0" {
			t.Fatalf("%s: method %q objects %s, want native 0", name, m, o)
		}
	}
}

// A server shutting down while a copy is re-tagged complete does not cut the
// retag: a copy left half tagged keeps complete objects under an incomplete
// manifest. completeNative runs to its end, within its own time limit.
func TestNativeRunShutdownMidRetag(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	run := queue(t, db, e.Job, "manual", nil)
	id, err := e.W.Claim(context.Background())
	if err != nil || id != run {
		t.Fatalf("claimed %s %v", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	e.B1.tagHook = func(tctx context.Context) error {
		once.Do(cancel)
		return tctx.Err()
	}
	e.W.Execute(ctx, run)
	r := loadRun(t, db, run)
	cs := loadCopies(t, db, run)
	if r.Status != "succeeded" || len(cs) != 2 || cs[0].Status != "succeeded" {
		t.Fatalf("run: %+v copies %+v", r, cs)
	}
	dir := runDir(t, db, "a", run)
	for _, o := range nativeBackup() {
		if tg := e.B1.tags[dir+"/"+o.rel]; tg[backup.StateTag] != backup.StateComplete {
			t.Fatalf("%s tagged %v", o.rel, tg)
		}
	}
	if tg := e.B1.tags[backup.ManifestPath(dir, run)]; tg[backup.StateTag] != backup.StateComplete {
		t.Fatalf("manifest tagged %v", tg)
	}
}

// VerifyNativeChain is the real engine's.
func (fakeEngine) VerifyNativeChain(ctx context.Context, kv secrets.KeyVault, keyName, runID string, signed [][]byte) ([]backup.NativeChainManifest, error) {
	return clickhouse.Engine{}.VerifyNativeChain(ctx, kv, keyName, runID, signed)
}

// seedIncremental is seedNative with weekly fulls and daily incrementals.
func seedIncremental(t *testing.T, db *store.DB) nativeEnv {
	t.Helper()
	e := seedNative(t, db)
	setOptions(t, db, e.Job, `{"method":"native","databases":["shop"],"incremental":"weekly_full_daily"}`)
	return e
}

// scheduled queues and runs a scheduled run of the job for at.
func scheduled(t *testing.T, e nativeEnv, db *store.DB, at time.Time) uuid.UUID {
	t.Helper()
	return runAt(t, e, db, "schedule", at)
}

// runAt queues and runs a run of the job with trigger for at (a manual one
// with scheduled_for set, so that its week and month are at's).
func runAt(t *testing.T, e nativeEnv, db *store.DB, trigger string, at time.Time) uuid.UUID {
	t.Helper()
	run := queue(t, db, e.Job, trigger, &at)
	claimAndRun(t, e.W, run)
	if r := loadRun(t, db, run); r.Status != "succeeded" {
		t.Fatalf("run for %s: %+v", at, r)
	}
	return run
}

// baseOf is the base the engine was given for run, "" for a full backup.
func baseOf(t *testing.T, e nativeEnv, run uuid.UUID) string {
	t.Helper()
	b := nativeCallOf(t, run).run.Base
	if b == nil {
		return ""
	}
	if b.URL != e.srv.URL+"/olympos/"+b.RunID+"/" {
		t.Fatalf("base URL %s of base %s", b.URL, b.RunID)
	}
	return b.RunID
}

// sidecarOf reads the signed manifest of run's copy on b, as stored.
func sidecarOf(t *testing.T, b *fakeBlobs, dir string, run uuid.UUID) []byte {
	t.Helper()
	var side struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(b.blobs[backup.ManifestPath(dir, run)], &side); err != nil {
		t.Fatal(err)
	}
	return side.Details[backup.NativeManifestDetail]
}

// tagsOf checks the tier every object and the manifest of run's copy on b
// is tagged with, complete.
func tagsOf(t *testing.T, db *store.DB, b *fakeBlobs, prefix string, run uuid.UUID, tier string) {
	t.Helper()
	dir := runDir(t, db, prefix, run)
	if tg := b.tags[backup.ManifestPath(dir, run)]; tg[backup.TierTag] != tier || tg[backup.StateTag] != backup.StateComplete {
		t.Errorf("%s: manifest of %s tagged %v, want %s", prefix, run, tg, tier)
	}
	n := 0
	for p, tg := range b.tags {
		if strings.HasPrefix(p, dir+"/") {
			n++
			if tg[backup.TierTag] != tier || tg[backup.StateTag] != backup.StateComplete {
				t.Errorf("%s: %s tagged %v, want %s", prefix, p, tg, tier)
			}
		}
	}
	if n == 0 {
		t.Fatalf("%s: no objects of %s", prefix, run)
	}
}

// TestNativeIncrementalChain (task 13, R45): weekly fulls, daily
// incrementals, by the job's time zone. The first run of the week, and of
// the month, is a full; the next one is an incremental on the latest run
// that succeeded on every destination and whose manifests verify. Its
// credential reads the chain's prefixes, the full first, and the endpoint
// serves it the chain's objects from storage, only those its manifests
// list. Its manifest is based on the base's and counts the parts it takes
// from it. The chain is kept at least weekly: a daily member is re-tagged
// weekly, objects and manifest, on every destination; a monthly one stays.
func TestNativeIncrementalChain(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	// Mon 23 Nov: the first scheduled run of the month (monthly), a full.
	full := scheduled(t, e, db, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC))
	// Tue 24 and Wed 25 Nov: daily incrementals.
	inc := scheduled(t, e, db, time.Date(2026, 11, 24, 2, 0, 0, 0, time.UTC))
	inc2 := scheduled(t, e, db, time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC))

	if b := baseOf(t, e, full); b != "" {
		t.Fatalf("the first run is based on %s", b)
	}
	if b := baseOf(t, e, inc); b != full.String() {
		t.Fatalf("the incremental is based on %q, want %s", b, full)
	}
	if b := baseOf(t, e, inc2); b != inc.String() {
		t.Fatalf("the second incremental is based on %q, want %s", b, inc)
	}

	// The credential reads the chain, the full first; a full's reads nothing.
	for run, want := range map[uuid.UUID]string{
		full: `{"write": "` + full.String() + `/"}`,
		inc:  `{"read": ["` + full.String() + `/"], "write": "` + inc.String() + `/"}`,
		inc2: `{"read": ["` + full.String() + `/", "` + inc.String() + `/"], "write": "` + inc2.String() + `/"}`,
	} {
		if got := credentialOf(t, db, run).Scope; got != want {
			t.Errorf("scope of %s: %s, want %s", run, got, want)
		}
	}

	// The endpoint served the base's .backup and listed each prefix of the
	// chain with the objects of its manifest; nothing else.
	call := nativeCallOf(t, inc2)
	if call.baseGet != http.StatusOK || call.unlisted != http.StatusNotFound || call.outside != http.StatusForbidden {
		t.Fatalf("reads of the base: .backup %d, unlisted %d, outside %d", call.baseGet, call.unlisted, call.outside)
	}
	_, mFull := readSidecar(t, e.B1, e.kv, runDir(t, db, "a", full), full)
	_, mInc := readSidecar(t, e.B1, e.kv, runDir(t, db, "a", inc), inc)
	for prefix, m := range map[string]*clickhouse.NativeManifest{full.String() + "/": mFull, inc.String() + "/": mInc} {
		var want []string
		for _, o := range m.Objects {
			want = append(want, o.Key)
		}
		if got := call.listed[prefix]; strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("list %s:\n got %v\nwant %v", prefix, got, want)
		}
	}

	// The manifests are a chain: each based on the one before, the rows of
	// the parts taken from the base counted from the base's manifest.
	for i, b := range []*fakeBlobs{e.B1, e.B2} {
		prefix := []string{"a", "b"}[i]
		var raws [][]byte
		for _, run := range []uuid.UUID{full, inc, inc2} {
			raws = append(raws, sidecarOf(t, b, runDir(t, db, prefix, run), run))
		}
		ms, err := clickhouse.VerifyChain(context.Background(), e.kv, nativeKey, inc2.String(), raws)
		if err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
		if rows := ms[2].Databases[0].Objects[0].Rows; rows != 52 || ms[1].Databases[0].Objects[0].Rows != 47 {
			t.Fatalf("copy %d: rows %d and %d, want 47 and 52", i, ms[1].Databases[0].Objects[0].Rows, rows)
		}
		if ms[2].Settings["base_backup"] != "S3('"+e.srv.URL+"/olympos/"+inc.String()+"/')" {
			t.Fatalf("copy %d settings: %v", i, ms[2].Settings)
		}
		// An incremental stores only what is new.
		if len(ms[1].Objects) != 3 {
			t.Fatalf("copy %d: the incremental stored %d objects", i, len(ms[1].Objects))
		}
	}

	// Retention (R45): the daily member inc is kept weekly now, the monthly
	// full stays monthly, the newest run is daily until it is a base. The
	// copy rows keep the tier each run was written with.
	for run, tier := range map[uuid.UUID]string{full: "monthly", inc: "daily", inc2: "daily"} {
		if cs := loadCopies(t, db, run); cs[0].Tier != tier || cs[1].Tier != tier {
			t.Fatalf("copies of %s: %+v, want %s", run, cs, tier)
		}
	}
	for i, b := range []*fakeBlobs{e.B1, e.B2} {
		prefix := []string{"a", "b"}[i]
		for run, tier := range map[uuid.UUID]string{full: "monthly", inc: "weekly", inc2: "daily"} {
			tagsOf(t, db, b, prefix, run, tier)
		}
	}

	// Mon 30 Nov: the first run of the week is a full (weekly).
	week := scheduled(t, e, db, time.Date(2026, 11, 30, 2, 0, 0, 0, time.UTC))
	// Tue 1 Dec: the first run of the month is a full, even a manual one
	// (daily) within the week (R45).
	month := runAt(t, e, db, "manual", time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC))
	// Tue 1 Dec: the first scheduled run of the month is monthly, and a
	// monthly copy is always a full.
	monthly := scheduled(t, e, db, time.Date(2026, 12, 1, 2, 0, 0, 0, time.UTC))
	// Wed 2 Dec: an incremental on it, which leaves it monthly.
	daily := scheduled(t, e, db, time.Date(2026, 12, 2, 2, 0, 0, 0, time.UTC))
	for run, want := range map[uuid.UUID]string{week: "", month: "", monthly: "", daily: monthly.String()} {
		if b := baseOf(t, e, run); b != want {
			t.Errorf("run %s based on %q, want %q", run, b, want)
		}
	}
	if cs := loadCopies(t, db, monthly); cs[0].Tier != "monthly" {
		t.Fatalf("the first scheduled run of December: %+v", cs)
	}
	tagsOf(t, db, e.B1, "a", monthly, "monthly")

	// Next Monday a full again.
	next := scheduled(t, e, db, time.Date(2026, 12, 7, 2, 0, 0, 0, time.UTC))
	if b := baseOf(t, e, next); b != "" {
		t.Fatalf("the first run of the next week is based on %s", b)
	}
}

// TestNativeIncrementalWeeklyCopyIsFull (R45): a weekly copy is a full too,
// although a manual run came first in the week.
func TestNativeIncrementalWeeklyCopyIsFull(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	scheduled(t, e, db, time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC)) // monthly
	manual := runAt(t, e, db, "manual", time.Date(2026, 11, 30, 1, 0, 0, 0, time.UTC))
	weekly := scheduled(t, e, db, time.Date(2026, 11, 30, 2, 0, 0, 0, time.UTC))
	if cs := loadCopies(t, db, weekly); cs[0].Tier != "weekly" || baseOf(t, e, weekly) != "" {
		t.Fatalf("the weekly copy: %+v, base %q (manual %s)", cs, baseOf(t, e, weekly), manual)
	}
}

// TestNativeIncrementalWeekByTimezone: the week and the month start in the
// job's time zone, not in UTC.
func TestNativeIncrementalWeekByTimezone(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	if _, err := db.Exec(context.Background(), `UPDATE backup_jobs SET timezone = 'Asia/Tokyo' WHERE id = $1`, e.Job); err != nil {
		t.Fatal(err)
	}
	at := func(d, h int) time.Time { return time.Date(2026, 11, d, h, 0, 0, 0, time.UTC) }
	// Sun 22 Nov 14:00 UTC is Sun 23:00 in Tokyo; 16:00 UTC is already
	// Monday there: a full. Mon 23 Nov 16:00 UTC is Tuesday there.
	sunday := runAt(t, e, db, "manual", at(22, 14))
	monday := runAt(t, e, db, "manual", at(22, 16))
	tuesday := runAt(t, e, db, "manual", at(23, 16))
	if baseOf(t, e, sunday) != "" || baseOf(t, e, monday) != "" || baseOf(t, e, tuesday) != monday.String() {
		t.Fatalf("week: %q %q %q", baseOf(t, e, sunday), baseOf(t, e, monday), baseOf(t, e, tuesday))
	}
	// Mon 30 Nov 14:00 UTC is Mon 23:00 in Tokyo (a new week: a full);
	// 15:30 UTC is Tue 1 Dec there, the first run of the month: a full
	// again; 16:30 UTC an incremental on it.
	mon := runAt(t, e, db, "manual", at(30, 14))
	dec := runAt(t, e, db, "manual", time.Date(2026, 11, 30, 15, 30, 0, 0, time.UTC))
	after := runAt(t, e, db, "manual", time.Date(2026, 11, 30, 16, 30, 0, 0, time.UTC))
	if baseOf(t, e, mon) != "" || baseOf(t, e, dec) != "" || baseOf(t, e, after) != dec.String() {
		t.Fatalf("month: %q %q %q", baseOf(t, e, mon), baseOf(t, e, dec), baseOf(t, e, after))
	}
}

// TestNativeIncrementalAfterPartial: a partial run is never a base, and the
// next run after one is a full.
func TestNativeIncrementalAfterPartial(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	first := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, first)
	e.B2.fail, e.B2.failOn = errors.New("503 ServerBusy"), "count.txt"
	partial := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, partial)
	if r := loadRun(t, db, partial); r.Status != "partial" {
		t.Fatalf("run: %+v", r)
	}
	e.B2.fail, e.B2.failOn = nil, ""
	after := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, after)
	if r := loadRun(t, db, after); r.Status != "succeeded" || baseOf(t, e, after) != "" {
		t.Fatalf("after a partial run: %+v, base %q", r, baseOf(t, e, after))
	}
	if baseOf(t, e, partial) != first.String() {
		t.Fatalf("the run after the first: base %q", baseOf(t, e, partial))
	}
}

// TestNativeIncrementalNotOnTestRun (R40): a test run holds no data; it is
// never a base, and is a full itself.
func TestNativeIncrementalNotOnTestRun(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	first := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, first)
	dry := queue(t, db, e.Job, "test", nil)
	claimAndRun(t, e.W, dry)
	if r := loadRun(t, db, dry); r.Status != "succeeded" || baseOf(t, e, dry) != "" || !nativeCallOf(t, dry).run.StructureOnly {
		t.Fatalf("test run: %+v, base %q", r, baseOf(t, e, dry))
	}
	next := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, next)
	if b := baseOf(t, e, next); b != first.String() {
		t.Fatalf("based on %q, want %s, not the test run %s", b, first, dry)
	}
}

// TestNativeIncrementalBaseDoesNotVerify: a base whose manifest does not
// verify is no base: the run is a full.
func TestNativeIncrementalBaseDoesNotVerify(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	first := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, first)
	// Its manifest on the destination the base is read from, changed.
	side := backup.ManifestPath(runDir(t, db, "a", first), first)
	e.B1.blobs[side] = bytes.Replace(e.B1.blobs[side], []byte(`"rows":42`), []byte(`"rows":43`), 1)
	next := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, next)
	if r := loadRun(t, db, next); r.Status != "succeeded" || baseOf(t, e, next) != "" {
		t.Fatalf("on a base that does not verify: %+v, base %q", r, baseOf(t, e, next))
	}
}

// TestNativeIncrementalTamperedBaseObject: the endpoint checks every object
// of the chain against its manifest while it serves it; one that changed in
// storage fails the GET, and so the run. The next run is a full: an
// incremental that failed may have failed on its base.
func TestNativeIncrementalTamperedBaseObject(t *testing.T) {
	db := testutil.DB(t)
	e := seedIncremental(t, db)
	first := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, first)
	p := runDir(t, db, "a", first) + "/.backup"
	e.B1.blobs[p] = bytes.Replace(e.B1.blobs[p], []byte("count.txt"), []byte("count.txT"), 1)
	bad := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, bad)
	if r := loadRun(t, db, bad); r.Status != "failed" || nativeCallOf(t, bad).baseGet == http.StatusOK {
		t.Fatalf("on a tampered base: %+v, GET %d", r, nativeCallOf(t, bad).baseGet)
	}
	next := queue(t, db, e.Job, "manual", nil)
	claimAndRun(t, e.W, next)
	if r := loadRun(t, db, next); r.Status != "succeeded" || baseOf(t, e, next) != "" {
		t.Fatalf("after a failed incremental: %+v, base %q", r, baseOf(t, e, next))
	}
}

// TestNativeIncrementalOff: without the option every run is a full.
func TestNativeIncrementalOff(t *testing.T) {
	db := testutil.DB(t)
	e := seedNative(t, db)
	for range 2 {
		run := queue(t, db, e.Job, "manual", nil)
		claimAndRun(t, e.W, run)
		if baseOf(t, e, run) != "" {
			t.Fatal("an incremental without the option")
		}
	}
}
