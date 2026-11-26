package clickhouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/signer"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// TestRunNativeAgainstIngest runs RunNative on ClickHouse 24.8 and 25.8 in
// Docker (the images of captureImages, pinned by digest) against a real
// ingest handler on the host, whose sink is a directory. ClickHouse reaches
// the handler at host.docker.internal. Skipped without Docker or the dev
// Postgres, unless OLYMPOS_REQUIRE_DOCKER=1.
//
// Per version: a full backup and an incremental on it reach BACKUP_CREATED;
// a stop mid-run KILLs the backup on the run's connection; and the gates of
// the endpoint against real ClickHouse (R13, R17, R18, 503 bodies): what it
// sends, how it takes 503 SlowDown for the rate and for parts that wait.
// Every request the handler sees is recorded, and the logs are checked for
// the secret.
func TestRunNativeAgainstIngest(t *testing.T) {
	requireDocker(t)
	db := testutil.DB(t)
	for _, img := range captureImages {
		t.Run(img.ver, func(t *testing.T) { testRunNative(t, db, img.image, img.server) })
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	require := os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1"
	if _, err := exec.LookPath("docker"); err != nil {
		if require {
			t.Fatal("docker not found")
		}
		t.Skip("docker not available")
	}
	if out, err := dockerT(t, 20*time.Second, "info", "--format", "{{.ServerVersion}}"); err != nil {
		if require {
			t.Fatalf("docker info: %v %s", err, out)
		}
		t.Skipf("docker daemon not available: %v %s", err, out)
	}
}

const (
	nativeCHUser     = "olympos"
	nativeCHPassword = "ch-canary-5b1e"
	// The big table's one column file is 64 MiB: over the 32 MiB single
	// upload limit, so it goes up in four 16 MiB parts, in parallel.
	nativeBigSchema = `
CREATE DATABASE big;
CREATE TABLE big.blob (id UInt64, b String) ENGINE = MergeTree ORDER BY id SETTINGS min_bytes_for_wide_part = 0;
INSERT INTO big.blob SELECT number, randomString(4096) FROM numbers(16384);
`
)

// nativeParts is how many parts the table of the rate gate has (about five
// objects each); OLYMPOS_NATIVE_PARTS changes it. Without the throttle of
// R29, ClickHouse sends far more than 200 requests a second, and a run of
// more than about 6,000 objects stayed over the rate for 30 s and was
// stopped for a rate storm (task 9: 2500 parts, on 24.8 and 25.8). With it,
// 1500 parts, about 7,500 objects, go up under the rate. That the endpoint
// stops a client that ignores the rate is TestHandlerRateStorm's (ingest).
var nativeParts = func() int {
	if n, err := strconv.Atoi(os.Getenv("OLYMPOS_NATIVE_PARTS")); err == nil && n > 0 {
		return n
	}
	return 1500
}()

func testRunNative(t *testing.T, db *store.DB, image, wantServer string) {
	chc := startNativeClickHouse(t, image, wantServer)
	chc.query(t, captureSchema)
	chc.query(t, nativeBigSchema)
	chc.query(t, fmt.Sprintf(`CREATE DATABASE parts;
CREATE TABLE parts.p (id UInt64) ENGINE = MergeTree PARTITION BY id ORDER BY id;
INSERT INTO parts.p SELECT number FROM numbers(%d) SETTINGS max_partitions_per_insert_block = 0;`, nativeParts))

	engineLogs := captureDefaultLog(t)

	// The full and incremental runs share a store: the incremental reads
	// its base from it.
	st := newDirStore(t, 0)
	var fullID string
	var fullRun *nativeTestRun
	t.Run("full", func(t *testing.T) {
		in := newIngest(t, db)
		r := in.open(t, st, nil)
		fullID, fullRun = r.id, r
		var target backup.NativeTarget
		r.before = func(_ context.Context, nt backup.NativeTarget) ([]string, error) { target = nt; return nil, nil }
		v, err := runNative(t, chc, r, nil, "spike", "big")
		if err != nil {
			t.Fatalf("RunNative: %v", err)
		}
		if v != wantServer {
			t.Fatalf("server version %q", v)
		}
		// R39: the size on disk of the databases, before the BACKUP; big.blob
		// alone is 64 MiB of random strings.
		if target.Bytes < 64<<20 || target.Bytes > 128<<20 {
			t.Fatalf("the databases hold %d bytes on disk", target.Bytes)
		}
		chc.wantStatus(t, r.id, statusCreated)
		r.s.Revoke("run ended")
		if _, ok := r.s.Captured(r.id + "/.backup"); !ok {
			t.Fatal("the session kept no .backup")
		}
		ops := in.rec.summary()
		t.Logf("requests of the full backup:\n%s", ops)
		in.rec.checkR13(t)
		if in.rec.count("POST", "uploadId", 200) == 0 {
			t.Fatal("no multipart upload completed")
		}
		in.checkNoSecret(t, r, engineLogs)
	})
	// R40: a test run's BACKUP has structure_only = 1. It goes through the
	// endpoint as a full one does, in seconds: the .backup lists only the
	// metadata/*.sql files, and the manifest builds from it.
	t.Run("structure only", func(t *testing.T) {
		in := newIngest(t, db)
		r := in.open(t, newDirStore(t, 0), nil)
		r.structureOnly = true
		start := time.Now()
		if _, err := runNative(t, chc, r, nil, "spike", "big"); err != nil {
			t.Fatalf("RunNative: %v", err)
		}
		took := time.Since(start).Round(time.Millisecond)
		chc.wantStatus(t, r.id, statusCreated)
		r.s.Revoke("run ended")
		objs := r.s.Objects()
		var keys []string
		for _, o := range objs {
			rel := strings.TrimPrefix(o.Key, r.id+"/")
			if rel != ".backup" && !strings.HasPrefix(rel, "metadata/") {
				t.Errorf("a structure-only backup stored %s", rel)
			}
			keys = append(keys, rel)
		}
		sort.Strings(keys)
		raw, ok := r.s.Captured(r.id + "/.backup")
		if !ok {
			t.Fatal("the session kept no .backup")
		}
		meta, err := ParseBackupMeta(raw)
		if err != nil {
			t.Fatal(err)
		}
		m, err := BuildNativeManifest(NativeBuild{RunID: r.id, ServerVersion: wantServer, Settings: statementSettings(r.id, true, ""),
			Objects: objs, Body: r.s.Captured, StructureOnly: true})
		if err != nil {
			t.Fatalf("manifest: %v", err)
		}
		if len(m.Databases) != 2 || len(m.PartRows) != 0 || rowsOf(t, m, "spike", "events") != 0 {
			t.Fatalf("manifest: %+v", m.Databases)
		}
		t.Logf("structure only, %s: %d objects (%s); .backup lists %d files, base %q", took, len(objs), strings.Join(keys, " "),
			len(meta.Files), meta.BaseBackup)
		t.Logf("requests:\n%s", in.rec.summary())
		in.rec.checkR13(t)
		in.checkNoSecret(t, r, engineLogs)
	})

	t.Run("incremental", func(t *testing.T) {
		if fullID == "" {
			t.Skip("no full backup to take it on")
		}
		chc.query(t, captureChange)
		in := newIngest(t, db)
		r := in.open(t, st, []string{fullID + "/"})
		base := &NativeBase{URL: in.url + "/olympos/" + fullID + "/", RunID: fullID}
		if _, err := runNative(t, chc, r, base, "spike", "big"); err != nil {
			t.Fatalf("RunNative: %v", err)
		}
		chc.wantStatus(t, r.id, statusCreated)
		r.s.Revoke("run ended")
		meta, ok := r.s.Captured(r.id + "/.backup")
		if !ok {
			t.Fatal("the session kept no .backup")
		}
		bm, err := ParseBackupMeta(meta)
		if err != nil {
			t.Fatalf("parse the incremental's .backup: %v", err)
		}
		if !strings.Contains(bm.BaseBackup, fullID) {
			t.Fatalf("the incremental's base is %q", bm.BaseBackup)
		}
		t.Logf("requests of the incremental:\n%s", in.rec.summary())
		in.rec.checkR13(t)
		if in.rec.count("GET", "", 200) == 0 {
			t.Fatal("the incremental read nothing of its base")
		}
		in.checkNoSecret(t, r, engineLogs)
	})

	// Task 13: a chain of three, as the worker takes it, on one endpoint: an
	// incremental on the full, then one on that incremental, whose
	// credential reads both runs before it. Their manifests build along the
	// chain; a Log table's count.txt that grew from 2 to 20 rows (ClickHouse
	// may take "2" from the base and write "0") counts 20.
	t.Run("chain", func(t *testing.T) {
		if fullRun == nil {
			t.Skip("no full backup to take it on")
		}
		in := newIngest(t, db)
		// The base is served as the worker serves it: whole objects only,
		// a ranged GET refused (ingest.WholeSource).
		whole := wholeStore{st}
		mid := in.openWith(t, st, whole, []string{fullID + "/"})
		midBase := &NativeBase{URL: in.url + "/olympos/" + fullID + "/", RunID: fullID}
		if _, err := runNative(t, chc, mid, midBase, "spike", "big"); err != nil {
			t.Fatalf("RunNative on the full: %v", err)
		}
		chc.wantStatus(t, mid.id, statusCreated)
		mid.s.Revoke("run ended")
		chc.query(t, `INSERT INTO spike.applog SELECT 100 + number, 'grown' FROM numbers(18);
INSERT INTO spike.applog_copy SELECT 100 + number, 'grown' FROM numbers(18);`)
		last := in.openWith(t, st, whole, []string{fullID + "/", mid.id + "/"})
		lastBase := &NativeBase{URL: in.url + "/olympos/" + mid.id + "/", RunID: mid.id}
		if _, err := runNative(t, chc, last, lastBase, "spike", "big"); err != nil {
			t.Fatalf("RunNative on the incremental: %v", err)
		}
		chc.wantStatus(t, last.id, statusCreated)
		last.s.Revoke("run ended")

		// What a run did not keep is its base chain's, read from the store.
		body := func(s *ingest.Session) func(string) ([]byte, bool) {
			return func(key string) ([]byte, bool) {
				if b, ok := s.Captured(key); ok {
					return b, true
				}
				b, err := os.ReadFile(st.path(key))
				return b, err == nil
			}
		}
		build := func(r *nativeTestRun, base *NativeBase, chain []*NativeManifest) *NativeManifest {
			t.Helper()
			baseURL := ""
			if base != nil {
				baseURL = base.URL
			}
			m, err := BuildNativeManifest(NativeBuild{RunID: r.id, ServerVersion: wantServer, Settings: statementSettings(r.id, false, baseURL),
				Objects: r.s.Objects(), Body: body(r.s), Base: chain, BaseURL: baseURL})
			if err != nil {
				t.Fatalf("manifest of %s: %v", r.id, err)
			}
			return m
		}
		mFull := build(fullRun, nil, nil)
		mMid := build(mid, midBase, []*NativeManifest{mFull})
		mLast := build(last, lastBase, []*NativeManifest{mFull, mMid})
		for _, name := range []string{"applog", "applog_copy"} {
			if got := rowsOf(t, mMid, "spike", name); got != 2 {
				t.Errorf("%s in the first incremental: %d rows, want 2", name, got)
			}
			if got := rowsOf(t, mLast, "spike", name); got != 20 {
				t.Errorf("%s in the second incremental: %d rows, want 20", name, got)
			}
		}
		if got, want := rowsOf(t, mLast, "spike", "events"), rowsOf(t, mFull, "spike", "events")+1000; got != want {
			t.Errorf("events: %d rows, want %d", got, want)
		}
		raw, _ := last.s.Captured(last.id + "/.backup")
		meta, err := ParseBackupMeta(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range meta.Files {
			if f.Name == "data/spike/applog/count.txt" {
				t.Logf("applog/count.txt in the second incremental: size %d, use_base %v, base_size %d, data_file %q",
					f.Size, f.UseBase, f.BaseSize, f.DataFile)
			}
		}
		kv := newFakeVault()
		var raws [][]byte
		for _, m := range []*NativeManifest{mFull, mMid, mLast} {
			raws = append(raws, signedJSON(t, kv, testManifestKey, m))
		}
		if _, err := VerifyChain(context.Background(), kv, testManifestKey, last.id, raws); err != nil {
			t.Fatalf("the chain: %v", err)
		}
		// ClickHouse reads its base whole: no GET with a Range, which the
		// source would refuse.
		gets, ranged := 0, 0
		for _, r := range in.rec.all() {
			if r.method == http.MethodGet && r.params == "" {
				gets++
				if r.rng != "" {
					ranged++
					t.Errorf("a ranged GET (%s), status %d", r.rng, r.status)
				}
			}
		}
		t.Logf("the chain's GetObjects: %d, with a Range: %d", gets, ranged)
		t.Logf("requests of the chain:\n%s", in.rec.summary())
		in.rec.checkR13(t)
		in.checkNoSecret(t, last, engineLogs)
	})

	t.Run("stop kills", func(t *testing.T) {
		// A slow sink keeps the backup running until the stop.
		slow := newDirStore(t, 2<<20)
		in := newIngest(t, db)
		r := in.open(t, slow, nil)
		go func() {
			select {
			case <-slow.first:
				r.s.Stop("test stop")
			case <-time.After(2 * time.Minute):
			}
		}()
		start := time.Now()
		_, err := runNative(t, chc, r, nil, "big")
		if err == nil || !strings.Contains(err.Error(), "test stop") || !strings.Contains(err.Error(), "KILL QUERY") {
			t.Fatalf("RunNative after a stop: %v", err)
		}
		t.Logf("stopped after %s: %v", time.Since(start).Round(time.Second), err)
		status := chc.status(t, r.id)
		if status != statusFailed && status != statusCancelled {
			t.Fatalf("system.backups: %s", status)
		}
		// The KILL went over the run's connection: the BACKUP and the KILL
		// came from the same client port.
		chc.query(t, "SYSTEM FLUSH LOGS")
		ports := chc.query(t, "SELECT DISTINCT port FROM system.query_log WHERE type = 'QueryStart' AND "+
			"(query_id = "+quoteString(nativeQueryID(r.id))+" OR (query LIKE 'KILL QUERY%' AND query LIKE '%"+r.id+"%'))")
		if n := len(strings.Fields(ports)); n != 1 {
			t.Fatalf("the BACKUP and its KILL came from %d client ports: %q", n, ports)
		}
		t.Logf("system.backups: %s; BACKUP and KILL on client port %s", status, ports)

		r.s.Revoke("run ended")
		rep := in.signed(t, r.cred, http.MethodGet, "/olympos/"+r.id+"/.lock")
		if rep != http.StatusForbidden {
			t.Fatalf("a request with the revoked credential: %d", rep)
		}
		in.checkNoSecret(t, r, engineLogs)
	})

	t.Run("cancel kills", func(t *testing.T) {
		slow := newDirStore(t, 2<<20)
		in := newIngest(t, db)
		r := in.open(t, slow, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-slow.first:
				cancel()
			case <-time.After(2 * time.Minute):
			}
		}()
		_, err := runNativeCtx(t, ctx, chc, r, nil, "big")
		if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) || !strings.Contains(err.Error(), "KILL QUERY made it") {
			t.Fatalf("RunNative after a cancel: %v", err)
		}
		if status := chc.status(t, r.id); status != statusFailed && status != statusCancelled {
			t.Fatalf("system.backups: %s", status)
		}
		r.s.Revoke("run ended")
		in.checkNoSecret(t, r, engineLogs)
	})

	// The run's connection breaks mid-run: the next poll fails, and the
	// backup is KILLed over a new connection.
	t.Run("lost connection kills", func(t *testing.T) {
		slow := newDirStore(t, 2<<20)
		in := newIngest(t, db)
		r := in.open(t, slow, nil)
		ec := chc.ec()
		var mu sync.Mutex
		var conns []net.Conn
		dial := ec.Dial
		ec.Dial = func(ctx context.Context) (net.Conn, error) {
			c, err := dial(ctx)
			if err == nil {
				mu.Lock()
				conns = append(conns, c)
				mu.Unlock()
			}
			return c, err
		}
		go func() {
			select {
			case <-slow.first:
				mu.Lock()
				_ = conns[0].Close()
				mu.Unlock()
			case <-time.After(2 * time.Minute):
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		_, err := Engine{}.RunNative(ctx, ec, NativeRun{URL: r.url, AccessKey: r.cred.AccessKey, Secret: r.cred.Secret,
			RunID: r.id, Databases: []string{"big"}, Stop: r.s.Stopped()})
		if err == nil || errors.Is(err, ErrNativeOrphan) || !strings.Contains(err.Error(), "KILL QUERY on a new connection made it") {
			t.Fatalf("RunNative after a lost connection: %v", err)
		}
		mu.Lock()
		n := len(conns)
		mu.Unlock()
		if n != 2 {
			t.Fatalf("%d connections, want the run's and the KILL's", n)
		}
		if status := chc.status(t, r.id); status != statusFailed && status != statusCancelled {
			t.Fatalf("system.backups: %s", status)
		}
		t.Logf("%v", err)
		r.s.Revoke("run ended")
		in.checkNoSecret(t, r, engineLogs)
	})

	// R41: before its BACKUP a run ends the native backups of runs that are
	// over, and only those: the one Before names is KILLed on the run's
	// connection, the other, a run still running, goes on.
	t.Run("orphans", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s, err := connect(ctx, chc.ec(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		in := newIngest(t, db)
		start := func() *nativeTestRun {
			slow := newDirStore(t, 2<<20)
			o := in.open(t, slow, nil)
			nr := NativeRun{URL: o.url, AccessKey: o.cred.AccessKey, Secret: o.cred.Secret, RunID: o.id, Databases: []string{"big"}}
			t.Cleanup(func() {
				_, _ = dockerT(t, time.Minute, "exec", chc.name, "clickhouse-client", "-u", nativeCHUser, "--password", nativeCHPassword,
					"-q", backup.NativeKillQuery(o.id))
			})
			if err := s.nativeExec(ctx, backupStatement(nr), nativeQueryID(o.id), nativeBackupSettings...); err != nil {
				t.Fatalf("BACKUP: %s", maskSecret(err.Error(), nr.Secret))
			}
			select {
			case <-slow.first:
			case <-time.After(2 * time.Minute):
				t.Fatal("the backup wrote nothing")
			}
			return o
		}
		over, live := start(), start()
		r := in.open(t, newDirStore(t, 0), nil)
		var seen []string
		r.before = func(_ context.Context, nt backup.NativeTarget) ([]string, error) {
			seen = nt.Running
			return []string{over.id}, nil
		}
		if _, err := runNative(t, chc, r, nil, "spike"); err != nil {
			t.Fatalf("RunNative: %v", err)
		}
		chc.wantStatus(t, r.id, statusCreated)
		if !slices.Contains(seen, over.id) || !slices.Contains(seen, live.id) || slices.Contains(seen, r.id) {
			t.Fatalf("running native backups %v; want %s and %s", seen, over.id, live.id)
		}
		if st := chc.status(t, over.id); st != statusFailed && st != statusCancelled {
			t.Fatalf("the left-over backup is %s: %s", st, chc.backupError(t, over.id))
		}
		if st := chc.status(t, live.id); st != statusCreating {
			t.Fatalf("the running run's backup is %s: %s", st, chc.backupError(t, live.id))
		}
		t.Logf("seen running %v; ended %s (%s); left %s (%s)", seen, over.id, chc.status(t, over.id), live.id, chc.status(t, live.id))
		r.s.Revoke("run ended")
	})

	// OLYMPOS_NATIVE_ORPHAN_PROBE=1: does a backup whose credential is
	// revoked, with no KILL, end on its own (task 9 round 3)? Watched for
	// 3 min, then KILLed.
	t.Run("probe orphan", func(t *testing.T) {
		if os.Getenv("OLYMPOS_NATIVE_ORPHAN_PROBE") != "1" {
			t.Skip("a probe; set OLYMPOS_NATIVE_ORPHAN_PROBE=1")
		}
		slow := newDirStore(t, 2<<20)
		in := newIngest(t, db)
		r := in.open(t, slow, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s, err := connect(ctx, chc.ec(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		nr := NativeRun{URL: r.url, AccessKey: r.cred.AccessKey, Secret: r.cred.Secret, RunID: r.id, Databases: []string{"big"}}
		if err := s.nativeExec(ctx, backupStatement(nr), nativeQueryID(r.id), nativeBackupSettings...); err != nil {
			t.Fatalf("BACKUP: %s", maskSecret(err.Error(), nr.Secret))
		}
		// Revoked while a part of the big file's multipart upload streams,
		// the case the spike saw retried (spike §3).
		retry(t, 2*time.Minute, "an UploadPart in flight", func() (string, error) {
			if in.rec.started("partNumber,uploadId") == 0 {
				return "", errors.New("none yet")
			}
			return "", nil
		})
		r.s.Revoke("probe")
		start := time.Now()
		var status string
		for time.Since(start) < 3*time.Minute {
			if status = chc.status(t, r.id); status != statusCreating {
				break
			}
			time.Sleep(5 * time.Second)
		}
		chc.query(t, "SYSTEM FLUSH LOGS")
		t.Logf("after the revoke: %s at %s; requests:\n%s", status, time.Since(start).Round(time.Second), in.rec.summary())
		t.Logf("system.backups error: %s", chc.query(t, "SELECT substring(error, 1, 300) FROM system.backups WHERE id = "+quoteString(r.id)))
		if status == statusCreating {
			t.Logf("still running at 3 min; KILL")
			chc.query(t, "KILL QUERY WHERE query_id = "+quoteString(nativeQueryID(r.id))+" SYNC")
		}
	})

	// The target checks run on the server before any BACKUP.
	t.Run("refused", func(t *testing.T) {
		chc.query(t, `CREATE DATABASE dist;
CREATE TABLE dist.local (x UInt8) ENGINE = MergeTree ORDER BY x;
CREATE TABLE dist.all AS dist.local ENGINE = Distributed(default, dist, local);`)
		in := newIngest(t, db)
		r := in.open(t, newDirStore(t, 0), nil)
		_, err := runNative(t, chc, r, nil, "spike", "dist")
		if !errors.Is(err, ErrNativeSharded) || !strings.Contains(err.Error(), "dist.all") {
			t.Fatalf("a Distributed table: %v", err)
		}
		if _, err := runNative(t, chc, r, nil, "spike", "nope"); err == nil || !strings.Contains(err.Error(), `"nope" does not exist`) {
			t.Fatalf("a missing database: %v", err)
		}
		// An error from Before ends the run before its BACKUP.
		r.before = func(context.Context, backup.NativeTarget) ([]string, error) { return nil, errors.New("no, thanks") }
		if _, err := runNative(t, chc, r, nil, "spike"); err == nil || err.Error() != "no, thanks" {
			t.Fatalf("Before refused: %v", err)
		}
		r.before = nil
		if n := len(in.rec.all()); n != 0 {
			t.Fatalf("a refused run sent %d requests", n)
		}
		if s := chc.status(t, r.id); s != "" {
			t.Fatalf("a refused run is in system.backups: %s", s)
		}
	})

	// R18 and the 503 bodies: parts that come before their turn while the
	// sink is slow, over a 1 MiB spill budget, are refused 503 SlowDown
	// unread; the run goes on.
	t.Run("gate spill", func(t *testing.T) {
		slow := newDirStore(t, 32<<20)
		in := newIngest(t, db, ingest.WithSpillLimit(1<<20))
		r := in.open(t, slow, nil)
		before := chc.serverLogCounts(t)
		if _, err := runNative(t, chc, r, nil, "big"); err != nil {
			t.Fatalf("RunNative: %v", err)
		}
		r.s.Revoke("run ended")
		after := chc.serverLogCounts(t)
		t.Logf("requests:\n%s", in.rec.summary())
		t.Logf("ClickHouse log lines during the run: %s", after.since(before))
		// What ClickHouse saw of a 503 whose body was not read (gate 4).
		t.Logf("the last broken pipes:\n%s", chc.logSample(t, "Broken pipe", 2))
		if n := in.rec.count("PUT", "partNumber,uploadId", 503); n == 0 {
			t.Fatal("no part was refused 503: the gate did not run")
		}
		in.rec.checkR13(t)
		in.checkNoSecret(t, r, engineLogs)
	})

	// R17 and R29: a table of many parts at the real rate (200 requests a
	// second). The run's throttle keeps ClickHouse under it: the run is
	// created, longer than the 30 s that stop a storm, and not stopped.
	t.Run("gate rate", func(t *testing.T) {
		in := newIngest(t, db)
		r := in.open(t, newDirStore(t, 0), nil)
		before := chc.serverLogCounts(t)
		start := time.Now()
		_, err := runNative(t, chc, r, nil, "parts")
		took := time.Since(start).Round(time.Second)
		r.s.Revoke("run ended")
		after := chc.serverLogCounts(t)
		t.Logf("%d parts, %s:\n%s", nativeParts, took, in.rec.summary())
		t.Logf("ClickHouse log lines during the run: %s", after.since(before))
		if err != nil {
			t.Fatalf("RunNative: %v", err)
		}
		chc.wantStatus(t, r.id, statusCreated)
		if ok := in.rec.count("PUT", "", http.StatusOK); nativeParts >= 1500 && ok <= 6000 {
			t.Fatalf("only %d objects: the run is not over the size an unthrottled run was stopped at", ok)
		}
		in.rec.checkR13(t)
	})
}

// runNative runs RunNative for r, forwarding the session's stop as Task 10
// does, with every request bounded.
func runNative(t *testing.T, chc *nativeCH, r *nativeTestRun, base *NativeBase, dbs ...string) (string, error) {
	t.Helper()
	return runNativeCtx(t, context.Background(), chc, r, base, dbs...)
}

func runNativeCtx(t *testing.T, ctx context.Context, chc *nativeCH, r *nativeTestRun, base *NativeBase, dbs ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	nr := NativeRun{URL: r.url, AccessKey: r.cred.AccessKey, Secret: r.cred.Secret, RunID: r.id, Base: base,
		Databases: dbs, StructureOnly: r.structureOnly, Stop: r.s.Stopped(), Before: r.before}
	return Engine{}.RunNative(ctx, chc.ec(), nr)
}

// nativeCH is one ClickHouse container.
type nativeCH struct {
	name, native string
}

func startNativeClickHouse(t *testing.T, image, wantServer string) *nativeCH {
	t.Helper()
	name := "olympos-native-" + randHex(t, 4)
	pullMissing(t, image)
	t.Cleanup(func() { _, _ = dockerT(t, time.Minute, "rm", "-f", "-v", name) })
	// host-gateway makes host.docker.internal the host on Linux too.
	mustDocker(t, 2*time.Minute, "run", "-d", "--pull", "never", "--name", name,
		"--add-host", "host.docker.internal:host-gateway", "--ulimit", "nofile=262144:262144",
		"-e", "CLICKHOUSE_USER="+nativeCHUser, "-e", "CLICKHOUSE_PASSWORD="+nativeCHPassword,
		"-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1", "-p", "127.0.0.1::9000", image)
	out := mustDocker(t, 30*time.Second, "port", name, "9000/tcp")
	c := &nativeCH{name: name, native: strings.Split(out, "\n")[0]}
	retry(t, 90*time.Second, "clickhouse ready", func() (string, error) {
		return dockerT(t, 30*time.Second, "exec", name, "clickhouse-client", "-u", nativeCHUser, "--password", nativeCHPassword, "-q", "SELECT 1")
	})
	if v := c.query(t, "SELECT version()"); v != wantServer {
		t.Fatalf("%s is ClickHouse %s, not %s", image, v, wantServer)
	}
	return c
}

// pullMissing pulls image when Docker does not have it yet. Only the 24.8
// image comes with the other tests (by its tag); the run itself never pulls,
// so that a pull is not timed as the start of a container.
func pullMissing(t *testing.T, image string) {
	t.Helper()
	if _, err := dockerT(t, 30*time.Second, "image", "inspect", "--format", "{{.Id}}", image); err == nil {
		return
	}
	mustDocker(t, 5*time.Minute, "pull", "--quiet", image)
}

func (c *nativeCH) query(t *testing.T, q string) string {
	t.Helper()
	out, err := dockerT(t, 5*time.Minute, "exec", c.name, "clickhouse-client", "-u", nativeCHUser, "--password", nativeCHPassword, "-n", "-q", q)
	if err != nil {
		t.Fatalf("clickhouse-client: %v %s", err, out)
	}
	return out
}

func (c *nativeCH) status(t *testing.T, runID string) string {
	t.Helper()
	return c.query(t, "SELECT status FROM system.backups WHERE id = "+quoteString(runID))
}

// backupError is the error system.backups gives for the run's backup.
func (c *nativeCH) backupError(t *testing.T, runID string) string {
	t.Helper()
	return c.query(t, "SELECT error FROM system.backups WHERE id = "+quoteString(runID))
}

func (c *nativeCH) wantStatus(t *testing.T, runID, want string) {
	t.Helper()
	if got := c.status(t, runID); got != want {
		t.Fatalf("system.backups: %s, want %s", got, want)
	}
}

func (c *nativeCH) ec() backup.EngineContext {
	return backup.EngineContext{
		Target: backup.TargetInfo{Engine: "clickhouse", Namespace: "shop", Service: "clickhouse", Port: 9000},
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", c.native)
		},
		Credential: func(context.Context) (backup.Credential, error) {
			return backup.Credential{Username: nativeCHUser, Secret: []byte(nativeCHPassword)}, nil
		},
		Options: []byte(`{"method":"native"}`),
	}
}

// logCounts counts lines of the server log that tell how ClickHouse took
// the endpoint's answers.
type logCounts map[string]int

var logPatterns = []string{"SlowDown", "retryable error", "Connection reset", "Broken pipe", "Timeout", "NETWORK_ERROR", "S3_ERROR"}

func (c *nativeCH) serverLogCounts(t *testing.T) logCounts {
	t.Helper()
	out := logCounts{}
	for _, p := range logPatterns {
		n, _ := dockerT(t, time.Minute, "exec", c.name, "sh", "-c",
			"grep -c -i "+strconv.Quote(p)+" /var/log/clickhouse-server/clickhouse-server.log || true")
		out[p], _ = strconv.Atoi(strings.TrimSpace(n))
	}
	return out
}

// logSample is the last lines of the server log that match pattern.
func (c *nativeCH) logSample(t *testing.T, pattern string, n int) string {
	t.Helper()
	out, _ := dockerT(t, time.Minute, "exec", c.name, "sh", "-c",
		"grep -i "+strconv.Quote(pattern)+" /var/log/clickhouse-server/clickhouse-server.log | tail -n "+strconv.Itoa(n)+" || true")
	return out
}

func (a logCounts) since(b logCounts) string {
	var parts []string
	for _, p := range logPatterns {
		parts = append(parts, fmt.Sprintf("%s=%d", p, a[p]-b[p]))
	}
	return strings.Join(parts, " ")
}

// nativeIngest is one ingest handler on the host, and what it saw.
type nativeIngest struct {
	reg  *ingest.Registry
	url  string // as ClickHouse reaches it
	srv  *httptest.Server
	logs *syncLog
	rec  *recorder
}

func newIngest(t *testing.T, db *store.DB, opts ...ingest.HandlerOption) *nativeIngest {
	t.Helper()
	fp, err := secrets.NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg := ingest.NewRegistry(db, fp, 8, nil)
	logs := &syncLog{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := ingest.NewHandler(reg, log, ingest.NewMetrics(), append([]ingest.HandlerOption{ingest.WithSpillDir(t.TempDir())}, opts...)...)
	rec := &recorder{h: h}
	// The container reaches the host's listener, so it is not on loopback.
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(rec)
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	port := l.Addr().(*net.TCPAddr).Port
	return &nativeIngest{reg: reg, url: fmt.Sprintf("http://host.docker.internal:%d", port), srv: srv, logs: logs, rec: rec}
}

type nativeTestRun struct {
	id, url string
	s       *ingest.Session
	cred    ingest.Credential
	// before is the run's NativeRun.Before, structureOnly its StructureOnly.
	before        func(context.Context, backup.NativeTarget) ([]string, error)
	structureOnly bool
}

func (in *nativeIngest) open(t *testing.T, st *dirStore, read []string) *nativeTestRun {
	t.Helper()
	return in.openWith(t, st, st, read)
}

// openWith is open with src serving the read prefixes.
func (in *nativeIngest) openWith(t *testing.T, st *dirStore, src ingest.Source, read []string) *nativeTestRun {
	t.Helper()
	id := uuid.New()
	o := ingest.OpenOptions{RunID: id, Kind: ingest.KindBackup, Scope: ingest.Scope{Write: id.String() + "/", Read: read},
		TTL: time.Hour, Sink: st, MaxBytes: 4 << 30}
	if len(read) > 0 {
		o.Source = src
	}
	s, cred, err := in.reg.Open(context.Background(), o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Revoke("test ended") })
	return &nativeTestRun{id: id.String(), url: in.url + "/olympos/" + id.String() + "/", s: s, cred: cred}
}

// signed sends a bodiless request signed with cred and returns its status.
func (in *nativeIngest) signed(t *testing.T, cred ingest.Credential, method, path string) int {
	t.Helper()
	req, err := http.NewRequest(method, in.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sha256.New().Sum(nil)))
	resp, err := in.srv.Client().Do(signer.SignV4(*req, cred.AccessKey, cred.Secret, "", "us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// checkNoSecret: neither the handler's log nor the engine's holds the
// run's secret.
func (in *nativeIngest) checkNoSecret(t *testing.T, r *nativeTestRun, engineLogs *syncLog) {
	t.Helper()
	for name, l := range map[string]*syncLog{"handler": in.logs, "engine": engineLogs} {
		if strings.Contains(l.String(), r.cred.Secret) {
			t.Fatalf("the %s log holds the run's secret", name)
		}
	}
	if !strings.Contains(engineLogs.String(), r.id) || !strings.Contains(engineLogs.String(), hidden) {
		t.Fatalf("the engine did not log the run's redacted statement:\n%s", engineLogs.String())
	}
}

// captureDefaultLog sends slog.Default, the engine's log, to a buffer for
// the test.
func captureDefaultLog(t *testing.T) *syncLog {
	t.Helper()
	prev := slog.Default()
	l := &syncLog{}
	slog.SetDefault(slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return l
}

type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// recorder records every request in front of the handler: method, the
// names of its query parameters, the declared payload hash of a bodiless
// request, and the status.
type recorder struct {
	h    http.Handler
	mu   sync.Mutex
	reqs []seenRequest
	// begun counts the requests that came in, by their parameter names.
	begun map[string]int
}

// started is how many requests with these parameter names came in, served
// or not yet.
func (rc *recorder) started(params string) int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.begun[params]
}

type seenRequest struct {
	method, params, sha256 string
	// rng is the request's Range header.
	rng    string
	length int64
	status int
	etag   string
}

const emptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var names []string
	for k := range r.URL.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	seen := seenRequest{method: r.Method, params: strings.Join(names, ","), length: r.ContentLength, rng: r.Header.Get("Range")}
	rc.mu.Lock()
	if rc.begun == nil {
		rc.begun = map[string]int{}
	}
	rc.begun[seen.params]++
	rc.mu.Unlock()
	if r.ContentLength == 0 {
		seen.sha256 = r.Header.Get("X-Amz-Content-Sha256")
	}
	sw := &statusRecorder{ResponseWriter: w}
	defer func() {
		seen.status = sw.status
		if seen.status == 0 {
			seen.status = http.StatusOK
		}
		seen.etag = sw.Header().Get("ETag")
		rc.mu.Lock()
		rc.reqs = append(rc.reqs, seen)
		rc.mu.Unlock()
	}()
	rc.h.ServeHTTP(sw, r)
}

func (rc *recorder) all() []seenRequest {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]seenRequest(nil), rc.reqs...)
}

// count is the requests of method with exactly these parameter names and
// this status.
func (rc *recorder) count(method, params string, status int) int {
	n := 0
	for _, r := range rc.all() {
		if r.method == method && r.params == params && r.status == status {
			n++
		}
	}
	return n
}

// summary is "count method ?params status" per kind of request.
func (rc *recorder) summary() string {
	kinds := map[string]int{}
	for _, r := range rc.all() {
		kinds[fmt.Sprintf("%-6s ?%-22s %d", r.method, r.params, r.status)]++
	}
	var lines []string
	for k, n := range kinds {
		lines = append(lines, fmt.Sprintf("  %6d  %s", n, k))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// checkR13: ClickHouse sends only what the handler serves (no HEAD, no
// ListObjectsV2, no parameter the handler does not know), signs every
// bodiless request with the empty body's SHA-256, and no request was
// refused 403 or 400.
func (rc *recorder) checkR13(t *testing.T) {
	t.Helper()
	known := map[string]bool{"": true, "max-keys,prefix": true, "marker,max-keys,prefix": true, "prefix": true,
		"uploads": true, "partNumber,uploadId": true, "uploadId": true}
	for _, r := range rc.all() {
		switch {
		case r.method == http.MethodHead:
			t.Errorf("ClickHouse sent HEAD ?%s", r.params)
		case !known[r.params]:
			t.Errorf("ClickHouse sent %s ?%s", r.method, r.params)
		case r.length == 0 && r.sha256 != emptyBodySHA256:
			t.Errorf("a bodiless %s ?%s declared the payload hash %q", r.method, r.params, r.sha256)
		case r.status == http.StatusForbidden || r.status == http.StatusBadRequest:
			t.Errorf("%s ?%s was refused %d", r.method, r.params, r.status)
		case r.method == http.MethodPut && r.status == http.StatusOK && len(r.etag) != 34:
			t.Errorf("PUT ?%s answered with the ETag %q", r.params, r.etag)
		}
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap gives the handler's http.ResponseController the connection.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// wholeStore is a dirStore served as the worker's chain source is: whole
// objects only (ingest.WholeSource).
type wholeStore struct{ *dirStore }

func (wholeStore) WholeObjects() {}

// dirStore is the run's sink and its base's source: objects in a temporary
// directory, by bucket-relative key. With bytesPerSecond > 0 every Put
// writes no faster, as a slow destination.
type dirStore struct {
	root           string
	bytesPerSecond float64
	first          chan struct{}
	firstOnce      sync.Once

	mu   sync.Mutex
	recs map[string]ingest.ObjectRecord
}

func newDirStore(t *testing.T, bytesPerSecond float64) *dirStore {
	return &dirStore{root: t.TempDir(), bytesPerSecond: bytesPerSecond, first: make(chan struct{}), recs: map[string]ingest.ObjectRecord{}}
}

func (d *dirStore) path(key string) string { return filepath.Join(d.root, filepath.FromSlash(key)) }

func (d *dirStore) Put(ctx context.Context, key string, r io.Reader) (ingest.ObjectRecord, error) {
	p := d.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return ingest.ObjectRecord{}, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return ingest.ObjectRecord{}, err
	}
	h := sha256.New()
	var n int64
	buf := make([]byte, 64<<10)
	for {
		m, rerr := r.Read(buf)
		if m > 0 {
			d.firstOnce.Do(func() { close(d.first) })
			_, _ = h.Write(buf[:m])
			if _, err := f.Write(buf[:m]); err != nil {
				rerr = err
			}
			n += int64(m)
			if d.bytesPerSecond > 0 {
				select {
				case <-time.After(time.Duration(float64(m) / d.bytesPerSecond * float64(time.Second))):
				case <-ctx.Done():
					rerr = ctx.Err()
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			_ = f.Close()
			_ = os.Remove(p)
			return ingest.ObjectRecord{}, rerr
		}
	}
	if err := f.Close(); err != nil {
		return ingest.ObjectRecord{}, err
	}
	rec := ingest.ObjectRecord{Key: key, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
	d.mu.Lock()
	d.recs[key] = rec
	d.mu.Unlock()
	return rec, nil
}

func (d *dirStore) Open(_ context.Context, key string) (io.ReadCloser, ingest.ObjectRecord, error) {
	d.mu.Lock()
	rec, ok := d.recs[key]
	d.mu.Unlock()
	if !ok {
		return nil, ingest.ObjectRecord{}, fmt.Errorf("%s: %w", key, fs.ErrNotExist)
	}
	f, err := os.Open(d.path(key))
	if err != nil {
		return nil, ingest.ObjectRecord{}, err
	}
	return f, rec, nil
}

func (d *dirStore) List(_ context.Context, prefix string) ([]ingest.ObjectRecord, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []ingest.ObjectRecord
	for k, rec := range d.recs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, rec)
		}
	}
	return out, nil
}
