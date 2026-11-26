package clickhouse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// TestRestoreNativeAgainstIngest (task 17) restores a native chain (a full
// and an incremental on it) of the spike schema, plus a ReplicatedMergeTree
// table, into a new ClickHouse that shares the source's Keeper, on 24.8 and
// 25.8 in Docker, through a real ingest handler on the host whose session
// serves the chain from a directory with the restore's own source
// (backup.NativeRestoreSource). Skipped without Docker or the dev Postgres,
// unless OLYMPOS_REQUIRE_DOCKER=1.
//
// Per version: the restore is RESTORED, every allowed table has the
// backup's rows and the source's content, the materialized view keeps
// feeding its table, a dictionary whose source names no DB reads its own
// database, the Replicated table is on its own Keeper path with a UUID of
// its own and the source keeps one replica, and what the allowlist leaves
// out is not created and is listed; a key the manifests do not list is
// 403; one byte changed in an object aborts its GET and fails the restore,
// and the source names the object; a stop or a cancel KILLs the RESTORE.
//
// The attacks of the security review v0.4, each refused or detected: a view
// joining a table after SAMPLE … OFFSET, or reading one through in() (2, 3),
// is left out; a key of a database left unselected is 403 (5); a .backup that
// lists a holder of a definition's size and checksum first is refused, and
// when RESTORE creates the holder anyway, the restore drops it and fails (1);
// a view reading a table without its database is left out, and RESTORE
// resolves such a name in the restored database, never in system (4).
// Whether ClickHouse sends a ranged GET is logged per version (the source
// refuses one).
func TestRestoreNativeAgainstIngest(t *testing.T) {
	requireDocker(t)
	db := testutil.DB(t)
	for _, img := range captureImages {
		t.Run(img.ver, func(t *testing.T) {
			t.Parallel() // each version has its own containers, Keeper and handler
			testRestoreNative(t, db, img.image, img.server)
		})
	}
}

// restoreSchema is added to the spike schema: a Replicated table, a
// dictionary whose source names no DB, a Memory table, two objects the
// allowlist leaves out (a URL table, and a table over a table function,
// which the manifest lists as "other"), two views on the database other,
// which is not backed up (findings 2 and 3 of the security review v0.4),
// spike.users, named like a table of system, and a table and a view that
// call encrypt and decrypt, whose secret arguments ClickHouse hides in
// system.tables (fix round 1, C).
const restoreSchema = `
CREATE TABLE spike.rep (id UInt64, v String) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/spike_rep', '{replica}') ORDER BY id;
INSERT INTO spike.rep SELECT number, toString(number) FROM numbers(1000);
CREATE DICTIONARY spike.cdict (id UInt64, name String) PRIMARY KEY id
    SOURCE(CLICKHOUSE(TABLE 'countries' USER '` + nativeCHUser + `' PASSWORD '` + nativeCHPassword + `'))
    LIFETIME(0) LAYOUT(HASHED());
CREATE TABLE spike.mem (id UInt64) ENGINE = Memory;
INSERT INTO spike.mem SELECT number FROM numbers(7);
CREATE TABLE spike.ext (x UInt8) ENGINE = URL('http://example.invalid/x', 'CSV');
CREATE TABLE spike.nums AS numbers(5);
CREATE DATABASE other;
CREATE TABLE other.secret (id UInt64) ENGINE = MergeTree ORDER BY id;
CREATE TABLE other.ids (id UInt64) ENGINE = MergeTree ORDER BY id;
INSERT INTO other.secret VALUES (42);
CREATE TABLE spike.sampletab (id UInt64) ENGINE = MergeTree ORDER BY id SAMPLE BY id;
CREATE VIEW spike.sampled AS SELECT s.id FROM spike.sampletab AS s SAMPLE 1/2 OFFSET 1/2, other.secret AS o;
CREATE VIEW spike.inview AS SELECT id FROM spike.countries WHERE in(id, other.ids);
CREATE TABLE spike.users (name String) ENGINE = Log;
INSERT INTO spike.users VALUES ('harmless');
CREATE TABLE spike.enc (id UInt64, c String DEFAULT encrypt('aes-256-ofb', toString(id), '12345678901234567890123456789012')) ENGINE = Log;
INSERT INTO spike.enc (id) VALUES (1);
CREATE VIEW spike.decv AS SELECT id, decrypt('aes-256-ofb', c, '12345678901234567890123456789012') AS p FROM spike.enc;
`

// restoreHashed are the tables whose content is compared, with the query
// that reads it as one value.
var restoreHashed = map[string]string{
	"events":      "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.events",
	"rep":         "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.rep",
	"countries":   "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.countries",
	"applog":      "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.applog",
	"mem":         "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.mem",
	"added":       "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.added",
	"daily":       "SELECT toString(count()) || ':' || toString(sum(cityHash64(day, finalizeAggregation(users), finalizeAggregation(total)))) FROM spike.daily",
	"big_amounts": "SELECT toString(count()) || ':' || toString(sum(cityHash64(*))) FROM spike.big_amounts",
}

func testRestoreNative(t *testing.T, db *store.DB, image, wantServer string) {
	suffix := randHex(t, 4)
	network := "olympos-t17-net-" + suffix
	mustDocker(t, time.Minute, "network", "create", network)
	// Registered first: runs after the containers are removed.
	t.Cleanup(func() { _, _ = dockerT(t, time.Minute, "network", "rm", network) })
	srcName := "olympos-t17-src-" + suffix
	src := startNativeKeeperCH(t, image, wantServer, srcName, keeperXML, network)
	dst := startNativeKeeperCH(t, image, wantServer, "olympos-t17-dst-"+suffix, sharedKeeperXML(srcName), network)

	src.query(t, captureSchema)
	src.query(t, nativeBigSchema)
	src.query(t, restoreSchema)
	srcUUID := src.query(t, "SELECT toString(uuid) FROM system.tables WHERE database = 'spike' AND name = 'rep'")

	// The chain: a full and an incremental on it, through one endpoint.
	in := newIngest(t, db)
	st := newDirStore(t, 0)
	full := in.open(t, st, nil)
	if _, err := runNative(t, src, full, nil, "spike", "big"); err != nil {
		t.Fatalf("full backup: %v", err)
	}
	full.s.Revoke("run ended")
	src.query(t, captureChange)
	inc := in.openWith(t, st, wholeStore{st}, []string{full.id + "/"})
	incBase := &NativeBase{URL: in.url + "/olympos/" + full.id + "/", RunID: full.id}
	if _, err := runNative(t, src, inc, incBase, "spike", "big"); err != nil {
		t.Fatalf("incremental backup: %v", err)
	}
	inc.s.Revoke("run ended")

	body := func(s *ingest.Session) func(string) ([]byte, bool) {
		return func(key string) ([]byte, bool) {
			if b, ok := s.Captured(key); ok {
				return b, true
			}
			b, err := os.ReadFile(st.path(key))
			return b, err == nil
		}
	}
	mFull, err := BuildNativeManifest(NativeBuild{RunID: full.id, ServerVersion: wantServer, Settings: statementSettings(full.id, false, ""),
		Objects: full.s.Objects(), Body: body(full.s)})
	if err != nil {
		t.Fatalf("manifest of the full: %v", err)
	}
	mInc, err := BuildNativeManifest(NativeBuild{RunID: inc.id, ServerVersion: wantServer, Settings: statementSettings(inc.id, false, incBase.URL),
		Objects: inc.s.Objects(), Body: body(inc.s), Base: []*NativeManifest{mFull}, BaseURL: incBase.URL})
	if err != nil {
		t.Fatalf("manifest of the incremental: %v", err)
	}
	kv := newFakeVault()
	signed := [][]byte{signedJSON(t, kv, testManifestKey, mFull), signedJSON(t, kv, testManifestKey, mInc)}
	chainSHA := []string{mFull.SHA256(), mInc.SHA256()}

	// chain is a chain to restore: its last run, each run's directory in st,
	// the signed manifests and the last one's SHA-256.
	type chain struct {
		last   string
		dirs   []string
		signed [][]byte
		sha    string
	}
	honest := chain{inc.id, []string{full.id, inc.id}, signed, chainSHA[1]}
	// checkOf is the restore check of ch for databases, as the executor runs
	// it: the chain verified and read whole for the check (whole), then
	// what the restore reads (NativeServed: served, or why not).
	checkOf := func(t *testing.T, ch chain, databases ...string) (*backup.NativeRestoreCheck, *backup.NativeRestoreSource, map[string]bool, error) {
		t.Helper()
		var whole *backup.NativeRestoreSource
		c, err := Engine{}.CheckNativeRestore(context.Background(), backup.NativeRestoreInput{KV: kv, KeyName: testManifestKey,
			RunID: ch.last, SHA256: ch.sha, Signed: ch.signed, IngestURL: in.url, Databases: databases,
			Bind: func(ms []backup.NativeChainManifest) (backup.NativeObjectReader, error) {
				var err error
				whole, err = backup.NewNativeRestoreSource(dirReader{st.root}, ms, ch.dirs, everyObject(ms), slog.Default())
				return readWhole(whole), err
			}})
		if err != nil {
			t.Fatalf("check: %v", err)
		}
		served, err := Engine{}.NativeServed(context.Background(), readWhole(whole), c.Manifests, databases, c.Objects)
		return c, whole, served, err
	}
	// check is checkOf the incremental, served by a restore source of what
	// the restore reads only.
	check := func(t *testing.T, databases ...string) (*backup.NativeRestoreCheck, *backup.NativeRestoreSource) {
		t.Helper()
		c, _, served, err := checkOf(t, honest, databases...)
		if err != nil {
			t.Fatalf("what the restore reads: %v", err)
		}
		rs, err := backup.NewNativeRestoreSource(dirReader{st.root}, c.Manifests, honest.dirs, served, slog.Default())
		if err != nil {
			t.Fatalf("the restore source: %v", err)
		}
		return c, rs
	}
	// restoreOf runs RestoreNative of the check c of ch into dst, with a
	// read-only session over the chain served by src; the request id is new.
	type restored struct {
		id   string
		res  *backup.RestoreResult
		err  error
		sess *ingest.Session
		cred ingest.Credential
		from int // the recorder's first request of this restore
	}
	restoreOf := func(t *testing.T, ctx context.Context, ch chain, c *backup.NativeRestoreCheck, src ingest.Source, during func(*ingest.Session),
		databases ...string) restored {
		t.Helper()
		r := restored{id: uuid.NewString(), from: len(in.rec.all())}
		var scope []string
		for _, d := range ch.dirs {
			scope = append(scope, d+"/")
		}
		s, cred, err := in.reg.Open(context.Background(), ingest.OpenOptions{RunID: uuid.MustParse(r.id), Kind: ingest.KindRestore,
			Scope: ingest.Scope{Read: scope}, TTL: time.Hour, Source: src})
		if err != nil {
			t.Fatalf("open the restore session: %v", err)
		}
		r.sess, r.cred = s, cred
		t.Cleanup(func() { s.Revoke("test ended") })
		nr := NativeRestore{URL: in.url + "/olympos/" + ch.last + "/", RunID: ch.last, AccessKey: cred.AccessKey, Secret: cred.Secret,
			DDL: c.DDL, Rows: c.Rows, Definitions: c.Definitions, Stop: s.Stopped()}
		for _, d := range c.Objects {
			nr.Decisions = append(nr.Decisions, Decision(d))
		}
		if during != nil {
			go during(s)
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		r.res, r.err = Engine{}.RestoreNative(ctx, backup.RestoreContext{EngineContext: dst.ec(), RequestID: r.id, Databases: databases}, nr)
		return r
	}
	restore := func(t *testing.T, ctx context.Context, c *backup.NativeRestoreCheck, src ingest.Source, during func(*ingest.Session), databases ...string) restored {
		t.Helper()
		return restoreOf(t, ctx, honest, c, src, during, databases...)
	}
	// ranged counts the GETs of a restore and those with a Range.
	ranged := func(r restored) (gets, withRange int, other string) {
		kinds := map[string]int{}
		for _, q := range in.rec.all()[r.from:] {
			kinds[fmt.Sprintf("%s ?%s %d", q.method, q.params, q.status)]++
			if q.method == http.MethodGet && q.params == "" {
				gets++
				if q.rng != "" {
					withRange++
				}
			}
		}
		return gets, withRange, fmt.Sprint(kinds)
	}

	t.Run("restores", func(t *testing.T) {
		c, rs := check(t, "spike")
		left := map[string]string{}
		for _, d := range c.Objects {
			if !d.Allowed {
				left[d.Name] = d.Reason
			}
		}
		if left["ext"] == "" || left["nums"] == "" || len(c.DDL) != 1 || c.DDL[restoreKey("spike", "rep")] == nil {
			t.Fatalf("the check: left out %v, DDL %d", left, len(c.DDL))
		}
		r := restore(t, context.Background(), c, rs, nil, "spike")
		gets, withRange, kinds := ranged(r)
		t.Logf("ClickHouse %s: the restore sent %d GetObjects, %d with a Range; requests %s", wantServer, gets, withRange, kinds)
		if r.err != nil {
			t.Fatalf("RestoreNative: %v\nsystem.backups: %s", r.err, dst.backupError(t, r.id))
		}
		if withRange > 0 {
			t.Errorf("ClickHouse %s sent %d ranged GETs, which the source refuses", wantServer, withRange)
		}
		if st := dst.query(t, "SELECT status FROM system.backups WHERE id = "+quoteString(r.id)); st != statusRestored {
			t.Fatalf("system.backups: %s", st)
		}
		if len(r.res.Items) != 1 || r.res.Items[0].Status != "succeeded" || !slices.Equal(r.res.Created, []string{"spike"}) {
			t.Fatalf("result: %+v", r.res)
		}
		skipped := strings.Join(r.res.Items[0].Skipped, "\n")
		// Findings 2 and 3 of the security review v0.4: a table joined after
		// SAMPLE … OFFSET and the table of in() are read, and they are not in
		// the backup.
		for name, want := range map[string]string{"sampled": "it reads other.secret, which is not in the backup",
			"inview": "it reads other.ids, which is not in the backup"} {
			if left[name] != want {
				t.Errorf("%s: left out %q, want %q", name, left[name], want)
			}
		}
		// Honest objects that call encrypt and decrypt are restored, as
		// approved, though the target hides their secret arguments.
		for _, name := range []string{"enc", "decv"} {
			if _, out := left[name]; out {
				t.Errorf("%s is left out: %s", name, left[name])
			}
		}
		if got := dst.query(t, "SELECT p FROM spike.decv WHERE id = 1"); got != "1" {
			t.Errorf("spike.decv on the target: %q", got)
		}
		for _, name := range []string{"ext", "nums", "sampled", "inview"} {
			if !strings.Contains(skipped, name+": "+left[name]) {
				t.Errorf("%s is not listed as left out: %q", name, skipped)
			}
			if n := dst.query(t, "SELECT count() FROM system.tables WHERE database = 'spike' AND name = "+quoteString(name)); n != "0" {
				t.Errorf("%s, left out, was created", name)
			}
		}
		for name, q := range restoreHashed {
			if a, b := src.query(t, q), dst.query(t, q); a != b {
				t.Errorf("%s: the source has %s, the restore %s", name, a, b)
			}
		}
		// What the target holds is what was decided (RestoreNative checked it;
		// here against the real system.tables, with the materialized view's
		// inner table and the dictionary), and an object no one decided is
		// named.
		var decisions []Decision
		for _, d := range c.Objects {
			decisions = append(decisions, Decision(d))
		}
		plan, err := planNativeRestore(r.id, []string{"spike"}, NativeRestore{Decisions: decisions, DDL: c.DDL, Rows: c.Rows, Definitions: c.Definitions})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		sess, err := connect(ctx, dst.ec(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer sess.close()
		if err := sess.checkRestoredObjects(ctx, slog.Default(), plan, false); err != nil {
			t.Fatalf("the restored objects: %v", err)
		}
		dst.query(t, "CREATE TABLE spike.surprise (x UInt8) ENGINE = Log")
		if err := sess.checkRestoredObjects(ctx, slog.Default(), plan, false); err == nil || !strings.Contains(err.Error(), "spike.surprise is not an object the restore was to create") {
			t.Fatalf("an object no one decided: %v", err)
		}
		dst.query(t, "DROP TABLE spike.surprise SYNC")

		// The RESTORE ran in the restored database (finding 4), not system.
		dst.query(t, "SYSTEM FLUSH LOGS")
		if got := dst.query(t, "SELECT DISTINCT current_database FROM system.query_log WHERE query_id = "+
			quoteString(backup.NativeRestoreQueryID(r.id))); got != "spike" {
			t.Errorf("the RESTORE's database: %q", got)
		}

		// The Replicated table: its own Keeper path and UUID; the source keeps
		// its one replica.
		if got := dst.query(t, "SELECT zookeeper_path FROM system.replicas WHERE database = 'spike' AND table = 'rep'"); got != keeperPath(r.id, "spike", "rep") {
			t.Fatalf("the restored rep's Keeper path: %s", got)
		}
		if got := dst.query(t, "SELECT toString(uuid) FROM system.tables WHERE database = 'spike' AND name = 'rep'"); got == srcUUID {
			t.Fatalf("the restored rep kept the backup's UUID %s", got)
		}
		if got := src.query(t, "SELECT total_replicas FROM system.replicas WHERE database = 'spike' AND table = 'rep'"); got != "1" {
			t.Fatalf("the source's total_replicas: %s", got)
		}
		// The dictionary reads its own database's table.
		if got := dst.query(t, "SELECT dictGet('spike.cdict', 'name', toUInt64(2))"); got != "Netherlands" {
			t.Fatalf("the dictionary: %q", got)
		}
		// The materialized view keeps feeding its table.
		dst.query(t, "INSERT INTO spike.events (id, ts, user_id, amount) VALUES (999999, toDateTime('2027-01-01 00:00:00'), 7, 950)")
		if got := dst.query(t, "SELECT toString(finalizeAggregation(total)) FROM spike.daily WHERE day = '2027-01-01'") +
			"," + dst.query(t, "SELECT count() FROM spike.big_amounts WHERE id = 999999"); got != "950,1" {
			t.Fatalf("the materialized views after an insert: %s", got)
		}
		// A key in the scope that the manifests do not list is refused.
		if code := in.signed(t, r.cred, http.MethodGet, "/olympos/"+full.id+"/data/spike/events/nope.bin"); code != http.StatusForbidden {
			t.Fatalf("a key the manifests do not list: %d", code)
		}
		// So is a key of the database left unselected (security review v0.4,
		// finding 5): the target holds the credential, and reads only what
		// the restore restores. (A small file of big whose bytes a file of
		// spike has, a part's metadata_version.txt, is served: ClickHouse
		// reads spike's from it, by size and checksum.)
		var bigData string
		for _, o := range mFull.Objects {
			if strings.HasPrefix(o.Key, full.id+"/data/big/") && o.Size > 1<<20 {
				bigData = o.Key
				break
			}
		}
		if bigData == "" {
			t.Fatal("no data of big in the full")
		}
		// And the definition of an object left out, which can hold an
		// external source's credentials (fix round 1, B).
		for _, key := range []string{bigData, full.id + "/metadata/big.sql", full.id + "/metadata/big/blob.sql", full.id + "/metadata/spike/ext.sql",
			full.id + "/metadata/spike/sampled.sql"} {
			if code := in.signed(t, r.cred, http.MethodGet, "/olympos/"+key); code != http.StatusForbidden {
				t.Errorf("%s, of a database not selected: %d", key, code)
			}
		}
		for _, key := range []string{inc.id + "/metadata/spike/events.sql", full.id + "/metadata/spike.sql"} {
			if code := in.signed(t, r.cred, http.MethodGet, "/olympos/"+key); code != http.StatusOK {
				t.Errorf("%s, which the restore reads: %d", key, code)
			}
		}
		r.sess.Revoke("restore ended")
	})

	// drop removes what a restore left on dst, so the next one finds it new.
	// It first waits until no RESTORE of an earlier subtest still runs (a
	// KILLed one can take a moment to end its threads).
	drop := func(t *testing.T) {
		t.Helper()
		retry(t, time.Minute, "no restore running on the target", func() (string, error) {
			n := dst.query(t, "SELECT (SELECT count() FROM system.processes WHERE startsWith(query_id, 'olympos-restore-')) + "+
				"(SELECT count() FROM system.backups WHERE status = 'RESTORING')")
			if n != "0" {
				return n, errors.New("a restore still runs")
			}
			return "", nil
		})
		dst.query(t, "DROP DATABASE IF EXISTS spike SYNC; DROP DATABASE IF EXISTS big SYNC")
	}

	// forge copies the full run to a new run, as a compromised source would
	// write it: edit changes its .backup and may add files (add). It returns
	// the new run, the objects stored, and its bodies.
	forge := func(t *testing.T, edit func(meta string, add func(name string, body []byte)) string) (string, []ingest.ObjectRecord, func(string) ([]byte, bool)) {
		t.Helper()
		id := uuid.NewString()
		from, to := st.path(full.id), st.path(id)
		if err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out := filepath.Join(to, strings.TrimPrefix(p, from))
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			return os.WriteFile(out, b, 0o644)
		}); err != nil {
			t.Fatal(err)
		}
		records := map[string]ingest.ObjectRecord{}
		for _, o := range full.s.Objects() {
			o.Key = id + strings.TrimPrefix(o.Key, full.id)
			records[o.Key] = o
		}
		write := func(name string, body []byte) {
			if err := os.MkdirAll(filepath.Dir(st.path(id+"/"+name)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(st.path(id+"/"+name), body, 0o644); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(body)
			records[id+"/"+name] = ingest.ObjectRecord{Key: id + "/" + name, Size: int64(len(body)), SHA256: hex.EncodeToString(h[:])}
		}
		meta, err := os.ReadFile(st.path(id + "/.backup"))
		if err != nil {
			t.Fatal(err)
		}
		write(".backup", []byte(edit(string(meta), write)))
		var objs []ingest.ObjectRecord
		for _, o := range records {
			objs = append(objs, o)
		}
		return id, objs, func(key string) ([]byte, bool) {
			b, err := os.ReadFile(st.path(key))
			return b, err == nil
		}
	}
	// signedAs is mFull's manifest as run id's, with objs as its objects,
	// signed: what a server that did not check the run would have signed.
	signedAs := func(t *testing.T, id string, objs []ingest.ObjectRecord) chain {
		t.Helper()
		m := mFull.clone()
		m.RunID, m.Objects = id, objs
		for i := range m.Databases {
			for j := range m.Databases[i].Objects {
				o := &m.Databases[i].Objects[j]
				o.DDLKey = id + strings.TrimPrefix(o.DDLKey, full.id)
			}
		}
		return chain{id, []string{id}, [][]byte{signedJSON(t, kv, testManifestKey, m)}, m.SHA256()}
	}
	readsSystem := func(t *testing.T) string {
		t.Helper()
		return dst.query(t, "SELECT count() FROM system.tables WHERE database = 'spike' AND create_table_query LIKE '%system.users%'")
	}

	// Finding 1: a .backup that lists a holder with the size and checksum of
	// spike.recent's definition first, holding a view on system.users.
	t.Run("a holder of a definition's size and checksum", func(t *testing.T) {
		drop(t)
		meta, err := os.ReadFile(st.path(full.id + "/.backup"))
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`<file><name>metadata/spike/recent\.sql</name><size>(\d+)</size><checksum>([0-9a-f]{32})</checksum>`).FindStringSubmatch(string(meta))
		if m == nil {
			t.Fatal("no metadata/spike/recent.sql in the full's .backup")
		}
		size, _ := strconv.Atoi(m[1])
		head := "CREATE VIEW spike.recent (`id` UInt64, `ts` DateTime, `amount` Float64) AS SELECT toUInt64(0) AS id, now() AS ts, " +
			"toFloat64(length(name)) AS amount FROM system.users WHERE name != '"
		if size < len(head)+1 {
			t.Fatalf("spike.recent's definition is %d bytes, too short for the holder", size)
		}
		hostile := head + strings.Repeat("x", size-len(head)-1) + "'"
		id, objs, body := forge(t, func(meta string, add func(string, []byte)) string {
			add("zz/holder", []byte(hostile))
			return strings.Replace(meta, "<contents>", "<contents><file><name>zz/holder</name><size>"+m[1]+"</size><checksum>"+m[2]+"</checksum></file>", 1)
		})
		// The run's manifest is refused.
		if _, err := BuildNativeManifest(NativeBuild{RunID: id, ServerVersion: wantServer, Settings: statementSettings(id, false, ""),
			Objects: objs, Body: body}); !errors.Is(err, ErrNativeMeta) ||
			!strings.Contains(err.Error(), `"metadata/spike/recent.sql": ClickHouse reads its size and checksum from "zz/holder"`) {
			t.Fatalf("the manifest of the forged run: %v", err)
		}
		// Signed anyway: the check allows spike.recent from its own file, and
		// the restore does not serve the .backup's files.
		ch := signedAs(t, id, objs)
		c, whole, _, err := checkOf(t, ch, "spike")
		if !errors.Is(err, backup.ErrNativeChain) || !strings.Contains(err.Error(), "zz/holder") {
			t.Fatalf("what the restore of the forged run reads: %v", err)
		}
		if d := decisionOf(t, decisionsOf(c), "spike", "recent"); !d.Allowed {
			t.Fatalf("spike.recent: %+v", d)
		}
		// Served whole anyway: RESTORE creates spike.recent from the holder,
		// and the restore drops it and fails, naming it.
		r := restoreOf(t, context.Background(), ch, c, whole, nil, "spike")
		if r.err == nil || !strings.Contains(r.err.Error(), "spike.recent is not what was approved (its definition is not the approved one); it was dropped") {
			t.Fatalf("RestoreNative of the holder: %v", r.err)
		}
		if n := dst.query(t, "SELECT count() FROM system.tables WHERE database = 'spike' AND name = 'recent'"); n != "0" || readsSystem(t) != "0" {
			t.Fatalf("after the restore: spike.recent %s, objects reading system.users %s", n, readsSystem(t))
		}
		t.Logf("ClickHouse %s, a holder of spike.recent: %v", wantServer, r.err)
		r.sess.Revoke("restore ended")
	})

	// Finding 4: a view of the backup that reads users without its database.
	t.Run("an unqualified name", func(t *testing.T) {
		drop(t)
		unq := []byte("CREATE VIEW spike.unq (`name` String) AS SELECT name FROM users")
		id, objs, body := forge(t, func(meta string, add func(string, []byte)) string {
			add("metadata/spike/unq.sql", unq)
			return strings.Replace(meta, "</contents>", fmt.Sprintf("<file><name>metadata/spike/unq.sql</name><size>%d</size>"+
				"<checksum>0123456789abcdef0123456789abcdef</checksum></file></contents>", len(unq)), 1)
		})
		m, err := BuildNativeManifest(NativeBuild{RunID: id, ServerVersion: wantServer, Settings: statementSettings(id, false, ""),
			Objects: objs, Body: body})
		if err != nil {
			t.Fatalf("the manifest of the run: %v", err)
		}
		ch := chain{id, []string{id}, [][]byte{signedJSON(t, kv, testManifestKey, m)}, m.SHA256()}
		c, whole, served, err := checkOf(t, ch, "spike")
		if err != nil {
			t.Fatal(err)
		}
		if d := decisionOf(t, decisionsOf(c), "spike", "unq"); d.Allowed || d.Reason != "it reads users without naming its database" {
			t.Fatalf("spike.unq: %+v", d)
		}
		rs, err := backup.NewNativeRestoreSource(dirReader{st.root}, c.Manifests, ch.dirs, served, slog.Default())
		if err != nil {
			t.Fatal(err)
		}
		r := restoreOf(t, context.Background(), ch, c, rs, nil, "spike")
		if r.err != nil {
			t.Fatalf("RestoreNative: %v", r.err)
		}
		if n := dst.query(t, "SELECT count() FROM system.tables WHERE database = 'spike' AND name = 'unq'"); n != "0" {
			t.Fatal("spike.unq, left out, was created")
		}
		r.sess.Revoke("restore ended")

		// Allowed anyway (an allowlist that missed it): RESTORE, in the
		// restored database, resolves users there, never in system, and the
		// restore fails: the view it made is not the approved one (it names
		// spike.users), so it is dropped.
		drop(t)
		for i, d := range c.Objects {
			if d.Name == "unq" {
				c.Objects[i].Allowed, c.Objects[i].Reason = true, ""
			}
		}
		c.Definitions[restoreKey("spike", "unq")] = unq
		r = restoreOf(t, context.Background(), ch, c, whole, nil, "spike")
		n := dst.query(t, "SELECT count() FROM system.tables WHERE database = 'spike' AND name = 'unq'")
		if r.err == nil || !strings.Contains(r.err.Error(), "spike.unq is not what was approved") || n != "0" || readsSystem(t) != "0" {
			t.Fatalf("RestoreNative of an unqualified view allowed: %v; spike.unq %s, objects reading system.users %s", r.err, n, readsSystem(t))
		}
		t.Logf("ClickHouse %s, an unqualified view allowed: %v", wantServer, r.err)
		r.sess.Revoke("restore ended")
	})

	t.Run("one byte changed", func(t *testing.T) {
		drop(t)
		c, rs := check(t, "spike")
		// A data file of the full's events, changed in storage after the check.
		var key string
		for _, o := range mFull.Objects {
			if strings.HasPrefix(o.Key, full.id+"/data/spike/events/") && strings.HasSuffix(o.Key, ".bin") && o.Size > 1024 {
				key = o.Key
				break
			}
		}
		if key == "" {
			t.Fatal("no data file of events in the full")
		}
		path := st.path(key)
		orig, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := append([]byte(nil), orig...)
		changed[len(changed)/2] ^= 0xff
		if err := os.WriteFile(path, changed, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(path, orig, 0o644) })
		r := restore(t, context.Background(), c, rs, nil, "spike")
		if r.err == nil {
			t.Fatal("a restore of a changed object succeeded")
		}
		if rs.Failed() != key {
			t.Fatalf("the source names %q, want %s", rs.Failed(), key)
		}
		if st := dst.query(t, "SELECT status FROM system.backups WHERE id = "+quoteString(r.id)); st == statusRestored || st == statusRestoring {
			t.Fatalf("system.backups: %s", st)
		}
		if !strings.Contains(in.logs.String(), `"status":"aborted"`) {
			t.Fatal("the GET of the changed object was not aborted")
		}
		t.Logf("ClickHouse %s, one byte changed in %s: %v", wantServer, strings.TrimPrefix(key, full.id+"/"), r.err)
		r.sess.Revoke("restore ended")
	})

	// A table whose restored rows are not the backup's fails the restore,
	// named; the other tables are as restored.
	t.Run("count mismatch", func(t *testing.T) {
		drop(t)
		c, rs := check(t, "spike")
		c.Rows[restoreKey("spike", "countries")]++
		r := restore(t, context.Background(), c, rs, nil, "spike")
		if r.err == nil || !strings.Contains(r.err.Error(), "spike.countries has 3 rows, the backup 4") {
			t.Fatalf("a row count that differs: %v", r.err)
		}
		if len(r.res.Items) != 1 || r.res.Items[0].Status != "failed" || !slices.Equal(r.res.Created, []string{"spike"}) {
			t.Fatalf("result: %+v", r.res)
		}
		r.sess.Revoke("restore ended")
	})

	// A stop or a cancel while the RESTORE runs KILLs it; the source is slow
	// so the RESTORE is still running.
	for _, how := range []string{"stop", "cancel"} {
		t.Run(how+" kills", func(t *testing.T) {
			drop(t)
			c, rs := check(t, "big")
			slow := &slowSource{Source: rs, delay: 300 * time.Millisecond, first: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			during := func(s *ingest.Session) {
				select {
				case <-slow.first:
				case <-time.After(2 * time.Minute):
					return
				}
				if how == "stop" {
					s.Stop("test stop")
				} else {
					cancel()
				}
			}
			r := restore(t, ctx, c, slow, during, "big")
			if r.err == nil || !strings.Contains(r.err.Error(), "KILL QUERY made it") || errors.Is(r.err, backup.ErrNativeOrphan) {
				t.Fatalf("RestoreNative after a %s: %v", how, r.err)
			}
			if st := dst.query(t, "SELECT status FROM system.backups WHERE id = "+quoteString(r.id)); st != statusRestoreFailed && st != statusRestoreCancelled {
				t.Fatalf("system.backups: %s", st)
			}
			retry(t, 15*time.Second, "the KILLed RESTORE gone from system.processes", func() (string, error) {
				if n := dst.query(t, "SELECT count() FROM system.processes WHERE query_id = "+quoteString(backup.NativeRestoreQueryID(r.id))); n != "0" {
					return n, errors.New("the RESTORE still runs")
				}
				return "", nil
			})
			t.Logf("ClickHouse %s, %s: %v", wantServer, how, r.err)

			r.sess.Revoke("restore ended")
		})
	}
}

// startNativeKeeperCH starts a ClickHouse of image with xml in config.d, on
// network, as startNativeClickHouse does (the native test's user, the host
// reachable as host.docker.internal), and waits until it reaches its Keeper.
func startNativeKeeperCH(t *testing.T, image, wantServer, name, xml, network string) *nativeCH {
	t.Helper()
	pullMissing(t, image)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keeper.xml"), []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s3-retries.xml"), []byte(testS3Retries), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dockerT(t, time.Minute, "rm", "-f", "-v", name) })
	mustDocker(t, 2*time.Minute, "create", "--pull", "never", "--name", name, "--network", network,
		"--add-host", "host.docker.internal:host-gateway", "--ulimit", "nofile=262144:262144",
		"-e", "CLICKHOUSE_USER="+nativeCHUser, "-e", "CLICKHOUSE_PASSWORD="+nativeCHPassword,
		"-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1", "-p", "127.0.0.1::9000", image)
	mustDocker(t, time.Minute, "cp", filepath.Join(dir, "keeper.xml"), name+":/etc/clickhouse-server/config.d/keeper.xml")
	mustDocker(t, time.Minute, "cp", filepath.Join(dir, "s3-retries.xml"), name+":/etc/clickhouse-server/users.d/s3-retries.xml")
	mustDocker(t, time.Minute, "start", name)
	out := mustDocker(t, 30*time.Second, "port", name, "9000/tcp")
	c := &nativeCH{name: name, native: strings.Split(out, "\n")[0]}
	retry(t, 90*time.Second, "clickhouse with keeper ready", func() (string, error) {
		return dockerT(t, 30*time.Second, "exec", name, "clickhouse-client", "-u", nativeCHUser, "--password", nativeCHPassword,
			"-q", "SELECT count() FROM system.zookeeper WHERE path = '/'")
	})
	if v := c.query(t, "SELECT version()"); v != wantServer {
		t.Fatalf("%s is ClickHouse %s, not %s", image, v, wantServer)
	}
	return c
}

// testS3Retries lowers the test servers' S3 retries. A RESTORE retries a
// failed GET up to backup_restore_s3_retry_attempts (1000 on 24.8 and
// 25.8) times, with a backoff of up to 5 s on 25.8, and a thread in that
// loop can keep a KILLed RESTORE from ending within nativeKillWait (30 s)
// when the errors are retryable (a reset connection, 5xx). The endpoint
// answers 403 once a session is stopped, which ends the loop at once, so
// this only keeps a test from waiting on a slow host; production keeps the
// defaults and the 30 s wait.
const testS3Retries = `<clickhouse><profiles><default>
  <backup_restore_s3_retry_attempts>3</backup_restore_s3_retry_attempts>
  <s3_retry_attempts>3</s3_retry_attempts>
</default></profiles></clickhouse>`

// dirReader reads a dirStore's objects as a destination's blobs: path is
// "<run-id>/<key>", as the dirStore stores them.
type dirReader struct{ root string }

func (d dirReader) Open(ctx context.Context, path string) (blob.Object, error) {
	// A destination's reader honours the request's context, as this one.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(d.root, filepath.FromSlash(path)))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return fileObject{f, fi.Size()}, nil
}

type fileObject struct {
	*os.File
	size int64
}

func (f fileObject) Size() int64 { return f.size }

// decisionsOf is the check's decisions as the engine's.
func decisionsOf(c *backup.NativeRestoreCheck) []Decision {
	out := make([]Decision, len(c.Objects))
	for i, d := range c.Objects {
		out[i] = Decision(d)
	}
	return out
}

// everyObject is the set of every object of ms: a source that serves the
// whole chain, as the check's reader.
func everyObject(ms []backup.NativeChainManifest) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		for _, o := range m.Objects {
			out[o.Key] = true
		}
	}
	return out
}

// readWhole is a NativeObjectReader over src.
func readWhole(src ingest.Source) backup.NativeObjectReader {
	return func(ctx context.Context, key string, limit int64) ([]byte, error) {
		rc, rec, err := src.Open(ctx, key)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		if rec.Size > limit {
			return nil, fmt.Errorf("%s is %d bytes, over %d", key, rec.Size, limit)
		}
		return io.ReadAll(rc)
	}
}

// slowSource delays every Open, so a RESTORE runs long enough to be ended;
// first is closed at the first Open. It serves whole objects, as the
// source it wraps.
type slowSource struct {
	ingest.Source
	delay time.Duration
	first chan struct{}
	once  sync.Once
}

func (s *slowSource) WholeObjects() {}

func (s *slowSource) Open(ctx context.Context, key string) (io.ReadCloser, ingest.ObjectRecord, error) {
	s.once.Do(func() { close(s.first) })
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ingest.ObjectRecord{}, ctx.Err()
	}
	return s.Source.Open(ctx, key)
}
