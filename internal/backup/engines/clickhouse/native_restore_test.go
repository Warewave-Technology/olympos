package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// The restore check of a native backup (design docs/design/clickhouse-native.md
// §6, task 16): the copy's chain verifies, the DDL of every object is read
// from the chain through a checked reader, and the allowlist decides for the
// selected databases only, with the Replicated rewrite run at check time.

const (
	nrFull        = "a0000000-0000-4000-8000-000000000001"
	nrInc         = "a0000000-0000-4000-8000-000000000002"
	nrURL         = "https://ingest.olympos.test:9444"
	nrManifestKey = "olympos-manifest"
)

// nrObj is an object of a fixture run: a metadata/*.sql (an object of a
// database) when db is set.
type nrObj struct {
	db, name, kind, ddl string
}

// nrChain builds and signs a chain of fixture runs, the full first; inc
// holds the objects of an incremental on it (nil: a full only). An
// incremental reuses the full's DDL of every object it does not list
// again, as ClickHouse does for unchanged metadata.
type nrChain struct {
	kv     *fakeVault
	signed [][]byte
	runs   []string
	sums   []string          // each run's manifest SHA-256, as its copy row records it
	bodies map[string][]byte // by bucket-relative key
	bound  [][]backup.NativeChainManifest
	// dbDDL are the databases' own definitions the full writes (Atomic
	// when not set).
	dbDDL map[string]string
}

func nrDDLKey(run, db, name string) string {
	return run + "/metadata/" + escapeForFileName(db) + "/" + escapeForFileName(name) + ".sql"
}

func newNRChain(t *testing.T, full, inc []nrObj, baseURL string, dbDDL ...string) *nrChain {
	t.Helper()
	c := &nrChain{kv: newFakeVault(), bodies: map[string][]byte{}, dbDDL: map[string]string{}}
	for i := 0; i+1 < len(dbDDL); i += 2 {
		c.dbDDL[dbDDL[i]] = dbDDL[i+1]
	}
	m1 := c.manifest(full, nrFull, nil, "")
	c.sign(t, m1)
	if inc != nil {
		m2 := c.manifest(inc, nrInc, m1, baseURL)
		c.sign(t, m2)
	}
	return c
}

// manifest is the manifest of run with objs; on base, the objects of base
// that objs does not list are carried with the base's DDL key.
func (c *nrChain) manifest(objs []nrObj, run string, base *NativeManifest, baseURL string) *NativeManifest {
	m := &NativeManifest{Format: NativeManifestFormat, RunID: run, ServerVersion: "25.8.1.1",
		Settings: statementSettings(run, false, baseURL), PartRows: map[string]uint64{}}
	if base != nil {
		m.BaseRunID, m.BaseManifestSHA256 = base.RunID, base.SHA256()
	}
	add := func(key string, body []byte) {
		c.bodies[key] = body
		m.Objects = append(m.Objects, ingest.ObjectRecord{Key: key, Size: int64(len(body)), SHA256: sum(string(body))})
	}
	add(run+"/.backup", []byte("<config/>"))
	// A database's own definition is written by the full; an incremental
	// keeps it in its base, as ClickHouse does with unchanged metadata.
	if base == nil {
		dbs := map[string]bool{}
		for _, o := range objs {
			if !dbs[o.db] {
				dbs[o.db] = true
				ddl := c.dbDDL[o.db]
				if ddl == "" {
					ddl = "CREATE DATABASE " + o.db + " UUID '6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60' ENGINE = Atomic"
				}
				add(run+"/metadata/"+escapeForFileName(o.db)+".sql", []byte(ddl))
			}
		}
	}
	at := map[string]int{}
	listed := map[string]bool{}
	put := func(db string, o NativeObject) {
		i, ok := at[db]
		if !ok {
			i = len(m.Databases)
			at[db] = i
			m.Databases = append(m.Databases, NativeDatabase{Name: db})
		}
		m.Databases[i].Objects = append(m.Databases[i].Objects, o)
	}
	for _, o := range objs {
		key := nrDDLKey(run, o.db, o.name)
		add(key, []byte(o.ddl))
		put(o.db, NativeObject{Name: o.name, Kind: o.kind, DDLKey: key})
		listed[o.db+"."+o.name] = true
	}
	if base != nil {
		for _, d := range base.Databases {
			for _, o := range d.Objects {
				if !listed[d.Name+"."+o.Name] {
					put(d.Name, o)
				}
			}
		}
	}
	return m
}

func (c *nrChain) sign(t *testing.T, m *NativeManifest) {
	t.Helper()
	c.signed = append(c.signed, signedJSON(t, c.kv, nrManifestKey, m))
	c.runs = append(c.runs, m.RunID)
	c.sums = append(c.sums, m.SHA256())
}

// input is the check of the chain's last run for databases.
func (c *nrChain) input(databases ...string) backup.NativeRestoreInput {
	return backup.NativeRestoreInput{
		KV: c.kv, KeyName: nrManifestKey, RunID: c.runs[len(c.runs)-1], SHA256: c.sums[len(c.sums)-1], Signed: c.signed, IngestURL: nrURL, Databases: databases,
		Bind: func(ms []backup.NativeChainManifest) (backup.NativeObjectReader, error) {
			c.bound = append(c.bound, ms)
			listed := map[string]bool{}
			for _, m := range ms {
				for _, o := range m.Objects {
					listed[o.Key] = true
				}
			}
			return func(_ context.Context, key string, limit int64) ([]byte, error) {
				b, ok := c.bodies[key]
				if !listed[key] || !ok {
					return nil, fmt.Errorf("%s: %w", key, fs.ErrNotExist)
				}
				if int64(len(b)) > limit {
					return nil, fmt.Errorf("%s is over %d bytes", key, limit)
				}
				return b, nil
			}, nil
		},
	}
}

func nrDecisions(ds []backup.NativeDecision) []string {
	var out []string
	for _, d := range ds {
		s := d.Database + "." + d.Name + " " + d.Kind
		if d.Allowed {
			s += " allowed"
		} else {
			s += ": " + d.Reason
		}
		out = append(out, s)
	}
	return out
}

var nrSchema = []nrObj{
	{"shop", "orders", KindTable, "CREATE TABLE shop.orders (`id` UInt64) ENGINE = MergeTree ORDER BY id"},
	{"shop", "report", KindView, "CREATE VIEW shop.report (`id` UInt64) AS SELECT o.id FROM shop.orders AS o JOIN stats.daily AS d ON o.id = d.id"},
	{"stats", "daily", KindTable, "CREATE TABLE stats.daily (`id` UInt64) ENGINE = Log"},
	{"x", "live", KindOther, "CREATE LIVE VIEW x.live AS SELECT 1"},
}

// TestCheckNativeRestoreSelection: the decisions are for the selected
// databases only, and an object that reads a database left unselected is
// left out ("which is not restored"); an object of kind other is left out
// with its reason. Every database of the backup is listed.
func TestCheckNativeRestoreSelection(t *testing.T) {
	c := newNRChain(t, nrSchema, nil, "")
	got, err := Engine{}.CheckNativeRestore(context.Background(), c.input())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"shop", "stats", "x"}; !reflect.DeepEqual(got.Databases, want) {
		t.Fatalf("databases %v, want %v", got.Databases, want)
	}
	want := []string{"shop.orders table allowed", "shop.report view allowed", "stats.daily table allowed", "x.live other: a live view is not restored"}
	if d := nrDecisions(got.Objects); !reflect.DeepEqual(d, want) {
		t.Fatalf("all databases:\n got %q\nwant %q", d, want)
	}
	if len(got.Manifests) != 1 || got.Manifests[0].RunID != nrFull || len(c.bound) != 1 {
		t.Fatalf("manifests %+v, bound %d", got.Manifests, len(c.bound))
	}

	got, err = Engine{}.CheckNativeRestore(context.Background(), c.input("shop"))
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"shop.orders table allowed", "shop.report view: it reads stats.daily, which is not restored"}
	if d := nrDecisions(got.Objects); !reflect.DeepEqual(d, want) {
		t.Fatalf("shop only:\n got %q\nwant %q", d, want)
	}
	if !reflect.DeepEqual(got.Databases, []string{"shop", "stats", "x"}) {
		t.Fatalf("a selection lists every database of the backup: %v", got.Databases)
	}
}

// TestCheckNativeRestoreReplicatedRewrite: an allowed Replicated table whose
// Keeper path the rewrite refuses is left out at check time with the
// rewrite's reason, and so is what depends on it.
func TestCheckNativeRestoreReplicatedRewrite(t *testing.T) {
	c := newNRChain(t, []nrObj{
		{"shop", "good", KindTable, "CREATE TABLE shop.good (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/shop/good', '{replica}') ORDER BY id"},
		{"shop", "bad", KindTable, "CREATE TABLE shop.bad (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY id"},
		{"shop", "defaults", KindTable, "CREATE TABLE shop.defaults (`id` UInt64) ENGINE = ReplicatedMergeTree ORDER BY id"},
		{"shop", "to_bad", KindMaterializedView, "CREATE MATERIALIZED VIEW shop.to_bad TO shop.bad (`id` UInt64) AS SELECT id FROM shop.good"},
	}, nil, "")
	got, err := Engine{}.CheckNativeRestore(context.Background(), c.input())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"shop.bad table: its Replicated engine's Keeper path and replica could not be found exactly (its Keeper path holds {uuid})",
		"shop.defaults table: its Replicated engine's Keeper path and replica could not be found exactly (no Keeper path or replica (the server's defaults))",
		"shop.good table allowed",
		"shop.to_bad materialized_view: its target shop.bad is not restored",
	}
	if d := nrDecisions(got.Objects); !reflect.DeepEqual(d, want) {
		t.Fatalf("\n got %q\nwant %q", d, want)
	}
	// Task 17: the restore gets the definition of the allowed Replicated
	// table, which it creates itself, and the row count of every allowed
	// table; nothing of what is left out.
	key := restoreKey("shop", "good")
	if len(got.DDL) != 1 || !strings.Contains(string(got.DDL[key]), "/clickhouse/tables/shop/good") {
		t.Fatalf("DDL: %q", got.DDL)
	}
	if !reflect.DeepEqual(got.Rows, map[string]uint64{key: 0}) {
		t.Fatalf("rows: %v", got.Rows)
	}
}

// TestCheckNativeRestoreChain: an incremental's chain verifies, and the DDL
// it reuses is read from its base.
func TestCheckNativeRestoreChain(t *testing.T) {
	c := newNRChain(t, nrSchema[:3], []nrObj{
		{"shop", "orders", KindTable, "CREATE TABLE shop.orders (`id` UInt64, `n` UInt8) ENGINE = MergeTree ORDER BY id"},
	}, nrURL+"/olympos/"+nrFull+"/")
	in := c.input()
	in.IngestURL = nrURL + "/" // a trailing slash names the same endpoint
	got, err := Engine{}.CheckNativeRestore(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"shop.orders table allowed", "shop.report view allowed", "stats.daily table allowed"}
	if d := nrDecisions(got.Objects); !reflect.DeepEqual(d, want) {
		t.Fatalf("\n got %q\nwant %q", d, want)
	}
	if len(got.Manifests) != 2 || got.Manifests[0].RunID != nrFull || got.Manifests[1].RunID != nrInc {
		t.Fatalf("manifests %+v", got.Manifests)
	}
}

// TestCheckNativeRestoreNotVerified: a chain whose base manifest does not
// verify is refused (backup.ErrNativeNotVerified); the objects of the copy's
// own manifest, which verifies by itself, are listed, every one left out
// with "the backup's manifest does not verify", and nothing was read. A copy
// whose own manifest does not verify lists nothing.
func TestCheckNativeRestoreNotVerified(t *testing.T) {
	c := newNRChain(t, nrSchema[:3], []nrObj{nrSchema[0]}, nrURL+"/olympos/"+nrFull+"/")
	c.signed[0] = []byte(strings.Replace(string(c.signed[0]), `"server_version":"25.8.1.1"`, `"server_version":"25.8.1.2"`, 1))
	got, err := Engine{}.CheckNativeRestore(context.Background(), c.input("shop"))
	if !errors.Is(err, backup.ErrNativeNotVerified) || got == nil {
		t.Fatalf("a base that does not verify: %+v, %v", got, err)
	}
	want := []string{
		"shop.orders table: the backup's manifest does not verify",
		"shop.report view: the backup's manifest does not verify",
	}
	if d := nrDecisions(got.Objects); !reflect.DeepEqual(d, want) {
		t.Fatalf("\n got %q\nwant %q", d, want)
	}
	if len(c.bound) != 0 || got.Manifests != nil {
		t.Fatalf("an unverified chain was bound for reads: %d, %+v", len(c.bound), got.Manifests)
	}
	// The copy's manifest verifies alone but is not the one its copy row
	// records (a sidecar from elsewhere): nothing is listed.
	in := c.input("shop")
	in.SHA256 = sum("another manifest")
	got, err = Engine{}.CheckNativeRestore(context.Background(), in)
	if !errors.Is(err, backup.ErrNativeNotVerified) || got == nil || len(got.Objects) != 0 || len(got.Databases) != 0 {
		t.Fatalf("a copy row with another SHA-256: %+v, %v", got, err)
	}

	c = newNRChain(t, nrSchema[:3], nil, "")
	c.signed[0] = []byte(strings.Replace(string(c.signed[0]), `"server_version":"25.8.1.1"`, `"server_version":"25.8.1.2"`, 1))
	got, err = Engine{}.CheckNativeRestore(context.Background(), c.input())
	if !errors.Is(err, backup.ErrNativeNotVerified) || got == nil || len(got.Objects) != 0 || len(got.Databases) != 0 {
		t.Fatalf("a copy whose manifest does not verify: %+v, %v", got, err)
	}
}

// TestCheckNativeRestoreDDLUnreadable: a DDL object the checked reader
// refuses (changed in storage) refuses the check as not verified.
func TestCheckNativeRestoreDDLUnreadable(t *testing.T) {
	c := newNRChain(t, nrSchema[:1], nil, "")
	delete(c.bodies, nrDDLKey(nrFull, "shop", "orders"))
	if got, err := (Engine{}).CheckNativeRestore(context.Background(), c.input()); !errors.Is(err, backup.ErrNativeNotVerified) || got == nil || len(got.Objects) != 0 {
		t.Fatalf("an unreadable definition: %+v, %v", got, err)
	}
	c = newNRChain(t, nrSchema[:1], nil, "")
	in := c.input()
	in.Bind = func([]backup.NativeChainManifest) (backup.NativeObjectReader, error) {
		return nil, errors.New("the manifest of run x is not the one its copy was written with")
	}
	if _, err := (Engine{}).CheckNativeRestore(context.Background(), in); !errors.Is(err, backup.ErrNativeNotVerified) {
		t.Fatalf("a chain that cannot be bound: %v", err)
	}
}

// TestCheckNativeRestoreIngestURL: each .backup names its base by URL, so a
// chain taken through another ingest.url is refused (backup.ErrNativeChain):
// ClickHouse would read its base from the old endpoint.
func TestCheckNativeRestoreIngestURL(t *testing.T) {
	c := newNRChain(t, nrSchema[:1], []nrObj{nrSchema[0]}, "https://old-ingest.test:9444/olympos/"+nrFull+"/")
	got, err := Engine{}.CheckNativeRestore(context.Background(), c.input())
	if !errors.Is(err, backup.ErrNativeChain) || errors.Is(err, backup.ErrNativeNotVerified) ||
		!strings.Contains(err.Error(), "https://old-ingest.test:9444/olympos/"+nrFull+"/") {
		t.Fatalf("a chain through another endpoint: %+v, %v", got, err)
	}
	if got != nil && slices.ContainsFunc(got.Objects, func(d backup.NativeDecision) bool { return d.Allowed }) {
		t.Fatalf("an object is allowed on a refused chain: %+v", got.Objects)
	}
}

// TestNativeRestoreStatement (task 17): the RESTORE names the selected
// databases, each with EXCEPT TABLES of its objects left out, reads with the
// request's credential, and sets R26 and the request id; what is logged of
// it hides the secret.
func TestNativeRestoreStatement(t *testing.T) {
	const req = "4b1d6c2e-7f3a-4e5b-8c9d-0a1b2c3d4e5f"
	repl := "CREATE TABLE shop.r UUID '6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60' (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/s1/r', 'r1') ORDER BY id"
	nr := NativeRestore{URL: nrURL + "/olympos/" + nrFull + "/", RunID: nrFull, AccessKey: "OLYKEY", Secret: "s3cr3t-canary",
		Decisions: []Decision{
			{Database: "shop", Name: "orders", Kind: KindTable, Allowed: true},
			{Database: "shop", Name: "r", Kind: KindTable, Allowed: true},
			{Database: "shop", Name: "ext", Kind: KindTable, Reason: "the URL engine is not on the restore allowlist"},
			{Database: "shop", Name: "odd`name", Kind: KindOther, Reason: "the backup lists it as an object Olympos does not classify"},
			{Database: "stats", Name: "v", Kind: KindView, Allowed: true},
		},
		DDL:  map[string][]byte{restoreKey("shop", "r"): []byte(repl)},
		Rows: map[string]uint64{restoreKey("shop", "orders"): 3, restoreKey("shop", "r"): 2},
	}
	p, err := planNativeRestore(req, []string{"shop", "stats"}, nr)
	if err != nil {
		t.Fatal(err)
	}
	stmt := restoreStatement(p, nr, req)
	want := "RESTORE DATABASE `shop` EXCEPT TABLES `shop`.`ext`, `shop`.`odd\\`name`, DATABASE `stats` FROM S3('" + nr.URL +
		"', 'OLYKEY', 's3cr3t-canary') SETTINGS async = 1, allow_different_table_def = 1, allow_s3_native_copy = 0, use_same_s3_credentials_for_base_backup = 1, id = '" + req + "'"
	if stmt != want {
		t.Fatalf("statement\n got %s\nwant %s", stmt, want)
	}
	if r := redactStatement(stmt); strings.Contains(r, nr.Secret) || !strings.Contains(r, "'OLYKEY', '[HIDDEN]'") {
		t.Fatalf("redacted: %s", r)
	}
	// The Replicated table is created with its path rewritten and no UUID.
	if got := p.creates[restoreKey("shop", "r")]; got != "CREATE TABLE shop.r (`id` UInt64) ENGINE = ReplicatedMergeTree('/olympos-restore/"+req+"/shop/r', '{replica}') ORDER BY id" {
		t.Fatalf("create: %s", got)
	}
	if !reflect.DeepEqual(nr.String(), "clickhouse.NativeRestore{run "+nrFull+", key OLYKEY, secret redacted}") ||
		strings.Contains(fmt.Sprintf("%v %+v %#v", nr, nr, nr), nr.Secret) {
		t.Fatal("a print of the restore holds the secret")
	}

	// What the plan refuses, before anything reaches the target.
	bad := func(name string, mut func(*NativeRestore), dbs ...string) {
		t.Helper()
		c := nr
		c.Decisions = slices.Clone(nr.Decisions)
		c.DDL, c.Rows = maps.Clone(nr.DDL), maps.Clone(nr.Rows)
		if mut != nil {
			mut(&c)
		}
		if len(dbs) == 0 {
			dbs = []string{"shop", "stats"}
		}
		if _, err := planNativeRestore(req, dbs, c); err == nil {
			t.Errorf("%s: planned", name)
		}
	}
	bad("an unselected database's decision", nil, "shop")
	bad("no database", nil, "")
	bad("a system database", nil, "system")
	bad("a decision twice", func(c *NativeRestore) { c.Decisions = append(c.Decisions, c.Decisions[0]) })
	bad("DDL of a table left out", func(c *NativeRestore) { c.DDL[restoreKey("shop", "ext")] = []byte(repl) })
	bad("DDL the rewrite refuses", func(c *NativeRestore) {
		c.DDL[restoreKey("shop", "r")] = []byte("CREATE TABLE shop.r (`id` UInt64) ENGINE = ReplicatedMergeTree ORDER BY id")
	})
	bad("no row count", func(c *NativeRestore) { delete(c.Rows, restoreKey("shop", "orders")) })
}

// TestRestoreNativeRefusesInput: RestoreNative checks its input before it
// dials the target.
func TestRestoreNativeRefusesInput(t *testing.T) {
	const req = "4b1d6c2e-7f3a-4e5b-8c9d-0a1b2c3d4e5f"
	good := NativeRestore{URL: nrURL + "/olympos/" + nrFull + "/", RunID: nrFull, AccessKey: "OLYKEY", Secret: "s3cr3t-canary"}
	dialed := false
	rc := backup.RestoreContext{RequestID: req, Databases: []string{"shop"}, EngineContext: backup.EngineContext{
		Dial: func(context.Context) (net.Conn, error) { dialed = true; return nil, errors.New("no") }}}
	for name, mut := range map[string]func(*NativeRestore, *backup.RestoreContext){
		"request id":  func(_ *NativeRestore, rc *backup.RestoreContext) { rc.RequestID = "x" },
		"run id":      func(nr *NativeRestore, _ *backup.RestoreContext) { nr.RunID = "x" },
		"credential":  func(nr *NativeRestore, _ *backup.RestoreContext) { nr.Secret = "" },
		"another url": func(nr *NativeRestore, _ *backup.RestoreContext) { nr.URL = nrURL + "/olympos/" + nrInc + "/" },
		"no database": func(_ *NativeRestore, rc *backup.RestoreContext) { rc.Databases = nil },
	} {
		nr, c := good, rc
		mut(&nr, &c)
		if _, err := (Engine{}).RestoreNative(context.Background(), c, nr); err == nil || strings.Contains(err.Error(), nr.Secret+"x") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if dialed {
		t.Fatal("the target was dialed for a refused restore")
	}
}

// TestServerErrorSummary (R52): what is kept of a failed RESTORE's message
// is its code, its name and the start of its first line, never quoted text
// or DDL.
func TestServerErrorSummary(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{"Code: 608. DB::Exception: The table has a different definition: CREATE TABLE src.r UUID '887e' (`x` UInt64) ENGINE = MergeTree " +
			"comparing to its definition in the backup: CREATE DICTIONARY d SOURCE(CLICKHOUSE(PASSWORD 'pw-canary')): While checking table src.r. (CANNOT_RESTORE_TABLE) (version 24.8.14.39 (official build))",
			"Code 608 CANNOT_RESTORE_TABLE: The table has a different definition"},
		{"Code: 499. DB::Exception: Message: Access Denied, bucket olympos, key 'r/data/x.bin': (S3_ERROR)\nStack trace: CREATE …",
			"Code 499 S3_ERROR: Message: Access Denied, bucket olympos, key"},
		{"Code: 394. DB::Exception: Query was cancelled. (QUERY_WAS_CANCELLED)", "Code 394 QUERY_WAS_CANCELLED: Query was cancelled."},
		{"something odd with \"quotes\"", "an error: something odd with"},
		{"", "an error"},
	} {
		got := serverErrorSummary(tc.msg, 0, "")
		if got != tc.want || strings.Contains(got, "pw-canary") || strings.Contains(got, "CREATE") {
			t.Errorf("serverErrorSummary(%q)\n got %q\nwant %q", tc.msg, got, tc.want)
		}
	}
	if got := serverErrorSummary("Syntax error: failed at position 9 ('SETTINGS')", 62, "SYNTAX_ERROR"); got != "Code 62 SYNTAX_ERROR: Syntax error: failed at position 9" {
		t.Errorf("an exception's code and name: %q", got)
	}
	long := "Code: 1. DB::Exception: " + strings.Repeat("x", 300)
	if got := serverErrorSummary(long, 0, ""); len([]rune(got)) > 140 {
		t.Errorf("not clipped: %d runes", len([]rune(got)))
	}
}

// TestRestoredObjects (M-2): after RESTORED the restored databases hold
// exactly the allowed objects, with the inner tables of the allowed
// materialized views; an object left out that is there, an object no one
// decided, or an allowed one that is missing fails the restore, named.
func TestRestoredObjects(t *testing.T) {
	const req = "4b1d6c2e-7f3a-4e5b-8c9d-0a1b2c3d4e5f"
	nr := NativeRestore{Decisions: []Decision{
		{Database: "shop", Name: "orders", Kind: KindTable, Allowed: true},
		{Database: "shop", Name: "mv", Kind: KindMaterializedView, Allowed: true},
		{Database: "shop", Name: "d", Kind: KindDictionary, Allowed: true},
		{Database: "shop", Name: "ext", Kind: KindTable, Reason: "the URL engine is not on the restore allowlist"},
	}, Rows: map[string]uint64{restoreKey("shop", "orders"): 1}}
	p, err := planNativeRestore(req, []string{"shop"}, nr)
	if err != nil {
		t.Fatal(err)
	}
	const mvUUID = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"
	good := []restoredObject{{"shop", ".inner_id." + mvUUID, "11111111-0d8e-4b7a-9c1e-1a2b3c4d5e60", "MergeTree"},
		{"shop", "d", "22222222-0d8e-4b7a-9c1e-1a2b3c4d5e60", "Dictionary"}, {"shop", "mv", mvUUID, "MaterializedView"},
		{"shop", "orders", "33333333-0d8e-4b7a-9c1e-1a2b3c4d5e60", "MergeTree"}}
	if err := p.restoredObjects(good); err != nil {
		t.Fatalf("what was decided: %v", err)
	}
	if err := p.restoredObjects(append(slices.Clone(good), restoredObject{"shop", "ext", "", "URL"})); err == nil ||
		!strings.Contains(err.Error(), "shop.ext was to be left out, and the target holds it") {
		t.Fatalf("a left out object restored: %v", err)
	}
	if err := p.restoredObjects(append(slices.Clone(good), restoredObject{"shop", ".inner_id.99999999-0d8e-4b7a-9c1e-1a2b3c4d5e60", "", "MergeTree"},
		restoredObject{"shop", "surprise", "", "Log"})); err == nil ||
		!strings.Contains(err.Error(), "shop.surprise is not an object the restore was to create") ||
		!strings.Contains(err.Error(), "shop..inner_id.99999999-0d8e-4b7a-9c1e-1a2b3c4d5e60 is not an object") {
		t.Fatalf("objects no one decided: %v", err)
	}
	// An inner table is never required (the view holds its data).
	if err := p.restoredObjects(good[1:]); err != nil {
		t.Fatalf("an allowed view without its inner table: %v", err)
	}
	if err := p.restoredObjects(good[:3]); err == nil || !strings.Contains(err.Error(), "shop.orders was to be restored, and the target does not hold it") {
		t.Fatalf("a missing allowed table: %v", err)
	}
}

// TestCheckNativeRestoreDatabaseEngine (R52): a selected database whose own
// definition is not CREATE DATABASE … ENGINE = Atomic is refused with the
// reason; an incremental's databases are read from its base.
func TestCheckNativeRestoreDatabaseEngine(t *testing.T) {
	objs := []nrObj{
		{"shop", "orders", KindTable, "CREATE TABLE shop.orders (`id` UInt64) ENGINE = MergeTree ORDER BY id"},
		{"repl", "t", KindTable, "CREATE TABLE repl.t (`id` UInt64) ENGINE = MergeTree ORDER BY id"},
	}
	c := newNRChain(t, objs, []nrObj{objs[0]}, nrURL+"/olympos/"+nrFull+"/",
		"repl", "CREATE DATABASE repl ENGINE = Replicated('/clickhouse/db/repl', '{shard}', '{replica}')")
	got, err := Engine{}.CheckNativeRestore(context.Background(), c.input())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"repl": "it has the Replicated database engine; a native restore creates Atomic databases only, " +
		"and RESTORE refuses a database of another engine (restore it with the logical method)"}
	if !reflect.DeepEqual(got.RefusedDatabases, want) {
		t.Fatalf("refused: %q", got.RefusedDatabases)
	}
	if got, err := (Engine{}).CheckNativeRestore(context.Background(), c.input("shop")); err != nil || len(got.RefusedDatabases) != 0 {
		t.Fatalf("shop only: %v %v", got.RefusedDatabases, err)
	}

	for body, want := range map[string]string{
		"CREATE DATABASE db ENGINE = Atomic":                                             "",
		"CREATE DATABASE db UUID '6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60' ENGINE = Atomic": "",
		"CREATE DATABASE db ENGINE = Atomic COMMENT 'x'":                                 "its definition holds more than ENGINE = Atomic, which RESTORE would compare with the database a native restore creates",
		"CREATE DATABASE db ENGINE = Ordinary":                                           "it has the Ordinary database engine; a native restore creates Atomic databases only, and RESTORE refuses a database of another engine (restore it with the logical method)",
		"CREATE DATABASE other ENGINE = Atomic":                                          "its definition cannot be read with certainty",
		"CREATE DATABASE db ENGINE = Atomic -- x":                                        "its definition cannot be read with certainty",
	} {
		if got := atomicDatabase(nrFull+"/metadata/db.sql", "db", []byte(body)); got != want {
			t.Errorf("%s:\n got %q\nwant %q", body, got, want)
		}
	}
	// A database whose definition is not in the backup is refused.
	c2 := newNRChain(t, objs[:1], nil, "")
	delete(c2.bodies, nrFull+"/metadata/shop.sql")
	if got, err := (Engine{}).CheckNativeRestore(context.Background(), c2.input()); err == nil {
		t.Fatalf("an unreadable database definition: %v", got.RefusedDatabases)
	}
}
