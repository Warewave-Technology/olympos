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
		{"CREATE TABLE shop.`.inner_id.1` (`v` String) ENGINE = Memory", KindMVInner, "shop", ".inner_id.1"},
		{"CREATE DATABASE shop\nENGINE = Atomic", kindDatabase, "shop", ""},
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
		{"CREATE VIEW shop.t AS SELECT 1", KindTable, "shop", "t", "does not create a table"},
		{"CREATE OR REPLACE TABLE shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "OR REPLACE"},
		{"CREATE TABLE IF NOT EXISTS shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "IF NOT EXISTS"},
		{"CREATE TEMPORARY TABLE shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "TEMPORARY"},
		{"CREATE TABLE shop.t ON CLUSTER c (x UInt8) ENGINE = Log", KindTable, "shop", "t", "ON CLUSTER"},
		{"CREATE DATABASE other ENGINE = Atomic", kindDatabase, "shop", "", "creates database other"},
		{"CREATE DATABASE shop ON CLUSTER c", kindDatabase, "shop", "", "ON CLUSTER"},
		{"ATTACH TABLE shop.t (x UInt8) ENGINE = Log", KindTable, "shop", "t", "not a CREATE"},
	}
	for _, c := range bad {
		_, err := checkCreate(c.stmt, c.kind, c.db, c.name)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%q: want error with %q, got %v", c.stmt, c.why, err)
		}
	}
	// CREATE DATABASE takes an engine and a comment, nothing else.
	for stmt, want := range map[string]bool{
		"CREATE DATABASE shop": true, "CREATE DATABASE shop ENGINE = Atomic COMMENT 'x'": true,
		"CREATE DATABASE shop ENGINE = Lazy(60)": true, "CREATE DATABASE shop ENGINE = Atomic SETTINGS x = 1": false,
	} {
		st, err := checkCreate(stmt, kindDatabase, "shop", "")
		if err != nil || (st.databaseProblem() == "") != want {
			t.Errorf("%q: %v %q", stmt, err, st.databaseProblem())
		}
	}
}

func TestCheckCreateEdits(t *testing.T) {
	st, err := checkCreate("CREATE TABLE shop.t UUID '6b2b0f4b-0d36-4bd4-9a0e-7d3b1e5c2f10' (x UInt8) ENGINE = Log", KindTable, "shop", "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := st.sql(); got != "CREATE TABLE shop.t (x UInt8) ENGINE = Log" {
		t.Fatalf("sql: %q", got)
	}
	st, err = checkCreate("CREATE TABLE shop.`.inner_id.6b2b` (`d` Date) ENGINE = SummingMergeTree ORDER BY d", KindMVInner, "shop", ".inner_id.6b2b")
	if err != nil {
		t.Fatal(err)
	}
	st.rename("mv`x__restored_data")
	if got := st.sql(); got != "CREATE TABLE shop.`mv\\`x__restored_data` (`d` Date) ENGINE = SummingMergeTree ORDER BY d" {
		t.Fatalf("renamed: %q", got)
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
		"CREATE MATERIALIZED VIEW shop.mv (`d` Date) ENGINE = ReplicatedSummingMergeTree('/ch/mv', '{replica}') ORDER BY d AS SELECT d FROM shop.e",
	} {
		if got, ok := rewriteReplicatedPath(in, id); ok || got != in {
			t.Errorf("rewrite(%q) = %q %v, want unchanged", in, got, ok)
		}
	}
}

func TestClassifyTables(t *testing.T) {
	tbl := func(name, engine string) Table { return Table{Name: name, Kind: KindTable, Engine: engine} }
	created := []struct {
		t   Table
		ddl string
	}{
		{tbl("e", "MergeTree"), "CREATE TABLE shop.e (`d` Date, `id` UInt64, `s` LowCardinality(Nullable(String)), `v2` UInt64 MATERIALIZED id * 2, " +
			"`h` UInt64 DEFAULT cityHash64(s), `ts` DateTime DEFAULT now(), `a` Array(String) CODEC(ZSTD(1)), " +
			"INDEX ix (id, s) TYPE bloom_filter(0.01) GRANULARITY 4) ENGINE = MergeTree PARTITION BY toYYYYMM(d) ORDER BY (d, id) " +
			"TTL d + toIntervalDay(30) SETTINGS index_granularity = 8192, storage_policy = 'default'"},
		{tbl("agg", "AggregatingMergeTree"), "CREATE TABLE shop.agg (`k` UInt8, `u` AggregateFunction(quantiles(0.5, 0.9), UInt64)) ENGINE = AggregatingMergeTree ORDER BY k SETTINGS index_granularity = 8192"},
		{tbl("r", "ReplicatedReplacingMergeTree"), "CREATE TABLE shop.r (`x` UInt64, `v` UInt8) ENGINE = ReplicatedReplacingMergeTree('/p', '{replica}', v) ORDER BY x"},
		{tbl("l", "TinyLog"), "CREATE TABLE shop.l (x UInt8) ENGINE = TinyLog"},
		{tbl("m", "Memory"), "CREATE TABLE shop.m (x UInt8) ENGINE = Memory COMMENT 'kept'"},
		{tbl("c", "MergeTree"), "CREATE TABLE shop.c (x UInt8) ENGINE = MergeTree ORDER BY x SETTINGS index_granularity = 8192 COMMENT 'x'"},
	}
	for _, c := range created {
		o, err := classify("shop", c.t, c.ddl)
		if err != nil || !o.create {
			t.Errorf("%s: %v %q", c.t.Name, err, o.reason)
		}
	}
	skipped := []struct {
		t        Table
		ddl, why string
	}{
		{tbl("k", "Kafka"), "CREATE TABLE shop.k (x String) ENGINE = Kafka SETTINGS kafka_broker_list = 'b:9092'", "engine Kafka"},
		{tbl("s", "S3"), "CREATE TABLE shop.s (x String) ENGINE = S3('https://bucket/x', 'KEY', 'SECRET', 'CSV')", "engine S3"},
		{tbl("d", "Distributed"), "CREATE TABLE shop.d (x String) ENGINE = Distributed('c', 'shop', 'e')", "cluster"},
		{tbl("m", "Merge"), "CREATE TABLE shop.m (x UInt8) ENGINE = Merge('shop', '^e$')", "engine Merge"},
		{tbl("b", "Buffer"), "CREATE TABLE shop.b (x UInt8) ENGINE = Buffer(shop, e, 1, 10, 100, 1, 10, 1, 10)", "engine Buffer"},
		{tbl("dt", "Dictionary"), "CREATE TABLE shop.dt (id UInt64) ENGINE = Dictionary(xmldict)", "engine Dictionary"},
		{tbl("j", "Join"), "CREATE TABLE shop.j (id UInt64) ENGINE = Join(ANY, LEFT, id)", "engine Join"},
		{tbl("st", "Set"), "CREATE TABLE shop.st (id UInt64) ENGINE = Set", "engine Set"},
		{tbl("km", "KeeperMap"), "CREATE TABLE shop.km (k String, v String) ENGINE = KeeperMap('/km') PRIMARY KEY k", "engine KeeperMap"},
		{tbl("rk", "EmbeddedRocksDB"), "CREATE TABLE shop.rk (k String, v String) ENGINE = EmbeddedRocksDB(0, '/var/lib/x', 1) PRIMARY KEY k", "engine EmbeddedRocksDB"},
		{tbl("n", "Null"), "CREATE TABLE shop.n (x UInt8) ENGINE = Null", "engine Null"},
		{tbl("x", "SomethingNew"), "CREATE TABLE shop.x (x String) ENGINE = SomethingNew", "SomethingNew"},
		{tbl("tf", "URL"), "CREATE TABLE shop.tf AS url('http://x/', 'CSV', 'a String')", "AS"},
		{tbl("cp", "MergeTree"), "CREATE TABLE shop.cp AS shop.e ENGINE = MergeTree ORDER BY x", "AS"},
		{tbl("em", "MergeTree"), "CREATE TABLE shop.em ENGINE = MergeTree ORDER BY x EMPTY AS SELECT 1 AS x", "AS"},
		// Settings outside the allowlist.
		{tbl("w", "MergeTree"), "CREATE TABLE shop.w (x String) ENGINE = MergeTree ORDER BY x SETTINGS disk = disk(type = s3, endpoint = 'https://b/')", "setting disk"},
		{tbl("w2", "MergeTree"), "CREATE TABLE shop.w2 (x String) ENGINE = MergeTree ORDER BY x SETTINGS disk = 'default'", "setting disk"},
		{tbl("w3", "MergeTree"), "CREATE TABLE shop.w3 (x String) ENGINE = MergeTree ORDER BY x SETTINGS index_granularity = 8192, min_age_to_force_merge_seconds = 1", "min_age_to_force_merge_seconds"},
		{tbl("w4", "MergeTree"), "CREATE TABLE shop.w4 (x String SETTINGS (max_compress_block_size = 1)) ENGINE = MergeTree ORDER BY x", "SETTINGS"},
		// Expressions.
		{tbl("f", "MergeTree"), "CREATE TABLE shop.f (x String DEFAULT file('/etc/passwd')) ENGINE = MergeTree ORDER BY x", "file()"},
		{tbl("h", "MergeTree"), "CREATE TABLE shop.h (x UInt64, y String DEFAULT hostName()) ENGINE = MergeTree ORDER BY x", "hostName()"},
		{tbl("cd", "MergeTree"), "CREATE TABLE shop.cd (x UInt64, y String DEFAULT currentDatabase()) ENGINE = MergeTree ORDER BY x", "currentDatabase()"},
		{tbl("gm", "MergeTree"), "CREATE TABLE shop.gm (x UInt64, y String DEFAULT getMacro('shard')) ENGINE = MergeTree ORDER BY x", "getMacro()"},
		{tbl("sq", "MergeTree"), "CREATE TABLE shop.sq (`k` String DEFAULT (SELECT any(x) FROM paimonS3('http://e/', 'k', 's'))) ENGINE = MergeTree ORDER BY k", "query"},
		{tbl("in", "MergeTree"), "CREATE TABLE shop.in (`k` UInt64 DEFAULT k IN (1, 2)) ENGINE = MergeTree ORDER BY k", "IN"},
		{tbl("ni", "MergeTree"), "CREATE TABLE shop.ni (`k` UInt64 DEFAULT nullIn(k, secret.t)) ENGINE = MergeTree ORDER BY k", "nullIn()"},
		{tbl("qf", "MergeTree"), "CREATE TABLE shop.qf (`k` UInt64 DEFAULT `file`('x')) ENGINE = MergeTree ORDER BY k", "file()"},
		{tbl("pr", "MergeTree"), "CREATE TABLE shop.pr (`k` UInt64, PROJECTION p (SELECT k ORDER BY k)) ENGINE = MergeTree ORDER BY k", "query"},
		{tbl("na", "MergeTree"), "CREATE TABLE shop.na (`k` UInt64 COMMENT 'é') ENGINE = MergeTree ORDER BY k", ""},
		{tbl("nb", "MergeTree"), "CREATE TABLE shop.nb (`k` UInt64\u00a0DEFAULT 1) ENGINE = MergeTree ORDER BY k", "outside ASCII"},
	}
	for _, c := range skipped {
		o, err := classify("shop", c.t, c.ddl)
		if err != nil {
			t.Errorf("%s: %v", c.t.Name, err)
			continue
		}
		if c.why == "" {
			if !o.create {
				t.Errorf("%s: not created: %q", c.t.Name, o.reason)
			}
			continue
		}
		if o.create || !strings.Contains(o.reason, c.why) {
			t.Errorf("%s: create=%v reason=%q, want a skip with %q", c.t.Name, o.create, o.reason, c.why)
		}
		if strings.Contains(o.reason, "SECRET") || strings.Contains(o.reason, "https://") || strings.Contains(o.reason, "b:9092") {
			t.Errorf("%s: reason carries DDL: %q", c.t.Name, o.reason)
		}
	}
	// The schema entry disagrees with the manifest's engine: refused.
	if _, err := classify("shop", tbl("e2", "Log"), "CREATE TABLE shop.e2 (x UInt8) ENGINE = MergeTree ORDER BY x"); err == nil ||
		!strings.Contains(err.Error(), "the backup recorded Log") {
		t.Errorf("engine mismatch: %v", err)
	}
}

// TestReviewProbes are the reviews' probes (rounds 1 and 2, confirmed on
// ClickHouse 24.8; the sc_* ones are real SHOW CREATE output): views,
// materialized views and dictionaries are never created, whatever they
// hold, and the table probes are not created either.
func TestReviewProbes(t *testing.T) {
	others := []struct{ kind, ddl string }{
		{KindDictionary, "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users' INVALIDATE_QUERY 'SELECT count() FROM url(''http://evil.example/'')')) LIFETIME(10) LAYOUT(FLAT())"},
		{KindDictionary, "CREATE DICTIONARY shop.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(HOST 'source-ch.prod.svc' DB 'shop' TABLE 'users' HOST 'localhost')) LIFETIME(10) LAYOUT(FLAT())"},
		{KindDictionary, "CREATE DICTIONARY shop.dx\n(\n    `id` UInt64,\n    `v` String\n)\nPRIMARY KEY id\nSOURCE(CLICKHOUSE(DB 'shop' TABLE 'src'))\nLIFETIME(MIN 0 MAX 0)\nLAYOUT(HASHED())\n" +
			"SETTINGS(additional_result_filter = 'substring((SELECT arrayStringConcat(groupArray(x), \\',\\') FROM secret.creds), intDiv(id, 256) + 1, 1) = char(id % 256)')"},
		{KindView, "CREATE VIEW shop.v AS SELECT ‘'’ AS a, x FROM url('http://e/', 'CSV', 'x String') -- '"},
		{KindView, "CREATE VIEW shop.a1\n(\n    `s.x` String\n)\nAS SELECT s.x\nFROM shop.order AS o, secret.creds AS s"},
		{KindView, "CREATE VIEW shop.a3\n(\n    `s.x` String\n)\nAS SELECT s.x\nFROM shop.t AS where, secret.creds AS s"},
		{KindView, "CREATE VIEW shop.c1b\n(\n    `number` UInt64\n)\nAS SELECT number\nFROM numbers(100)\nWHERE number IN (secret.nums)"},
		{KindView, "CREATE VIEW shop.c2\n(\n    `number` UInt64\n)\nAS SELECT number\nFROM numbers(100)\nWHERE nullIn(number, secret.nums)"},
		{KindView, "CREATE VIEW shop.d4\n(\n    `n` UInt64\n)\nAS SELECT n\nFROM shop.grid\n" +
			"SETTINGS additional_table_filters = {'shop.grid':'substring((SELECT arrayStringConcat(groupArray(x), \\',\\') FROM secret.creds), intDiv(n, 256) + 1, 1) = char(n % 256)'}"},
		{KindView, "CREATE VIEW shop.v DEFINER = default SQL SECURITY DEFINER AS SELECT * FROM query_log"},
		{KindView, "CREATE VIEW shop.v AS SELECT * FROM merge(currentDatabase(), '^query_log$')"},
		{KindView, "CREATE VIEW shop.v AS SELECT * FROM ((SELECT 1 AS x) UNION ALL SELECT x FROM secret.creds)"},
		{KindMaterializedView, "CREATE MATERIALIZED VIEW shop.mv TO shop.t (`x` String) DEFINER = default SQL SECURITY DEFINER AS SELECT s.x FROM shop.src AS e, secret.creds AS s"},
		{KindMaterializedView, "CREATE MATERIALIZED VIEW shop.mv TO query_log AS SELECT * FROM shop.src"},
		{KindMaterializedView, "CREATE MATERIALIZED VIEW shop.mv ENGINE = MergeTree ORDER BY x POPULATE AS SELECT x FROM shop.src"},
		{KindOther, "CREATE LIVE VIEW shop.lv AS SELECT 1"},
	}
	for _, c := range others {
		o, err := classify("shop", Table{Name: "x", Kind: c.kind}, c.ddl)
		if err != nil || o.create || o.reason != notRecreated {
			t.Errorf("%s %q: create=%v reason=%q err=%v", c.kind, c.ddl, o.create, o.reason, err)
		}
	}
	tables := []struct{ engine, ddl string }{
		{"Merge", "CREATE TABLE shop.t (`query` String) ENGINE = Merge(currentDatabase(), '^query_log$')"},
		{"Dictionary", "CREATE TABLE shop.t (`id` UInt64) ENGINE = Dictionary(xmldict)"},
		{"Buffer", "CREATE TABLE shop.t (`x` UInt64) ENGINE = Buffer(currentDatabase(), 'query_log', 1, 1, 1, 1, 1, 1, 1)"},
		{"MergeTree", "CREATE TABLE shop.t (`d` Date, `x` UInt64) ENGINE = MergeTree ORDER BY x TTL d + toIntervalDay(dictGet('secret.d', 'v', x))"},
		{"MergeTree", "CREATE TABLE shop.t (`x` UInt64, INDEX i joinGet('secret.j','v',x) TYPE minmax) ENGINE = MergeTree ORDER BY x"},
		{"MergeTree", "CREATE TABLE shop.t (`x` UInt64) ENGINE = MergeTree ORDER BY x SETTINGS disk = 'default'"},
		{"MergeTree", "CREATE TABLE shop.t (`k` String DEFAULT (SELECT any(x) FROM paimonS3('http://e/', 'k', 's'))) ENGINE = MergeTree ORDER BY k"},
		{"EmbeddedRocksDB", "CREATE TABLE shop.t (`k` String, `v` String) ENGINE = EmbeddedRocksDB(0, '/var/lib/clickhouse/store/abc/other_rocksdb', 1) PRIMARY KEY k"},
	}
	for _, c := range tables {
		o, err := classify("shop", Table{Name: "t", Kind: KindTable, Engine: c.engine}, c.ddl)
		if err != nil || o.create {
			t.Errorf("%q: create=%v reason=%q err=%v", c.ddl, o.create, o.reason, err)
		}
	}
}
