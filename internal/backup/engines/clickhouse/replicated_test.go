package clickhouse

import (
	"errors"
	"strings"
	"testing"
)

// The native restore's Replicated tables (design
// docs/design/clickhouse-native.md, §6 Execute step 3): the backup's own
// CREATE TABLE with only the engine's Keeper path and replica replaced.

const rrRequest = "4b1d6c2e-7f3a-4e5b-8c9d-0a1b2c3d4e5f"

const rrUUID = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"

// rrPath is the Keeper path of db1.t1 under rrRequest, as a ClickHouse string.
const rrPath = "'/olympos-restore/" + rrRequest + "/db1/t1'"

// assertRewritten checks a rewrite: the output is in, with only its Keeper
// path and replica literals (path and replica, as written in in) replaced by
// the restore's, and the engine's arguments read back are those.
func assertRewritten(t *testing.T, in, path, replica, db, table string) {
	t.Helper()
	out, err := rewriteReplicatedEngine(in, rrRequest, db, table)
	if err != nil {
		t.Fatalf("rewriteReplicatedEngine(%q): %v", in, err)
	}
	p := strings.Index(in, path)
	if p < 0 {
		t.Fatalf("the test's path %q is not in %q", path, in)
	}
	r := strings.Index(in[p+len(path):], replica)
	if r < 0 {
		t.Fatalf("the test's replica %q is not after its path in %q", replica, in)
	}
	r += p + len(path)
	want := in[:p] + quoteString(keeperPath(rrRequest, db, table)) + in[p+len(path):r] + "'{replica}'" + in[r+len(replica):]
	if out != want {
		t.Fatalf("rewriteReplicatedEngine(%q)\n got %q\nwant %q", in, out, want)
	}
	_, args, err := sourceEngine(out)
	if err != nil || len(args) < 2 || len(args[0]) != 1 || len(args[1]) != 1 {
		t.Fatalf("the rewritten statement's engine arguments do not read back: %v %v", args, err)
	}
	if args[0][0].val != keeperPath(rrRequest, db, table) || args[1][0].val != replicaName {
		t.Fatalf("the rewritten engine's arguments are %q, %q", args[0][0].val, args[1][0].val)
	}
}

func TestRewriteReplicatedExplicitAndMacroPaths(t *testing.T) {
	// An explicit path and a {database}/{table} macro path (spike §8), with
	// the UUID ClickHouse writes into the metadata.
	explicit := "CREATE TABLE db1.t1 UUID '" + rrUUID + "' (`id` UInt64, `s` String) " +
		"ENGINE = ReplicatedMergeTree('/clickhouse/tables/shard1/db1/t1', 'r1') ORDER BY id SETTINGS index_granularity = 8192"
	out, err := rewriteReplicatedEngine(explicit, rrRequest, "db1", "t1")
	if err != nil {
		t.Fatal(err)
	}
	want := "CREATE TABLE db1.t1 UUID '" + rrUUID + "' (`id` UInt64, `s` String) " +
		"ENGINE = ReplicatedMergeTree(" + rrPath + ", '{replica}') ORDER BY id SETTINGS index_granularity = 8192"
	if out != want {
		t.Fatalf("explicit path:\n got %q\nwant %q", out, want)
	}

	macro := "CREATE TABLE db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/{database}/{table}', '{replica}') ORDER BY id"
	out, err = rewriteReplicatedEngine(macro, rrRequest, "db1", "t1")
	if err != nil {
		t.Fatal(err)
	}
	want = "CREATE TABLE db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree(" + rrPath + ", '{replica}') ORDER BY id"
	if out != want {
		t.Fatalf("macro path:\n got %q\nwant %q", out, want)
	}
}

func TestRewriteReplicatedAuxiliaryKeeper(t *testing.T) {
	// A path on an auxiliary Keeper (zookeeper_name:path) goes to the
	// default Keeper's restore path: the prefix is not kept.
	in := "CREATE TABLE db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('aux_keeper:/clickhouse/tables/db1/t1', 'r1') ORDER BY id"
	out, err := rewriteReplicatedEngine(in, rrRequest, "db1", "t1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "aux_keeper") || !strings.Contains(out, "ReplicatedMergeTree("+rrPath+", '{replica}')") {
		t.Fatalf("auxiliary Keeper path kept: %q", out)
	}
	assertRewritten(t, in, "'aux_keeper:/clickhouse/tables/db1/t1'", "'r1'", "db1", "t1")
}

func TestRewriteReplicatedFamily(t *testing.T) {
	// Every Replicated engine the allowlist allows; the arguments after the
	// replica (version, sign, columns) stay as written.
	cols := "(`id` UInt64, `ver` UInt32, `sign` Int8, `a` UInt64, `b` UInt64, `agg` AggregateFunction(sum, UInt64))"
	for _, c := range []struct{ engine, rest string }{
		{"ReplicatedMergeTree", ""},
		{"ReplicatedReplacingMergeTree", ""},
		{"ReplicatedReplacingMergeTree", ", ver"},
		{"ReplicatedReplacingMergeTree", " ,ver , sign"},
		{"ReplicatedSummingMergeTree", ", (a, b)"},
		{"ReplicatedSummingMergeTree", ", a"},
		{"ReplicatedAggregatingMergeTree", ""},
		{"ReplicatedCollapsingMergeTree", ", sign"},
		{"ReplicatedVersionedCollapsingMergeTree", ",\n\tsign,\n\tver"},
		{"ReplicatedCoalescingMergeTree", ""},
		{"ReplicatedCoalescingMergeTree", ", (a, b)"},
		// The pre-20 syntax: date column, sampling key, key and granularity.
		{"ReplicatedMergeTree", ", d, intHash32(id), (d, intHash32(id)), 8192"},
	} {
		in := "CREATE TABLE db1.t1 " + cols + " ENGINE = " + c.engine + "('/clickhouse/tables/{shard}/db1/t1',  'r-{replica}'" + c.rest + ")\nORDER BY id"
		t.Run(c.engine+c.rest, func(t *testing.T) {
			assertRewritten(t, in, "'/clickhouse/tables/{shard}/db1/t1'", "'r-{replica}'", "db1", "t1")
		})
	}
}

func TestRewriteReplicatedKeywordsAndQuoting(t *testing.T) {
	// Keywords are read in any case, as ClickHouse reads them; the names
	// may be quoted either way, and the spacing around the arguments stays.
	for _, in := range []string{
		"create table db1.t1 (`id` UInt64) engine = ReplicatedMergeTree('/p', 'r') order by id",
		"CREATE TABLE `db1`.\"t1\" (id UInt64) ENGINE=ReplicatedMergeTree(  '/p'  ,\n'r'  ) ORDER BY id",
		"Create Table \"db1\".`t1` UUID '" + rrUUID + "' (id UInt64) Engine = ReplicatedMergeTree('/p','r')",
		// Columns named engine or replicated are not a second engine.
		"CREATE TABLE db1.t1 (`engine` String, replicated UInt8, ENGINE String) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY (replicated, engine)",
	} {
		assertRewritten(t, in, "'/p'", "'r'", "db1", "t1")
	}
}

func TestRewriteReplicatedOtherStringsUnchanged(t *testing.T) {
	// Strings with escaped quotes, backslashes and non-ASCII bytes in other
	// clauses are not decoded and written again: they stay byte for byte,
	// and so do codecs, TTLs, indexes and projections.
	in := "CREATE TABLE db1.t1 UUID '" + rrUUID + "' (" +
		"`id` UInt64 CODEC(Delta(8), ZSTD(3)), " +
		"`s` String DEFAULT 'it''s a \\'quoted\\' \\\\ value' COMMENT 'çağ \\x41 \\n', " +
		"`d` DateTime, " +
		"INDEX ix s TYPE bloom_filter GRANULARITY 4, " +
		"PROJECTION p (SELECT id ORDER BY s)" +
		") ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/it''s/{database}', 'r\\'1', id) " +
		"PARTITION BY toYYYYMM(d) ORDER BY (id, s) TTL d + toIntervalDay(30) " +
		"SETTINGS index_granularity = 8192 COMMENT 'a \"table\" comment, with ''quotes'''"
	assertRewritten(t, in, "'/clickhouse/tables/it''s/{database}'", "'r\\'1'", "db1", "t1")
}

func TestRewriteReplicatedEscapesNames(t *testing.T) {
	// Database and table names reach the path only escaped as ClickHouse
	// escapes file names: no "/", ".", "{" or byte outside [A-Za-z0-9_]
	// survives, so a name adds no path component and no macro.
	cases := []struct{ db, table, stmtDB, stmtTable, path string }{
		{"my-db", "t.1/x", "`my-db`", "`t.1/x`", "/olympos-restore/" + rrRequest + "/my%2Ddb/t%2E1%2Fx"},
		{"db1", "{replica}", "db1", "`{replica}`", "/olympos-restore/" + rrRequest + "/db1/%7Breplica%7D"},
		{"..", "çay", "`..`", "`çay`", "/olympos-restore/" + rrRequest + "/%2E%2E/%C3%A7ay"},
		{"db 1", "it's", "`db 1`", "'it''s'", ""}, // a string is not a table name
	}
	for _, c := range cases {
		in := "CREATE TABLE " + c.stmtDB + "." + c.stmtTable + " (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id"
		out, err := rewriteReplicatedEngine(in, rrRequest, c.db, c.table)
		if c.path == "" {
			if err == nil {
				t.Errorf("%q: no error, got %q", in, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if keeperPath(rrRequest, c.db, c.table) != c.path || !strings.Contains(out, "ReplicatedMergeTree('"+c.path+"', '{replica}')") {
			t.Errorf("%q: got %q, want path %q", in, out, c.path)
		}
		assertRewritten(t, in, "'/p'", "'r'", c.db, c.table)
	}
}

func TestRewriteReplicatedRefused(t *testing.T) {
	head := "CREATE TABLE db1.t1 (`id` UInt64, `ver` UInt32) ENGINE = "
	for _, c := range []struct{ name, in, reason string }{
		// The server's defaults or {uuid}: refused on an Atomic database
		// outside ON CLUSTER (spike §8), and not a path Olympos can replace.
		{"no arguments", head + "ReplicatedMergeTree ORDER BY id", "no Keeper path or replica (the server's defaults)"},
		{"empty arguments", head + "ReplicatedMergeTree() ORDER BY id", "no Keeper path or replica (the server's defaults)"},
		{"a path only", head + "ReplicatedMergeTree('/p') ORDER BY id", "no Keeper path or replica (the server's defaults)"},
		{"engine parameters only", head + "ReplicatedReplacingMergeTree(ver) ORDER BY id", "no Keeper path or replica (the server's defaults)"},
		{"an empty argument", head + "ReplicatedMergeTree('/p', ) ORDER BY id", "its replica is not one plain string"},
		{"an empty path", head + "ReplicatedMergeTree('', 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"an empty replica", head + "ReplicatedMergeTree('/p', '') ORDER BY id", "its replica is not one plain string"},
		{"{uuid}", head + "ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY id", "its Keeper path holds {uuid}"},
		{"{UUID}", head + "ReplicatedMergeTree('/clickhouse/tables/{UUID}', '{replica}') ORDER BY id", "its Keeper path holds {uuid}"},
		// Two engines, or a second Replicated call.
		{"two ENGINE clauses", head + "ReplicatedMergeTree('/p', 'r') ORDER BY id ENGINE = MergeTree", "a second ENGINE clause"},
		{"two ENGINE clauses, Replicated second", head + "ReplicatedMergeTree('/p', 'r') ENGINE = ReplicatedMergeTree('/q', 'r2') ORDER BY id", "a second ENGINE clause"},
		{"a Replicated call in a column", "CREATE TABLE db1.t1 (`id` UInt64 DEFAULT ReplicatedMergeTree('/q', 'r')) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "a second Replicated engine call"},
		{"a Replicated call in a clause", head + "ReplicatedMergeTree('/p', 'r') ORDER BY replicatedMergeTree('/q', 'r')", "a second Replicated engine call"},
		// Comments: the lexer does not read them.
		{"a block comment between the arguments", head + "ReplicatedMergeTree('/p', /* x */ 'r') ORDER BY id", "its definition holds text Olympos does not read"},
		{"a line comment between the arguments", head + "ReplicatedMergeTree('/p', -- x\n'r') ORDER BY id", "its definition holds text Olympos does not read"},
		{"a comment elsewhere", head + "ReplicatedMergeTree('/p', 'r') ORDER BY id -- x", "its definition holds text Olympos does not read"},
		// A path or replica that is not one plain string.
		{"a concatenated path", head + "ReplicatedMergeTree('/p' || '/q', 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"a function path", head + "ReplicatedMergeTree(concat('/p', '{shard}'), 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"an identifier path", head + "ReplicatedMergeTree(path, 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"a quoted identifier path", head + "ReplicatedMergeTree(`/p`, 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"a number path", head + "ReplicatedMergeTree(1, 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"two adjacent strings", head + "ReplicatedMergeTree('/p' '/q', 'r') ORDER BY id", "its Keeper path is not one plain string"},
		{"a function replica", head + "ReplicatedMergeTree('/p', concat('r', '1')) ORDER BY id", "its replica is not one plain string"},
		{"a macro replica outside quotes", head + "ReplicatedMergeTree('/p', {replica}) ORDER BY id", "its definition holds text Olympos does not read"},
		{"an identifier replica", head + "ReplicatedMergeTree('/p', r1) ORDER BY id", "its replica is not one plain string"},
		// Engines that are not a Replicated engine Olympos restores.
		{"MergeTree", head + "MergeTree ORDER BY id", "its engine is not a Replicated engine Olympos restores"},
		{"MergeTree with strings", head + "MergeTree('/p', 'r') ORDER BY id", "its engine is not a Replicated engine Olympos restores"},
		{"ReplicatedGraphiteMergeTree", head + "ReplicatedGraphiteMergeTree('/p', 'r', 'rollup') ORDER BY id", "its engine is not a Replicated engine Olympos restores"},
		{"ReplicatedLog", head + "ReplicatedLog('/p', 'r')", "its engine is not a Replicated engine Olympos restores"},
		{"Distributed", head + "Distributed('c', 'db1', 'x')", "its engine is not a Replicated engine Olympos restores"},
		{"engine name in lower case", head + "replicatedmergetree('/p', 'r') ORDER BY id", "its engine is not a Replicated engine Olympos restores"},
		{"engine name quoted", head + "`ReplicatedMergeTree`('/p', 'r') ORDER BY id", "its engine is not a Replicated engine Olympos restores"},
		{"no engine", "CREATE TABLE db1.t1 (`id` UInt64)", "no ENGINE = after the columns"},
		// Not one CREATE TABLE of db1.t1.
		{"another table", "CREATE TABLE db1.t2 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "its definition creates db1.t2, not db1.t1"},
		{"another database", "CREATE TABLE db2.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "its definition creates db2.t1, not db1.t1"},
		{"unqualified", "CREATE TABLE t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "not a CREATE TABLE db.name"},
		{"ATTACH", "ATTACH TABLE db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "not a CREATE TABLE db.name"},
		{"a materialized view", "CREATE MATERIALIZED VIEW db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id AS SELECT 1", "not a CREATE TABLE db.name"},
		{"IF NOT EXISTS", "CREATE TABLE IF NOT EXISTS db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "not a CREATE TABLE db.name"},
		{"AS another table", "CREATE TABLE db1.t1 AS db1.t0 ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "no column list"},
		{"a bad UUID", "CREATE TABLE db1.t1 UUID 'x' (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id", "a UUID Olympos does not read"},
		{"two statements", head + "ReplicatedMergeTree('/p', 'r') ORDER BY id; DROP TABLE db1.t0", "more than one statement"},
		{"a trailing semicolon", head + "ReplicatedMergeTree('/p', 'r') ORDER BY id;", "more than one statement"},
		{"a query parameter", head + "ReplicatedMergeTree('/p', 'r') ORDER BY {p:Identifier}", "its definition holds text Olympos does not read"},
		{"invalid UTF-8", head + "ReplicatedMergeTree('/p', 'r') COMMENT '\xff'", "its definition is too long or not UTF-8"},
		{"too long", head + "ReplicatedMergeTree('/p', 'r') COMMENT '" + strings.Repeat("x", maxSchemaEntry) + "'", "its definition is too long or not UTF-8"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := rewriteReplicatedEngine(c.in, rrRequest, "db1", "t1")
			if err == nil || out != "" {
				t.Fatalf("rewriteReplicatedEngine(%.200q) = %q, %v; want an error and no output", c.in, out, err)
			}
			if !errors.Is(err, errReplicatedEngine) || !strings.Contains(err.Error(), "("+c.reason) {
				t.Fatalf("error %v: want errReplicatedEngine with %q", err, c.reason)
			}
		})
	}
}

func TestRewriteReplicatedRequestAndNames(t *testing.T) {
	in := "CREATE TABLE db1.t1 (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id"
	// The request id goes into the path as it is: only what requestIDRe
	// takes.
	for _, id := range []string{"", "-x", "a/b", "../x", "a{uuid}", "a b", "a\nb", strings.Repeat("a", 65)} {
		if out, err := rewriteReplicatedEngine(in, id, "db1", "t1"); err == nil || out != "" || !errors.Is(err, errReplicatedEngine) {
			t.Errorf("request id %q: got %q, %v; want an error", id, out, err)
		}
	}
	if _, err := rewriteReplicatedEngine(in, strings.Repeat("a", 64), "db1", "t1"); err != nil {
		t.Errorf("a 64-byte request id: %v", err)
	}
	// An empty name would leave a path component empty.
	for _, n := range [][2]string{{"", "t1"}, {"db1", ""}} {
		stmt := "CREATE TABLE `" + n[0] + "`.`" + n[1] + "` (`id` UInt64) ENGINE = ReplicatedMergeTree('/p', 'r') ORDER BY id"
		if out, err := rewriteReplicatedEngine(stmt, rrRequest, n[0], n[1]); err == nil || out != "" {
			t.Errorf("names %q: got %q, %v; want an error", n, out, err)
		}
	}
}
