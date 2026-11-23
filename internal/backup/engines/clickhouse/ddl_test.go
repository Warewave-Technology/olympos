package clickhouse

import (
	"errors"
	"strings"
	"testing"
)

func TestLexSQL(t *testing.T) {
	toks, err := lexSQL("CREATE TABLE `a``b`.\"c\\\"d\" ('it''s;', 'x\\'y', 1e-5, 0x1F, 0x1e-5, 0b101, 1.5, 2., t.1, a::String, a <= b, a != b, a || b, x -> x);")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range toks {
		got = append(got, tk.val)
	}
	want := []string{"CREATE", "TABLE", "a`b", ".", `c"d`, "(", "it's;", ",", "x'y", ",", "1e-5", ",", "0x1F", ",", "0x1e", "-", "5", ",",
		"0b101", ",", "1.5", ",", "2.", ",", "t", ".", "1", ",", "a", "::", "String", ",", "a", "<=", "b", ",", "a", "!=", "b", ",",
		"a", "||", "b", ",", "x", "->", "x", ")", ";"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tokens:\n got %q\nwant %q", got, want)
	}
	// 0x1e- followed by a name: the number ends at 0x1e, the call is seen.
	toks, err = lexSQL("0x1e-dictGetUInt64('secret.d', 'v', id)")
	if err != nil || len(toks) < 4 || toks[0].val != "0x1e" || toks[2].val != "dictGetUInt64" || !toks[3].punct("(") {
		t.Fatalf("hex then call: %v %+v", err, toks)
	}
	for _, bad := range []string{
		"SELECT 'open", "SELECT `open", "SELECT \x01", "SELECT ‘x’", "SELECT\u00a01",
		"SELECT 1 -- comment", "SELECT /* c */ 1", "SELECT 1 # c", "SELECT $a$ x $a$", "SELECT $$x$$",
		"SELECT @@version", "SELECT ?", "SELECT {x:String}", "SELECT {'a': 1}", "SELECT a & b", "SELECT !a",
		"SELECT 1p-uptime()", "SELECT 1e-x", "SELECT 1.2.hostName()", "SELECT 0x", "SELECT 0xg", "SELECT 12abc",
		"SELECT 'a\\Nb'", "SELECT 'a\\x4'", "SELECT 1e", "SELECT x == 1",
		"SELECT t.0x2", "SELECT t.1e5", "SELECT t.1.5", "SELECT t.0b1", "SELECT x<=>1",
	} {
		if _, err := lexSQL(bad); err == nil || !errors.Is(err, errLex) {
			t.Errorf("%q: expected an errLex, got %v", bad, err)
		}
	}
}

// TestSourceEngine: the engine and its arguments are read by position
// from SHOW CREATE text, and nothing else of it.
func TestSourceEngine(t *testing.T) {
	str := func(args [][]token) string {
		var out []string
		for _, a := range args {
			var v []string
			for _, tk := range a {
				v = append(v, tk.val)
			}
			out = append(out, strings.Join(v, " "))
		}
		return strings.Join(out, "|")
	}
	ok := []struct{ ddl, engine, args string }{
		{"CREATE TABLE shop.r\n(\n    `x` UInt64,\n    `v` UInt8\n)\nENGINE = ReplacingMergeTree(v)\nORDER BY x\nSETTINGS index_granularity = 8192", "ReplacingMergeTree", "v"},
		{"CREATE TABLE shop.r UUID '3b0f6c1e-2d4a-4e5f-9a1b-7c8d9e0f1a2b' (`x` UInt8, `ver` UInt8) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}', ver) ORDER BY x",
			"ReplicatedReplacingMergeTree", "/clickhouse/tables/{uuid}/{shard}|{replica}|ver"},
		{"CREATE TABLE shop.s (`k` UInt8, `a` UInt64, `b` UInt64) ENGINE = SummingMergeTree((a, b)) ORDER BY k", "SummingMergeTree", "( a , b )"},
		{"CREATE TABLE shop.m (`x` UInt8) ENGINE = MergeTree ORDER BY x", "MergeTree", ""},
		{"CREATE TABLE shop.g (`x` UInt8) ENGINE = GraphiteMergeTree() ORDER BY x", "GraphiteMergeTree", ""},
		{"CREATE TABLE `shop`.`.inner_id.1` (`x` UInt8) ENGINE = CollapsingMergeTree(`x`) ORDER BY x", "CollapsingMergeTree", "x"},
		{"CREATE TABLE t (`x` UInt8) ENGINE = Memory", "Memory", ""},
		// An ENGINE word later in the statement is not read.
		{"CREATE TABLE shop.b1 (`engine` UInt8) ENGINE = ReplacingMergeTree ORDER BY engine = file('/etc/hostname')", "ReplacingMergeTree", ""},
	}
	for _, c := range ok {
		e, args, err := sourceEngine(c.ddl)
		if err != nil || e != c.engine || str(args) != c.args {
			t.Errorf("%q: %q %q %v, want %q %q", c.ddl, e, str(args), err, c.engine, c.args)
		}
	}
	// An empty argument is kept as an empty slice (refused by every engine).
	if _, args, err := sourceEngine("CREATE TABLE shop.t (x UInt8) ENGINE = ReplacingMergeTree(, x) ORDER BY x"); err != nil || len(args) != 2 || len(args[0]) != 0 {
		t.Errorf("empty argument: %v %v", args, err)
	}
	for _, bad := range []string{
		"", "CREATE", "CREATE TABLE", "CREATE TABLE shop.", "CREATE TABLE shop.t", "CREATE TABLE shop.t (x UInt8)",
		"CREATE TABLE shop.t (x UInt8) ORDER BY x ENGINE = MergeTree", "CREATE TABLE shop.t (x UInt8) ENGINE MergeTree",
		"CREATE TABLE shop.t (x UInt8) ENGINE = ", "CREATE TABLE shop.t (x UInt8) ENGINE = MergeTree(", "CREATE TABLE shop.t (x UInt8] ENGINE = MergeTree",
		"CREATE VIEW shop.v AS SELECT 1", "CREATE TABLE shop.t AS url('http://x/', CSV)", "CREATE TABLE shop.t -- c\n(x UInt8) ENGINE = Log",
		"CREATE TABLE shop.t (x UInt8) ENGINE = ReplacingMergeTree(x]",
	} {
		if e, args, err := sourceEngine(bad); err == nil {
			t.Errorf("%q: read as %q %v", bad, e, args)
		}
	}
}

// An entry over maxSchemaEntry is refused before it is lexed; one of exactly
// that size is read.
func TestSourceEngineSizeCap(t *testing.T) {
	const stmt = "CREATE TABLE shop.t (x UInt8) ENGINE = Memory"
	pad := func(n int) string { return stmt + strings.Repeat(" ", n-len(stmt)) }
	if e, _, err := sourceEngine(pad(maxSchemaEntry)); err != nil || e != "Memory" {
		t.Errorf("entry of the cap: %q %v", e, err)
	}
	if _, _, err := sourceEngine(pad(maxSchemaEntry + 1)); err == nil {
		t.Error("entry over the cap was read")
	}
	if _, _, err := sourceEngine("CREATE TABLE shop.t (x UInt8) ENGINE = ReplacingMergeTree(" + strings.Repeat(",", maxSchemaEntry) + ")"); err == nil {
		t.Error("a run of commas over the cap was read")
	}
}
