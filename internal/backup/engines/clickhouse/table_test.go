package clickhouse

import (
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// oracleCalls are the only names a generated CREATE TABLE writes before
// "(": type constructors, engines, tuple() and the partition forms.
// Aggregate function names are allowed inside AggregateFunction and
// SimpleAggregateFunction only.
var oracleCalls = words(`Nullable LowCardinality Array Map Variant Tuple Nested Decimal Decimal32 Decimal64 Decimal128 Decimal256
	FixedString Time64 DateTime DateTime64 Enum8 Enum16 Enum Object Dynamic AggregateFunction SimpleAggregateFunction
	MergeTree ReplacingMergeTree SummingMergeTree AggregatingMergeTree CollapsingMergeTree VersionedCollapsingMergeTree
	ReplicatedMergeTree ReplicatedReplacingMergeTree ReplicatedSummingMergeTree ReplicatedAggregatingMergeTree
	ReplicatedCollapsingMergeTree ReplicatedVersionedCollapsingMergeTree tuple toYYYYMM toYYYYMMDD toDate toStartOfMonth`)

// oracleWords are the only bare words: keywords, engines and type names
// (every column and element name is quoted).
var oracleWords = words(`CREATE TABLE ENGINE PARTITION ORDER BY PRIMARY KEY SETTINGS allow_nullable_key max_types
	Log TinyLog StripeLog Memory MergeTree ReplacingMergeTree SummingMergeTree AggregatingMergeTree CollapsingMergeTree
	Int8 Int16 Int32 Int64 Int128 Int256 UInt8 UInt16 UInt32 UInt64 UInt128 UInt256 Float32 Float64 BFloat16 Bool String UUID
	IPv4 IPv6 Date Date32 DateTime Time Nothing Point Ring LineString MultiLineString Polygon MultiPolygon JSON Dynamic`)

// literalParents may hold string literals: enum names, time zones,
// Object('json') and aggregate parameters.
var literalParents = words(`Enum8 Enum16 Enum DateTime DateTime64 Object`)

// assertGenerated is the review's check, independent of the generator: the
// statement holds nothing but generated text. Every name is quoted or one
// of oracleWords; every call is one of oracleCalls (aggregate names only
// inside aggregate types); every string is an enum name, a time zone, an
// aggregate parameter, or one of allowed (the Keeper path and replica);
// punctuation is ( ) , = - and the one "." of the table name. No
// comments, no operators, no other function.
func assertGenerated(t testing.TB, sql string, allowed ...string) {
	t.Helper()
	toks, err := lexSQL(sql)
	if err != nil {
		t.Fatalf("generated SQL does not lex: %v\n%s", err, sql)
	}
	fail := func(i int, why string) {
		t.Helper()
		t.Fatalf("generated SQL: %s at token %d (%q)\n%s", why, i, tokenAt(toks, i).val, sql)
	}
	at := func(i int) token { return tokenAt(toks, i) }
	if !at(0).is("CREATE") || at(0).val != "CREATE" || at(1).val != "TABLE" || at(2).kind != tokQIdent || !at(3).punct(".") ||
		at(4).kind != tokQIdent || !at(5).punct("(") {
		fail(0, "not CREATE TABLE `db`.`table` (")
	}
	allow := map[string]bool{}
	for _, a := range allowed {
		allow[a] = true
	}
	var stack []string
	top := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1]
	}
	inAggregate := func() bool {
		for _, s := range stack {
			if s == "AggregateFunction" || s == "SimpleAggregateFunction" {
				return true
			}
		}
		return false
	}
	for i := 5; i < len(toks); i++ {
		tk := toks[i]
		switch tk.kind {
		case tokWord:
			call := at(i + 1).punct("(")
			agg := inAggregate() && aggregateName(tk.val)
			switch {
			case call && (tk.val == "BY" || tk.val == "KEY"):
				// ORDER BY (a, b): a tuple of columns, not a call.
			case call && (oracleCalls[tk.val] || agg):
				stack = append(stack, tk.val)
				i++
			case call:
				fail(i, "a call to "+tk.val)
			case !oracleWords[tk.val] && !agg:
				fail(i, "a bare name")
			}
		case tokQIdent:
			if at(i + 1).punct("(") {
				fail(i, "a quoted call")
			}
		case tokString:
			if !allow[tk.val] && !literalParents[top()] && !(inAggregate() && aggregateName(top())) {
				fail(i, "a string literal outside a type")
			}
		case tokNumber:
		case tokPunct:
			switch tk.val {
			case "(":
				stack = append(stack, "")
			case ")":
				if len(stack) == 0 {
					fail(i, "unbalanced")
				}
				stack = stack[:len(stack)-1]
			case ",", "=", "-":
			default:
				fail(i, "punctuation "+tk.val)
			}
		}
	}
	if len(stack) != 0 {
		t.Fatalf("generated SQL is unbalanced:\n%s", sql)
	}
}

func cols(spec ...string) []Column {
	var out []Column
	for _, s := range spec {
		name, typ, _ := strings.Cut(s, " ")
		c := Column{Name: name, Type: typ}
		if k, rest, ok := strings.Cut(typ, " "); ok && (rest == "DEFAULT" || rest == "MATERIALIZED" || rest == "ALIAS" || rest == "EPHEMERAL") {
			c.Type, c.DefaultKind = k, rest
		}
		out = append(out, c)
	}
	return out
}

func TestBuildTable(t *testing.T) {
	cases := []struct {
		name string
		t    Table
		ddl  string
		want string
		lost []string // substrings of the not-restored list
	}{
		{"partitioned MergeTree", Table{Engine: "MergeTree", PartitionKey: "toYYYYMM(d)", SortingKey: "d, id", PrimaryKey: "d",
			Columns: cols("d Date", "id UInt64", "s LowCardinality(Nullable(String))", "h UInt64 DEFAULT", "v2 UInt64 MATERIALIZED", "a UInt64 ALIAS")},
			"", "CREATE TABLE `shop`.`t` (`d` Date, `id` UInt64, `s` LowCardinality(Nullable(String)), `h` UInt64) ENGINE = MergeTree " +
				"PARTITION BY toYYYYMM(`d`) ORDER BY (`d`, `id`) PRIMARY KEY `d`",
			[]string{"DEFAULT expressions of `h`", "columns `v2`, `a` (not in the backup's data)", "TTL"}},
		{"expression keys fall back", Table{Engine: "MergeTree", PartitionKey: "intDiv(id, 100)", SortingKey: "id, cityHash64(s)", PrimaryKey: "id",
			Columns: cols("id UInt64", "s String")},
			"", "CREATE TABLE `shop`.`t` (`id` UInt64, `s` String) ENGINE = MergeTree ORDER BY tuple()",
			[]string{"its partition key", "its sorting key (ORDER BY tuple() instead)", "its primary key"}},
		{"nullable key", Table{Engine: "MergeTree", SortingKey: "n", Columns: cols("n Nullable(UInt8)")},
			"", "CREATE TABLE `shop`.`t` (`n` Nullable(UInt8)) ENGINE = MergeTree ORDER BY `n` SETTINGS allow_nullable_key = 1", nil},
		{"quoted key names", Table{Engine: "MergeTree", SortingKey: "`we ird`, tuple", PartitionKey: "(`x`, tuple)",
			Columns: []Column{{Name: "we ird", Type: "UInt8"}, {Name: "x", Type: "UInt8"}, {Name: "tuple", Type: "UInt8"}}},
			"", "CREATE TABLE `shop`.`t` (`we ird` UInt8, `x` UInt8, `tuple` UInt8) ENGINE = MergeTree PARTITION BY (`x`, `tuple`) ORDER BY (`we ird`, `tuple`)", nil},
		{"Replacing with version", Table{Engine: "ReplacingMergeTree", SortingKey: "k", Columns: cols("k UInt8", "v UInt32", "del UInt8")},
			"CREATE TABLE shop.t (`k` UInt8, `v` UInt32, `del` UInt8) ENGINE = ReplacingMergeTree(v, del) ORDER BY k TTL now() SETTINGS x = 1",
			"CREATE TABLE `shop`.`t` (`k` UInt8, `v` UInt32, `del` UInt8) ENGINE = ReplacingMergeTree(`v`, `del`) ORDER BY `k`", nil},
		{"Replacing without", Table{Engine: "ReplacingMergeTree", SortingKey: "k", Columns: cols("k UInt8")},
			"CREATE TABLE shop.t (`k` UInt8) ENGINE = ReplacingMergeTree ORDER BY k",
			"CREATE TABLE `shop`.`t` (`k` UInt8) ENGINE = ReplacingMergeTree ORDER BY `k`", nil},
		{"Summing columns", Table{Engine: "SummingMergeTree", SortingKey: "k", Columns: cols("k UInt8", "a UInt64", "b UInt64")},
			"CREATE TABLE shop.t (`k` UInt8, `a` UInt64, `b` UInt64) ENGINE = SummingMergeTree((a, b)) ORDER BY k",
			"CREATE TABLE `shop`.`t` (`k` UInt8, `a` UInt64, `b` UInt64) ENGINE = SummingMergeTree((`a`, `b`)) ORDER BY `k`", nil},
		{"Summing one", Table{Engine: "SummingMergeTree", SortingKey: "k", Columns: cols("k UInt8", "a UInt64")},
			"CREATE TABLE shop.t (`k` UInt8, `a` UInt64) ENGINE = SummingMergeTree(a) ORDER BY k",
			"CREATE TABLE `shop`.`t` (`k` UInt8, `a` UInt64) ENGINE = SummingMergeTree(`a`) ORDER BY `k`", nil},
		{"Collapsing", Table{Engine: "CollapsingMergeTree", SortingKey: "k", Columns: cols("k UInt8", "sign Int8")},
			"CREATE TABLE shop.t (`k` UInt8, `sign` Int8) ENGINE = CollapsingMergeTree(sign) ORDER BY k",
			"CREATE TABLE `shop`.`t` (`k` UInt8, `sign` Int8) ENGINE = CollapsingMergeTree(`sign`) ORDER BY `k`", nil},
		{"VersionedCollapsing", Table{Engine: "VersionedCollapsingMergeTree", SortingKey: "k", Columns: cols("k UInt8", "sign Int8", "ver UInt8")},
			"CREATE TABLE shop.t (`k` UInt8, `sign` Int8, `ver` UInt8) ENGINE = VersionedCollapsingMergeTree(sign, ver) ORDER BY k",
			"CREATE TABLE `shop`.`t` (`k` UInt8, `sign` Int8, `ver` UInt8) ENGINE = VersionedCollapsingMergeTree(`sign`, `ver`) ORDER BY `k`", nil},
		{"Aggregating", Table{Engine: "AggregatingMergeTree", SortingKey: "k",
			Columns: cols("k UInt8", "u AggregateFunction(uniq, UInt64)", "q AggregateFunction(quantiles(0.5, 0.9), Float64)", "s SimpleAggregateFunction(sum, UInt64)")},
			"", "CREATE TABLE `shop`.`t` (`k` UInt8, `u` AggregateFunction(uniq, UInt64), `q` AggregateFunction(quantiles(0.5, 0.9), Float64), " +
				"`s` SimpleAggregateFunction(sum, UInt64)) ENGINE = AggregatingMergeTree ORDER BY `k`", nil},
		{"Replicated default path", Table{Engine: "ReplicatedMergeTree", SortingKey: "x", Columns: cols("x UInt64")},
			"", "CREATE TABLE `shop`.`t` (`x` UInt64) ENGINE = ReplicatedMergeTree('/olympos-restore/" + reqID + "/shop/t', '{replica}') ORDER BY `x`", nil},
		{"Replicated Replacing, source path dropped", Table{Engine: "ReplicatedReplacingMergeTree", SortingKey: "x", Columns: cols("x UInt64", "v UInt8")},
			"CREATE TABLE shop.t (`x` UInt64, `v` UInt8) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}', v) ORDER BY x",
			"CREATE TABLE `shop`.`t` (`x` UInt64, `v` UInt8) ENGINE = ReplicatedReplacingMergeTree('/olympos-restore/" + reqID + "/shop/t', '{replica}', `v`) ORDER BY `x`", nil},
		{"Replicated Replacing without path", Table{Engine: "ReplicatedReplacingMergeTree", SortingKey: "x", Columns: cols("x UInt64", "v UInt8")},
			"CREATE TABLE shop.t (`x` UInt64, `v` UInt8) ENGINE = ReplicatedReplacingMergeTree(v) ORDER BY x",
			"CREATE TABLE `shop`.`t` (`x` UInt64, `v` UInt8) ENGINE = ReplicatedReplacingMergeTree('/olympos-restore/" + reqID + "/shop/t', '{replica}', `v`) ORDER BY `x`", nil},
		{"Log", Table{Engine: "TinyLog", SortingKey: "x", Columns: cols("x UInt8")}, "",
			"CREATE TABLE `shop`.`t` (`x` UInt8) ENGINE = TinyLog", []string{"any codecs, constraints, comments and settings"}},
		{"Memory", Table{Engine: "Memory", Columns: cols("x UInt8")}, "", "CREATE TABLE `shop`.`t` (`x` UInt8) ENGINE = Memory", nil},
		{"StripeLog", Table{Engine: "StripeLog", Columns: cols("x UInt8")}, "", "CREATE TABLE `shop`.`t` (`x` UInt8) ENGINE = StripeLog", nil},
		{"odd names", Table{Engine: "Log", Columns: []Column{{Name: "a`b\n\\c", Type: "String"}}}, "",
			"CREATE TABLE `shop`.`t` (`a\\`b\\x0a\\\\c` String) ENGINE = Log", nil},
	}
	for _, c := range cases {
		c.t.Name, c.t.Kind = "t", KindTable
		def, why := buildTable("shop", "t", c.t, c.ddl, reqID)
		if why != "" {
			t.Errorf("%s: not created: %s", c.name, why)
			continue
		}
		if def.sql != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, def.sql, c.want)
		}
		assertGenerated(t, def.sql, def.keeperPath, replicaName)
		lost := strings.Join(def.notRestored, "; ")
		for _, l := range c.lost {
			if !strings.Contains(lost, l) {
				t.Errorf("%s: not-restored list %q lacks %q", c.name, lost, l)
			}
		}
	}
}

func TestBuildTableRefuses(t *testing.T) {
	r := func(engine, ddl string, columns ...string) Table {
		return Table{Name: "t", Kind: KindTable, Engine: engine, SortingKey: "k", Columns: cols(columns...)}
	}
	cases := []struct {
		name string
		t    Table
		ddl  string
		why  string
	}{
		{"Kafka", r("Kafka", "", "k String"), "", "engine Kafka is not restored"},
		{"Distributed", r("Distributed", "", "k String"), "", "points at a cluster"},
		{"Graphite", r("GraphiteMergeTree", "", "k String"), "", "rollup rules"},
		{"Replicated Graphite", r("ReplicatedGraphiteMergeTree", "", "k String"), "", "rollup rules"},
		{"KeeperMap", r("KeeperMap", "", "k String"), "", "engine KeeperMap"},
		{"EmbeddedRocksDB", r("EmbeddedRocksDB", "", "k String"), "", "engine EmbeddedRocksDB"},
		{"Merge", r("Merge", "", "k String"), "", "engine Merge"},
		{"ReplicatedLog", r("ReplicatedLog", "", "k String"), "", "engine ReplicatedLog"},
		{"a DEFAULT column is created", r("MergeTree", "", "k String", "f String DEFAULT"), "", ""},
		{"type with a call", Table{Engine: "Memory", Columns: []Column{{Name: "x", Type: "AggregateFunction(file('/etc/passwd'), String)"}}}, "", "type Olympos does not restore"},
		{"type with a default", Table{Engine: "Memory", Columns: []Column{{Name: "x", Type: "String DEFAULT hostName()"}}}, "", "type Olympos does not restore"},
		{"unknown kind", Table{Engine: "Memory", Columns: []Column{{Name: "x", Type: "String", DefaultKind: "FILE"}}}, "", "kind Olympos does not read"},
		{"duplicate", Table{Engine: "Memory", Columns: []Column{{Name: "x", Type: "String"}, {Name: "x", Type: "String"}}}, "", "appears twice"},
		{"no name", Table{Engine: "Memory", Columns: []Column{{Name: "", Type: "String"}}}, "", "no name"},
		{"only computed", Table{Engine: "Memory", Columns: []Column{{Name: "x", Type: "String", DefaultKind: "ALIAS"}}}, "", "no columns"},
		{"no columns", Table{Engine: "Memory"}, "", "no columns"},
		{"Replacing unreadable", r("ReplacingMergeTree", "", "k UInt8", "v UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplacingMergeTree(v) -- x", "could not be read"},
		{"Replacing without schema entry", r("ReplacingMergeTree", "", "k UInt8"), "", "could not be read"},
		{"Replacing other engine", r("ReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = MergeTree ORDER BY k", "names engine MergeTree"},
		{"Replacing expression", r("ReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplacingMergeTree(k + 1) ORDER BY k", "not columns"},
		{"Replacing call", r("ReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplacingMergeTree(file('/etc/passwd')) ORDER BY k", "not columns"},
		{"Replacing unknown column", r("ReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplacingMergeTree(v) ORDER BY k", "not columns"},
		{"Replacing string", r("ReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplacingMergeTree('k') ORDER BY k", "not columns"},
		{"Replacing number", r("ReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplacingMergeTree(1) ORDER BY k", "not columns"},
		{"Replacing old syntax", r("ReplacingMergeTree", "", "d Date", "k UInt8", "v UInt8"), "CREATE TABLE shop.t (d Date, k UInt8, v UInt8) ENGINE = ReplacingMergeTree(d, (k), 8192, v)", "not columns"},
		{"Replacing on a computed column", Table{Name: "t", Engine: "ReplacingMergeTree", Columns: []Column{{Name: "k", Type: "UInt8"}, {Name: "v", Type: "UInt8", DefaultKind: "MATERIALIZED"}}},
			"CREATE TABLE shop.t (k UInt8, v UInt8 MATERIALIZED k) ENGINE = ReplacingMergeTree(v) ORDER BY k", "not columns"},
		{"Collapsing without sign", r("CollapsingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = CollapsingMergeTree ORDER BY k", "not columns"},
		{"VersionedCollapsing one", r("VersionedCollapsingMergeTree", "", "k UInt8", "s Int8"), "CREATE TABLE shop.t (k UInt8, s Int8) ENGINE = VersionedCollapsingMergeTree(s) ORDER BY k", "not columns"},
		{"Summing expression", r("SummingMergeTree", "", "k UInt8", "a UInt8"), "CREATE TABLE shop.t (k UInt8, a UInt8) ENGINE = SummingMergeTree((a, a * 2)) ORDER BY k", "not columns"},
		{"Summing empty tuple", r("SummingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = SummingMergeTree(tuple()) ORDER BY k", "not columns"},
		{"Replicated path concat", r("ReplicatedReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplicatedReplacingMergeTree(concat('/a', 'b'), '{replica}') ORDER BY k", "not columns"},
		{"Replicated one string", r("ReplicatedReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplicatedReplacingMergeTree('/a', k) ORDER BY k", "could not be read"},
		{"Replicated empty arg", r("ReplicatedReplacingMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = ReplicatedReplacingMergeTree('/a', '{replica}', ) ORDER BY k", "not columns"},
		{"Graphite nil args", r("GraphiteMergeTree", "", "k UInt8"), "CREATE TABLE shop.t (k UInt8) ENGINE = GraphiteMergeTree() ORDER BY k", "rollup rules"},
		{"Replacing expression key", Table{Engine: "ReplacingMergeTree", SortingKey: "k, lower(s)", Columns: cols("k UInt8", "s String")},
			"CREATE TABLE shop.t (k UInt8, s String) ENGINE = ReplacingMergeTree ORDER BY (k, lower(s))", "sorting key is not a column list"},
		{"Aggregating expression key", Table{Engine: "AggregatingMergeTree", SortingKey: "cityHash64(k)", Columns: cols("k UInt8")}, "", "sorting key is not a column list"},
		{"Summing expression partition", Table{Engine: "ReplicatedSummingMergeTree", SortingKey: "k", PartitionKey: "intDiv(k, 2)", Columns: cols("k UInt8")},
			"CREATE TABLE shop.t (k UInt8) ENGINE = ReplicatedSummingMergeTree('/p', 'r') ORDER BY k", "partition key is not"},
		{"Collapsing key on a computed column", Table{Engine: "CollapsingMergeTree", SortingKey: "m",
			Columns: []Column{{Name: "s", Type: "Int8"}, {Name: "m", Type: "UInt8", DefaultKind: "MATERIALIZED"}}},
			"CREATE TABLE shop.t (s Int8, m UInt8 MATERIALIZED 1) ENGINE = CollapsingMergeTree(s) ORDER BY m", "sorting key is not a column list"},
	}
	for _, c := range cases {
		c.t.Name, c.t.Kind = "t", KindTable
		def, why := buildTable("shop", "t", c.t, c.ddl, reqID)
		if c.why == "" {
			if why != "" {
				t.Errorf("%s: %s", c.name, why)
			}
			continue
		}
		if why == "" || !strings.Contains(why, c.why) {
			t.Errorf("%s: why=%q def=%+v, want %q", c.name, why, def, c.why)
		}
		if strings.Contains(why, "/etc/passwd") || strings.Contains(why, "hostName") {
			t.Errorf("%s: the reason quotes the backup's text: %q", c.name, why)
		}
	}
}

func TestKeys(t *testing.T) {
	cs := columnSet{"a": "UInt8", "b": "UInt8", "we ird": "UInt8", "tuple": "UInt8"}
	for in, want := range map[string]string{
		"": "", "a": "a", "a, b": "a|b", "(a, b)": "a|b", "tuple(a, b)": "a|b", "tuple()": "", "`we ird`": "we ird", "\"we ird\", a": "we ird|a",
		"tuple": "tuple",
	} {
		got, ok := keyColumns(in, cs)
		if !ok || strings.Join(got, "|") != want {
			t.Errorf("keyColumns(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"c", "a,", ", a", "a b", "a + b", "toDate(a)", "(a, (b))", "a.b", "a, file('x')", "engine = file('/etc/hostname')",
		"t.case + WHEN(id)", "Mod(a, 2)", "a -- x", "(a", "tuple(a", "TUPLE(a)", "`tuple`(a)", "cityHash64(a)", "a, b, "} {
		if got, ok := keyColumns(in, cs); ok {
			t.Errorf("keyColumns(%q) = %q, want a refusal", in, got)
		}
	}
	for in, want := range map[string]string{
		"": "", "toYYYYMM(a)": "toYYYYMM(`a`)", "toYYYYMMDD(`we ird`)": "toYYYYMMDD(`we ird`)", "toDate(b)": "toDate(`b`)",
		"toStartOfMonth(a)": "toStartOfMonth(`a`)", "a": "`a`", "(a, b)": "(`a`, `b`)", "tuple()": "",
	} {
		got, _, ok := partitionKey(in, cs)
		if !ok || got != want {
			t.Errorf("partitionKey(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"toYYYYMM(c)", "toyyyymm(a)", "toYYYYMM(a, 'UTC')", "toYYYYMM(toDate(a))", "toMonday(a)", "intDiv(a, 10)",
		"TODAY(a)", "engine = TODAY(d)", "Mod(a, 2)", "toYYYYMM(file('x'))", "`toYYYYMM`(a)"} {
		if got, _, ok := partitionKey(in, cs); ok {
			t.Errorf("partitionKey(%q) = %q, want a refusal", in, got)
		}
	}
}

// probeTable makes manifest tables from a reviewer probe's DDL, with the
// probe's text placed in every field the generator reads: column types
// as written (with their DEFAULT, CODEC, … clauses), column types without
// them, keys from its ORDER BY / PARTITION BY / PRIMARY KEY, and the whole
// statement as a type and as every key.
func probeTables(ddl string) []Table {
	engine := "MergeTree"
	toks, err := lexSQL(ddl)
	if err == nil {
		for i := 0; i+2 < len(toks); i++ {
			if toks[i].depth == 0 && toks[i].is("ENGINE") && toks[i+1].punct("=") && toks[i+2].ident() {
				engine = toks[i+2].val
				break
			}
		}
	}
	whole := Table{Engine: engine, PartitionKey: ddl, SortingKey: ddl, PrimaryKey: ddl, Columns: []Column{{Name: "x", Type: ddl}}}
	out := []Table{whole, {Engine: engine, Columns: []Column{{Name: "id", Type: "UInt64"}, {Name: "x", Type: ddl, DefaultKind: "DEFAULT"}}}}
	if err != nil {
		return out
	}
	text := func(from, to int) string {
		if from >= to || to > len(toks) {
			return ""
		}
		return ddl[toks[from].start:toks[to-1].end]
	}
	raw, trimmed := Table{Engine: engine}, Table{Engine: engine}
	open := -1
	for i, tk := range toks {
		if tk.depth == 0 && tk.punct("(") {
			open = i
			break
		}
	}
	if open >= 0 {
		if c := matching(toks, open); c > 0 {
			for _, el := range splitArgs(toks, open, c) {
				if len(el) < 2 || !el[0].ident() {
					continue
				}
				from := el[1].start
				to := el[len(el)-1].end
				raw.Columns = append(raw.Columns, Column{Name: el[0].val, Type: ddl[from:to]})
				cut := to
				kind := ""
				for _, tk := range el[1:] {
					if tk.depth == el[0].depth && tk.kind == tokWord {
						if u := strings.ToUpper(tk.val); u == "DEFAULT" || u == "MATERIALIZED" || u == "ALIAS" || u == "EPHEMERAL" || u == "CODEC" || u == "TTL" || u == "COMMENT" {
							cut = tk.start
							if u != "CODEC" && u != "TTL" && u != "COMMENT" {
								kind = u
							}
							break
						}
					}
				}
				trimmed.Columns = append(trimmed.Columns, Column{Name: el[0].val, Type: strings.TrimSpace(ddl[from:cut]), DefaultKind: kind})
			}
		}
	}
	// Keys: the text after ORDER BY, PARTITION BY, PRIMARY KEY up to the next
	// depth-0 clause word.
	clause := func(a, b string) string {
		for i := 0; i+1 < len(toks); i++ {
			if toks[i].depth == 0 && toks[i].is(a) && toks[i+1].is(b) {
				j := i + 2
				for ; j < len(toks); j++ {
					if tk := toks[j]; tk.depth == 0 && (tk.is("ORDER") || tk.is("PARTITION") || tk.is("PRIMARY") || tk.is("SAMPLE") ||
						tk.is("TTL") || tk.is("SETTINGS") || tk.is("COMMENT")) {
						break
					}
				}
				return text(i+2, j)
			}
		}
		return ""
	}
	for _, t := range []*Table{&raw, &trimmed} {
		t.SortingKey, t.PartitionKey, t.PrimaryKey = clause("ORDER", "BY"), clause("PARTITION", "BY"), clause("PRIMARY", "KEY")
	}
	return append(out, raw, trimmed)
}

// TestReviewProbes: every table DDL of the five review rounds' probes
// (testdata/review_probes.json, from the reviewers' probe8 … probe12 and
// the round 1–4 tests) is fed to the generator in every field it reads.
// Whatever is created is generated text only (assertGenerated): no
// function but the date partition forms, no string but the Keeper path,
// the replica macro and literals inside types.
func TestReviewProbes(t *testing.T) {
	b, err := os.ReadFile("testdata/review_probes.json")
	if err != nil {
		t.Fatal(err)
	}
	var probes []struct{ Src, DDL string }
	if err := json.Unmarshal(b, &probes); err != nil {
		t.Fatal(err)
	}
	if len(probes) < 250 {
		t.Fatalf("only %d probes", len(probes))
	}
	created, total := 0, 0
	for _, p := range probes {
		for _, tbl := range probeTables(p.DDL) {
			for _, engine := range []string{tbl.Engine, "ReplicatedReplacingMergeTree", "SummingMergeTree", "Memory"} {
				tbl.Name, tbl.Kind, tbl.Engine = "t", KindTable, engine
				total++
				def, why := buildTable("shop", "t", tbl, p.DDL, reqID)
				if why != "" {
					continue
				}
				created++
				assertGenerated(t, def.sql, def.keeperPath, replicaName)
				for _, bad := range []string{"file(", "dictGet", "joinGet", "currentDatabase", "hostName", "url(", "WHEN(", "Mod(", "TODAY(", "AND(", "Map(1"} {
					if strings.Contains(def.sql, bad) {
						t.Fatalf("%s: generated SQL holds %q:\n%s", p.Src, bad, def.sql)
					}
				}
			}
		}
	}
	t.Logf("%d probes, %d tables tried, %d generated", len(probes), total, created)
	if created == 0 {
		t.Fatal("no probe table was generated: the test checks nothing")
	}
}

// ddlVocabulary is what random statements are made of.
var ddlVocabulary = append([]string{
	"CREATE", "TABLE", "shop", ".", "t", "ENGINE", "=", "ReplacingMergeTree", "ReplicatedReplacingMergeTree", "SummingMergeTree",
	"CollapsingMergeTree", "VersionedCollapsingMergeTree", "GraphiteMergeTree", "ORDER", "BY", "tuple", "toYYYYMM", "k", "v",
	"`k`", "\"v\"", "'/p'", "'{replica}'", "UUID", "'u'", "file", "'/etc/passwd'", "+", "*", "]", "[",
}, typeVocabulary...)

// TestGeneratorRandom: random statements, types and keys never panic, and
// every generated statement is generated text only.
func TestGeneratorRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	engines := []string{"MergeTree", "ReplacingMergeTree", "ReplicatedReplacingMergeTree", "SummingMergeTree", "ReplicatedSummingMergeTree",
		"CollapsingMergeTree", "VersionedCollapsingMergeTree", "AggregatingMergeTree", "GraphiteMergeTree", "Log", "Memory"}
	generated := 0
	for i := 0; i < 30000; i++ {
		ddl := randomText(rng, ddlVocabulary, rng.Intn(30))
		if rng.Intn(2) == 0 {
			ddl = "CREATE TABLE shop.t (k UInt8, v UInt8) ENGINE = " + randomText(rng, ddlVocabulary, rng.Intn(10))
		}
		tbl := Table{Name: "t", Kind: KindTable, Engine: engines[rng.Intn(len(engines))],
			SortingKey: randomText(rng, ddlVocabulary, rng.Intn(5)), PartitionKey: randomText(rng, ddlVocabulary, rng.Intn(5)),
			PrimaryKey: randomText(rng, ddlVocabulary, rng.Intn(3)),
			Columns:    []Column{{Name: "k", Type: "UInt8"}, {Name: "v", Type: "UInt8"}, {Name: randomText(rng, ddlVocabulary, 2), Type: randomText(rng, typeVocabulary, rng.Intn(6))}}}
		if rng.Intn(2) == 0 {
			tbl.SortingKey = []string{"k", "k, v", "(v, k)", "tuple()", "v"}[rng.Intn(5)]
		}
		def, why := buildTable("shop", "t", tbl, ddl, reqID)
		if why != "" {
			continue
		}
		generated++
		assertGenerated(t, def.sql, def.keeperPath, replicaName)
	}
	t.Logf("%d statements generated", generated)
	if generated == 0 {
		t.Fatal("nothing generated")
	}
}

func FuzzBuildTable(f *testing.F) {
	f.Add("CREATE TABLE shop.t (k UInt8, v UInt8) ENGINE = ReplacingMergeTree(v) ORDER BY k", "ReplacingMergeTree", "k", "toYYYYMM(k)", "UInt8")
	f.Add("CREATE TABLE shop.t (k UInt8) ENGINE = GraphiteMergeTree() ORDER BY k", "GraphiteMergeTree", "", "", "String")
	f.Add("CREATE TABLE shop.t (k UInt8) ENGINE = SummingMergeTree((k, v))", "ReplicatedSummingMergeTree", "k, v", "", "AggregateFunction(uniq, UInt64)")
	f.Fuzz(func(t *testing.T, ddl, engine, key, partition, typ string) {
		tbl := Table{Name: "t", Kind: KindTable, Engine: engine, SortingKey: key, PartitionKey: partition, PrimaryKey: key,
			Columns: []Column{{Name: "k", Type: "UInt8"}, {Name: "v", Type: typ}}}
		_, _, _ = sourceEngine(ddl)
		def, why := buildTable("shop", "t", tbl, ddl, reqID)
		if why == "" {
			assertGenerated(t, def.sql, def.keeperPath, replicaName)
		}
	})
}

// An engine name from the backup is quoted in a report at most
// maxEngineNameInReason bytes long, cut at a character boundary, and the
// report is printable.
func TestEngineNameInReasons(t *testing.T) {
	long := strings.Repeat("a", 500)
	multi := strings.Repeat("\u00e9", 100) // 2 bytes each
	check := func(what, why string) {
		t.Helper()
		if !strings.Contains(why, "\u2026") || len(why) > 200 || !utf8.ValidString(why) {
			t.Errorf("%s: %d bytes: %q", what, len(why), why)
		}
		if strings.ContainsAny(printable(why), "\n\r") {
			t.Errorf("%s: not printable: %q", what, printable(why))
		}
	}
	for _, name := range []string{long, multi, "x\ny" + long} {
		check("engineSkipReason", engineSkipReason(name))
	}
	check("a long Graphite name", engineSkipReason(long+"GraphiteMergeTree"))
	// The schema entry names a long engine; the backup recorded another.
	tbl := Table{Name: "t", Engine: "ReplacingMergeTree", SortingKey: "k", Columns: cols("k UInt8")}
	_, why := buildTable("shop", "t", tbl, "CREATE TABLE shop.t (k UInt8) ENGINE = "+long+" ORDER BY k", reqID)
	check("schema entry names a long engine", why)
	if !strings.Contains(why, "names engine") {
		t.Errorf("reason: %q", why)
	}
	if got := engineSkipReason("Kafka"); got != "engine Kafka is not restored by Olympos (it restores MergeTree, Log and Memory tables)" {
		t.Errorf("short name changed: %q", got)
	}
}
