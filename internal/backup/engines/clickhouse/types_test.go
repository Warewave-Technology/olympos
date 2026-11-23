package clickhouse

import (
	"math/rand"
	"strings"
	"testing"
)

func TestCanonicalTypeAccepts(t *testing.T) {
	cases := []struct{ in, want string }{
		{"UInt64", ""}, {"Int256", ""}, {"Float32", ""}, {"BFloat16", ""}, {"Bool", ""}, {"String", ""}, {"UUID", ""},
		{"IPv4", ""}, {"IPv6", ""}, {"Date", ""}, {"Date32", ""}, {"DateTime", ""}, {"JSON", ""}, {"Dynamic", ""},
		{"Point", ""}, {"MultiPolygon", ""},
		{"DateTime('Europe/Istanbul')", ""}, {"DateTime64(3)", ""}, {"DateTime64(6, 'UTC')", ""}, {"DateTime64(9,'Etc/GMT+3')", "DateTime64(9, 'Etc/GMT+3')"},
		{"Decimal(18, 4)", ""}, {"Decimal(76,0)", "Decimal(76, 0)"}, {"Decimal32(2)", ""}, {"Decimal256(10)", ""},
		{"FixedString(16)", ""}, {"FixedString(007)", "FixedString(7)"},
		{"Nullable(String)", ""}, {"LowCardinality(Nullable(String))", ""}, {"Array(Array(Nullable(UInt8)))", ""},
		{"Map(String, UInt64)", ""}, {"Map(LowCardinality(String), Array(Float64))", ""},
		{"Tuple(UInt8, String)", ""}, {"Tuple(a UInt8, b Array(String))", "Tuple(`a` UInt8, `b` Array(String))"},
		{"Tuple(`we ird` String, `x``y` UInt8)", "Tuple(`we ird` String, `x\\`y` UInt8)"},
		{"Nested(a String, b UInt8)", "Nested(`a` String, `b` UInt8)"},
		{"Enum8('a' = 1, 'b' = -2)", ""}, {"Enum16('it''s' = 1000, 'x\\ny' = 2)", "Enum16('it\\'s' = 1000, 'x\\x0ay' = 2)"},
		{"Enum8('ç' = 1)", ""},
		{"Object('json')", ""}, {"Dynamic(max_types = 3)", ""}, {"Variant(String, UInt64, Array(UInt8))", ""},
		{"AggregateFunction(uniq, UInt64)", ""}, {"AggregateFunction(quantiles(0.5, 0.9), Float64)", ""},
		{"AggregateFunction(sumIf, UInt64, UInt8)", ""}, {"AggregateFunction(count)", ""},
		{"AggregateFunction(1, sumMap, Array(UInt8), Array(UInt64))", ""}, {"AggregateFunction(uniqExactStateIf, String, UInt8)", ""},
		{"AggregateFunction(argMax, String, DateTime)", ""}, {"AggregateFunction(groupArrayArray, Array(String))", ""},
		{"AggregateFunction(sequenceMatch('(?1)(?2)'), DateTime, UInt8, UInt8)", ""}, {"AggregateFunction(topK(10), String)", ""},
		{"SimpleAggregateFunction(sum, UInt64)", ""}, {"SimpleAggregateFunction(anyLast, Nullable(String))", ""},
		{"SimpleAggregateFunction(groupUniqArrayArray, Array(String))", ""}, {"SimpleAggregateFunction(maxMap, Tuple(Array(UInt8), Array(UInt64)))", ""},
		{"  UInt64\n", "UInt64"},
	}
	for _, c := range cases {
		want := c.want
		if want == "" {
			want = c.in
		}
		got, err := canonicalType(c.in)
		if err != nil || got != want {
			t.Errorf("canonicalType(%q) = %q, %v; want %q", c.in, got, err, want)
			continue
		}
		// What Olympos writes reads back as itself.
		if again, err := canonicalType(got); err != nil || again != got {
			t.Errorf("canonicalType(%q) = %q, %v; not stable", got, again, err)
		}
	}
}

func TestCanonicalTypeRefuses(t *testing.T) {
	for _, in := range []string{
		"", "uint64", "STRING", "Nullable", "Nullable()", "Nullable(String, String)", "Array(String", "Array(String))", "String(1)",
		"UInt64 DEFAULT 1", "String CODEC(ZSTD(1))", "UInt8, x String", "String) ENGINE = File(TSV, '/etc/passwd') --", "String; DROP TABLE x",
		"Decimal(18)", "Decimal(1e3, 2)", "Decimal(0x12, 2)", "Decimal(-1, 2)", "FixedString('a')", "FixedString(1.5)",
		"FixedString(99999999999999999999)",
		"DateTime(currentDatabase())", "DateTime('../../etc/passwd')", "DateTime('a b')", "DateTime('/etc/passwd')", "DateTime('')", "DateTime('+3')", "DateTime(UTC)", "DateTime64(3, 4)",
		"DateTime64('UTC')", "DateTime64(3, 'UTC', 1)",
		"Enum8('a')", "Enum8('a' = 'b')", "Enum8(a = 1)", "Enum8('a' = 1 + 1)", "Enum8('a' = file('x'))", "Enum8()",
		"Object('secret')", "Object(json)", "JSON(max_dynamic_paths = 10)", "JSON(a.b UInt32)", "Dynamic(max_types = file('x'))",
		"Dynamic(other = 1)", "Variant()", "Map(String)", "Tuple()", "Tuple(a UInt8, String)", "Tuple(UInt8, b String)",
		"Nested(String)", "Tuple(a)",
		"AggregateFunction(file('/etc/passwd'), String)", "AggregateFunction(sum, (SELECT 1))", "AggregateFunction(dictGet, String)",
		"AggregateFunction(sumResample(0, 10, 1), UInt64, UInt8)", "AggregateFunction(myUDF, UInt64)", "AggregateFunction(SUM, UInt64)",
		"AggregateFunction(quantiles(x), Float64)", "AggregateFunction(quantiles(1e-3), Float64)", "AggregateFunction(quantiles(), Float64)",
		"AggregateFunction(quantiles(0.5 + 1), Float64)", "AggregateFunction(`uniq`, UInt64)", "AggregateFunction(uniq, file('x'))",
		"AggregateFunction(1, 2, sum, UInt64)", "AggregateFunction()", "SimpleAggregateFunction(sum)", "SimpleAggregateFunction(1, sum, UInt64)",
		"SimpleAggregateFunction(hostName, String)",
		"`UInt64`", "\"String\"", "'String'", "Nullable(`String`)", "LowCardinality(String) -- x", "Array(String) /* x */",
		"@@version", "{t:String}", "Nullable(String) ", "String\x00",
		strings.Repeat("Array(", 40) + "UInt8" + strings.Repeat(")", 40),
	} {
		if got, err := canonicalType(in); err == nil {
			t.Errorf("canonicalType(%q) = %q, want a refusal", in, got)
		}
	}
}

func TestAggregateName(t *testing.T) {
	for _, n := range []string{"sum", "sumIf", "uniqExactState", "uniqCombined64Merge", "groupArrayArray", "sumMapIfOrNull", "argMaxStateIf", "countDistinct"} {
		if !aggregateName(n) {
			t.Errorf("%s refused", n)
		}
	}
	for _, n := range []string{"", "file", "sumResample", "Sum", "sumX", "dictGet", "uniqUDF", strings.Repeat("sumIf", 40)} {
		if aggregateName(n) {
			t.Errorf("%s accepted", n)
		}
	}
}

// typeVocabulary is what random type texts are made of.
var typeVocabulary = []string{
	"UInt8", "String", "Nullable", "LowCardinality", "Array", "Map", "Tuple", "Nested", "Decimal", "Decimal32", "FixedString",
	"DateTime", "DateTime64", "Enum8", "Enum16", "Object", "Dynamic", "Variant", "AggregateFunction", "SimpleAggregateFunction",
	"JSON", "max_types", "uniq", "sumIf", "quantiles", "file", "currentDatabase", "a", "`b c`", "'UTC'", "'json'", "'x'",
	"(", ")", "(", ")", ",", ",", "=", "-", "1", "0.5", "1e5", "0x1", ";", "--", "/*", "@@", "{", "}", "'", "`", "\\", ".", "::", " ",
	"\x00", " ", "SELECT", "ENGINE",
}

func randomText(rng *rand.Rand, vocab []string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if rng.Intn(20) == 0 {
			b.WriteByte(byte(rng.Intn(256)))
			continue
		}
		b.WriteString(vocab[rng.Intn(len(vocab))])
		if rng.Intn(3) == 0 {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// TestCanonicalTypeRandom: random token soups never panic, and whatever
// is accepted reads back as itself and holds no call but type and
// aggregate names.
func TestCanonicalTypeRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	accepted := 0
	for i := 0; i < 50000; i++ {
		in := randomText(rng, typeVocabulary, 1+rng.Intn(14))
		out, err := canonicalType(in)
		if err != nil {
			continue
		}
		accepted++
		checkCanonicalType(t, in, out)
	}
	t.Logf("%d random types accepted", accepted)
}

func checkCanonicalType(t *testing.T, in, out string) {
	t.Helper()
	if again, err := canonicalType(out); err != nil || again != out {
		t.Fatalf("canonicalType(%q) = %q, which reads back as %q, %v", in, out, again, err)
	}
	assertGenerated(t, "CREATE TABLE `d`.`t` (`c` "+out+") ENGINE = Memory")
}

func FuzzCanonicalType(f *testing.F) {
	for _, s := range []string{"UInt64", "LowCardinality(Nullable(String))", "AggregateFunction(quantiles(0.5), Float64)",
		"Tuple(a String, b Map(String, UInt8))", "Enum8('a' = -1)", "DateTime64(3, 'UTC')", "AggregateFunction(file('x'), String)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := canonicalType(in)
		if err == nil {
			checkCanonicalType(t, in, out)
		}
	})
}
