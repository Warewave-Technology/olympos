package clickhouse

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClickHouse/ch-go/proto"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

func TestRegistered(t *testing.T) {
	e, ok := backup.EngineFor("clickhouse")
	if !ok {
		t.Fatal("engine not registered")
	}
	if e.Ext() != "zip" || e.ContentType() != "application/zip" || e.Name() != "clickhouse" {
		t.Fatalf("unexpected engine metadata %q %q %q", e.Name(), e.Ext(), e.ContentType())
	}
}

func TestParseOptions(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", "  "} {
		o, err := ParseOptions(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if len(o.Databases) != 0 || o.tables != nil {
			t.Fatalf("%q: expected defaults, got %+v", raw, o)
		}
		if !o.wantDatabase("analytics") || o.wantDatabase("system") || o.wantDatabase("INFORMATION_SCHEMA") || o.wantDatabase("information_schema") {
			t.Fatalf("%q: default database selection wrong", raw)
		}
	}

	o, err := ParseOptions(json.RawMessage(`{"databases":[" b ","a","b"],"tables":["a.t1","b.t2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.Databases, ",") != "a,b" {
		t.Fatalf("databases not normalized: %v", o.Databases)
	}
	if !o.wantDatabase("a") || o.wantDatabase("c") {
		t.Fatal("database filter wrong")
	}
	if !o.wantTable("a", "t1") || o.wantTable("a", "t2") || !o.wantTable("b", "t2") {
		t.Fatal("table filter wrong")
	}

	o, err = ParseOptions(json.RawMessage(`{"tables":["x.y.z"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !o.wantTable("x", "y.z") || strings.Join(o.requestedDatabases(), ",") != "x" || o.wantDatabase("other") {
		t.Fatal("tables-only selection wrong")
	}

	bad := map[string]string{
		`{"databse":["a"]}`:                    "unknown field",
		`{"databases":"a"}`:                    "cannot unmarshal",
		`{"databases":[""]}`:                   "empty name",
		`{"databases":["system"]}`:             "system database",
		`{"tables":["noDot"]}`:                 "database.table",
		`{"tables":[".t"]}`:                    "database.table",
		`{"tables":["system.parts"]}`:          "system database",
		`{"databases":["a"],"tables":["b.t"]}`: "not in the selected databases",
		`{"ca_pem":"not a cert"}`:              "no valid certificate",
		`{} {}`:                                "trailing data",
		`[1]`:                                  "cannot unmarshal",
	}
	for raw, want := range bad {
		_, err := ParseOptions(json.RawMessage(raw))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", raw, err, want)
		}
	}
}

func TestOptionsMethod(t *testing.T) {
	// Existing jobs have no method: empty means logical and still parses.
	for _, raw := range []string{``, `{}`, `{"databases":["a"]}`, `{"method":""}`, `{"method":"logical"}`} {
		o, err := ParseOptions(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if o.Native() || o.Incremental != "" {
			t.Fatalf("%q: expected logical, got %+v", raw, o)
		}
	}
	o, err := ParseOptions(json.RawMessage(`{"method":"native"}`))
	if err != nil || !o.Native() || o.Incremental != "" {
		t.Fatalf("native: %+v %v", o, err)
	}
	o, err = ParseOptions(json.RawMessage(`{"method":"native","incremental":"weekly_full_daily","databases":["a"]}`))
	if err != nil || !o.Native() || o.Incremental != IncrementalWeeklyFullDaily {
		t.Fatalf("native incremental: %+v %v", o, err)
	}

	bad := map[string]struct{ field, want string }{
		`{"method":"fast"}`:                                      {"method", "native"},
		`{"method":"Native"}`:                                    {"method", "native"},
		`{"method":" native"}`:                                   {"method", "native"},
		`{"method":"native","incremental":"hourly"}`:             {"incremental", "weekly_full_daily"},
		`{"incremental":"weekly_full_daily"}`:                    {"incremental", `method "native"`},
		`{"method":"logical","incremental":"weekly_full_daily"}`: {"incremental", `method "native"`},
		`{"method":"","incremental":"weekly_full_daily"}`:        {"incremental", `method "native"`},
		`{"method":"logical","incremental":"hourly"}`:            {"incremental", "weekly_full_daily"},
	}
	for raw, w := range bad {
		_, err := ParseOptions(json.RawMessage(raw))
		if err == nil || !strings.Contains(err.Error(), w.want) {
			t.Errorf("%s: got %v, want error containing %q", raw, err, w.want)
			continue
		}
		if f := (Engine{}).CheckOptions(json.RawMessage(raw), backup.OptionsEnv{IngestEnabled: true}); f[w.field] == "" || len(f) != 1 {
			t.Errorf("%s: fields %v, want only %q", raw, f, w.field)
		}
	}
}

func TestCheckOptions(t *testing.T) {
	on, off := backup.OptionsEnv{IngestEnabled: true}, backup.OptionsEnv{}
	e := Engine{}
	for _, raw := range []string{``, `{}`, `{"method":"logical"}`, `{"databases":["a"]}`} {
		if f := e.CheckOptions(json.RawMessage(raw), off); f != nil {
			t.Errorf("%q with ingest off: %v", raw, f)
		}
	}
	native := json.RawMessage(`{"method":"native","incremental":"weekly_full_daily"}`)
	if f := e.CheckOptions(native, on); f != nil {
		t.Fatalf("native with ingest on: %v", f)
	}
	if f := e.CheckOptions(native, off); f["method"] == "" || len(f) != 1 {
		t.Fatalf("native with ingest off: %v", f)
	}
	// A native run backs up whole databases, so a table filter is refused.
	tables := json.RawMessage(`{"method":"native","databases":["a"],"tables":["a.t"]}`)
	if f := e.CheckOptions(tables, on); !strings.Contains(f["tables"], `method "native"`) || len(f) != 1 {
		t.Fatalf("native with tables: %v", f)
	}
	if f := e.CheckOptions(json.RawMessage(`{"method":"logical","tables":["a.t"]}`), on); f != nil {
		t.Fatalf("logical with tables: %v", f)
	}
	if f := e.CheckOptions(json.RawMessage(`{"databse":["a"]}`), on); !strings.Contains(f["engine_options"], "unknown field") || len(f) != 1 {
		t.Fatalf("typo: %v", f)
	}
}

func TestPathSegment(t *testing.T) {
	cases := map[string]string{
		"events":           "events",
		".inner_id.abc-1":  ".inner_id.abc-1",
		"we/ird name":      "we%2Fird%20name",
		"..":               "%2E%2E",
		".":                "%2E",
		"":                 "%00",
		"ünï":              "%C3%BCn%C3%AF",
		"202401":           "202401",
		`a\b`:              "a%5Cb",
		"../../etc/passwd": "..%2F..%2Fetc%2Fpasswd",
	}
	for in, want := range cases {
		if got := pathSegment(in); got != want {
			t.Errorf("pathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuoting(t *testing.T) {
	if got := quoteIdent("a`b\\c"); got != "`a\\`b\\\\c`" {
		t.Errorf("quoteIdent: %s", got)
	}
	if got := quoteString(`it's \ x`); got != `'it\'s \\ x'` {
		t.Errorf("quoteString: %s", got)
	}
}

// TestNativeBlockLayout checks the Native format framing byte by byte.
func TestNativeBlockLayout(t *testing.T) {
	r := &nativeResult{rows: 2, cols: []nativeColumn{
		{name: "a", typ: "UInt8", data: &proto.ColUInt8{1, 2}},
		{name: "s", typ: "String", data: func() *proto.ColStr {
			var c proto.ColStr
			c.Append("x")
			c.Append("yz")
			return &c
		}()},
	}}
	var out bytes.Buffer
	var buf proto.Buffer
	if err := writeNativeBlock(&out, &buf, r); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		2, 2, // columns, rows
		1, 'a', 5, 'U', 'I', 'n', 't', '8', 1, 2,
		1, 's', 6, 'S', 't', 'r', 'i', 'n', 'g', 1, 'x', 2, 'y', 'z',
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("got %v\nwant %v", out.Bytes(), want)
	}

	var hdr bytes.Buffer
	if err := rowBinaryHeader(&hdr, []string{"a"}, []string{"UInt8"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hdr.Bytes(), []byte{1, 1, 'a', 5, 'U', 'I', 'n', 't', '8'}) {
		t.Fatalf("rowbinary header %v", hdr.Bytes())
	}
}

func TestNativeSupported(t *testing.T) {
	for _, ty := range []string{"UInt64", "String", "LowCardinality(String)", "Nullable(String)", "Array(String)",
		"DateTime('UTC')", "DateTime64(3, 'UTC')", "Decimal(18, 4)", "Enum8('a' = 1, 'b' = 2)", "UUID", "Map(String, String)", "Date"} {
		if !nativeSupported(ty) {
			t.Errorf("%s should be supported", ty)
		}
	}
	for _, ty := range []string{"AggregateFunction(uniq, UInt64)", "Tuple(a UInt8, b String)", "Variant(String, UInt64)"} {
		if nativeSupported(ty) {
			t.Errorf("%s should fall back", ty)
		}
	}
}

func TestSelectCovered(t *testing.T) {
	admin := []string{"GRANT SHOW, SELECT, INSERT ON *.* TO olympos WITH GRANT OPTION"}
	if ok, _ := selectCovered(admin, "shop", ""); !ok {
		t.Error("*.* should cover")
	}
	tableOnly := []string{"GRANT SELECT ON shop.users TO ro", "GRANT SELECT(id) ON shop.x TO ro", "GRANT r1 TO ro"}
	if ok, why := selectCovered(tableOnly, "shop", ""); ok || !strings.Contains(why, "shop.*") {
		t.Errorf("table grant must not cover db: %v %s", ok, why)
	}
	if ok, _ := selectCovered(tableOnly, "shop", "users"); !ok {
		t.Error("table grant should cover the table")
	}
	if ok, _ := selectCovered(tableOnly, "shop", "x"); ok {
		t.Error("column grant must not cover the table")
	}
	role := []string{"GRANT SELECT ON `my-db`.* TO r1", "GRANT SHOW TABLES, SELECT ON shop.* TO r1", "REVOKE SELECT ON shop.secret FROM r1"}
	if ok, _ := selectCovered(role, "my-db", ""); !ok {
		t.Error("quoted db grant should cover")
	}
	if ok, why := selectCovered(role, "shop", ""); ok || !strings.Contains(why, "revoked") {
		t.Errorf("partial revoke must fail db coverage: %v %s", ok, why)
	}
	if ok, _ := selectCovered(role, "shop", "users"); !ok {
		t.Error("revoke of another table must not affect users")
	}
	if ok, _ := selectCovered([]string{"GRANT ALL ON shop.* TO u"}, "shop", ""); !ok {
		t.Error("ALL should cover")
	}
}
