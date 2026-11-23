package clickhouse

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
)

func TestRestoreRegistered(t *testing.T) {
	if _, ok := backup.RestorerFor("clickhouse"); !ok {
		t.Fatal("restorer not registered")
	}
	if _, ok := restore.InspectorFor("clickhouse"); !ok {
		t.Fatal("inspector not registered")
	}
}

// fakeBackup is an archive with schema entries, data entries and a
// manifest, for planning tests.
type fakeBackup struct {
	m     Manifest
	files map[string]string
}

func newFakeBackup() *fakeBackup {
	return &fakeBackup{m: Manifest{Format: ManifestFormat, Engine: Name}, files: map[string]string{}}
}

func (b *fakeBackup) db(name, engine string) *Database {
	entry := "schema/" + pathSegment(name) + ".sql"
	b.files[entry] = "CREATE DATABASE " + quoteIdent(name) + "\nENGINE = " + engine + ";\n"
	b.m.Databases = append(b.m.Databases, Database{Name: name, Engine: engine, SchemaEntry: entry})
	return &b.m.Databases[len(b.m.Databases)-1]
}

// obj adds an object; data rows per partition (none: no data).
func (b *fakeBackup) obj(d *Database, t Table, ddl string, rows ...uint64) {
	t.SchemaEntry = "schema/" + pathSegment(d.Name) + "/" + pathSegment(t.Name) + ".sql"
	b.files[t.SchemaEntry] = ddl + ";\n"
	if len(rows) > 0 {
		t.HasData = true
		if t.DataFormat == "" {
			t.DataFormat = FormatNative
		}
		for i, n := range rows {
			id := string(rune('a' + i))
			p := Partition{ID: id, Rows: n}
			if n > 0 {
				p.Entry = "data/" + pathSegment(d.Name) + "/" + pathSegment(t.Name) + "/" + id + ".native"
				b.files[p.Entry] = strings.Repeat("x", int(n))
				p.Bytes = int64(n)
			}
			t.Partitions = append(t.Partitions, p)
			t.Rows += n
		}
	}
	d.Tables = append(d.Tables, t)
}

func (b *fakeBackup) entries(t *testing.T) map[string]*zip.File {
	t.Helper()
	var buf bytes.Buffer
	a := newArchive(&buf, time.Now())
	for name, c := range b.files {
		if _, err := a.writeFile(name, []byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	mj, _ := json.Marshal(b.m)
	if _, err := a.writeFile("manifest.json", mj); err != nil {
		t.Fatal(err)
	}
	if err := a.close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*zip.File{}
	for _, f := range zr.File {
		out[f.Name] = f
	}
	return out
}

const reqID = "0f6c1d9e-5d1a-4a53-8e0b-7a1f3c2b9d44"

func shopBackup() *fakeBackup {
	b := newFakeBackup()
	shop := b.db("shop", "Atomic")
	b.obj(shop, Table{Name: "events", Kind: KindTable, Engine: "MergeTree", PartitionKey: "d", SortingKey: "x", PrimaryKey: "x",
		Columns: []Column{{Name: "d", Type: "Date"}, {Name: "x", Type: "UInt64"}, {Name: "x2", Type: "UInt64", DefaultKind: "MATERIALIZED", DefaultExpression: "x * 2"}}},
		"CREATE TABLE shop.events (`d` Date, `x` UInt64, `x2` UInt64 MATERIALIZED x * 2) ENGINE = MergeTree PARTITION BY d ORDER BY x", 3, 0, 2)
	b.obj(shop, Table{Name: "agg", Kind: KindTable, Engine: "AggregatingMergeTree", DataFormat: FormatRowBinary, SortingKey: "k", PrimaryKey: "k",
		Columns: []Column{{Name: "k", Type: "UInt8"}, {Name: "u", Type: "AggregateFunction(uniq, UInt64)"}}},
		"CREATE TABLE shop.agg (`k` UInt8, `u` AggregateFunction(uniq, UInt64)) ENGINE = AggregatingMergeTree ORDER BY k", 4)
	b.obj(shop, Table{Name: "r", Kind: KindTable, Engine: "ReplicatedMergeTree", SortingKey: "x", PrimaryKey: "x", Columns: []Column{{Name: "x", Type: "UInt64"}}},
		"CREATE TABLE shop.r (`x` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x", 1)
	b.obj(shop, Table{Name: "k", Kind: KindTable, Engine: "Kafka"},
		"CREATE TABLE shop.k (`x` String) ENGINE = Kafka SETTINGS kafka_broker_list = 'broker:9092', kafka_sasl_password = 'kafka-secret'")
	b.obj(shop, Table{Name: "dt", Kind: KindTable, Engine: "Dictionary"},
		"CREATE TABLE shop.dt (`id` UInt64, `name` String) ENGINE = Dictionary(shop.users_dict)")
	b.obj(shop, Table{Name: "users_dict", Kind: KindDictionary, Engine: "Dictionary"},
		"CREATE DICTIONARY shop.users_dict (`id` UInt64, `name` String) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'shop' TABLE 'events' USER 'u' PASSWORD '[HIDDEN]')) LIFETIME(MIN 0 MAX 0) LAYOUT(FLAT())")
	b.obj(shop, Table{Name: "v", Kind: KindView, Engine: "View"}, "CREATE VIEW shop.v (`x` UInt64) AS SELECT x FROM shop.events")
	b.obj(shop, Table{Name: "mv", Kind: KindMaterializedView, Engine: "MaterializedView", UUID: "11111111-1111-1111-1111-111111111111"},
		"CREATE MATERIALIZED VIEW shop.mv (`d` Date, `c` UInt64) ENGINE = SummingMergeTree ORDER BY d AS SELECT d, count() AS c FROM shop.events GROUP BY d")
	b.obj(shop, Table{Name: ".inner_id.11111111-1111-1111-1111-111111111111", Kind: KindMVInner, Engine: "SummingMergeTree", InnerOf: "mv",
		SortingKey: "d", PrimaryKey: "d", Columns: []Column{{Name: "d", Type: "Date"}, {Name: "c", Type: "UInt64"}}},
		"CREATE TABLE shop.`.inner_id.11111111-1111-1111-1111-111111111111` (`d` Date, `c` UInt64) ENGINE = SummingMergeTree ORDER BY d", 2)
	b.obj(shop, Table{Name: "mv_k", Kind: KindMaterializedView, Engine: "MaterializedView"},
		"CREATE MATERIALIZED VIEW shop.mv_k TO shop.events (`d` Date, `x` UInt64) AS SELECT toDate(now()) AS d, length(x) AS x FROM shop.k")
	return b
}

func TestPlanDatabaseAndSteps(t *testing.T) {
	b := shopBackup()
	entries := b.entries(t)
	ts := &targetState{dbs: map[string]targetDB{}}
	p, msg := planDatabase(&b.m.Databases[0], entries, ts, reqID)
	if msg != "" {
		t.Fatal(msg)
	}
	plans := []*dbPlan{p}
	var got []string
	for _, s := range steps(plans) {
		got = append(got, s.String())
	}
	want := []string{
		"database shop",
		"table shop.events", "table shop.agg", "table shop.r", "table shop.mv__restored_data",
		"data shop.events", "data shop.agg", "data shop.r", "data shop.mv__restored_data",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("steps:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	skipped := strings.Join(p.skipped, "\n")
	for _, w := range []string{
		"shop.k (table): engine Kafka is not restored",
		"shop.dt (table): engine Dictionary is not restored",
		"shop.users_dict (dictionary): " + notRecreated,
		"shop.v (view): " + notRecreated,
		"shop.mv (materialized view): " + notRecreated,
		"shop.mv_k (materialized view): " + notRecreated,
	} {
		if !strings.Contains(skipped, w) {
			t.Errorf("skipped lacks %q:\n%s", w, skipped)
		}
	}
	if strings.Contains(skipped, "broker") || strings.Contains(skipped, "kafka-secret") {
		t.Fatalf("skipped carries DDL: %s", skipped)
	}
	notes := strings.Join(p.notes, "\n")
	for _, w := range []string{
		"shop.r: its Keeper path is /olympos-restore/" + reqID + "/shop/r (replica {replica})",
		"the data of materialized view shop.mv was restored into table shop.mv__restored_data; recreate the view with TO `shop`.`mv__restored_data`",
		"shop.events: created from its columns, types, engine and keys; not restored: the MATERIALIZED, ALIAS and EPHEMERAL columns `x2` " +
			"(not in the backup's data); any codecs, TTL, indexes, projections, constraints, comments, sampling key and settings; re-apply them from your schema",
		"shop.mv__restored_data: created from its columns",
	} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
	want = []string{
		"CREATE TABLE `shop`.`events` (`d` Date, `x` UInt64) ENGINE = MergeTree PARTITION BY `d` ORDER BY `x`",
		"CREATE TABLE `shop`.`agg` (`k` UInt8, `u` AggregateFunction(uniq, UInt64)) ENGINE = AggregatingMergeTree ORDER BY `k`",
		"CREATE TABLE `shop`.`r` (`x` UInt64) ENGINE = ReplicatedMergeTree('/olympos-restore/" + reqID + "/shop/r', '{replica}') ORDER BY `x`",
		"CREATE TABLE `shop`.`mv__restored_data` (`d` Date, `c` UInt64) ENGINE = SummingMergeTree ORDER BY `d`",
	}
	for i, o := range p.objs {
		if o.sql != want[i] {
			t.Errorf("%s:\n got %s\nwant %s", o.target, o.sql, want[i])
		}
		if o.t.Kind == KindMVInner && (o.target != "mv__restored_data" || o.t.Rows != 2) {
			t.Errorf("mv inner: %+v", o)
		}
	}
	if p.create != "CREATE DATABASE `shop` ENGINE = Atomic" {
		t.Fatalf("create: %q", p.create)
	}

	// An existing empty database is restored into, without CREATE DATABASE.
	ts.dbs["shop"] = targetDB{engine: "Atomic"}
	p, msg = planDatabase(&b.m.Databases[0], entries, ts, reqID)
	if msg != "" || !p.exists || p.create != "" {
		t.Fatalf("existing empty: %q %+v", msg, p)
	}
	if s := steps([]*dbPlan{p}); s[0].String() != "table shop.events" {
		t.Fatalf("first step: %s", s[0])
	}

	// The view's data table would collide with a table of the backup.
	b.obj(&b.m.Databases[0], Table{Name: "mv__restored_data", Kind: KindTable, Engine: "Memory", Columns: []Column{{Name: "x", Type: "UInt8"}}}, "")
	if _, msg := planDatabase(&b.m.Databases[0], b.entries(t), &targetState{dbs: map[string]targetDB{}}, reqID); !strings.Contains(msg, "which the backup also holds") {
		t.Fatalf("collision: %q", msg)
	}
}

// TestPlanInnerTables: a materialized view's data table needs its view in
// the backup, a unique name the target can store, and its name in a note
// is printable (review round 3).
func TestPlanInnerTables(t *testing.T) {
	plan := func(views []string, inner ...string) (*dbPlan, string) {
		b := newFakeBackup()
		shop := b.db("shop", "Atomic")
		for _, v := range views {
			b.obj(shop, Table{Name: v, Kind: KindMaterializedView, Engine: "MaterializedView"}, "CREATE MATERIALIZED VIEW x")
		}
		for i, in := range inner {
			name := ".inner_id." + string(rune('a'+i))
			b.obj(shop, Table{Name: name, Kind: KindMVInner, Engine: "Memory", InnerOf: in, Columns: []Column{{Name: "x", Type: "UInt8"}}},
				"CREATE TABLE shop."+quoteIdent(name)+" (x UInt8) ENGINE = Memory", 1)
		}
		return planDatabase(&b.m.Databases[0], b.entries(t), &targetState{dbs: map[string]targetDB{}}, reqID)
	}
	if _, msg := plan(nil, "nope"); !strings.Contains(msg, `names no materialized view "nope"`) {
		t.Errorf("no view: %q", msg)
	}
	if _, msg := plan([]string{"v"}, ""); !strings.Contains(msg, "names no materialized view") {
		t.Errorf("empty InnerOf: %q", msg)
	}
	if _, msg := plan([]string{"dup"}, "dup", "dup"); !strings.Contains(msg, "which the backup also holds") {
		t.Errorf("duplicate target: %q", msg)
	}
	long := strings.Repeat("a", 240)
	if _, msg := plan([]string{long}, long); !strings.Contains(msg, "too long") {
		t.Errorf("long name: %q", msg)
	}
	odd := "m`v'x\n" + "y"
	p, msg := plan([]string{odd, "line\nbreak"}, odd, "line\nbreak")
	if msg != "" {
		t.Fatal(msg)
	}
	for _, o := range p.objs {
		if !strings.HasSuffix(o.target, "__restored_data") || o.sql != "CREATE TABLE `shop`."+quoteIdent(o.target)+" (`x` UInt8) ENGINE = Memory" {
			t.Errorf("target %q: %s", o.target, o.sql)
		}
		assertGenerated(t, o.sql)
	}
	for _, n := range p.notes {
		if strings.ContainsAny(n, "\n\r\x00") {
			t.Errorf("note not printable: %q", n)
		}
	}
	if !strings.Contains(strings.Join(p.notes, "|"), `line\x0abreak__restored_data`) {
		t.Errorf("notes: %q", p.notes)
	}
}

func TestPlanDatabaseRefuses(t *testing.T) {
	cases := []struct {
		name string
		mod  func(b *fakeBackup, ts *targetState)
		want string
	}{
		{"exists with objects", func(b *fakeBackup, ts *targetState) { ts.dbs["shop"] = targetDB{engine: "Atomic", objects: 1} }, "exists on the target with tables"},
		{"exists Replicated", func(b *fakeBackup, ts *targetState) { ts.dbs["shop"] = targetDB{engine: "Replicated"} }, "Replicated database engine"},
		{"Replicated in backup", func(b *fakeBackup, ts *targetState) {
			b.m.Databases[0].Engine = "Replicated"
		}, "Replicated database engine"},
		{"MySQL database", func(b *fakeBackup, ts *targetState) { b.m.Databases[0].Engine = "MySQL" }, "proxy for another system"},
		{"missing data entry", func(b *fakeBackup, ts *targetState) { delete(b.files, "data/shop/events/c.native") }, "missing from the backup"},
		{"data entry of another table", func(b *fakeBackup, ts *targetState) {
			b.m.Databases[0].Tables[0].Partitions[0].Entry = "data/shop/agg/a.native"
		}, "missing from the backup"},
		{"wrong size", func(b *fakeBackup, ts *targetState) { b.files["data/shop/events/a.native"] = "xx" }, "has 2 bytes"},
		{"rows disagree", func(b *fakeBackup, ts *targetState) { b.m.Databases[0].Tables[0].Rows = 99 }, "hold 5 rows, its table 99"},
		{"unknown data format", func(b *fakeBackup, ts *targetState) { b.m.Databases[0].Tables[0].DataFormat = "CSV" }, `unknown data format "CSV"`},
	}
	for _, c := range cases {
		b := shopBackup()
		ts := &targetState{dbs: map[string]targetDB{}}
		c.mod(b, ts)
		_, msg := planDatabase(&b.m.Databases[0], b.entries(t), ts, reqID)
		if !strings.Contains(msg, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, msg, c.want)
		}
	}
	// A Replicated table without a request id.
	b := shopBackup()
	if _, msg := planDatabase(&b.m.Databases[0], b.entries(t), &targetState{dbs: map[string]targetDB{}}, ""); !strings.Contains(msg, "request's id") {
		t.Errorf("no request id: %q", msg)
	}
	if _, msg := planDatabase(nil, nil, &targetState{}, reqID); !strings.Contains(msg, "no such database") {
		t.Errorf("absent: %q", msg)
	}
}

func TestClientMessage(t *testing.T) {
	cases := []struct{ in, want, not string }{
		{"Code: 27. DB::Exception: Cannot parse input: expected '\\t' before: 'secret-row-value': (at row 1)\n: While executing ParallelParsingBlockInputFormat. (CANNOT_PARSE_INPUT_ASSERTION_FAILED)\n(query: INSERT INTO shop.t FORMAT Native)",
			"Code: 27 (CANNOT_PARSE_INPUT_ASSERTION_FAILED); the client's message is not shown", "secret-row-value"},
		{"Code: 210. DB::NetException: SSL Exception: error:0A000086:SSL routines::certificate verify failed (127.0.0.1:4321). (NETWORK_ERROR)",
			"Code: 210. DB::NetException: SSL Exception: error:0A000086:SSL routines::certificate verify failed", ""},
		{"Code: 516. DB::Exception: Received from 127.0.0.1:1. DB::Exception: olympos: Authentication failed. (AUTHENTICATION_FAILED)", "Authentication failed", ""},
		{"Bad arguments: unrecognised option 'secret-row'", "no error code", "secret-row"},
		{"Code: 36. DB::Exception: Cannot convert 'secret-row' (BAD_ARGUMENTS)", "Code: 36 (BAD_ARGUMENTS)", "secret-row"},
	}
	for _, c := range cases {
		got := clientMessage(c.in)
		if !strings.Contains(got, c.want) || (c.not != "" && strings.Contains(got, c.not)) {
			t.Errorf("clientMessage(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadManifest(t *testing.T) {
	b := newFakeBackup()
	b.m.DryRun = true
	if _, err := readManifest(b.entries(t)); err == nil || !strings.Contains(err.Error(), "dry run") {
		t.Fatalf("dry run: %v", err)
	}
	b = newFakeBackup()
	b.m.Format = "other"
	if _, err := readManifest(b.entries(t)); err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("format: %v", err)
	}
	if _, err := readManifest(map[string]*zip.File{}); err == nil {
		t.Fatal("no manifest")
	}
}

// fakeRun runs plans with a step function in place of the target.
func fakeRun(plans []*dbPlan, fn func(st step) error) (*backup.RestoreResult, []string) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Created: []string{}}
	for _, p := range plans {
		res.Items = append(res.Items, backup.RestoreItem{Name: p.db.Name, Status: "failed"})
	}
	var calls []string
	r := &restorer{rc: backup.RestoreContext{Progress: func(backup.Progress) {}}, res: res, items: map[string]*backup.RestoreItem{}}
	for i := range res.Items {
		r.items[res.Items[i].Name] = &res.Items[i]
	}
	r.stepFn = func(_ context.Context, st step) error {
		calls = append(calls, st.String())
		return fn(st)
	}
	r.run(context.Background(), plans)
	return res, calls
}

func twoPlans() []*dbPlan {
	obj := func(db, name, kind string, data bool) *objPlan {
		t := Table{Name: name, Kind: kind, Engine: "MergeTree"}
		if data {
			t.HasData = true
			t.Partitions = []Partition{{ID: "all", Entry: "data/x", Rows: 1}}
		}
		return &objPlan{db: db, t: t, target: name}
	}
	a := &dbPlan{db: Database{Name: "a"}, create: databaseSQL("a"), objs: []*objPlan{obj("a", "t", KindTable, true), obj("a", "u", KindTable, false)}}
	b := &dbPlan{db: Database{Name: "b"}, create: databaseSQL("b"), objs: []*objPlan{obj("b", "t", KindTable, true)}}
	return []*dbPlan{a, b}
}

func TestRunStopsAtTheFirstFailure(t *testing.T) {
	res, calls := fakeRun(twoPlans(), func(st step) error {
		if st.String() == "data a.t" {
			return errors.New("3 rows written, the backup holds 4")
		}
		return nil
	})
	if strings.Join(calls, ",") != "database a,database b,table a.t,table a.u,table b.t,data a.t" {
		t.Fatalf("calls: %v", calls)
	}
	a, b := res.Items[0], res.Items[1]
	if a.Status != "failed" || a.Error != "a.t (data): 3 rows written, the backup holds 4" {
		t.Fatalf("a: %+v", a)
	}
	if b.Status != "failed" || !strings.Contains(b.Error, "the restore stopped after a.t failed") {
		t.Fatalf("b: %+v", b)
	}
	// a finished, b fails: a stays succeeded.
	res, _ = fakeRun(twoPlans(), func(st step) error {
		if st.String() == "data b.t" {
			return errors.New("boom")
		}
		return nil
	})
	if res.Items[0].Status != "succeeded" || res.Items[1].Status != "failed" || res.Items[1].Error != "b.t (data): boom" {
		t.Fatalf("result: %+v", res.Items)
	}
}

// TestCreateError: a refused CREATE is reported by error code and name,
// never with the server's message.
func TestCreateError(t *testing.T) {
	exc := &ch.Exception{Code: proto.ErrBadArguments, Name: "DB::Exception", Message: "DB::Exception: file contents: root:x:0:0"}
	got := createError(fmt.Errorf("query: %w", exc)).Error()
	if got != "the target refused it: Code 36 BAD_ARGUMENTS" {
		t.Fatalf("createError = %q", got)
	}
	if got := createError(&ch.Exception{Code: proto.Error(999999), Message: "secret"}).Error(); got != "the target refused it: Code 999999 UNKNOWN" {
		t.Fatalf("unknown code: %q", got)
	}
	conn := errors.New("read: connection reset by peer")
	if got := createError(conn); got != conn {
		t.Fatalf("connection error: %v", got)
	}
}

// TestPlanDatabaseEngine: a database is created with the Atomic engine,
// whatever the backup's was, and the result says so.
func TestPlanDatabaseEngine(t *testing.T) {
	b := newFakeBackup()
	b.db("old", "Ordinary")
	b.files["schema/old.sql"] = "CREATE DATABASE old ENGINE = Ordinary COMMENT 'x' SETTINGS evil = file('/etc/passwd')"
	p, msg := planDatabase(&b.m.Databases[0], b.entries(t), &targetState{dbs: map[string]targetDB{}}, reqID)
	if msg != "" || p.create != "CREATE DATABASE `old` ENGINE = Atomic" ||
		!strings.Contains(strings.Join(p.notes, "\n"), "old: created with the Atomic database engine (the backup's was Ordinary)") {
		t.Fatalf("%q %q %v", msg, p.create, p.notes)
	}
	if got := databaseSQL("we`ird\nname"); got != "CREATE DATABASE `we\\`ird\\x0aname` ENGINE = Atomic" {
		t.Fatalf("databaseSQL: %s", got)
	}
}

// A schema entry over maxSchemaEntry is not read (readSmall refuses it from
// its size, before opening it), so the table that needs its engine
// parameters is reported, not created; one of exactly the cap is read.
func TestPlanOversizedSchemaEntry(t *testing.T) {
	plan := func(entryBytes int) *dbPlan {
		b := newFakeBackup()
		shop := b.db("shop", "Atomic")
		const head = "CREATE TABLE shop.t (`k` UInt8) "
		const tail = "ENGINE = ReplacingMergeTree(k) ORDER BY k"
		// obj appends ";\n" to the statement.
		ddl := head + strings.Repeat(" ", entryBytes-len(head)-len(tail)-2) + tail
		b.obj(shop, Table{Name: "t", Kind: KindTable, Engine: "ReplacingMergeTree", SortingKey: "k", PrimaryKey: "k",
			Columns: []Column{{Name: "k", Type: "UInt8"}}}, ddl)
		p, msg := planDatabase(&b.m.Databases[0], b.entries(t), &targetState{dbs: map[string]targetDB{}}, reqID)
		if msg != "" {
			t.Fatal(msg)
		}
		return p
	}
	if p := plan(maxSchemaEntry); len(p.objs) != 1 || len(p.skipped) != 0 {
		t.Errorf("entry of the cap: %d tables, skipped %q", len(p.objs), p.skipped)
	}
	p := plan(maxSchemaEntry + 1)
	if len(p.objs) != 0 || len(p.skipped) != 1 || !strings.Contains(p.skipped[0], "its engine parameters could not be read from its schema entry; not created") {
		t.Errorf("entry over the cap: %d tables, skipped %q", len(p.objs), p.skipped)
	}
}

// The settings that keep a restore from losing columns or data silently.
func TestRestoreSettings(t *testing.T) {
	has := map[string]string{}
	for _, s := range ddlSettings {
		has[s.Key] = s.Value
	}
	if has["flatten_nested"] != "0" {
		t.Errorf("ddlSettings must set flatten_nested = 0: %v", ddlSettings)
	}
	if _, ok := has["allow_suspicious_codecs"]; ok {
		t.Errorf("ddlSettings sets allow_suspicious_codecs, and no codec is generated")
	}
	if !slices.Contains(insertSettings, "--input_format_skip_unknown_fields=0") {
		t.Errorf("insertSettings must not skip unknown fields: %v", insertSettings)
	}
}
