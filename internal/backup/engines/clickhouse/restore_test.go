package clickhouse

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	b.obj(shop, Table{Name: "events", Kind: KindTable, Engine: "MergeTree",
		Columns: []Column{{Name: "d", Type: "Date"}, {Name: "x", Type: "UInt64"}, {Name: "x2", Type: "UInt64", DefaultKind: "MATERIALIZED", DefaultExpression: "x * 2"}}},
		"CREATE TABLE shop.events (`d` Date, `x` UInt64) ENGINE = MergeTree PARTITION BY d ORDER BY x", 3, 0, 2)
	b.obj(shop, Table{Name: "agg", Kind: KindTable, Engine: "AggregatingMergeTree", DataFormat: FormatRowBinary},
		"CREATE TABLE shop.agg (`k` UInt8, `u` AggregateFunction(uniq, UInt64)) ENGINE = AggregatingMergeTree ORDER BY k", 4)
	b.obj(shop, Table{Name: "r", Kind: KindTable, Engine: "ReplicatedMergeTree"},
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
	b.obj(shop, Table{Name: ".inner_id.11111111-1111-1111-1111-111111111111", Kind: KindMVInner, Engine: "SummingMergeTree", InnerOf: "mv"},
		"CREATE TABLE shop.`.inner_id.11111111-1111-1111-1111-111111111111` (`d` Date, `c` UInt64) ENGINE = SummingMergeTree ORDER BY d", 2)
	// Reads the Kafka table, which is not created: not created either.
	b.obj(shop, Table{Name: "mv_k", Kind: KindMaterializedView, Engine: "MaterializedView"},
		"CREATE MATERIALIZED VIEW shop.mv_k TO shop.events (`d` Date, `x` UInt64) AS SELECT toDate(now()) AS d, length(x) AS x FROM shop.k")
	// Reads the view above, which is not created.
	b.obj(shop, Table{Name: "mv_k2", Kind: KindMaterializedView, Engine: "MaterializedView"},
		"CREATE MATERIALIZED VIEW shop.mv_k2 (`d` Date) ENGINE = Memory AS SELECT d FROM shop.mv_k")
	return b
}

func TestPlanDatabaseAndSteps(t *testing.T) {
	b := shopBackup()
	entries := b.entries(t)
	ts := &targetState{dbs: map[string]targetDB{}}
	p, msg := planDatabase(&b.m.Databases[0], entries, ts, map[string]bool{"shop": true}, reqID)
	if msg != "" {
		t.Fatal(msg)
	}
	plans := []*dbPlan{p}
	dropUnsatisfied(plans)
	var got []string
	for _, s := range steps(plans) {
		got = append(got, s.String())
	}
	want := []string{
		"database shop",
		"table shop.events", "table shop.agg", "table shop.r",
		"data shop.events", "data shop.agg", "data shop.r",
		"dictionary shop.users_dict", "dictionary shop.dt",
		"view shop.v",
		"materialized view shop.mv",
		"inner data shop.mv",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("steps:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	skipped := strings.Join(p.skipped, "\n")
	for _, w := range []string{"shop.k (table): engine Kafka", "shop.mv_k (materialized view): it uses shop.k", "shop.mv_k2 (materialized view): it uses shop.mv_k"} {
		if !strings.Contains(skipped, w) {
			t.Errorf("skipped lacks %q:\n%s", w, skipped)
		}
	}
	if strings.Contains(skipped, "broker") || strings.Contains(skipped, "kafka-secret") {
		t.Fatalf("skipped carries DDL: %s", skipped)
	}
	notes := strings.Join(p.notes, "\n")
	if !strings.Contains(notes, "shop.r: its Keeper path was moved under /olympos-restore/"+reqID+"/") ||
		!strings.Contains(notes, "shop.users_dict: the backup holds a secret") ||
		!strings.Contains(notes, "shop.events: MATERIALIZED columns (x2)") {
		t.Fatalf("notes: %s", notes)
	}
	for _, o := range p.objs {
		if o.t.Name == "r" && !strings.Contains(o.st.sql(), "'/olympos-restore/"+reqID+"/clickhouse/tables/{uuid}/{shard}'") {
			t.Fatalf("r: %s", o.st.sql())
		}
		if o.t.Name == "mv" && (o.inner == nil || o.inner.Rows != 2) {
			t.Fatalf("mv inner: %+v", o.inner)
		}
	}
	if p.create == nil || p.create.sql() != "CREATE DATABASE `shop`\nENGINE = Atomic" {
		t.Fatalf("create: %+v", p.create)
	}

	// An existing empty database is restored into, without CREATE DATABASE.
	ts.dbs["shop"] = targetDB{engine: "Atomic"}
	p, msg = planDatabase(&b.m.Databases[0], entries, ts, map[string]bool{"shop": true}, reqID)
	if msg != "" || !p.exists || p.create != nil {
		t.Fatalf("existing empty: %q %+v", msg, p)
	}
	if s := steps([]*dbPlan{p}); s[0].String() != "table shop.events" {
		t.Fatalf("first step: %s", s[0])
	}
}

func TestPlanDatabaseRefuses(t *testing.T) {
	restored := map[string]bool{"shop": true}
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
		{"wrong name in DDL", func(b *fakeBackup, ts *targetState) {
			b.files["schema/shop/events.sql"] = "CREATE TABLE shop.other (`x` UInt8) ENGINE = MergeTree ORDER BY x"
		}, "events: the schema entry creates shop.other, not shop.events"},
		{"two statements", func(b *fakeBackup, ts *targetState) {
			b.files["schema/shop/v.sql"] = "CREATE VIEW shop.v AS SELECT 1; DROP DATABASE other"
		}, "more than one statement"},
		{"other database", func(b *fakeBackup, ts *targetState) {
			b.files["schema/shop.sql"] = "CREATE DATABASE other ENGINE = Atomic"
		}, "creates database other"},
		{"missing data entry", func(b *fakeBackup, ts *targetState) { delete(b.files, "data/shop/events/c.native") }, "missing from the backup"},
		{"data entry of another table", func(b *fakeBackup, ts *targetState) {
			b.m.Databases[0].Tables[0].Partitions[0].Entry = "data/shop/agg/a.native"
		}, "missing from the backup"},
		{"wrong size", func(b *fakeBackup, ts *targetState) { b.files["data/shop/events/a.native"] = "xx" }, "has 2 bytes"},
		{"rows disagree", func(b *fakeBackup, ts *targetState) { b.m.Databases[0].Tables[0].Rows = 99 }, "hold 5 rows, its table 99"},
		{"ReplacingMergeTree replaced by Log", func(b *fakeBackup, ts *targetState) { b.m.Databases[0].Tables[0].Engine = "Log" }, "the backup recorded Log"},
	}
	for _, c := range cases {
		b := shopBackup()
		ts := &targetState{dbs: map[string]targetDB{}}
		c.mod(b, ts)
		_, msg := planDatabase(&b.m.Databases[0], b.entries(t), ts, restored, reqID)
		if !strings.Contains(msg, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, msg, c.want)
		}
	}
	// A Replicated table without a request id.
	b := shopBackup()
	if _, msg := planDatabase(&b.m.Databases[0], b.entries(t), &targetState{dbs: map[string]targetDB{}}, restored, ""); !strings.Contains(msg, "request's id") {
		t.Errorf("no request id: %q", msg)
	}
	if _, msg := planDatabase(nil, nil, &targetState{}, restored, reqID); !strings.Contains(msg, "no such database") {
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
		return &objPlan{db: db, t: t}
	}
	a := &dbPlan{db: Database{Name: "a"}, create: &createStmt{}, objs: []*objPlan{obj("a", "t", KindTable, true), obj("a", "v", KindView, false)}}
	b := &dbPlan{db: Database{Name: "b"}, create: &createStmt{}, objs: []*objPlan{obj("b", "t", KindTable, true), obj("b", "w", KindView, false)}}
	return []*dbPlan{a, b}
}

func TestRunStopsAtTheFirstFailure(t *testing.T) {
	res, calls := fakeRun(twoPlans(), func(st step) error {
		if st.String() == "data a.t" {
			return errors.New("3 rows written, the backup holds 4")
		}
		return nil
	})
	if strings.Join(calls, ",") != "database a,database b,table a.t,table b.t,data a.t" {
		t.Fatalf("calls: %v", calls)
	}
	a, b := res.Items[0], res.Items[1]
	if a.Status != "failed" || a.Error != "a.t (data): 3 rows written, the backup holds 4" {
		t.Fatalf("a: %+v", a)
	}
	if b.Status != "failed" || !strings.Contains(b.Error, "the restore stopped after a.t failed") {
		t.Fatalf("b: %+v", b)
	}
}

func TestRunRetriesUnknownTables(t *testing.T) {
	tries := 0
	res, calls := fakeRun(twoPlans(), func(st step) error {
		if st.String() == "view a.v" {
			if tries++; tries == 1 {
				return &ch.Exception{Code: proto.ErrUnknownTable, Name: "UNKNOWN_TABLE", Message: "no b.x yet"}
			}
		}
		return nil
	})
	if res.Items[0].Status != "succeeded" || res.Items[1].Status != "succeeded" || tries != 2 ||
		strings.Join(calls[len(calls)-3:], ",") != "view a.v,view b.w,view a.v" {
		t.Fatalf("result: %+v %v", res.Items, calls)
	}
	// Always unknown: the phase makes no progress and fails.
	res, _ = fakeRun(twoPlans(), func(st step) error {
		if st.String() == "view a.v" {
			return &ch.Exception{Code: proto.ErrUnknownTable, Name: "UNKNOWN_TABLE", Message: "no b.x"}
		}
		return nil
	})
	// b finished all its steps.
	if res.Items[0].Status != "failed" || !strings.Contains(res.Items[0].Error, "a.v (view)") || res.Items[1].Status != "succeeded" {
		t.Fatalf("result: %+v", res.Items)
	}
}
