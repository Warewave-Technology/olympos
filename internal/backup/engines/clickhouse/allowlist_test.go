package clickhouse

import (
	"maps"
	"reflect"
	"strings"
	"testing"
)

// The restore allowlist (design docs/design/clickhouse-native.md, Owner
// decision option 1): every case asserts the exact reason, so a rule that
// stops matching shows up as a changed reason, not only as a changed
// verdict.

const alRun = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"

// missingDDL marks an object whose definition is not in the ddl map.
const missingDDL = "\x00missing"

type alObj struct{ db, name, kind, ddl string }

func alKey(db, name string) string {
	return alRun + "/metadata/" + escapeForFileName(db) + "/" + escapeForFileName(name) + ".sql"
}

// classifyObjs lists objs in the manifest's form (databases in the order
// they first appear) and classifies them.
func classifyObjs(objs []alObj) []Decision {
	var dbs []NativeDatabase
	at := map[string]int{}
	ddl := map[string][]byte{}
	for _, o := range objs {
		i, ok := at[o.db]
		if !ok {
			i = len(dbs)
			at[o.db] = i
			dbs = append(dbs, NativeDatabase{Name: o.db})
		}
		key := alKey(o.db, o.name)
		dbs[i].Objects = append(dbs[i].Objects, NativeObject{Name: o.name, Kind: o.kind, DDLKey: key})
		if o.ddl != missingDDL {
			ddl[key] = []byte(o.ddl)
		}
	}
	return Classify(dbs, ddl)
}

func decisionOf(t *testing.T, got []Decision, db, name string) Decision {
	t.Helper()
	for _, d := range got {
		if d.Database == db && d.Name == name {
			return d
		}
	}
	t.Fatalf("no decision for %s.%s in %+v", db, name, got)
	return Decision{}
}

// alBase is the backup every case adds to: restored tables, a table and a
// dictionary left out, and a dictionary and a view on the restored set.
var alBase = []alObj{
	{"db", "events", KindTable, "CREATE TABLE db.events UUID '2ed0ba03-27bb-41a6-93da-0581520543d1' (`id` UInt64, `arr` Array(UInt8), `arr2` Array(UInt8)) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192"},
	{"db", "logs", KindTable, "CREATE TABLE db.logs (`id` UInt64, `msg` String) ENGINE = Log"},
	{"db", "ext", KindTable, "CREATE TABLE db.ext (`id` UInt64) ENGINE = URL('http://example.invalid/x', 'CSV')"},
	{"db", "dict", KindDictionary, "CREATE DICTIONARY db.dict (`id` UInt64, `msg` String) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'db' TABLE 'logs')) LIFETIME(MIN 0 MAX 300) LAYOUT(HASHED())"},
	{"db", "extdict", KindDictionary, "CREATE DICTIONARY db.extdict (`id` UInt64) PRIMARY KEY id SOURCE(HTTP(URL 'http://example.invalid/d' FORMAT 'TSV')) LIFETIME(300) LAYOUT(FLAT())"},
	{"db", "v", KindView, "CREATE VIEW db.v (`id` UInt64) AS SELECT id FROM db.events"},
}

type alCase struct {
	name    string
	objs    []alObj // added to alBase
	check   string  // the object of db checked ("x" when empty)
	allowed bool
	reason  string
}

func runAlCases(t *testing.T, cases []alCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyObjs(append(append([]alObj{}, alBase...), c.objs...))
			name := c.check
			if name == "" {
				name = "x"
			}
			d := decisionOf(t, got, "db", name)
			if d.Allowed != c.allowed || d.Reason != c.reason {
				t.Errorf("db.%s: got allowed=%v reason %q, want allowed=%v reason %q", name, d.Allowed, d.Reason, c.allowed, c.reason)
			}
			if d.Allowed && d.Reason != "" {
				t.Errorf("an allowed object with a reason: %q", d.Reason)
			}
		})
	}
}

func tbl(ddl string) []alObj  { return []alObj{{"db", "x", KindTable, ddl}} }
func view(ddl string) []alObj { return []alObj{{"db", "x", KindView, ddl}} }
func mv(ddl string) []alObj   { return []alObj{{"db", "x", KindMaterializedView, ddl}} }
func dict(ddl string) []alObj { return []alObj{{"db", "x", KindDictionary, ddl}} }

// dictOn is a dictionary on db.x with the given SOURCE and LAYOUT.
func dictOn(source, layout string) []alObj {
	return dict("CREATE DICTIONARY db.x (`id` UInt64, `msg` String) PRIMARY KEY id SOURCE(" + source + ") LIFETIME(MIN 0 MAX 300) LAYOUT(" + layout + ")")
}

func TestClassifyBase(t *testing.T) {
	got := classifyObjs(alBase)
	want := []Decision{
		{Database: "db", Name: "events", Kind: KindTable, Allowed: true},
		{Database: "db", Name: "logs", Kind: KindTable, Allowed: true},
		{Database: "db", Name: "ext", Kind: KindTable, Reason: "the URL engine is not on the restore allowlist"},
		{Database: "db", Name: "dict", Kind: KindDictionary, Allowed: true},
		{Database: "db", Name: "extdict", Kind: KindDictionary, Reason: "its source is HTTP, not a local ClickHouse table"},
		{Database: "db", Name: "v", Kind: KindView, Allowed: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestClassifyTables(t *testing.T) {
	runAlCases(t, []alCase{
		{name: "MergeTree with codecs, TTL, indexes, a projection, settings and a comment", allowed: true, objs: tbl(
			"CREATE TABLE db.x UUID '2ed0ba03-27bb-41a6-93da-0581520543d1' (`id` UInt64, `ts` DateTime DEFAULT now(), " +
				"`user_id` UInt32 CODEC(Delta(4), ZSTD(3)), `payload` String DEFAULT '' CODEC(ZSTD(1)), `e` Enum8('a' = 1, 'b' = 2), " +
				"INDEX idx_user user_id TYPE minmax GRANULARITY 4, INDEX idx_p payload TYPE set(100) GRANULARITY 1, " +
				"PROJECTION p (SELECT user_id, count() GROUP BY user_id)) ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY id " +
				"TTL ts + toIntervalYear(5) SETTINGS index_granularity = 8192, storage_policy = 'default' COMMENT 'events'")},
		{name: "ReplicatedMergeTree", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/db/x', '{replica}') ORDER BY id")},
		{name: "ReplicatedReplacingMergeTree", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64, `v` UInt64) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/x', '{replica}', v) ORDER BY id")},
		{name: "AggregatingMergeTree", allowed: true, objs: tbl("CREATE TABLE db.x (`day` Date, `users` AggregateFunction(uniq, UInt32)) ENGINE = AggregatingMergeTree ORDER BY day SETTINGS index_granularity = 8192")},
		{name: "old MergeTree syntax", allowed: true, objs: tbl("CREATE TABLE db.x (`d` Date, `id` UInt64) ENGINE = MergeTree(d, (id, d), 8192)")},
		{name: "Log", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = Log")},
		{name: "TinyLog", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = TinyLog")},
		{name: "StripeLog", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = StripeLog")},
		{name: "Memory", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = Memory")},
		{name: "Memory with settings", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = Memory SETTINGS max_rows_to_keep = 100")},
		{name: "the disk named default", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS disk = 'default'")},
		{name: "a quoted identifier holding url(", allowed: true, objs: tbl("CREATE TABLE db.x (`url(` String, `s3('a')` String) ENGINE = Log")},
		{name: "a string holding s3(", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64, `s` String DEFAULT 's3(\\'http://x\\')') ENGINE = Log")},
		{name: "a table named like a table function", check: "file", allowed: true, objs: []alObj{{"db", "file", KindTable, "CREATE TABLE db.file (`id` UInt64) ENGINE = Log"}}},
		{name: "a projection named like a table function", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64, PROJECTION file (SELECT id ORDER BY id)) ENGINE = MergeTree ORDER BY id")},
		{name: "a default from a restored dictionary", allowed: true, objs: tbl("CREATE TABLE db.x (`id` UInt64, `msg` String DEFAULT dictGet('db.dict', 'msg', id)) ENGINE = Log")},

		// R47: a Graphite table needs the target's graphite_rollup
		// configuration, which Olympos does not know; what reads it drops.
		{name: "GraphiteMergeTree", reason: "the GraphiteMergeTree engine needs the graphite_rollup configuration on the target server", objs: tbl("CREATE TABLE db.x (`Path` String, `Time` DateTime, `Value` Float64, `Version` UInt32) ENGINE = GraphiteMergeTree('graphite_rollup') ORDER BY (Path, Time)")},
		{name: "ReplicatedGraphiteMergeTree", reason: "the ReplicatedGraphiteMergeTree engine needs the graphite_rollup configuration on the target server", objs: tbl("CREATE TABLE db.x (`Path` String, `Time` DateTime, `Value` Float64, `Version` UInt32) ENGINE = ReplicatedGraphiteMergeTree('/clickhouse/x', '{replica}', 'graphite_rollup') ORDER BY (Path, Time)")},
		{name: "a view on a Graphite table", check: "gv", reason: "it reads db.x, which is not restored", objs: []alObj{
			{"db", "x", KindTable, "CREATE TABLE db.x (`Path` String, `Time` DateTime, `Value` Float64, `Version` UInt32) ENGINE = GraphiteMergeTree('graphite_rollup') ORDER BY (Path, Time)"},
			{"db", "gv", KindView, "CREATE VIEW db.gv AS SELECT Path FROM db.x"},
		}},
		{name: "an MV with an inner Graphite table", reason: "the GraphiteMergeTree engine needs the graphite_rollup configuration on the target server", objs: mv("CREATE MATERIALIZED VIEW db.x (`Path` String, `Time` DateTime, `Value` Float64, `Version` UInt32) ENGINE = GraphiteMergeTree('graphite_rollup') ORDER BY (Path, Time) AS SELECT toString(id) AS Path, now() AS Time, 0. AS Value, 1 AS Version FROM db.events")},
		// R49: an encryption codec needs the target's keys.
		{name: "AES_128_GCM_SIV", reason: "its AES_128_GCM_SIV codec needs encryption keys on the target server", objs: tbl("CREATE TABLE db.x (`id` UInt64, `secret` String CODEC(AES_128_GCM_SIV)) ENGINE = MergeTree ORDER BY id")},
		{name: "AES_256_GCM_SIV after other codecs", reason: "its AES_256_GCM_SIV codec needs encryption keys on the target server", objs: tbl("CREATE TABLE db.x (`id` UInt64 CODEC(Delta(8), ZSTD(3), AES_256_GCM_SIV)) ENGINE = Log")},
		{name: "a view on an encrypted table", check: "ev", reason: "it reads db.x, which is not restored", objs: []alObj{
			{"db", "x", KindTable, "CREATE TABLE db.x (`id` UInt64, `secret` String CODEC(AES_128_GCM_SIV)) ENGINE = MergeTree ORDER BY id"},
			{"db", "ev", KindView, "CREATE VIEW db.ev AS SELECT id FROM db.x"},
		}},
		{name: "a backquoted encryption codec", reason: "its AES_256_GCM_SIV codec needs encryption keys on the target server",
			objs: tbl("CREATE TABLE db.x (`id` UInt64, `secret` String CODEC(`AES_256_GCM_SIV`)) ENGINE = MergeTree ORDER BY id")},
		{name: "a double-quoted encryption codec", reason: "its AES_128_GCM_SIV codec needs encryption keys on the target server",
			objs: tbl("CREATE TABLE db.x (`id` UInt64, `secret` String CODEC(Delta, \"aes_128_gcm_siv\")) ENGINE = MergeTree ORDER BY id")},
		{name: "another quoted codec", reason: reasonUncertain,
			objs: tbl("CREATE TABLE db.x (`id` UInt64, `s` String CODEC(`ZSTD`(1))) ENGINE = MergeTree ORDER BY id")},
		{name: "a column named like an encryption codec", allowed: true, objs: tbl("CREATE TABLE db.x (`AES_128_GCM_SIV` String CODEC(ZSTD(1)), `s` String DEFAULT 'AES_256_GCM_SIV') ENGINE = MergeTree ORDER BY AES_128_GCM_SIV")},
		{name: "inline disk", reason: "its settings define a disk inline", objs: tbl(
			"CREATE TABLE db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS disk = disk(type = s3, endpoint = 'http://example.invalid/b/', access_key_id = 'a', secret_access_key = 'b'), index_granularity = 8192")},
		{name: "inline disk on a Log", reason: "its settings define a disk inline", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = Log SETTINGS disk = disk(type = local, path = '/tmp/x/')")},
		{name: "named disk", reason: "its settings put it on the disk s3disk", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS disk = 's3disk'")},
		{name: "named disk on a Log", reason: "its settings put it on the disk cold", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = StripeLog SETTINGS disk = 'cold'")},
		{name: "storage policy", reason: "its storage policy s3_main is not the default", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192, storage_policy = 's3_main'")},
		{name: "storage policy not a string", reason: "cannot be parsed with certainty", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS storage_policy = s3_main")},
		{name: "a query in a default", reason: "its definition holds a query", objs: tbl("CREATE TABLE db.x (`id` UInt64, `m` UInt64 DEFAULT (SELECT max(id) FROM db.events)) ENGINE = Log")},
		{name: "a table function in a default", reason: "it calls file, which reads outside the restored set", objs: tbl("CREATE TABLE db.x (`id` UInt64, `s` String DEFAULT file('secret.txt')) ENGINE = Log")},
		{name: "a default from a dictionary left out", reason: "it reads db.extdict, which is not restored", objs: tbl("CREATE TABLE db.x (`id` UInt64, `s` String DEFAULT dictGet('db.extdict', 's', id)) ENGINE = Log")},
		{name: "a table over a table function", reason: "a table over the table function url", objs: tbl("CREATE TABLE db.x (`id` UInt64) AS url('http://example.invalid/y', CSV, 'id UInt64')")},
		{name: "a table as another", reason: "cannot be parsed with certainty", objs: tbl("CREATE TABLE db.x (`id` UInt64) AS db.events")},
		{name: "a table with its query", reason: "cannot be parsed with certainty", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id AS SELECT id FROM db.events")},
		{name: "an unknown clause", reason: "cannot be parsed with certainty", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = Log WHATEVER 1")},
		{name: "engine case", reason: "the mergetree engine is not on the restore allowlist", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = mergetree ORDER BY id")},
		{name: "quoted engine", reason: "cannot be parsed with certainty", objs: tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = `MergeTree` ORDER BY id")},
		{name: "no engine", reason: "cannot be parsed with certainty", objs: tbl("CREATE TABLE db.x (`id` UInt64)")},
	})
}

func TestClassifyEnginesLeftOut(t *testing.T) {
	var cases []alCase
	for _, e := range []struct{ engine, args string }{
		{"Distributed", "('c', 'db', 'events', rand())"},
		{"Kafka", "('k:9092', 'topic', 'g', 'JSONEachRow')"},
		{"URL", "('http://example.invalid/x', 'CSV')"},
		{"S3", "('http://example.invalid/b/x.csv', 'CSV')"},
		{"MySQL", "('h:3306', 'db', 't', 'u', 'p')"},
		{"PostgreSQL", "('h:5432', 'db', 't', 'u', 'p')"},
		{"MongoDB", "('h:27017', 'db', 'c', 'u', 'p')"},
		{"HDFS", "('hdfs://h:9000/x', 'TSV')"},
		{"RabbitMQ", ""},
		{"NATS", ""},
		{"File", "(CSV)"},
		{"Executable", "('script.sh', 'TSV', (SELECT 1))"},
		{"ExecutablePool", "('script.sh', 'TSV', (SELECT 1))"},
		{"Buffer", "(db, events, 1, 10, 100, 10000, 1000000, 10000000, 100000000)"},
		{"Merge", "('db', '^ev')"},
		{"Null", ""},
		{"Set", ""},
		{"Join", "(ANY, LEFT, id)"},
		{"Dictionary", "(db.dict)"},
		{"SharedMergeTree", ""},
		{"EmbeddedRocksDB", ""},
		{"SQLite", "('/x.db', 't')"},
	} {
		cases = append(cases, alCase{
			name:   e.engine,
			objs:   tbl("CREATE TABLE db.x (`id` UInt64) ENGINE = " + e.engine + e.args),
			reason: "the " + e.engine + " engine is not on the restore allowlist",
		})
	}
	runAlCases(t, cases)
}

func TestClassifyViews(t *testing.T) {
	runAlCases(t, []alCase{
		{name: "a view on a restored table", allowed: true, objs: view("CREATE VIEW db.x UUID '59ceceba-0bb1-42b7-a667-1067790fc917' (`id` UInt64) AS SELECT id FROM db.events WHERE id > (now() - toIntervalDay(1))")},
		{name: "a view on a view", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.v")},
		{name: "unqualified names are of the view's database", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM events")},
		{name: "backquoted names", allowed: true, objs: view("CREATE VIEW db.x AS SELECT `id` FROM `db`.`events` AS `e`")},
		{name: "joins, a comma join, subqueries and IN", allowed: true, objs: view(
			"CREATE VIEW db.x AS SELECT e.id FROM db.events AS e INNER JOIN db.logs AS l ON e.id = l.id, db.v AS w " +
				"LEFT JOIN (SELECT id FROM db.logs) AS s USING (id) WHERE e.id IN (SELECT id FROM db.v) AND e.id NOT IN db.logs " +
				"AND EXISTS (SELECT 1 FROM db.events) GROUP BY e.id ORDER BY e.id ASC LIMIT 10")},
		{name: "a union", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events UNION ALL SELECT id FROM db.logs UNION DISTINCT (SELECT id FROM db.v)")},
		{name: "array join with several arrays", allowed: true, objs: view("CREATE VIEW db.x AS SELECT a, b FROM db.events ARRAY JOIN arr AS a, arr2 AS b WHERE a > 0")},
		{name: "a CTE shadowing a table left out", allowed: true, objs: view("CREATE VIEW db.x AS WITH ext AS (SELECT id FROM db.events) SELECT id FROM ext")},
		{name: "a CTE reading an earlier CTE", allowed: true, objs: view("CREATE VIEW db.x AS WITH a AS (SELECT id FROM db.events), b AS (SELECT id FROM a) SELECT id FROM b")},
		{name: "a scalar WITH", allowed: true, objs: view("CREATE VIEW db.x AS WITH 10 AS lim, (SELECT max(id) FROM db.logs) AS m SELECT id FROM db.events WHERE id < m LIMIT 5 WITH TIES")},
		{name: "dictGet on a restored dictionary", allowed: true, objs: view("CREATE VIEW db.x AS SELECT dictGet('db.dict', 'msg', id) AS m FROM db.events")},
		{name: "a string holding s3(", allowed: true, objs: view("CREATE VIEW db.x AS SELECT 's3(\\'http://example.invalid/b\\')' AS a, 'FROM url(x)' AS b FROM db.events")},
		{name: "a quoted identifier holding url(", allowed: true, objs: view("CREATE VIEW db.x AS SELECT `url(` FROM db.events")},
		{name: "a function named like a column", allowed: true, objs: view("CREATE VIEW db.x AS SELECT format('{} {}', id, id) AS f, arrayMap(x -> (x + 1), arr) AS a FROM db.events FINAL")},
		{name: "definer and SQL security", allowed: true, objs: view("CREATE VIEW db.x (`id` UInt64) DEFINER = alice SQL SECURITY DEFINER AS SELECT id FROM db.events")},
		{name: "APPLY with a lambda and a parametric function", allowed: true, objs: view("CREATE VIEW db.x AS SELECT * APPLY(x -> toString(x)) APPLY(quantile(0.9)) FROM db.logs")},
		{name: "IN tuple(", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN tuple(1, 2) AND id NOT IN array(3)")},
		{name: "IN a tuple", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN (1, 2) AND (id, id) IN ((1, 1), (2, 2))")},
		{name: "no table at all", allowed: true, objs: view("CREATE VIEW db.x AS SELECT 1 AS one")},

		{name: "url(", reason: "it reads the table function url", objs: view("CREATE VIEW db.x AS SELECT * FROM url('http://example.invalid/x', CSV, 'id UInt64')")},
		{name: "s3(", reason: "it reads the table function s3", objs: view("CREATE VIEW db.x AS SELECT * FROM s3('http://example.invalid/b/x.csv', 'CSV')")},
		{name: "remote(", reason: "it reads the table function remote", objs: view("CREATE VIEW db.x AS SELECT * FROM remote('h:9000', db.events)")},
		{name: "file(", reason: "it reads the table function file", objs: view("CREATE VIEW db.x AS SELECT * FROM file('a.csv', CSV)")},
		{name: "cluster(", reason: "it reads the table function cluster", objs: view("CREATE VIEW db.x AS SELECT * FROM cluster('c', db.events)")},
		{name: "input(", reason: "it reads the table function input", objs: view("CREATE VIEW db.x AS SELECT * FROM input('id UInt64')")},
		{name: "numbers(", reason: "it reads the table function numbers", objs: view("CREATE VIEW db.x AS SELECT number FROM numbers(10)")},
		{name: "a backquoted table function", reason: "it reads the table function url", objs: view("CREATE VIEW db.x AS SELECT * FROM `url`('http://example.invalid/x', CSV)")},
		{name: "a table function in a join", reason: "it reads the table function postgresql", objs: view("CREATE VIEW db.x AS SELECT e.id FROM db.events AS e JOIN postgresql('h:5432', 'db', 't', 'u', 'p') AS p ON e.id = p.id")},
		{name: "a table function after a comma", reason: "it reads the table function mysql", objs: view("CREATE VIEW db.x AS SELECT 1 FROM db.events AS e, mysql('h:3306', 'db', 't', 'u', 'p') AS m")},
		{name: "a table function inside a subquery", reason: "it reads the table function remoteSecure", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN (SELECT id FROM remoteSecure('h:9440', db.events))")},
		{name: "a table function inside a scalar subquery", reason: "it reads the table function clusterAllReplicas", objs: view("CREATE VIEW db.x AS SELECT (SELECT count() FROM clusterAllReplicas('c', system.one)) AS n FROM db.events")},
		{name: "a table function in a CTE", reason: "it reads the table function s3", objs: view("CREATE VIEW db.x AS WITH a AS (SELECT * FROM s3('http://example.invalid/b/x')) SELECT * FROM a")},
		{name: "a table function after IN", reason: "it reads the table function url", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN url('http://example.invalid/ids', CSV, 'id UInt64')")},
		{name: "IN merge(", reason: "it reads the table function merge", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN merge('db', '^ex')")},
		{name: "IN numbers(", reason: "it reads the table function numbers", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id NOT IN numbers(10)")},
		{name: "IN a table function not on any list", reason: "it reads the table function someNewFn", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id GLOBAL IN someNewFn(1)")},
		{name: "IN view(", reason: "it reads the table function view", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN view(SELECT id FROM db.events)")},
		{name: "IN dictionary(", reason: "it reads the table function dictionary", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN dictionary('db.extdict')")},
		{name: "IN a qualified function", reason: "it reads the table function f", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id IN db.f(1)")},
		{name: "file() as a scalar", reason: "it calls file, which reads outside the restored set", objs: view("CREATE VIEW db.x AS SELECT file('secret.txt') AS s FROM db.events")},
		{name: "hasColumnInTable with a host", reason: "it calls hasColumnInTable, which reads outside the restored set", objs: view("CREATE VIEW db.x AS SELECT hasColumnInTable('h', 'db', 't', 'c') AS h")},
		{name: "APPLY(file)", reason: "it calls file, which reads outside the restored set", objs: view("CREATE VIEW db.x AS SELECT * APPLY(file) FROM db.logs")},
		{name: "APPLY file", reason: "it calls file, which reads outside the restored set", objs: view("CREATE VIEW db.x AS SELECT COLUMNS('msg') APPLY file FROM db.logs")},
		{name: "APPLY dictGet", reason: "it calls dictGet on a name Olympos cannot read", objs: view("CREATE VIEW db.x AS SELECT * APPLY(dictGet) FROM db.logs")},
		{name: "a comment inside FROM", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT id FROM /* url( */ db.events")},
		{name: "a line comment", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events -- x\n")},
		{name: "a view on a table outside the backup", reason: "it reads other.t, which is not in the backup", objs: view("CREATE VIEW db.x AS SELECT id FROM other.t")},
		{name: "a view on system", reason: "it reads system.one, which is not in the backup", objs: view("CREATE VIEW db.x AS SELECT dummy FROM system.one")},
		{name: "a view on a table left out", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS SELECT id FROM db.ext")},
		{name: "a join on a table left out", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS SELECT e.id FROM db.events AS e JOIN db.ext AS u ON e.id = u.id")},
		{name: "IN a table left out", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id GLOBAL IN db.ext")},
		{name: "dictGet on a dictionary left out", reason: "it reads db.extdict, which is not restored", objs: view("CREATE VIEW db.x AS SELECT dictGetString('db.extdict', 's', id) AS s FROM db.events")},
		{name: "joinGet on a table left out", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS SELECT joinGet(db.ext, 'v', id) AS s FROM db.events")},
		{name: "dictGet on an expression", reason: "it calls dictGet on a name Olympos cannot read", objs: view("CREATE VIEW db.x AS SELECT dictGet(concat('db.', 'dict'), 'msg', id) AS s FROM db.events")},
		// A CTE is visible in its own SELECT only: the same name in the
		// outer query or another branch of a union is a table.
		{name: "a CTE does not reach the outer query", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS SELECT id FROM ext WHERE id IN (WITH ext AS (SELECT id FROM db.events) SELECT id FROM ext)")},
		{name: "a CTE does not reach another union branch", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS WITH ext AS (SELECT id FROM db.events) SELECT id FROM ext UNION ALL SELECT id FROM ext")},
		{name: "a qualified name is not a CTE", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS WITH ext AS (SELECT id FROM db.events) SELECT id FROM db.ext")},
		{name: "a CTE does not see itself", reason: "it reads db.ext, which is not restored", objs: view("CREATE VIEW db.x AS WITH ext AS (SELECT id FROM ext) SELECT id FROM ext")},
		{name: "a recursive CTE", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS WITH RECURSIVE r AS (SELECT 1 AS n) SELECT n FROM r")},
		{name: "a function's FROM is a table", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT substring(msg FROM 1) FROM db.logs")},
		{name: "unbalanced parentheses", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT (id FROM db.events")},
		{name: "mismatched brackets", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT (id] FROM db.events")},
		{name: "an unbalanced quote", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT 'a FROM db.events")},
		{name: "two statements", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events; DROP TABLE db.events")},
		{name: "not a query", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS db.events")},
		{name: "query parameters", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id = {p:UInt64}")},
		{name: "a subquery source that is not a query", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT 1 FROM (db.events)")},
		{name: "deep nesting", reason: "cannot be parsed with certainty", objs: view("CREATE VIEW db.x AS SELECT " + strings.Repeat("(", 300) + "1" + strings.Repeat(")", 300))},
	})
}

// TestClassifyFromClause: SAMPLE … OFFSET is part of the table expression,
// and a word after AS is an alias, so neither ends the FROM clause: the
// sources after them are read (security review v0.4, finding 2).
func TestClassifyFromClause(t *testing.T) {
	runAlCases(t, []alCase{
		{name: "SAMPLE as ClickHouse writes it", allowed: true, objs: view("CREATE VIEW db.x (`id` UInt64) AS SELECT id FROM db.events SAMPLE 1 / 2 OFFSET 1 / 2 WHERE id > 0")},
		{name: "SAMPLE a ratio", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events SAMPLE 0.1")},
		{name: "SAMPLE rows, then a comma join", allowed: true, objs: view("CREATE VIEW db.x AS SELECT e.id FROM db.events AS e SAMPLE 10000, db.logs AS l")},
		{name: "FINAL and SAMPLE, then a join", allowed: true, objs: view("CREATE VIEW db.x AS SELECT e.id FROM db.events AS e FINAL SAMPLE 1 / 10 OFFSET 1 / 2 INNER JOIN db.logs AS l ON e.id = l.id LIMIT 10 OFFSET 5")},
		{name: "LIMIT with an offset", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events ORDER BY id LIMIT 5, 10")},

		// The review's reproductions.
		{name: "SAMPLE … OFFSET, then a table", reason: "it reads other.secret, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events SAMPLE 1/2 OFFSET 1/2, other.secret")},
		{name: "SAMPLE … OFFSET, then a table function", reason: "it reads the table function merge",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events SAMPLE 1/2 OFFSET 1/2, merge('system', '^users$')")},
		{name: "SAMPLE 1 OFFSET 0, then a table", reason: "it reads other.secret, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events SAMPLE 1 OFFSET 0, other.secret")},
		{name: "a source aliased limit", reason: "it reads other.secret, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events AS limit, other.secret")},
		{name: "a source aliased offset, then a table function", reason: "it reads the table function remote",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events AS offset, remote('h:9000', system.users)")},
		{name: "SAMPLE … OFFSET in a subquery", reason: "it reads other.secret, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT id FROM db.logs WHERE id IN (SELECT id FROM db.events SAMPLE 1 / 2 OFFSET 1 / 2, other.secret)")},
		{name: "SAMPLE … OFFSET in a union branch", reason: "it reads other.secret, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT id FROM db.logs UNION ALL SELECT id FROM db.events SAMPLE 1 / 2 OFFSET 1 / 2, other.secret")},
		// What Olympos does not read with certainty.
		{name: "a clause word as an alias without AS", reason: reasonUncertain, objs: view("CREATE VIEW db.x AS SELECT * FROM db.events limit, other.secret")},
		{name: "SAMPLE an expression", reason: reasonUncertain, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events SAMPLE id")},
		{name: "SAMPLE OFFSET an expression", reason: reasonUncertain, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events SAMPLE 1 / 2 OFFSET (1 / 2)")},
	})
}

// TestClassifyInForms: the function forms of IN, and a table name in
// brackets after IN, read a table (security review v0.4, finding 3).
// ClickHouse itself writes "x IN db.t" and "in(x, db.t)" as
// "x IN (db.t)".
func TestClassifyInForms(t *testing.T) {
	cases := []alCase{
		{name: "IN (a restored table)", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE (id IN (db.logs)) AND (id GLOBAL NOT IN (db.v))")},
		{name: "in() on a restored table", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE in(id, db.logs)")},
		{name: "in() on a tuple", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE in(id, (1, 2)) AND notIn(id, tuple(3)) AND globalIn(id, [4, 5])")},
		{name: "in() on a subquery", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE globalNotIn(id, (SELECT id FROM db.logs))")},
		{name: "IN a CTE in brackets", allowed: true, objs: view("CREATE VIEW db.x AS WITH c AS (SELECT id FROM db.logs) SELECT id FROM db.events WHERE id IN (c)")},

		// The review's reproductions.
		{name: "in() on a table outside the backup", reason: "it reads other.ids, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE in(id, other.ids)")},
		{name: "IN (a table outside the backup)", reason: "it reads other.ids, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE id IN (other.ids)")},
		{name: "IN ((a table)) outside the backup", reason: "it reads other.ids, which is not in the backup",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE id NOT IN ((other.ids))")},
		{name: "IN (a table left out)", reason: "it reads db.ext, which is not restored",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE id GLOBAL IN (db.ext)")},
		{name: "in() on a table function", reason: "it reads the table function url",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE notIn(id, url('http://example.invalid/ids', CSV, 'id UInt64'))")},
		{name: "in() on a table function in brackets", reason: "it reads the table function numbers",
			objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE in(id, (numbers(10)))")},
		// The operator follows an operand, the function starts one.
		{name: "the operator on a tuple with a call", allowed: true, objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE (id IN (1, toUInt64(2))) AND (toString(id) NOT IN ('a', lower('B')))")},
		{name: "NOT in()", reason: "it reads other.ids, which is not in the backup", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE NOT in(id, other.ids)")},
		{name: "in () after AND", reason: "it reads other.ids, which is not in the backup", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE id > 0 AND in (id, other.ids)")},
		{name: "in() in brackets", reason: "it reads other.ids, which is not in the backup", objs: view("CREATE VIEW db.x AS SELECT id FROM db.events WHERE (in(id, other.ids))")},
		{name: "in() in the select list", reason: "it reads other.ids, which is not in the backup", objs: view("CREATE VIEW db.x AS SELECT in(id, other.ids) AS f FROM db.events")},
		{name: "in() with three arguments", reason: reasonUncertain, objs: view("CREATE VIEW db.x AS SELECT notIn(id, 1, 2) AS f FROM db.events")},
		{name: "in() in a column default", reason: "it reads other.ids, which is not in the backup",
			objs: tbl("CREATE TABLE db.x (`id` UInt64, `f` UInt8 DEFAULT in(id, other.ids)) ENGINE = Log")},
		{name: "IN (a table) in a dictionary's query", reason: "it reads other.ids, which is not in the backup",
			objs: dictOn("CLICKHOUSE(QUERY 'SELECT id, msg FROM db.logs WHERE id IN (other.ids)')", "FLAT()")},
	}
	// Every form of the in family, the global ones too, with a table in
	// brackets or not.
	for _, f := range []string{"in", "notIn", "globalIn", "globalNotIn", "nullIn", "notNullIn", "globalNullIn", "globalNotNullIn",
		"inIgnoreSet", "notInIgnoreSet", "globalInIgnoreSet", "globalNotInIgnoreSet", "nullInIgnoreSet", "notNullInIgnoreSet",
		"globalNullInIgnoreSet", "globalNotNullInIgnoreSet"} {
		for _, arg := range []string{"other.ids", "(other.ids)"} {
			cases = append(cases, alCase{name: f + " " + arg, reason: "it reads other.ids, which is not in the backup",
				objs: view("CREATE VIEW db.x AS SELECT * FROM db.events WHERE " + f + "(id, " + arg + ")")})
		}
	}
	runAlCases(t, cases)
}

func TestClassifyMaterializedViews(t *testing.T) {
	runAlCases(t, []alCase{
		{name: "TO a restored table", allowed: true, objs: mv("CREATE MATERIALIZED VIEW db.x UUID 'f0128b77-346e-4f76-b6ad-18eb944a2104' TO db.logs (`id` UInt64, `msg` String) AS SELECT id, toString(id) AS msg FROM db.events")},
		{name: "TO an unqualified table", allowed: true, objs: mv("CREATE MATERIALIZED VIEW db.x TO logs AS SELECT id, '' AS msg FROM events")},
		{name: "an inner table", allowed: true, objs: mv("CREATE MATERIALIZED VIEW db.x UUID '73f0f9df-cd2d-4d2f-b190-88f9be7a8aae' TO INNER UUID 'e24ac6f2-3215-4237-b418-e0ef2c318dde' (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192 AS SELECT id FROM db.events WHERE id > 900")},
		{name: "an inner table, no TO INNER", allowed: true, objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id AS SELECT id FROM db.events")},
		{name: "an inner table with a codec", allowed: true, objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64 CODEC(Delta(8), ZSTD(1))) ENGINE = ReplacingMergeTree ORDER BY id AS SELECT id FROM db.events")},
		{name: "TO a Replicated table", allowed: true, objs: []alObj{
			{"db", "rt", KindTable, "CREATE TABLE db.rt (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/rt', '{replica}') ORDER BY id"},
			{"db", "x", KindMaterializedView, "CREATE MATERIALIZED VIEW db.x TO db.rt (`id` UInt64) AS SELECT id FROM db.events"},
		}},
		{name: "definer", allowed: true, objs: mv("CREATE MATERIALIZED VIEW db.x TO db.logs (`id` UInt64) DEFINER = alice SQL SECURITY DEFINER AS SELECT id FROM db.events")},
		{name: "a target named file", allowed: true, objs: []alObj{
			{"db", "file", KindTable, "CREATE TABLE db.file (`id` UInt64) ENGINE = Log"},
			{"db", "x", KindMaterializedView, "CREATE MATERIALIZED VIEW db.x TO db.file (`id` UInt64) AS SELECT id FROM db.events"},
		}},

		{name: "reading a table outside the backup", reason: "it reads other.src, which is not in the backup", objs: mv("CREATE MATERIALIZED VIEW db.x TO db.logs (`id` UInt64) AS SELECT id FROM other.src")},
		{name: "reading a table left out", reason: "it reads db.ext, which is not restored", objs: mv("CREATE MATERIALIZED VIEW db.x TO db.logs (`id` UInt64) AS SELECT id FROM db.ext")},
		{name: "TO a table outside the backup", reason: "its target other.t is not in the backup", objs: mv("CREATE MATERIALIZED VIEW db.x TO other.t (`id` UInt64) AS SELECT id FROM db.events")},
		{name: "TO a table left out", reason: "its target db.ext is not restored", objs: mv("CREATE MATERIALIZED VIEW db.x TO db.ext (`id` UInt64) AS SELECT id FROM db.events")},
		{name: "TO a view", reason: "its target db.v is not a table", objs: mv("CREATE MATERIALIZED VIEW db.x TO db.v (`id` UInt64) AS SELECT id FROM db.events")},
		{name: "refreshable", reason: "a refreshable materialized view runs its query on a schedule", objs: mv("CREATE MATERIALIZED VIEW db.x REFRESH EVERY 1 HOUR TO db.logs (`id` UInt64) AS SELECT id FROM db.events")},
		{name: "refreshable, append", reason: "a refreshable materialized view runs its query on a schedule", objs: mv("CREATE MATERIALIZED VIEW db.x REFRESH AFTER 1 MINUTE APPEND TO db.logs (`id` UInt64) AS SELECT id FROM db.events")},
		// R48: RESTORE creates an inner table from the backup's statement,
		// with the source's Keeper path.
		{name: "an inner ReplicatedMergeTree", reason: "its inner table's Replicated engine keeps the backup's Keeper path", objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/x', '{replica}') ORDER BY id AS SELECT id FROM db.events")},
		{name: "an inner Replicated table, TO INNER", reason: "its inner table's Replicated engine keeps the backup's Keeper path", objs: mv("CREATE MATERIALIZED VIEW db.x TO INNER UUID 'e24ac6f2-3215-4237-b418-e0ef2c318dde' (`id` UInt64) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY id AS SELECT id FROM db.events")},
		{name: "a view on an MV with an inner Replicated table", check: "mvv", reason: "it reads db.x, which is not restored", objs: []alObj{
			{"db", "x", KindMaterializedView, "CREATE MATERIALIZED VIEW db.x (`id` UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/x', '{replica}') ORDER BY id AS SELECT id FROM db.events"},
			{"db", "mvv", KindView, "CREATE VIEW db.mvv AS SELECT id FROM db.x"},
		}},
		{name: "an inner table with an encryption codec", reason: "its AES_256_GCM_SIV codec needs encryption keys on the target server", objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64 CODEC(Delta(8), ZSTD(1), AES_256_GCM_SIV)) ENGINE = MergeTree ORDER BY id AS SELECT id FROM db.events")},
		{name: "an inner Kafka table", reason: "the Kafka engine is not on the restore allowlist", objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64) ENGINE = Kafka('k:9092', 't', 'g', 'JSONEachRow') AS SELECT id FROM db.events")},
		{name: "an inner table on a disk", reason: "its settings define a disk inline", objs: mv("CREATE MATERIALIZED VIEW db.x TO INNER UUID 'e24ac6f2-3215-4237-b418-e0ef2c318dde' (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS disk = disk(type = s3, endpoint = 'http://example.invalid/b/') AS SELECT id FROM db.events")},
		{name: "an inner table on a storage policy", reason: "its storage policy tiered is not the default", objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id SETTINGS storage_policy = 'tiered' AS SELECT id FROM db.events")},
		{name: "a table function", reason: "it reads the table function url", objs: mv("CREATE MATERIALIZED VIEW db.x TO db.logs (`id` UInt64) AS SELECT id FROM db.events WHERE id IN (SELECT id FROM url('http://example.invalid/x', CSV, 'id UInt64'))")},
		{name: "TO and an engine", reason: "cannot be parsed with certainty", objs: mv("CREATE MATERIALIZED VIEW db.x TO db.logs (`id` UInt64) ENGINE = MergeTree ORDER BY id AS SELECT id FROM db.events")},
		{name: "neither TO nor an engine", reason: "cannot be parsed with certainty", objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64) AS SELECT id FROM db.events")},
		{name: "populate", reason: "cannot be parsed with certainty", objs: mv("CREATE MATERIALIZED VIEW db.x (`id` UInt64) ENGINE = MergeTree ORDER BY id POPULATE AS SELECT id FROM db.events")},
	})
}

func TestClassifyDictionaries(t *testing.T) {
	runAlCases(t, []alCase{
		{name: "CLICKHOUSE TABLE and DB in the set", allowed: true, objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'logs')", "HASHED()")},
		{name: "CLICKHOUSE TABLE, no DB", allowed: true, objs: dictOn("CLICKHOUSE(TABLE 'logs')", "FLAT()")},
		{name: "CLICKHOUSE on a view", allowed: true, objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'v' WHERE 'id > 0' UPDATE_FIELD 'id' UPDATE_LAG 15)", "HASHED(SHARDS 4)")},
		{name: "CLICKHOUSE QUERY", allowed: true, objs: dictOn("CLICKHOUSE(QUERY 'SELECT id, msg FROM db.logs WHERE id IN (SELECT id FROM db.events)' INVALIDATE_QUERY 'SELECT max(id) FROM db.logs')", "COMPLEX_KEY_HASHED()")},
		{name: "CLICKHOUSE with a user", allowed: true, objs: dictOn("CLICKHOUSE(USER 'dict_reader' PASSWORD 'pw' DB 'db' TABLE 'logs')", "CACHE(SIZE_IN_CELLS 1000)")},
		{name: "every clause", allowed: true, objs: dict("CREATE DICTIONARY db.x UUID '17b3193b-2a52-40fd-81f0-92c7bc4553fa' (`id` UInt64, `start` Date, `end` Date, `msg` String DEFAULT '' INJECTIVE) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'db' TABLE 'logs')) LIFETIME(300) LAYOUT(RANGE_HASHED()) RANGE(MIN start MAX end) SETTINGS(format_csv_allow_single_quotes = 0) COMMENT 'x'")},

		{name: "HTTP", reason: "its source is HTTP, not a local ClickHouse table", objs: dictOn("HTTP(URL 'http://example.invalid/d' FORMAT 'TSV')", "FLAT()")},
		{name: "EXECUTABLE", reason: "its source is EXECUTABLE, not a local ClickHouse table", objs: dictOn("EXECUTABLE(COMMAND 'cat /etc/passwd' FORMAT 'TSV')", "FLAT()")},
		{name: "EXECUTABLE_POOL", reason: "its source is EXECUTABLE_POOL, not a local ClickHouse table", objs: dictOn("EXECUTABLE_POOL(COMMAND 'x' FORMAT 'TSV')", "FLAT()")},
		{name: "FILE", reason: "its source is FILE, not a local ClickHouse table", objs: dictOn("FILE(PATH '/etc/passwd' FORMAT 'TSV')", "FLAT()")},
		{name: "MYSQL", reason: "its source is MYSQL, not a local ClickHouse table", objs: dictOn("MYSQL(HOST 'h' PORT 3306 USER 'u' PASSWORD 'p' DB 'db' TABLE 't')", "FLAT()")},
		{name: "POSTGRESQL", reason: "its source is POSTGRESQL, not a local ClickHouse table", objs: dictOn("POSTGRESQL(HOST 'h' PORT 5432 USER 'u' PASSWORD 'p' DB 'db' TABLE 't')", "FLAT()")},
		{name: "lower-case source", reason: "its source is MONGODB, not a local ClickHouse table", objs: dictOn("mongodb(HOST 'h' PORT 27017 DB 'db' COLLECTION 'c')", "FLAT()")},
		{name: "CLICKHOUSE with HOST", reason: "its ClickHouse source names a host", objs: dictOn("CLICKHOUSE(HOST 'other.example.invalid' PORT 9000 USER 'default' PASSWORD '' DB 'db' TABLE 'logs')", "FLAT()")},
		{name: "CLICKHOUSE with localhost", reason: "its ClickHouse source names a host", objs: dictOn("CLICKHOUSE(HOST 'localhost' DB 'db' TABLE 'logs')", "FLAT()")},
		{name: "CLICKHOUSE with PORT", reason: "its ClickHouse source names a port", objs: dictOn("CLICKHOUSE(PORT 9001 DB 'db' TABLE 'logs')", "FLAT()")},
		{name: "CLICKHOUSE with a named collection", reason: "its ClickHouse source has NAME, which Olympos does not restore", objs: dictOn("CLICKHOUSE(NAME remote_ch DB 'db' TABLE 'logs')", "FLAT()")},
		{name: "CLICKHOUSE with SECURE", reason: "its ClickHouse source has SECURE, which Olympos does not restore", objs: dictOn("CLICKHOUSE(SECURE 1 DB 'db' TABLE 'logs')", "FLAT()")},
		{name: "a table outside the backup", reason: "it reads other.t, which is not in the backup", objs: dictOn("CLICKHOUSE(DB 'other' TABLE 't')", "FLAT()")},
		{name: "a table left out", reason: "it reads db.ext, which is not restored", objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'ext')", "FLAT()")},
		{name: "a QUERY with a table function", reason: "it reads the table function url", objs: dictOn("CLICKHOUSE(QUERY 'SELECT id, msg FROM url(\\'http://example.invalid/x\\', CSV, \\'id UInt64, msg String\\')')", "FLAT()")},
		{name: "a QUERY on a table left out", reason: "it reads db.ext, which is not restored", objs: dictOn("CLICKHOUSE(QUERY 'SELECT id, \\'\\' AS msg FROM db.ext')", "FLAT()")},
		{name: "a WHERE with a table function", reason: "it reads the table function remote", objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'logs' WHERE 'id IN (SELECT id FROM remote(\\'h\\', db.logs))')", "FLAT()")},
		{name: "an INVALIDATE_QUERY with a table function", reason: "it reads the table function s3", objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'logs' INVALIDATE_QUERY 'SELECT count() FROM s3(\\'http://example.invalid/b\\')')", "FLAT()")},
		{name: "a QUERY with a comment", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(QUERY 'SELECT id, msg FROM db.logs -- x')", "FLAT()")},
		{name: "a QUERY that is not a query", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(QUERY 'db.logs')", "FLAT()")},
		{name: "QUERY and DB", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(DB 'db' QUERY 'SELECT id, msg FROM db.logs')", "FLAT()")},
		{name: "an unqualified table in a QUERY", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(QUERY 'SELECT id, msg FROM logs')", "FLAT()")},
		{name: "TABLE and QUERY", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(TABLE 'logs' QUERY 'SELECT id, msg FROM db.logs')", "FLAT()")},
		{name: "neither TABLE nor QUERY", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(DB 'db')", "FLAT()")},
		{name: "a key twice", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'logs' TABLE 'ext')", "FLAT()")},
		{name: "a value that is not one token", reason: "cannot be parsed with certainty", objs: dictOn("CLICKHOUSE(DB 'db' TABLE concat('lo', 'gs'))", "FLAT()")},
		{name: "SSD_CACHE", reason: "its layout SSD_CACHE is not on the restore allowlist", objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'logs')", "SSD_CACHE(PATH '/var/lib/clickhouse/x' BLOCK_SIZE 4096)")},
		{name: "an unknown layout", reason: "its layout WHATEVER is not on the restore allowlist", objs: dictOn("CLICKHOUSE(DB 'db' TABLE 'logs')", "WHATEVER()")},
		{name: "an unknown clause", reason: "cannot be parsed with certainty", objs: dict("CREATE DICTIONARY db.x (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'db' TABLE 'logs')) LAYOUT(FLAT()) WHATEVER(1)")},
		{name: "no source", reason: "cannot be parsed with certainty", objs: dict("CREATE DICTIONARY db.x (`id` UInt64) PRIMARY KEY id LIFETIME(300) LAYOUT(FLAT())")},
		{name: "a column expression reading a file", reason: "it calls file, which reads outside the restored set", objs: dict("CREATE DICTIONARY db.x (`id` UInt64, `msg` String EXPRESSION file('x')) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'db' TABLE 'logs')) LIFETIME(300) LAYOUT(FLAT())")},
	})
}

// TestClassifyLedger: Kind and Engine in the manifest come from the
// statement's prefix only; the definition behind DDLKey decides.
func TestClassifyLedger(t *testing.T) {
	runAlCases(t, []alCase{
		// Kind other (R28) is never restored; the reason comes from the DDL.
		{name: "other: live view", reason: "a live view is not restored", objs: []alObj{{"db", "x", KindOther, "CREATE LIVE VIEW db.x UUID '1c78f33f-4038-4c07-af2d-4348f363be72' (`1` UInt8) AS SELECT 1"}}},
		{name: "other: window view", reason: "a window view is not restored", objs: []alObj{{"db", "x", KindOther, "CREATE WINDOW VIEW db.x ENGINE = Memory AS SELECT 1"}}},
		{name: "other: function", reason: "CREATE FUNCTION is not restored", objs: []alObj{{"db", "x", KindOther, "CREATE FUNCTION db.x AS x -> x"}}},
		{name: "other: or replace", reason: "CREATE OR REPLACE is not restored", objs: []alObj{{"db", "x", KindOther, "CREATE OR REPLACE TABLE db.x (`x` UInt8) ENGINE = Log"}}},
		{name: "other: table function", reason: "a table over the table function url", objs: []alObj{{"db", "x", KindOther, "CREATE TABLE db.x (`id` UInt64) AS url('http://example.invalid/y', CSV, 'id UInt64')"}}},
		{name: "other: parameterized view", reason: "cannot be parsed with certainty", objs: []alObj{{"db", "x", KindOther, "CREATE VIEW db.x AS SELECT {p:UInt8}"}}},
		{name: "other: attach", reason: "cannot be parsed with certainty", objs: []alObj{{"db", "x", KindOther, "ATTACH TABLE db.x (`x` UInt8) ENGINE = Log"}}},
		{name: "other: not UTF-8", reason: "cannot be parsed with certainty", objs: []alObj{{"db", "x", KindOther, "CREATE TABLE db.x (`\xff` UInt8) ENGINE = Log"}}},
		{name: "other: too large", reason: "cannot be parsed with certainty", objs: []alObj{{"db", "x", KindOther, "CREATE TABLE db.x (`x` UInt8) ENGINE = Log COMMENT '" + strings.Repeat("x", maxSchemaEntry) + "'"}}},
		{name: "other: a definition that would be allowed", reason: "the backup lists it as an object Olympos does not classify", objs: []alObj{{"db", "x", KindOther, "CREATE TABLE db.x (`x` UInt8) ENGINE = Log"}}},
		// An other from a name mismatch is left out under its key's name.
		{name: "other: another name", check: "fake", reason: "its definition creates db.events, not db.fake", objs: []alObj{{"db", "fake", KindOther, "CREATE TABLE db.events (`id` UInt64) ENGINE = Log"}}},
		{name: "other: another database", check: "fake", reason: "its definition creates other.fake, not db.fake", objs: []alObj{{"db", "fake", KindOther, "CREATE TABLE other.fake (`id` UInt64) ENGINE = Log"}}},
		{name: "other: an inner table's file", check: ".inner_id.4b99399c-2e2e-41b9-9785-38b96b090af2", reason: "a file named like a materialized view's inner table",
			objs: []alObj{{"db", ".inner_id.4b99399c-2e2e-41b9-9785-38b96b090af2", KindOther, "CREATE TABLE db.`.inner_id.4b99399c-2e2e-41b9-9785-38b96b090af2` (`x` UInt8) ENGINE = MergeTree ORDER BY x"}}},
		// The kind the manifest names is not trusted either.
		{name: "a table listed as a view", reason: "its definition is a table, not the view the backup lists", objs: []alObj{{"db", "x", KindView, "CREATE TABLE db.x (`x` UInt8) ENGINE = Log"}}},
		{name: "a URL table listed as a dictionary", reason: "its definition is a table, not the dictionary the backup lists", objs: []alObj{{"db", "x", KindDictionary, "CREATE TABLE db.x (`x` UInt8) ENGINE = URL('http://example.invalid/x', 'CSV')"}}},
		{name: "a name mismatch listed as a table", reason: "its definition creates db.y, not db.x", objs: tbl("CREATE TABLE db.y (`x` UInt8) ENGINE = Log")},
		{name: "an unknown kind", reason: "its kind function is not restored", objs: []alObj{{"db", "x", "function", "CREATE TABLE db.x (`x` UInt8) ENGINE = Log"}}},
		{name: "no definition", reason: "its definition is not in the backup", objs: tbl(missingDDL)},
		{name: "an empty definition", reason: "cannot be parsed with certainty", objs: tbl("")},
	})
}

func TestClassifyManifestShape(t *testing.T) {
	ok := "CREATE TABLE db.x (`x` UInt8) ENGINE = Log"
	t.Run("a key of another name", func(t *testing.T) {
		dbs := []NativeDatabase{{Name: "db", Objects: []NativeObject{{Name: "x", Kind: KindTable, DDLKey: alKey("db", "y")}}}}
		got := Classify(dbs, map[string][]byte{alKey("db", "y"): []byte(ok)})
		want := []Decision{{Database: "db", Name: "x", Kind: KindTable, Reason: "its definition is filed under another name"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
	t.Run("an object twice", func(t *testing.T) {
		o := NativeObject{Name: "x", Kind: KindTable, DDLKey: alKey("db", "x")}
		dbs := []NativeDatabase{{Name: "db", Objects: []NativeObject{o, o}}}
		got := Classify(dbs, map[string][]byte{alKey("db", "x"): []byte(ok)})
		d := Decision{Database: "db", Name: "x", Kind: KindTable, Reason: "the backup lists it twice"}
		if !reflect.DeepEqual(got, []Decision{d, d}) {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("nothing", func(t *testing.T) {
		if got := Classify(nil, nil); len(got) != 0 {
			t.Errorf("got %+v", got)
		}
	})
}

// TestClassifyDependents: what an object reads must be restored, so one
// left out leaves out what reads it, to a fixed point, each naming the
// object it reads.
func TestClassifyDependents(t *testing.T) {
	got := classifyObjs([]alObj{
		{"a", "src", KindTable, "CREATE TABLE a.src (`id` UInt64) ENGINE = Kafka('k:9092', 't', 'g', 'JSONEachRow')"},
		{"a", "t", KindTable, "CREATE TABLE a.t (`id` UInt64) ENGINE = MergeTree ORDER BY id"},
		// Listed before what it reads: the order of the manifest does not
		// matter.
		{"b", "v3", KindView, "CREATE VIEW b.v3 AS SELECT id FROM b.v2"},
		{"b", "v2", KindView, "CREATE VIEW b.v2 AS SELECT id FROM b.v1 UNION ALL SELECT id FROM a.t"},
		{"b", "v1", KindView, "CREATE VIEW b.v1 AS SELECT id FROM a.src"},
		{"b", "d", KindDictionary, "CREATE DICTIONARY b.d (`id` UInt64) PRIMARY KEY id SOURCE(CLICKHOUSE(DB 'b' TABLE 'v3')) LIFETIME(300) LAYOUT(FLAT())"},
		{"b", "mv", KindMaterializedView, "CREATE MATERIALIZED VIEW b.mv TO a.t (`id` UInt64) AS SELECT dictGet('b.d', 'id', id) AS id FROM a.t"},
		{"b", "ok", KindView, "CREATE VIEW b.ok AS SELECT id FROM a.t"},
		// Two views on each other, both on the set: a cycle stays allowed.
		{"b", "c1", KindView, "CREATE VIEW b.c1 AS SELECT id FROM b.c2"},
		{"b", "c2", KindView, "CREATE VIEW b.c2 AS SELECT id FROM b.c1 UNION ALL SELECT id FROM a.t"},
	})
	want := []Decision{
		{Database: "a", Name: "src", Kind: KindTable, Reason: "the Kafka engine is not on the restore allowlist"},
		{Database: "a", Name: "t", Kind: KindTable, Allowed: true},
		{Database: "b", Name: "v3", Kind: KindView, Reason: "it reads b.v2, which is not restored"},
		{Database: "b", Name: "v2", Kind: KindView, Reason: "it reads b.v1, which is not restored"},
		{Database: "b", Name: "v1", Kind: KindView, Reason: "it reads a.src, which is not restored"},
		{Database: "b", Name: "d", Kind: KindDictionary, Reason: "it reads b.v3, which is not restored"},
		{Database: "b", Name: "mv", Kind: KindMaterializedView, Reason: "it reads b.d, which is not restored"},
		{Database: "b", Name: "ok", Kind: KindView, Allowed: true},
		{Database: "b", Name: "c1", Kind: KindView, Allowed: true},
		{Database: "b", Name: "c2", Kind: KindView, Allowed: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
}

// TestClassifyNativeTestdata: the objects ClickHouse 24.8 and 25.8 wrote
// for the spike schema (testdata/native) are all restored, a full backup
// and an incremental over it alike; with one table's engine changed, what
// reads it is left out.
func TestClassifyNativeTestdata(t *testing.T) {
	for _, ver := range nativeVersions {
		t.Run(ver, func(t *testing.T) {
			full := metadataFiles(t, ver, "full", captureFullRun)
			incr := metadataFiles(t, ver, "incremental", captureIncrRun)
			// The incremental's view of the chain: what it wrote, and the
			// base's metadata for what it did not.
			chain := maps.Clone(full)
			for k := range incr {
				name := k[strings.LastIndex(k, "/")+1:]
				delete(chain, captureFullRun+"/metadata/spike/"+name)
			}
			maps.Copy(chain, incr)
			for run, files := range map[string]map[string][]byte{"full": full, "incremental": chain} {
				dbs, err := ObjectsFromMetadata(files)
				if err != nil {
					t.Fatal(err)
				}
				got := Classify(dbs, files)
				if n := len(dbs[0].Objects); len(got) != n || n < 9 {
					t.Fatalf("%s: %d decisions for %d objects", run, len(got), n)
				}
				for _, d := range got {
					if !d.Allowed {
						t.Errorf("%s: %s.%s (%s) left out: %s", run, d.Database, d.Name, d.Kind, d.Reason)
					}
				}
			}

			// spike.events behind a Distributed engine: the MVs and the view
			// on it are left out, naming it; the dictionary and the tables
			// are not affected.
			changed := maps.Clone(full)
			key := captureFullRun + "/metadata/spike/events.sql"
			body := string(full[key])
			changed[key] = []byte(body[:strings.Index(body, "ENGINE = MergeTree")] + "ENGINE = Distributed('c', 'spike', 'x', rand())")
			dbs, err := ObjectsFromMetadata(changed)
			if err != nil {
				t.Fatal(err)
			}
			reasons := map[string]string{}
			for _, d := range Classify(dbs, changed) {
				reasons[d.Name] = d.Reason
			}
			want := map[string]string{
				"applog": "", "applog_copy": "", "countries": "", "countries_dict": "", "daily": "",
				"events":      "the Distributed engine is not on the restore allowlist",
				"big_amounts": "it reads spike.events, which is not restored",
				"daily_mv":    "it reads spike.events, which is not restored",
				"recent":      "it reads spike.events, which is not restored",
			}
			if !reflect.DeepEqual(reasons, want) {
				t.Errorf("got %v\nwant %v", reasons, want)
			}
		})
	}
}

// TestClassifyPrefixes: every prefix of the real definitions and of alBase
// (cut inside a string, a bracket, a name, …) is read without a panic, and
// comes out with a kind or a reason.
func TestClassifyPrefixes(t *testing.T) {
	var bodies []string
	for _, ver := range nativeVersions {
		for _, b := range metadataFiles(t, ver, "full", captureFullRun) {
			bodies = append(bodies, string(b))
		}
	}
	for _, o := range alBase {
		bodies = append(bodies, o.ddl)
	}
	for _, body := range bodies {
		for n := 0; n <= len(body); n++ {
			def := readDefinition("spike", "x", []byte(body[:n]))
			if def.reason == "" && def.kind == "" {
				t.Errorf("%q: no kind and no reason", body[:n])
			}
		}
	}
}
