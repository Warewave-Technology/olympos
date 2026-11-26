package clickhouse

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// The restore integration test runs the real clickhouse client of the
// version pinned in deploy/tools.env (the binary the server image ships):
// OLYMPOS_CLICKHOUSE_CLIENT (a path), clickhouse on PATH (Linux), or the
// official static Linux binary in the user cache, downloaded and checked
// against the release's SHA-512 when OLYMPOS_FETCH_CLICKHOUSE=1. Outside
// Linux the Linux binary runs in a container with host networking, so it
// reaches the restore's 127.0.0.1 bridge.

func pinnedClickHouseVersion(t *testing.T) string {
	t.Helper()
	f, err := os.Open("../../../../deploy/tools.env")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "CLICKHOUSE_VERSION="); ok {
			return v
		}
	}
	t.Fatal("CLICKHOUSE_VERSION not in deploy/tools.env")
	return ""
}

// restoreClientBin returns the binary the restore runs as `<bin> client`.
func restoreClientBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("OLYMPOS_CLICKHOUSE_CLIENT"); p != "" {
		if runtime.GOOS == "linux" {
			return p
		}
		return dockerClientWrapper(t, p)
	}
	if runtime.GOOS == "linux" {
		if p, err := exec.LookPath("clickhouse"); err == nil {
			return p
		}
	}
	ver := pinnedClickHouseVersion(t)
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Skipf("no user cache directory for the clickhouse client: %v", err)
	}
	dir := filepath.Join(cache, "olympos-test", "clickhouse-"+ver+"-linux-"+runtime.GOARCH)
	bin := filepath.Join(dir, "clickhouse")
	if _, err := os.Stat(bin); err != nil {
		if os.Getenv("OLYMPOS_FETCH_CLICKHOUSE") != "1" {
			t.Skipf("clickhouse client %s not found: set OLYMPOS_CLICKHOUSE_CLIENT to a clickhouse binary, put clickhouse on PATH (Linux), "+
				"or set OLYMPOS_FETCH_CLICKHOUSE=1 to download the official static binary (~200 MB) into %s", ver, dir)
		}
		fetchClickHouse(t, ver, dir)
	}
	if runtime.GOOS == "linux" {
		return bin
	}
	return dockerClientWrapper(t, bin)
}

// fetchClickHouse downloads clickhouse-common-static-<ver>-<arch>.tgz,
// checks its SHA-512 against the release's and extracts usr/bin/clickhouse
// into dir (as scripts/fetch-tools.sh does).
func fetchClickHouse(t *testing.T, ver, dir string) {
	t.Helper()
	name := fmt.Sprintf("clickhouse-common-static-%s-%s.tgz", ver, runtime.GOARCH)
	base := "https://github.com/ClickHouse/ClickHouse/releases/download/v" + ver + "-lts/"
	get := func(url string) io.ReadCloser {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("download %s: %v", url, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("download %s: %s", url, resp.Status)
		}
		return resp.Body
	}
	sumBody := get(base + name + ".sha512")
	sumLine, _ := io.ReadAll(io.LimitReader(sumBody, 4096))
	sumBody.Close()
	want, _, _ := strings.Cut(strings.TrimSpace(string(sumLine)), " ")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tgz := filepath.Join(dir, name+".part")
	f, err := os.Create(tgz)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tgz)
	h := sha512.New()
	body := get(base + name)
	_, err = io.Copy(io.MultiWriter(f, h), body)
	body.Close()
	f.Close()
	if err != nil {
		t.Fatalf("download %s: %v", name, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		t.Fatalf("%s: SHA-512 %s, the release says %s", name, got, want)
	}
	f, err = os.Open(tgz)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	member := "clickhouse-common-static-" + ver + "/usr/bin/clickhouse"
	for {
		hd, err := tr.Next()
		if errors.Is(err, io.EOF) {
			t.Fatalf("%s has no %s", name, member)
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimPrefix(hd.Name, "./") != member {
			continue
		}
		tmp := filepath.Join(dir, "clickhouse.part")
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			t.Fatal(err)
		}
		out.Close()
		if err := os.Rename(tmp, filepath.Join(dir, "clickhouse")); err != nil {
			t.Fatal(err)
		}
		return
	}
}

// dockerClientWrapper is a script that runs the Linux binary bin in a
// container with host networking; the directory of --config-file is
// mounted at the same path, the login passes by variable name only.
func dockerClientWrapper(t *testing.T, bin string) string {
	t.Helper()
	dockerBin, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not available")
	}
	host, _ := docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	script := `#!/bin/sh
set -e
mounts=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--config-file" ]; then d=$(/usr/bin/dirname "$a"); mounts="-v $d:$d:ro"; fi
  prev="$a"
done
export DOCKER_HOST='` + host + `'
exec '` + dockerBin + `' run --rm -i --network host -e CLICKHOUSE_USER -e CLICKHOUSE_PASSWORD -e HOME=/tmp \
  -v '` + bin + `':/opt/olympos/clickhouse:ro $mounts --entrypoint /opt/olympos/clickhouse ` + chImage + ` "$@"
`
	p := filepath.Join(t.TempDir(), "clickhouse")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

const restoreFixtureSQL = `
CREATE DATABASE rs;
CREATE TABLE rs.events (d Date, id UInt64, s LowCardinality(Nullable(String)), v String, v2 UInt64 MATERIALIZED id * 2)
ENGINE = MergeTree PARTITION BY toYYYYMM(d) ORDER BY id;
INSERT INTO rs.events SELECT toDate('2024-01-01') + intDiv(number, 20), number, if(number % 5 = 0, NULL, toString(number % 13)), repeat('x', number % 7)
FROM numbers(1000);

CREATE TABLE rs.agg (k UInt8, u AggregateFunction(uniq, UInt64)) ENGINE = AggregatingMergeTree ORDER BY k;
INSERT INTO rs.agg SELECT number % 4, uniqState(number) FROM numbers(1000) GROUP BY number % 4;

CREATE TABLE rs.rep (k UInt8, v UInt32) ENGINE = ReplacingMergeTree(v) ORDER BY k;
INSERT INTO rs.rep SETTINGS optimize_on_insert = 0 VALUES (1, 1), (1, 2), (2, 3);

CREATE TABLE rs.audit (msg String) ENGINE = TinyLog;
INSERT INTO rs.audit VALUES ('a'), ('b'), ('c');

CREATE VIEW rs.v AS SELECT id FROM rs.events WHERE id < 100;

CREATE MATERIALIZED VIEW rs.mv ENGINE = SummingMergeTree ORDER BY d AS SELECT d, count() AS c FROM rs.events GROUP BY d;
CREATE TABLE rs.daily (d Date, c UInt64) ENGINE = SummingMergeTree ORDER BY d;
CREATE MATERIALIZED VIEW rs.mv_to TO rs.daily AS SELECT d, count() AS c FROM rs.events GROUP BY d;
CREATE MATERIALIZED VIEW rs.mv_chain ENGINE = MergeTree ORDER BY d AS SELECT d, c FROM rs.mv;

CREATE TABLE rs.k (x String) ENGINE = Kafka SETTINGS kafka_broker_list = '127.0.0.1:1', kafka_topic_list = 'olympos-t', kafka_group_name = 'olympos-g', kafka_format = 'JSONEachRow';
CREATE MATERIALIZED VIEW rs.mv_k TO rs.audit AS SELECT x AS msg FROM rs.k;

CREATE DICTIONARY rs.dict (id UInt64, v String) PRIMARY KEY id
SOURCE(CLICKHOUSE(DB 'rs' TABLE 'events' USER '` + chUser + `' PASSWORD '` + chPassword + `')) LAYOUT(HASHED()) LIFETIME(0);

INSERT INTO rs.events SELECT toDate('2024-03-01') + intDiv(number, 20), number, 'late', '' FROM numbers(1000, 500);
-- Into the view's inner table through the view: mv_chain reads it.
INSERT INTO rs.mv VALUES ('2025-01-01', 7);

-- Restored from their columns, types, engine and keys only: settings,
-- defaults, codecs, TTL, indexes, constraints and comments are dropped.
CREATE TABLE rs.bad_set (x UInt8) ENGINE = MergeTree ORDER BY x SETTINGS min_age_to_force_merge_seconds = 10;
INSERT INTO rs.bad_set VALUES (1);
CREATE TABLE rs.bad_expr (x UInt64, h String DEFAULT hostName()) ENGINE = MergeTree ORDER BY x;
INSERT INTO rs.bad_expr (x) VALUES (1);
CREATE TABLE rs.rich (d DateTime, id UInt64 CODEC(ZSTD(1)), s String DEFAULT currentUser() COMMENT 'c', n Nullable(UInt32),
  INDEX ix s TYPE bloom_filter GRANULARITY 1, CONSTRAINT pos CHECK id >= 0)
ENGINE = MergeTree ORDER BY (id, lower(s)) PARTITION BY toYYYYMMDD(d) TTL d + INTERVAL 50 YEAR
SETTINGS index_granularity = 1024 COMMENT 'rich';
INSERT INTO rs.rich SELECT toDateTime('2024-01-01 00:00:00') + number * 3600, number, toString(number), if(number % 3 = 0, NULL, number) FROM numbers(200);
-- Not created: a ReplacingMergeTree whose sorting key is an expression
-- (another key would merge its rows differently).
CREATE TABLE rs.rep_expr (k UInt8, s String) ENGINE = ReplacingMergeTree ORDER BY (k, lower(s));
INSERT INTO rs.rep_expr VALUES (1, 'a');
-- Every engine in scope, with engine parameters and AggregateFunction types.
CREATE TABLE rs.summ (k UInt8, a UInt64, b UInt64, c String) ENGINE = SummingMergeTree((a, b)) ORDER BY k;
INSERT INTO rs.summ SETTINGS optimize_on_insert = 0 SELECT number % 5, number, 1, 'x' FROM numbers(100);
CREATE TABLE rs.coll (k UInt8, sign Int8) ENGINE = CollapsingMergeTree(sign) ORDER BY k;
INSERT INTO rs.coll SETTINGS optimize_on_insert = 0 VALUES (1, 1), (1, -1), (2, 1);
CREATE TABLE rs.vcoll (k UInt8, sign Int8, ver UInt16) ENGINE = VersionedCollapsingMergeTree(sign, ver) ORDER BY k;
INSERT INTO rs.vcoll SETTINGS optimize_on_insert = 0 VALUES (1, 1, 1), (1, -1, 1), (2, 1, 1);
CREATE TABLE rs.aggf (k UInt8, q AggregateFunction(quantiles(0.5, 0.9), Float64), si AggregateFunction(sumIf, UInt64, UInt8),
  s SimpleAggregateFunction(sum, UInt64), m SimpleAggregateFunction(max, Nullable(String)))
ENGINE = AggregatingMergeTree ORDER BY k;
INSERT INTO rs.aggf SELECT number % 3, quantilesState(0.5, 0.9)(toFloat64(number)), sumIfState(number, toUInt8(number % 2)), sum(number), max(toString(number))
FROM numbers(300) GROUP BY number % 3;
CREATE TABLE rs.nkey (n Nullable(UInt8), v String) ENGINE = MergeTree ORDER BY n SETTINGS allow_nullable_key = 1;
INSERT INTO rs.nkey VALUES (NULL, 'a'), (1, 'b');
CREATE TABLE rs.slog (x UInt8) ENGINE = StripeLog;
INSERT INTO rs.slog VALUES (1), (2);
CREATE TABLE rs.plog (x UInt8) ENGINE = Log;
INSERT INTO rs.plog VALUES (3);
CREATE TABLE rs.mem (x UInt8, t Tuple(a UInt8, b Map(String, Array(Nullable(Int64))))) ENGINE = Memory;
INSERT INTO rs.mem VALUES (1, (2, {'k': [1, NULL]}));
CREATE TABLE rs.odd (` + "`we``ird col`" + ` UInt8, ` + "`tab\tcol`" + ` Enum8('it''s' = 1, 'b' = -2), dt DateTime64(3, 'Europe/Istanbul'), dec Decimal(18, 4))
ENGINE = MergeTree ORDER BY ` + "`we``ird col`" + `;
INSERT INTO rs.odd VALUES (1, 'it''s', '2024-01-01 00:00:00.123', 1.5), (2, 'b', '2024-01-02 00:00:00', -2.25);
-- A Nested column kept as Nested (flatten_nested = 0): the target must
-- create it the same way, or its data is dropped (n.a, n.b are other names).
SET flatten_nested = 0;
CREATE TABLE rs.nest (k UInt8, n Nested(a UInt8, b String)) ENGINE = MergeTree ORDER BY k;
INSERT INTO rs.nest VALUES (1, [(1, 'x'), (2, 'y')]), (2, [(3, 'z')]), (3, []);
SET flatten_nested = 1;

CREATE DATABASE rs2;
CREATE TABLE rs2.t (n UInt64, p Tuple(a UInt8, b String)) ENGINE = MergeTree ORDER BY n;
INSERT INTO rs2.t SELECT number, tuple(toUInt8(number % 200), toString(number)) FROM numbers(5000);
`

func TestRestoreIntegration(t *testing.T) {
	env := startClickHouse(t)
	bin := restoreClientBin(t)
	SetClientBin(bin)
	t.Cleanup(func() { SetClientBin("") })
	chq(t, restoreFixtureSQL)
	ctx := context.Background()

	var buf bytes.Buffer
	if _, err := (Engine{}).Run(ctx, env.ec(false, map[string]any{"databases": []string{"rs", "rs2"}}), &buf); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	m := manifestOf(t, archive)
	for _, d := range m.Databases {
		for _, tb := range d.Tables {
			if d.Name == "rs" && tb.Name == "agg" && tb.DataFormat != FormatRowBinary {
				t.Fatalf("agg should be RowBinary: %+v", tb)
			}
		}
	}

	// Before (on the source) and after (on the restored tables): a
	// materialized view's rows are in <view>__restored_data.
	type check struct{ before, after string }
	same := func(q string) check { return check{q, q} }
	checks := map[string]check{
		"events": same("SELECT count(), sum(cityHash64(formatRow('RowBinary', *))) FROM rs.events"),
		"rep":    same("SELECT count(), sum(cityHash64(k, v)) FROM rs.rep"),
		"bad":    same("SELECT count(), sum(cityHash64(x, h)) FROM rs.bad_expr"),
		"rich":   same("SELECT count(), sum(cityHash64(d, id, s, n)) FROM rs.rich"),
		"summ":   same("SELECT count(), sum(a), sum(b) FROM rs.summ"),
		"coll":   same("SELECT count(), sum(sign) FROM rs.coll"),
		"vcoll":  same("SELECT count(), sum(sign * ver) FROM rs.vcoll"),
		"aggf": same("SELECT arrayStringConcat(groupArray(toString((k, finalizeAggregation(q), finalizeAggregation(si), s, m))), ';') " +
			"FROM (SELECT * FROM rs.aggf ORDER BY k)"),
		"nest":  same("SELECT count(), toString(groupArray((k, n))) FROM (SELECT * FROM rs.nest ORDER BY k)"),
		"nkey":  same("SELECT count(), countIf(n IS NULL) FROM rs.nkey"),
		"slog":  same("SELECT count(), sum(x) FROM rs.slog"),
		"plog":  same("SELECT count(), sum(x) FROM rs.plog"),
		"mem":   same("SELECT count(), toString(groupArray(t)) FROM rs.mem"),
		"odd":   same("SELECT count(), sum(cityHash64(formatRow('RowBinary', *))), toString(groupArray(`tab\tcol`)) FROM rs.odd"),
		"audit": same("SELECT count(), sum(cityHash64(msg)) FROM rs.audit"),
		"agg":   same("SELECT count(), sum(cityHash64(k, finalizeAggregation(u))) FROM rs.agg"),
		"daily": same("SELECT count(), sum(c) FROM rs.daily"),
		"mv": {"SELECT count(), sum(c), sum(cityHash64(d, c)) FROM rs.mv",
			"SELECT count(), sum(c), sum(cityHash64(d, c)) FROM rs.mv__restored_data"},
		"mv_chain": {"SELECT count(), sum(c) FROM rs.mv_chain", "SELECT count(), sum(c) FROM rs.mv_chain__restored_data"},
		"rs2":      same("SELECT count(), sum(cityHash64(formatRow('RowBinary', *))) FROM rs2.t"),
	}
	before := map[string]string{}
	for k, q := range checks {
		before[k] = chq(t, q.before)
	}
	if !strings.Contains(chq(t, "SELECT type FROM system.columns WHERE database = 'rs' AND table = 'nest' AND name = 'n'"), "Nested(") ||
		!strings.Contains(before["nest"], `[(1,\'x\'),(2,\'y\')]`) {
		t.Fatalf("fixture: rs.nest is not a Nested column: %s", before["nest"])
	}
	if before["mv_chain"] == "0\t0" || before["daily"] == "0\t0" || !strings.HasPrefix(before["rep"], "3\t") {
		t.Fatalf("fixture: %v", before)
	}

	// The target: rs gone, rs2 there without tables (restored into).
	chq(t, "DROP DATABASE rs SYNC; DROP DATABASE rs2 SYNC; CREATE DATABASE rs2")
	inspect := func() map[string]bool {
		t.Helper()
		rep, err := Engine{}.InspectRestoreTarget(ctx, env.ec(false, nil), []string{"rs", "rs2"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(rep.ServerVersion, "24.") {
			t.Fatalf("version: %+v", rep)
		}
		return rep.Existing
	}
	if ex := inspect(); len(ex) != 1 || ex["rs2"] {
		t.Fatalf("inspect before: %v", ex)
	}

	rcFor := func(useTLS bool, dbs ...string) (backup.RestoreContext, *[]backup.Progress) {
		opts := map[string]any{}
		if useTLS {
			opts["ca_pem"] = env.caPEM
		}
		var prog []backup.Progress
		rc := backup.RestoreContext{
			EngineContext: env.ec(useTLS, opts),
			RequestID:     "5b0e3d2a-9c1f-4f6e-8a7d-2c4b6e8f0a1c",
			Archive:       memObject{bytes.NewReader(archive)},
			Databases:     dbs,
			Progress:      func(p backup.Progress) { prog = append(prog, p) },
		}
		return rc, &prog
	}
	canary := func(res *backup.RestoreResult) {
		t.Helper()
		b, _ := json.Marshal(res)
		if bytes.Contains(b, []byte(chPassword)) {
			t.Fatalf("result carries the password: %s", b)
		}
	}

	// A CREATE the target refuses: only the error code and name are
	// reported, never the server's message (it can quote what the
	// statement made the server read). Nothing is created.
	crafted := withManifest(t, archive, func(m *Manifest) {
		for i := range m.Databases {
			if m.Databases[i].Name == "rs2" {
				m.Databases[i].Tables[0].Columns[0].Type = "Nullable(Array(UInt8))"
			}
		}
	})
	rc, _ := rcFor(false, "rs2")
	rc.Archive = memObject{bytes.NewReader(crafted)}
	res, err := Engine{}.Restore(ctx, rc)
	if err != nil || len(res.Items) != 1 || res.Items[0].Status != "failed" ||
		!strings.HasSuffix(res.Items[0].Error, "rs2.t (table): the target refused it: Code 43 ILLEGAL_TYPE_OF_ARGUMENT") {
		t.Fatalf("refused CREATE: %v %+v", err, res)
	}
	if got := chq(t, "SELECT count() FROM system.tables WHERE database = 'rs2'"); got != "0" {
		t.Fatalf("rs2 after a refused CREATE: %s tables", got)
	}

	// rs2 over TLS: clickhouse client verifies the target's name through
	// the local bridge.
	rc, _ = rcFor(true, "rs2")
	res, err = Engine{}.Restore(ctx, rc)
	if err != nil {
		t.Fatalf("restore rs2: %v (%+v)", err, res)
	}
	canary(res)
	if len(res.Items) != 1 || res.Items[0].Status != "succeeded" || res.Items[0].Rows != 5000 || res.Items[0].Tables != 1 || len(res.Created) != 0 {
		t.Fatalf("rs2: %+v", res)
	}
	if got := chq(t, checks["rs2"].after); got != before["rs2"] {
		t.Fatalf("rs2: before %s, after %s", before["rs2"], got)
	}

	// rs in plaintext (transfer mode compressed).
	rc, prog := rcFor(false, "rs")
	res, err = Engine{}.Restore(ctx, rc)
	if err != nil {
		t.Fatalf("restore rs: %v (%+v)", err, res)
	}
	canary(res)
	t.Logf("result: %+v", res)
	it := res.Items[0]
	if len(res.Items) != 1 || it.Status != "succeeded" || strings.Join(res.Created, ",") != "rs" {
		t.Fatalf("rs: %+v", res)
	}
	var reported bool
	for _, p := range *prog {
		if strings.Join(p.Created, ",") == "rs" {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("Created not reported through Progress: %+v", *prog)
	}
	skipped := strings.Join(it.Skipped, "\n")
	for _, w := range []string{
		"rs.k (table): engine Kafka is not restored",
		"rs.v (view): " + notRecreated,
		"rs.mv (materialized view): " + notRecreated,
		"rs.mv_to (materialized view): " + notRecreated,
		"rs.mv_k (materialized view): " + notRecreated,
		"rs.dict (dictionary): " + notRecreated,
		"rs.rep_expr (table): its sorting key is not a column list (another key changes how its rows merge); not created (create it by hand)",
	} {
		if !strings.Contains(skipped, w) {
			t.Errorf("skipped lacks %q:\n%s", w, skipped)
		}
	}
	if strings.Contains(skipped, "127.0.0.1:1") || strings.Contains(skipped, "olympos-t") {
		t.Fatalf("skipped carries DDL: %s", skipped)
	}
	notes := strings.Join(res.Notes, "\n")
	for _, w := range []string{
		"the data of materialized view rs.mv was restored into table rs.mv__restored_data; recreate the view with TO `rs`.`mv__restored_data`",
		"rs.events: created from its columns, types, engine and keys; not restored: the MATERIALIZED, ALIAS and EPHEMERAL columns `v2`",
		"rs.bad_expr: created from its columns, types, engine and keys; not restored: the DEFAULT expressions of `h`",
		"rs.rich: created from its columns, types, engine and keys; not restored: the DEFAULT expressions of `s`; its sorting key (ORDER BY tuple() instead)",
		"rs.audit: created from its columns, types, engine and keys; not restored: any codecs, constraints, comments and settings; re-apply them from your schema",
	} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
	for k, q := range checks {
		if k == "rs2" {
			continue
		}
		if got := chq(t, q.after); got != before[k] {
			t.Errorf("%s: before %s, after restore %s", k, before[k], got)
		}
	}
	// Only tables, each an ordinary one.
	if got := chq(t, "SELECT arrayStringConcat(groupArray(name), ',') FROM (SELECT name FROM system.tables WHERE database = 'rs' ORDER BY name)"); got !=
		"agg,aggf,audit,bad_expr,bad_set,coll,daily,events,mem,mv__restored_data,mv_chain__restored_data,nest,nkey,odd,plog,rep,rich,slog,summ,vcoll" {
		t.Errorf("restored objects: %s", got)
	}
	// The tables are what Olympos generated: engine, parameters and keys
	// kept; MATERIALIZED columns, defaults, codecs, indexes, constraints,
	// TTL, comments and settings not.
	for table, want := range map[string]string{
		"rich":    "MergeTree PARTITION BY toYYYYMMDD(d) ORDER BY tuple() SETTINGS index_granularity = 8192",
		"rep":     "ReplacingMergeTree(v) ORDER BY k SETTINGS index_granularity = 8192",
		"summ":    "SummingMergeTree((a, b)) ORDER BY k SETTINGS index_granularity = 8192",
		"vcoll":   "VersionedCollapsingMergeTree(sign, ver) ORDER BY k SETTINGS index_granularity = 8192",
		"events":  "MergeTree PARTITION BY toYYYYMM(d) ORDER BY id SETTINGS index_granularity = 8192",
		"nkey":    "MergeTree ORDER BY n SETTINGS allow_nullable_key = 1, index_granularity = 8192",
		"bad_set": "MergeTree ORDER BY x SETTINGS index_granularity = 8192",
	} {
		got := chq(t, "SELECT engine_full FROM system.tables WHERE database = 'rs' AND name = '"+table+"'")
		if got != want {
			t.Errorf("%s: engine_full %q, want %q", table, got, want)
		}
	}
	ddl := chq(t, "SELECT arrayStringConcat(groupArray(create_table_query), '\\n') FROM system.tables WHERE database = 'rs'")
	for _, no := range []string{"DEFAULT", "MATERIALIZED", "CODEC", "INDEX", "CONSTRAINT", "TTL", "COMMENT", "currentUser", "hostName", "lower(", "v2", "1024",
		"min_age_to_force_merge_seconds"} {
		if strings.Contains(ddl, no) {
			t.Errorf("a restored table holds %q:\n%s", no, ddl)
		}
	}
	// The Nested column stays one column (not flattened into n.a and n.b),
	// and the restored data equals the source's (the "nest" check above).
	if got := chq(t, "SELECT arrayStringConcat(groupArray(name || ' ' || type), ',') FROM (SELECT name, type FROM system.columns WHERE database = 'rs' AND table = 'nest' ORDER BY position)"); got !=
		"k UInt8,n Nested(a UInt8, b String)" {
		t.Errorf("rs.nest columns on the target: %s", got)
	}
	var wantRows int64
	for _, d := range m.Databases {
		if d.Name != "rs" {
			continue
		}
		for _, tb := range d.Tables {
			if tb.Name != "k" && tb.Name != "rep_expr" {
				wantRows += int64(tb.Rows)
			}
		}
	}
	if it.Rows != wantRows {
		t.Errorf("rows: %d, the backup holds %d", it.Rows, wantRows)
	}

	if ex := inspect(); len(ex) != 2 || !ex["rs"] || !ex["rs2"] {
		t.Fatalf("inspect after: %v", ex)
	}
	// Again: rs now holds tables, so nothing is written.
	rc, _ = rcFor(false, "rs")
	res, err = Engine{}.Restore(ctx, rc)
	if err != nil || len(res.Items) != 1 || res.Items[0].Status != "failed" || len(res.Created) != 0 ||
		!strings.Contains(res.Items[0].Error, "exists on the target with tables") || !strings.Contains(res.Items[0].Error, "nothing was written") {
		t.Fatalf("second restore: %v %+v", err, res)
	}

	t.Run("ClientVerifiesTLS", func(t *testing.T) { testClientTLS(t, env) })
}

// testClientTLS runs clickhouse client through the bridge with a wrong TLS
// name and without the target's CA: both are refused, and nothing is
// inserted.
func testClientTLS(t *testing.T, env *chEnv) {
	ctx := context.Background()
	opts := Options{CAPEM: env.caPEM}
	insert := func(ec backup.EngineContext) error {
		dir := t.TempDir()
		c, err := newClientRunner(ctx, ec, opts, dir, chUser, chPassword)
		if err != nil {
			return err
		}
		_, err = c.insert(ctx, "INSERT INTO rs2.t FORMAT RowBinaryWithNamesAndTypes", strings.NewReader(""))
		return err
	}
	before := chq(t, "SELECT count() FROM rs2.t")
	ok := env.ec(true, nil)
	// Connected, verified and logged in: the server answers that an empty
	// stdin has no rows.
	if err := insert(ok); err == nil || !strings.Contains(err.Error(), "NO_DATA_TO_INSERT") {
		t.Fatalf("right name: %v", err)
	}
	wrong := env.ec(true, nil)
	wrong.TLSServerName = "other.svc"
	err := insert(wrong)
	if err == nil || !strings.Contains(err.Error(), "NETWORK_ERROR") && !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("wrong name: %v", err)
	}
	if strings.Contains(err.Error(), chPassword) {
		t.Fatal("error carries the password")
	}
	t.Logf("wrong name: %v", err)
	// Another CA: the client itself must refuse the chain.
	otherCA, _, _ := testCerts(t)
	opts.CAPEM = otherCA
	if err := insert(ok); err == nil || !strings.Contains(err.Error(), "NETWORK_ERROR") {
		t.Fatalf("unknown CA: expected a refusal, got %v", err)
	} else {
		t.Logf("unknown CA: %v", err)
	}
	opts.CAPEM = ""
	if err := insert(ok); err == nil || !strings.Contains(err.Error(), "no CA is trusted") {
		t.Fatalf("no CA: expected a refusal, got %v", err)
	}
	if after := chq(t, "SELECT count() FROM rs2.t"); after != before {
		t.Fatalf("rows changed: %s -> %s", before, after)
	}
}

// manifestOf reads the manifest of an archive.
func manifestOf(t *testing.T, b []byte) Manifest {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]*zip.File{}
	for _, f := range zr.File {
		entries[f.Name] = f
	}
	m, err := readManifest(entries)
	if err != nil {
		t.Fatal(err)
	}
	return *m
}

// withManifest returns the archive b with its manifest changed by mod.
func withManifest(t *testing.T, b []byte, mod func(*Manifest)) []byte {
	t.Helper()
	m := manifestOf(t, b)
	mod(&m)
	mj, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	a := newArchive(&out, time.Now())
	for _, f := range zr.File {
		data := mj
		if f.Name != "manifest.json" {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err = io.ReadAll(r)
			_ = r.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := a.writeFile(f.Name, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

type memObject struct{ *bytes.Reader }

func (memObject) Close() error { return nil }

// keeperXML runs an embedded Keeper and the macros Replicated tables need.
const keeperXML = `<clickhouse>
  <keeper_server>
    <tcp_port>9181</tcp_port>
    <server_id>1</server_id>
    <log_storage_path>/var/lib/clickhouse/coordination/log</log_storage_path>
    <snapshot_storage_path>/var/lib/clickhouse/coordination/snapshots</snapshot_storage_path>
    <raft_configuration><server><id>1</id><hostname>localhost</hostname><port>9234</port></server></raft_configuration>
  </keeper_server>
  <zookeeper><node><host>localhost</host><port>9181</port></node></zookeeper>
  <macros><shard>s1</shard><replica>r1</replica></macros>
</clickhouse>`

// startKeeperServer starts a ClickHouse server with xml in config.d (on
// network unless empty) and waits until it reaches its Keeper. q runs a
// query in the container.
func startKeeperServer(t *testing.T, name, xml, network string) (*chEnv, func(string) string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keeper.xml"), []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"create", "--name", name,
		"-e", "CLICKHOUSE_USER=" + chUser, "-e", "CLICKHOUSE_PASSWORD=" + chPassword, "-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
		"-p", "127.0.0.1::9000"}
	if network != "" {
		args = append(args, "--network", network)
	}
	_, _ = docker("rm", "-f", "-v", name)
	if out, err := docker(append(args, chImage)...); err != nil {
		t.Fatalf("docker create: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = docker("rm", "-f", "-v", name) })
	if out, err := docker("cp", filepath.Join(dir, "keeper.xml"), name+":/etc/clickhouse-server/config.d/keeper.xml"); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	if out, err := docker("start", name); err != nil {
		t.Fatalf("docker start: %v %s", err, out)
	}
	port, err := docker("port", name, "9000/tcp")
	if err != nil {
		t.Fatalf("docker port: %v %s", err, port)
	}
	env := &chEnv{native: strings.Split(port, "\n")[0]}
	q := func(query string) string {
		t.Helper()
		cmd := exec.Command("docker", "exec", "-i", name, "clickhouse-client", "-u", chUser, "--password", chPassword, "-n", "-q", query)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", query, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	ctx := context.Background()
	deadline := time.Now().Add(90 * time.Second)
	for {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		s, err := connect(cctx, env.ec(false, nil), Options{})
		if err == nil {
			_, err = s.queryValue(cctx, "SELECT toString(count()) FROM system.zookeeper WHERE path = '/'")
			s.close()
		}
		cancel()
		if err == nil {
			return env, q
		}
		if time.Now().After(deadline) {
			logs, _ := docker("logs", "--tail", "50", name)
			t.Fatalf("clickhouse with keeper not ready: %v\n%s", err, logs)
		}
		time.Sleep(time.Second)
	}
}

// TestRestoreReplicatedIntegration restores Replicated tables (SHOW
// CREATE's default {uuid} path, and an explicit one) into a server whose
// Keeper still holds the source tables: the restored tables live under
// /olympos-restore/<request id>/ and the source's are untouched.
func TestRestoreReplicatedIntegration(t *testing.T) {
	startClickHouse(t) // skips without Docker, like the other tests
	bin := restoreClientBin(t)
	SetClientBin(bin)
	t.Cleanup(func() { SetClientBin("") })

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	env, q := startKeeperServer(t, "olympos-t8-keeper-"+hex.EncodeToString(rnd[:]), keeperXML, "")
	ctx := context.Background()

	q(`CREATE DATABASE rp;
CREATE TABLE rp.t UUID '3b0f6c1e-2d4a-4e5f-9a1b-7c8d9e0f1a2b' (x UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x;
CREATE TABLE rp.e (x UInt64, v UInt8) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/rp_e', '{replica}', v) ORDER BY x;
CREATE TABLE rp.a (k UInt8, u AggregateFunction(uniq, UInt64)) ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/rp_a', '{replica}') ORDER BY k;
INSERT INTO rp.t SELECT number FROM numbers(1000);
INSERT INTO rp.e SELECT number, 1 FROM numbers(10);
INSERT INTO rp.a SELECT number % 4, uniqState(number) FROM numbers(100) GROUP BY number % 4;`)
	if got := q("SELECT create_table_query FROM system.tables WHERE database = 'rp' AND name = 't'"); !strings.Contains(got, "{uuid}") {
		t.Fatalf("SHOW CREATE should carry the {uuid} path: %s", got)
	}
	var buf bytes.Buffer
	if _, err := (Engine{}).Run(ctx, env.ec(false, map[string]any{"databases": []string{"rp"}}), &buf); err != nil {
		t.Fatal(err)
	}
	// The source's tables stay (and keep their Keeper state) under
	// another name.
	q("RENAME DATABASE rp TO rp_src")

	const id = "7d1b0c2e-3f4a-4b5c-8d6e-9f0a1b2c3d4e"
	rc := backup.RestoreContext{EngineContext: env.ec(false, nil), RequestID: id, Archive: memObject{bytes.NewReader(buf.Bytes())},
		Databases: []string{"rp"}, Progress: func(backup.Progress) {}}
	res, err := Engine{}.Restore(ctx, rc)
	if err != nil || len(res.Items) != 1 || res.Items[0].Status != "succeeded" || res.Items[0].Rows != 1014 || res.Items[0].Tables != 3 {
		t.Fatalf("restore: %v %+v", err, res)
	}
	paths := q("SELECT arrayStringConcat(groupArray(concat(table, '=', zookeeper_path)), ',') FROM (SELECT table, zookeeper_path FROM system.replicas WHERE database = 'rp' ORDER BY table)")
	want := "a=/olympos-restore/" + id + "/rp/a,e=/olympos-restore/" + id + "/rp/e,t=/olympos-restore/" + id + "/rp/t"
	if paths != want {
		t.Fatalf("restored Keeper paths: %s, want %s", paths, want)
	}
	if got := q("SELECT count() FROM rp.t") + "," + q("SELECT count() FROM rp.e") + "," + q("SELECT sum(finalizeAggregation(u)) FROM rp.a"); got != "1000,10,100" {
		t.Fatalf("restored rows: %s", got)
	}
	if got := q("SELECT count() FROM rp_src.t") + "," + q("SELECT count() FROM system.replicas WHERE database = 'rp_src' AND zookeeper_path NOT LIKE '/olympos-restore/%'"); got != "1000,3" {
		t.Fatalf("source tables: %s", got)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "rp.t: its Keeper path is /olympos-restore/"+id+"/rp/t (replica {replica})") {
		t.Fatalf("notes: %v", res.Notes)
	}
}

// sharedKeeperXML points a server at the Keeper of host, as replica r2 of
// the same shard: what a second ClickHouse of the same cluster sees.
func sharedKeeperXML(host string) string {
	return `<clickhouse>
  <zookeeper><node><host>` + host + `</host><port>9181</port></node></zookeeper>
  <macros><shard>s1</shard><replica>r2</replica></macros>
</clickhouse>`
}

// TestRestoreReplicatedSharedKeeper restores Replicated tables into another
// server that shares the source's Keeper (#57). Had the restore kept the
// source's Keeper paths, the restored tables would join the source tables'
// replica set as r2, with no error, and the two would copy each other's
// data. The source tables keep their one replica and their rows.
func TestRestoreReplicatedSharedKeeper(t *testing.T) {
	startClickHouse(t) // skips without Docker, like the other tests
	bin := restoreClientBin(t)
	SetClientBin(bin)
	t.Cleanup(func() { SetClientBin("") })

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	suffix := hex.EncodeToString(rnd[:])
	network := "olympos-t8-net-" + suffix
	if out, err := docker("network", "create", network); err != nil {
		t.Fatalf("docker network create: %v %s", err, out)
	}
	// Registered first: runs after the containers are removed.
	t.Cleanup(func() { _, _ = docker("network", "rm", network) })
	srcName := "olympos-t8-src-" + suffix
	src, qs := startKeeperServer(t, srcName, keeperXML, network)
	dst, qd := startKeeperServer(t, "olympos-t8-dst-"+suffix, sharedKeeperXML(srcName), network)
	ctx := context.Background()

	qs(`CREATE DATABASE rp;
CREATE TABLE rp.t UUID '3b0f6c1e-2d4a-4e5f-9a1b-7c8d9e0f1a2b' (x UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x;
CREATE TABLE rp.e (x UInt64, v UInt8) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/rp_e', '{replica}', v) ORDER BY x;
CREATE TABLE rp.a (k UInt8, u AggregateFunction(uniq, UInt64)) ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/rp_a', '{replica}') ORDER BY k;
INSERT INTO rp.t SELECT number FROM numbers(1000);
INSERT INTO rp.e SELECT number, 1 FROM numbers(10);
INSERT INTO rp.a SELECT number % 4, uniqState(number) FROM numbers(100) GROUP BY number % 4;`)
	var buf bytes.Buffer
	if _, err := (Engine{}).Run(ctx, src.ec(false, map[string]any{"databases": []string{"rp"}}), &buf); err != nil {
		t.Fatal(err)
	}

	const id = "5c2e8a1f-0b3d-4e6f-9a7b-1c2d3e4f5a6b"
	rc := backup.RestoreContext{EngineContext: dst.ec(false, nil), RequestID: id, Archive: memObject{bytes.NewReader(buf.Bytes())},
		Databases: []string{"rp"}, Progress: func(backup.Progress) {}}
	res, err := Engine{}.Restore(ctx, rc)
	if err != nil || len(res.Items) != 1 || res.Items[0].Status != "succeeded" || res.Items[0].Rows != 1014 || res.Items[0].Tables != 3 {
		t.Fatalf("restore: %v %+v", err, res)
	}

	// The target: its own paths, as r2, with the backup's rows.
	paths := qd("SELECT arrayStringConcat(groupArray(concat(table, '=', zookeeper_path, '@', replica_name)), ',') FROM (SELECT table, zookeeper_path, replica_name FROM system.replicas WHERE database = 'rp' ORDER BY table)")
	want := "a=/olympos-restore/" + id + "/rp/a@r2,e=/olympos-restore/" + id + "/rp/e@r2,t=/olympos-restore/" + id + "/rp/t@r2"
	if paths != want {
		t.Fatalf("restored Keeper paths: %s, want %s", paths, want)
	}
	if got := qd("SELECT count() FROM rp.t") + "," + qd("SELECT count() FROM rp.e") + "," + qd("SELECT sum(finalizeAggregation(u)) FROM rp.a"); got != "1000,10,100" {
		t.Fatalf("restored rows: %s", got)
	}

	// The source: one replica per table, r1 alone under its Keeper paths.
	if got := qs("SELECT arrayStringConcat(groupArray(concat(table, '=', toString(total_replicas))), ',') FROM (SELECT table, total_replicas FROM system.replicas WHERE database = 'rp' ORDER BY table)"); got != "a=1,e=1,t=1" {
		t.Fatalf("source replicas: %s, want a=1,e=1,t=1", got)
	}
	for _, p := range []string{"/clickhouse/tables/3b0f6c1e-2d4a-4e5f-9a1b-7c8d9e0f1a2b/s1/replicas", "/clickhouse/tables/s1/rp_e/replicas", "/clickhouse/tables/s1/rp_a/replicas"} {
		if got := qs("SELECT arrayStringConcat(groupArray(name), ',') FROM system.zookeeper WHERE path = '" + p + "'"); got != "r1" {
			t.Fatalf("replicas under %s: %q, want r1", p, got)
		}
	}

	// Writes stay on their side: a new row on each, then both sync.
	qd("INSERT INTO rp.e VALUES (100, 2)")
	qs("INSERT INTO rp.t SELECT number FROM numbers(1000, 5)")
	qs("SYSTEM SYNC REPLICA rp.e")
	qd("SYSTEM SYNC REPLICA rp.t")
	if got := qs("SELECT count() FROM rp.e") + "," + qd("SELECT count() FROM rp.t"); got != "10,1000" {
		t.Fatalf("source rp.e, target rp.t after writes on the other side: %s, want 10,1000", got)
	}
	if got := qs("SELECT count() FROM rp.t") + "," + qd("SELECT count() FROM rp.e"); got != "1005,11" {
		t.Fatalf("source rp.t, target rp.e after their own writes: %s, want 1005,11", got)
	}
}
