package clickhouse

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
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

CREATE TABLE rs.rep (k UInt8, v UInt32) ENGINE = ReplacingMergeTree ORDER BY k;
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

-- Tables not created: a setting outside the allowlist, a function
-- outside it.
CREATE TABLE rs.bad_set (x UInt8) ENGINE = MergeTree ORDER BY x SETTINGS min_age_to_force_merge_seconds = 10;
INSERT INTO rs.bad_set VALUES (1);
CREATE TABLE rs.bad_expr (x UInt64, h String DEFAULT hostName()) ENGINE = MergeTree ORDER BY x;
INSERT INTO rs.bad_expr (x) VALUES (1);

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
		"audit":  same("SELECT count(), sum(cityHash64(msg)) FROM rs.audit"),
		"agg":    same("SELECT count(), sum(cityHash64(k, finalizeAggregation(u))) FROM rs.agg"),
		"v2":     same("SELECT sum(v2) FROM rs.events"),
		"daily":  same("SELECT count(), sum(c) FROM rs.daily"),
		"mv": {"SELECT count(), sum(c), sum(cityHash64(d, c)) FROM rs.mv",
			"SELECT count(), sum(c), sum(cityHash64(d, c)) FROM rs.mv__restored_data"},
		"mv_chain": {"SELECT count(), sum(c) FROM rs.mv_chain", "SELECT count(), sum(c) FROM rs.mv_chain__restored_data"},
		"rs2":      same("SELECT count(), sum(cityHash64(formatRow('RowBinary', *))) FROM rs2.t"),
	}
	before := map[string]string{}
	for k, q := range checks {
		before[k] = chq(t, q.before)
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

	// rs2 over TLS: clickhouse client verifies the target's name through
	// the local bridge.
	rc, _ := rcFor(true, "rs2")
	res, err := Engine{}.Restore(ctx, rc)
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
		"rs.bad_set (table): it has setting min_age_to_force_merge_seconds",
		"rs.bad_expr (table): an expression of it calls hostName()",
		"rs.v (view): " + notRecreated,
		"rs.mv (materialized view): " + notRecreated,
		"rs.mv_to (materialized view): " + notRecreated,
		"rs.mv_k (materialized view): " + notRecreated,
		"rs.dict (dictionary): " + notRecreated,
	} {
		if !strings.Contains(skipped, w) {
			t.Errorf("skipped lacks %q:\n%s", w, skipped)
		}
	}
	if strings.Contains(skipped, "127.0.0.1:1") || strings.Contains(skipped, "olympos-t") {
		t.Fatalf("skipped carries DDL: %s", skipped)
	}
	if n := strings.Join(res.Notes, "\n"); !strings.Contains(n, "the data of materialized view rs.mv was restored into table rs.mv__restored_data; recreate the view with TO `rs`.`mv__restored_data`") ||
		!strings.Contains(n, "rs.events: MATERIALIZED columns (v2)") {
		t.Fatalf("notes: %v", res.Notes)
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
		"agg,audit,daily,events,mv__restored_data,mv_chain__restored_data,rep" {
		t.Errorf("restored objects: %s", got)
	}
	var wantRows int64
	for _, d := range m.Databases {
		if d.Name != "rs" {
			continue
		}
		for _, tb := range d.Tables {
			if tb.Name != "k" && tb.Name != "bad_set" && tb.Name != "bad_expr" {
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

const keeperContainer = "olympos-t8-keeper-ch"

// TestRestoreReplicatedIntegration restores Replicated tables (SHOW
// CREATE's default {uuid} path, and an explicit one) into a server whose
// Keeper still holds the source tables: the restored tables live under
// /olympos-restore/<request id>/ and the source's are untouched.
func TestRestoreReplicatedIntegration(t *testing.T) {
	startClickHouse(t) // skips without Docker, like the other tests
	bin := restoreClientBin(t)
	SetClientBin(bin)
	t.Cleanup(func() { SetClientBin("") })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keeper.xml"), []byte(keeperXML), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _ = docker("rm", "-f", keeperContainer)
	if out, err := docker("create", "--name", keeperContainer,
		"-e", "CLICKHOUSE_USER="+chUser, "-e", "CLICKHOUSE_PASSWORD="+chPassword, "-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
		"-p", "127.0.0.1::9000", chImage); err != nil {
		t.Fatalf("docker create: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = docker("rm", "-f", keeperContainer) })
	if out, err := docker("cp", filepath.Join(dir, "keeper.xml"), keeperContainer+":/etc/clickhouse-server/config.d/keeper.xml"); err != nil {
		t.Fatalf("docker cp: %v %s", err, out)
	}
	if out, err := docker("start", keeperContainer); err != nil {
		t.Fatalf("docker start: %v %s", err, out)
	}
	port, err := docker("port", keeperContainer, "9000/tcp")
	if err != nil {
		t.Fatalf("docker port: %v %s", err, port)
	}
	env := &chEnv{native: strings.Split(port, "\n")[0]}
	q := func(query string) string {
		t.Helper()
		cmd := exec.Command("docker", "exec", "-i", keeperContainer, "clickhouse-client", "-u", chUser, "--password", chPassword, "-n", "-q", query)
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
			break
		}
		if time.Now().After(deadline) {
			logs, _ := docker("logs", "--tail", "50", keeperContainer)
			t.Fatalf("clickhouse with keeper not ready: %v\n%s", err, logs)
		}
		time.Sleep(time.Second)
	}

	q(`CREATE DATABASE rp;
CREATE TABLE rp.t UUID '3b0f6c1e-2d4a-4e5f-9a1b-7c8d9e0f1a2b' (x UInt64) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY x;
CREATE TABLE rp.e (x UInt64, v UInt8) ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/rp_e', '{replica}', v) ORDER BY x;
INSERT INTO rp.t SELECT number FROM numbers(1000);
INSERT INTO rp.e SELECT number, 1 FROM numbers(10);`)
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
	if err != nil || len(res.Items) != 1 || res.Items[0].Status != "succeeded" || res.Items[0].Rows != 1010 || res.Items[0].Tables != 2 {
		t.Fatalf("restore: %v %+v", err, res)
	}
	paths := q("SELECT arrayStringConcat(groupArray(concat(table, '=', zookeeper_path)), ',') FROM (SELECT table, zookeeper_path FROM system.replicas WHERE database = 'rp' ORDER BY table)")
	want := "e=/olympos-restore/" + id + "/clickhouse/tables/s1/rp_e,t=/olympos-restore/" + id + "/clickhouse/tables/rp/t/s1"
	if paths != want {
		t.Fatalf("restored Keeper paths: %s, want %s", paths, want)
	}
	if got := q("SELECT count() FROM rp.t") + "," + q("SELECT count() FROM rp.e"); got != "1000,10" {
		t.Fatalf("restored rows: %s", got)
	}
	if got := q("SELECT count() FROM rp_src.t") + "," + q("SELECT count() FROM system.replicas WHERE database = 'rp_src' AND zookeeper_path NOT LIKE '/olympos-restore/%'"); got != "1000,2" {
		t.Fatalf("source tables: %s", got)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "rp.t: its Keeper path was moved under /olympos-restore/"+id+"/") {
		t.Fatalf("notes: %v", res.Notes)
	}
}
