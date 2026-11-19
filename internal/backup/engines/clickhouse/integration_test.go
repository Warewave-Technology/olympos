package clickhouse

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/targettls"
)

// Integration tests against a real ClickHouse in Docker (container
// olympos-m6-ch, random host ports). Skipped without Docker unless
// OLYMPOS_REQUIRE_DOCKER=1.

const (
	chImage     = "clickhouse/clickhouse-server:24.8"
	chContainer = "olympos-m6-ch"
	chUser      = "olympos"
	chPassword  = "s3cret-canary-7f3a"
	chTLSName   = "clickhouse.shop.svc"
)

type chEnv struct {
	native, secure string // host:port
	caPEM          string
}

func docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func startClickHouse(t *testing.T) *chEnv {
	t.Helper()
	require := os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1"
	if _, err := exec.LookPath("docker"); err != nil {
		if require {
			t.Fatal("docker not found")
		}
		t.Skip("docker not available")
	}
	if out, err := docker("info", "--format", "{{.ServerVersion}}"); err != nil {
		if require {
			t.Fatalf("docker info: %v %s", err, out)
		}
		t.Skip("docker daemon not available")
	}

	caPEM, certPEM, keyPEM := testCerts(t)
	dir := t.TempDir()
	tlsXML := `<clickhouse>
  <tcp_port_secure>9440</tcp_port_secure>
  <openSSL><server>
    <certificateFile>/etc/clickhouse-server/certs/server.crt</certificateFile>
    <privateKeyFile>/etc/clickhouse-server/certs/server.key</privateKeyFile>
    <verificationMode>none</verificationMode>
    <loadDefaultCAFile>false</loadDefaultCAFile>
    <disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols>
  </server></openSSL>
</clickhouse>`
	files := map[string]string{"tls.xml": tlsXML, "server.crt": certPEM, "server.key": keyPEM}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, _ = docker("rm", "-f", chContainer)
	if out, err := docker("create", "--name", chContainer,
		"-e", "CLICKHOUSE_USER="+chUser, "-e", "CLICKHOUSE_PASSWORD="+chPassword,
		"-e", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
		"-p", "127.0.0.1::9000", "-p", "127.0.0.1::9440", chImage); err != nil {
		t.Fatalf("docker create: %v %s", err, out)
	}
	t.Cleanup(func() { _, _ = docker("rm", "-f", chContainer) })
	// docker cp (not bind mounts) so it works with any Docker host.
	if out, err := docker("cp", dir+"/.", chContainer+":/etc/clickhouse-server/certs"); err != nil {
		t.Fatalf("docker cp certs: %v %s", err, out)
	}
	if out, err := docker("cp", filepath.Join(dir, "tls.xml"), chContainer+":/etc/clickhouse-server/config.d/tls.xml"); err != nil {
		t.Fatalf("docker cp tls.xml: %v %s", err, out)
	}
	if out, err := docker("start", chContainer); err != nil {
		t.Fatalf("docker start: %v %s", err, out)
	}
	port := func(p string) string {
		out, err := docker("port", chContainer, p+"/tcp")
		if err != nil {
			t.Fatalf("docker port: %v %s", err, out)
		}
		return strings.Split(out, "\n")[0]
	}
	env := &chEnv{native: port("9000"), secure: port("9440"), caPEM: caPEM}

	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := connect(ctx, env.ec(false, nil), Options{})
		if err == nil {
			_, err = s.queryValue(ctx, "SELECT toString(1)")
			s.close()
		}
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := docker("logs", "--tail", "50", chContainer)
			t.Fatalf("clickhouse not ready: %v\n%s", err, logs)
		}
		time.Sleep(time.Second)
	}
	return env
}

func (e *chEnv) ec(useTLS bool, opts any) backup.EngineContext {
	addr := e.native
	if useTLS {
		addr = e.secure
	}
	raw, _ := json.Marshal(opts)
	if opts == nil {
		raw = nil
	}
	return backup.EngineContext{
		Target: backup.TargetInfo{Engine: "clickhouse", Namespace: "shop", Service: "clickhouse", Port: 9000},
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		UseTLS:        useTLS,
		TLSServerName: chTLSName,
		Credential: func(context.Context) (backup.Credential, error) {
			return backup.Credential{Username: chUser, Secret: []byte(chPassword)}, nil
		},
		Options: raw,
	}
}

// clickhouseClient runs clickhouse-client inside the container.
func clickhouseClient(t *testing.T, stdin []byte, user, pass string, args ...string) string {
	t.Helper()
	full := append([]string{"exec", "-i", chContainer, "clickhouse-client", "-u", user, "--password", pass}, args...)
	// A hung client (seen once on CI) fails with the server log instead of
	// running into the package timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		logs := ""
		if ctx.Err() != nil {
			logs, _ = docker("logs", "--tail", "80", chContainer)
		}
		t.Fatalf("clickhouse-client %v: %v\n%s\n%s", args, err, out, logs)
	}
	return strings.TrimSpace(string(out))
}

func chq(t *testing.T, query string) string {
	t.Helper()
	return clickhouseClient(t, nil, chUser, chPassword, "-n", "-q", query)
}

const fixtureSQL = `
CREATE DATABASE shop;
CREATE DATABASE other;
CREATE TABLE other.t (x UInt8) ENGINE = MergeTree ORDER BY x;
INSERT INTO other.t VALUES (1);

CREATE TABLE shop.events (
  ts DateTime('UTC'),
  day Date,
  id UInt64,
  user LowCardinality(String),
  amount Decimal(18, 4),
  tags Array(String),
  note Nullable(String),
  kind Enum8('a' = 1, 'b' = 2),
  uid UUID,
  attrs Map(String, String),
  price Float64,
  sparse_col UInt32,
  dbl UInt64 MATERIALIZED id * 2
) ENGINE = MergeTree PARTITION BY toYYYYMM(day) ORDER BY (day, id)
SETTINGS ratio_of_defaults_for_sparse_serialization = 0.5;

CREATE MATERIALIZED VIEW shop.mv_daily ENGINE = SummingMergeTree ORDER BY day
AS SELECT day, count() AS c FROM shop.events GROUP BY day;

INSERT INTO shop.events (ts, day, id, user, amount, tags, note, kind, uid, attrs, price, sparse_col)
SELECT toDateTime('2024-01-01 00:00:00', 'UTC') + number * 3600, toDate('2024-01-01') + intDiv(number, 24), number,
       concat('u', toString(number % 7)), number / 3, [toString(number), 'x'], if(number % 3 = 0, NULL, toString(number)),
       if(number % 2 = 0, 'a', 'b'), generateUUIDv4(), map('k', toString(number), 'q', 'v'), number * 1.5,
       if(number % 100 = 0, toUInt32(number), 0)
FROM numbers(2000);
INSERT INTO shop.events (ts, day, id, user, amount, tags, note, kind, uid, attrs, price, sparse_col)
SELECT toDateTime('2024-01-01 00:00:00', 'UTC') + number * 3600, toDate('2024-01-01') + intDiv(number, 24), number,
       'late', 0, [], NULL, 'a', generateUUIDv4(), map(), 0, 0
FROM numbers(2000, 1000);

CREATE TABLE shop.users (id UInt32, name String) ENGINE = MergeTree ORDER BY id;
INSERT INTO shop.users SELECT number, concat('name-', toString(number)) FROM numbers(50);

CREATE TABLE shop.big (n UInt64, s LowCardinality(String), a Array(UInt32)) ENGINE = MergeTree ORDER BY n;
INSERT INTO shop.big SELECT number, toString(number % 1000), range(toUInt32(number % 5)) FROM numbers(300000);

CREATE TABLE shop.audit (at DateTime, msg String) ENGINE = TinyLog;
INSERT INTO shop.audit VALUES ('2024-01-01 00:00:00', 'hello'), ('2024-01-02 00:00:00', 'world');

CREATE TABLE shop.agg (k UInt8, u AggregateFunction(uniq, UInt64), t Tuple(a UInt8, b String))
ENGINE = AggregatingMergeTree ORDER BY k;
INSERT INTO shop.agg SELECT number % 4, uniqState(number), tuple(toUInt8(number % 4), 'x') FROM numbers(1000) GROUP BY number % 4;

CREATE TABLE shop.` + "`we/ird name`" + ` (v String) ENGINE = Memory;
INSERT INTO shop.` + "`we/ird name`" + ` VALUES ('a'), ('b'), ('c');

CREATE TABLE shop.dist AS shop.users ENGINE = Merge(shop, '^users$');

CREATE VIEW shop.v_users AS SELECT id, name FROM shop.users WHERE id > 10;

CREATE DICTIONARY shop.user_dict (id UInt64, name String) PRIMARY KEY id
SOURCE(CLICKHOUSE(DB 'shop' TABLE 'users' USER '` + chUser + `' PASSWORD '` + chPassword + `'))
LAYOUT(FLAT()) LIFETIME(0);

CREATE USER ro IDENTIFIED WITH plaintext_password BY 'ro_pw';
GRANT SELECT ON shop.users TO ro;
GRANT SELECT ON shop.events TO ro;
`

func TestIntegration(t *testing.T) {
	env := startClickHouse(t)
	chq(t, fixtureSQL)

	// The fixture must really exercise sparse serialization (the reason we
	// announce protocol revision 54453).
	if got := chq(t, "SELECT count() FROM system.parts_columns WHERE database = 'shop' AND table = 'events' AND column = 'sparse_col' AND serialization_kind = 'Sparse' AND active"); got == "0" {
		t.Fatal("fixture has no sparse column parts")
	}

	t.Run("TestConnection", func(t *testing.T) { testConnection(t, env) })
	t.Run("DryRun", func(t *testing.T) { testDryRun(t, env) })
	t.Run("BackupAndRestore", func(t *testing.T) { testBackupRestore(t, env) })
	t.Run("TLS", func(t *testing.T) { testTLS(t, env) })
	// Last: drops the source database.
	t.Run("RestoreScript", func(t *testing.T) { testRestoreScript(t, env) })
}

// testRestoreScript runs the "Everything at once" script of docs/restore.md
// against a backup, after dropping the source database.
func testRestoreScript(t *testing.T, env *chEnv) {
	for _, tool := range []string{"bash", "jq", "unzip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	doc, err := os.ReadFile("../../../../docs/restore.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(doc), "### Everything at once")
	if !ok {
		t.Fatal("restore script section not found")
	}
	_, after, _ = strings.Cut(after, "```bash\n")
	script, _, _ := strings.Cut(after, "```")
	const chLine = "CH=(clickhouse-client --config-file ./restore-client.xml)"
	if !strings.Contains(script, chLine) {
		t.Fatal("script has no CH line")
	}
	script = strings.Replace(script, chLine,
		"CH=(docker exec -i "+chContainer+" clickhouse-client -u "+chUser+" --password "+chPassword+")", 1)

	var buf bytes.Buffer
	if _, err := (Engine{}).Run(context.Background(), env.ec(false, map[string]any{"databases": []string{"shop"}}), &buf); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	zipPath, scriptPath := filepath.Join(dir, "backup.zip"), filepath.Join(dir, "restore.sh")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	sum := func(table string) string {
		return chq(t, fmt.Sprintf("SELECT count(), sum(cityHash64(formatRow('RowBinary', *))) FROM shop.%s", quoteIdent(table)))
	}
	tables := []string{"events", "users", "audit", "big", "we/ird name", "v_users"}
	before := map[string]string{}
	for _, tb := range tables {
		before[tb] = sum(tb)
	}
	// Aggregating/Summing engines: compare merged values, not stored rows.
	aggq := "SELECT count(), sum(cityHash64(k, finalizeAggregation(u), t)) FROM shop.agg; " +
		"SELECT count(), sum(c), sum(cityHash64(day, c)) FROM (SELECT day, sum(c) AS c FROM shop.mv_daily GROUP BY day)"
	aggBefore := chq(t, aggq)
	chq(t, "DROP DATABASE IF EXISTS shop_restore SYNC; DROP DATABASE shop SYNC")

	cmd := exec.Command("bash", scriptPath, zipPath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore script: %v\n%s", err, out)
	}
	for _, tb := range tables {
		if got := sum(tb); got != before[tb] {
			t.Errorf("%s: before %s, after restore %s", tb, before[tb], got)
		}
	}
	if got := chq(t, aggq); got != aggBefore {
		t.Errorf("agg: before %s, after %s", aggBefore, got)
	}
	// The dictionary exists again (its source password is '[HIDDEN]' and has
	// to be re-entered, see docs/restore.md).
	if got := chq(t, "SELECT count() FROM system.tables WHERE database = 'shop' AND name IN ('user_dict', 'dist')"); got != "2" {
		t.Errorf("dictionary/merge table not restored: %s", got)
	}
}

func testConnection(t *testing.T, env *chEnv) {
	ctx := context.Background()
	ct, err := Engine{}.TestConnection(ctx, env.ec(false, map[string]any{"databases": []string{"shop"}}))
	if err != nil {
		t.Fatal(err)
	}
	if !ct.OK || ct.Error != "" {
		t.Fatalf("connection test failed: %+v", ct)
	}
	if !strings.HasPrefix(ct.ServerVersion, "24.") || ct.TLS {
		t.Fatalf("version/tls: %+v", ct)
	}
	if strings.Join(ct.Databases, ",") != "default,other,shop" {
		t.Fatalf("databases: %v", ct.Databases)
	}
	names := map[string]bool{}
	for _, p := range ct.Privileges {
		names[p.Name] = p.OK
	}
	for _, n := range []string{"connect", "SHOW GRANTS", "SHOW on shop", "SELECT on shop.*", "SELECT grant on shop.*"} {
		if !names[n] {
			t.Errorf("privilege %q missing or failed: %+v", n, ct.Privileges)
		}
	}

	// Wrong password: reported in the result, not as an error.
	bad := env.ec(false, nil)
	bad.Credential = func(context.Context) (backup.Credential, error) {
		return backup.Credential{Username: chUser, Secret: []byte("wrong")}, nil
	}
	ct, err = Engine{}.TestConnection(ctx, bad)
	if err != nil {
		t.Fatal(err)
	}
	if ct.OK || ct.Error == "" {
		t.Fatalf("wrong password should fail: %+v", ct)
	}

	// Restricted user: sees only shop.users, so the grant check must flag
	// the database as not fully covered.
	ro := env.ec(false, map[string]any{"databases": []string{"shop"}})
	ro.Credential = func(context.Context) (backup.Credential, error) {
		return backup.Credential{Username: "ro", Secret: []byte("ro_pw")}, nil
	}
	ct, err = Engine{}.TestConnection(ctx, ro)
	if err != nil {
		t.Fatal(err)
	}
	if ct.OK {
		t.Fatalf("restricted user should not pass: %+v", ct)
	}
	var flagged bool
	for _, p := range ct.Privileges {
		if p.Name == "SELECT grant on shop.*" && !p.OK && strings.Contains(p.Detail, "not granted") {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("grant check did not flag: %+v", ct.Privileges)
	}
	// ...but with a tables allow-list matching its grants it passes.
	ro.Options = json.RawMessage(`{"tables":["shop.users","shop.events"]}`)
	if ct, _ = (Engine{}).TestConnection(ctx, ro); !ct.OK {
		t.Fatalf("restricted user with tables allow-list: %+v", ct)
	}
	// It cannot read system.parts: partitions come from _partition_id.
	z, _ := runBackup(t, ro)
	if z.manifest.RowsSource != "count()" {
		t.Fatalf("rows_source: %q", z.manifest.RowsSource)
	}
	if ev := z.table(t, "shop", "events"); len(ev.Partitions) != 5 || ev.Rows != 3000 || ev.RowsExpected != 3000 {
		t.Fatalf("restricted events: %+v", ev)
	}
	if len(z.manifest.Warnings) != 0 {
		t.Fatalf("warnings: %v", z.manifest.Warnings)
	}

	// Invalid options are an error.
	if _, err := (Engine{}).TestConnection(ctx, env.ec(false, map[string]any{"nope": 1})); err == nil {
		t.Fatal("expected options error")
	}
}

type zipped struct {
	names    []string
	files    map[string][]byte
	manifest Manifest
}

func runBackup(t *testing.T, ec backup.EngineContext) (*zipped, *backup.RunResult) {
	t.Helper()
	var buf bytes.Buffer
	res, err := Engine{}.Run(context.Background(), ec, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	z := &zipped{files: map[string][]byte{}}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		z.names = append(z.names, f.Name)
		z.files[f.Name] = b
	}
	if len(z.names) == 0 || z.names[len(z.names)-1] != "manifest.json" {
		t.Fatalf("manifest.json must be the last entry: %v", z.names)
	}
	if err := json.Unmarshal(z.files["manifest.json"], &z.manifest); err != nil {
		t.Fatal(err)
	}
	for name, b := range z.files {
		if bytes.Contains(b, []byte(chPassword)) {
			t.Fatalf("entry %s contains the password", name)
		}
	}
	return z, res
}

func (z *zipped) table(t *testing.T, db, name string) Table {
	t.Helper()
	for _, d := range z.manifest.Databases {
		if d.Name != db {
			continue
		}
		for _, tb := range d.Tables {
			if tb.Name == name {
				return tb
			}
		}
	}
	t.Fatalf("table %s.%s not in manifest", db, name)
	return Table{}
}

func testDryRun(t *testing.T, env *chEnv) {
	ec := env.ec(false, map[string]any{"databases": []string{"shop"}})
	ec.Test = true
	z, res := runBackup(t, ec)
	for _, n := range z.names {
		if strings.HasPrefix(n, "data/") {
			t.Fatalf("dry run wrote data entry %s", n)
		}
	}
	if !z.manifest.DryRun || z.manifest.Totals.DataEntries != 0 || res.Details["dry_run"] != true {
		t.Fatalf("dry run manifest: %+v", z.manifest.Totals)
	}
	ev := z.table(t, "shop", "events")
	if ev.HasData || len(ev.Partitions) != 5 || ev.RowsExpected != 3000 {
		t.Fatalf("events in dry run: %+v", ev)
	}
	if _, ok := z.files["schema/shop/events.sql"]; !ok {
		t.Fatalf("schema missing: %v", z.names)
	}
}

func testBackupRestore(t *testing.T, env *chEnv) {
	z, res := runBackup(t, env.ec(false, map[string]any{"databases": []string{"shop"}}))
	m := z.manifest
	t.Logf("entries: %v", z.names)
	t.Logf("details: %v", res.Details)

	if m.Format != ManifestFormat || m.Engine != "clickhouse" || !strings.HasPrefix(m.ServerVersion, "24.") ||
		m.Transfer.Compression != "zstd" || m.Transfer.Protocol != "native" || m.Transfer.TLS {
		t.Fatalf("manifest header: %+v", m)
	}
	if len(m.Databases) != 1 || m.Databases[0].Name != "shop" {
		t.Fatalf("databases: %+v", m.Databases)
	}
	if len(m.Warnings) != 0 {
		t.Fatalf("warnings: %v", m.Warnings)
	}
	for _, n := range z.names {
		if strings.Contains(n, "other") {
			t.Fatalf("unselected database in archive: %s", n)
		}
	}

	ev := z.table(t, "shop", "events")
	if ev.Kind != KindTable || ev.DataFormat != FormatNative || len(ev.Partitions) != 5 || ev.Rows != 3000 || ev.RowsExpected != 3000 {
		t.Fatalf("events: %+v", ev)
	}
	for _, p := range ev.Partitions {
		want := "data/shop/events/" + p.ID + ".native"
		b, ok := z.files[want]
		if p.Entry != want || !ok {
			t.Fatalf("partition entry %+v (%v)", p, ok)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != p.SHA256 || int64(len(b)) != p.Bytes {
			t.Fatalf("partition %s sha/size mismatch", p.ID)
		}
		if p.Rows != p.RowsExpected || p.Rows == 0 {
			t.Fatalf("partition rows %+v", p)
		}
	}
	if len(ev.Columns) != 13 || ev.Columns[12].Name != "dbl" || ev.Columns[12].DefaultKind != "MATERIALIZED" {
		t.Fatalf("columns: %+v", ev.Columns)
	}
	if u := z.table(t, "shop", "users"); u.DataFormat != FormatNative || u.Rows != 50 || len(u.Partitions) != 1 || u.Partitions[0].Entry != "data/shop/users/all.native" {
		t.Fatalf("users: %+v", u)
	}
	if a := z.table(t, "shop", "agg"); a.DataFormat != FormatRowBinary || a.Rows != 4 || a.Partitions[0].Entry != "data/shop/agg/all.rowbinary" || a.FallbackReason == "" {
		t.Fatalf("agg: %+v", a)
	}
	if w := z.table(t, "shop", "we/ird name"); w.Rows != 3 || w.Partitions[0].Entry != "data/shop/we%2Fird%20name/all.native" {
		t.Fatalf("weird: %+v", w)
	}
	// Several blocks (max_block_size) concatenated in one Native entry.
	if b := z.table(t, "shop", "big"); b.Rows != 300000 || b.DataFormat != FormatNative || len(b.Partitions) != 1 {
		t.Fatalf("big: %+v", b)
	}
	if d := z.table(t, "shop", "audit"); d.Rows != 2 || !d.HasData {
		t.Fatalf("audit: %+v", d)
	}
	if d := z.table(t, "shop", "dist"); d.HasData || !strings.Contains(d.DataNote, "engine Merge") {
		t.Fatalf("dist: %+v", d)
	}
	if v := z.table(t, "shop", "v_users"); v.Kind != KindView || v.HasData {
		t.Fatalf("view: %+v", v)
	}
	if d := z.table(t, "shop", "user_dict"); d.Kind != KindDictionary || !strings.HasPrefix(string(z.files[d.SchemaEntry]), "CREATE DICTIONARY shop.user_dict") {
		t.Fatalf("dict: %+v %s", d, z.files[d.SchemaEntry])
	}
	mv := z.table(t, "shop", "mv_daily")
	if mv.Kind != KindMaterializedView || mv.UUID == "" {
		t.Fatalf("mv: %+v", mv)
	}
	inner := z.table(t, "shop", ".inner_id."+mv.UUID)
	if inner.Kind != KindMVInner || inner.InnerOf != "mv_daily" || inner.Rows == 0 {
		t.Fatalf("mv inner: %+v", inner)
	}
	if _, ok := z.files["schema/shop.sql"]; !ok {
		t.Fatal("schema/shop.sql missing")
	}
	// Restore order: tables, then dictionaries, then views/MVs.
	pos := map[string]int{}
	for i, n := range m.RestoreOrder {
		pos[n] = i
	}
	if pos["shop.users"] > pos["shop.user_dict"] || pos["shop.user_dict"] > pos["shop.mv_daily"] || pos["shop.events"] > pos["shop.v_users"] {
		t.Fatalf("restore order: %v", m.RestoreOrder)
	}
	if _, ok := pos["shop..inner_id."+mv.UUID]; ok {
		t.Fatal("inner table must not be in restore order")
	}

	// ---- Restore into shop_restore following docs/restore.md ----
	chq(t, "CREATE DATABASE shop_restore")
	rewrite := func(stmt string) string {
		return strings.ReplaceAll(stmt, "shop.", "shop_restore.")
	}
	tables := map[string]Table{}
	for _, tb := range m.Databases[0].Tables {
		tables["shop."+tb.Name] = tb
	}
	load := func(target string, tb Table) {
		for _, p := range tb.Partitions {
			if p.Entry == "" {
				continue
			}
			clickhouseClient(t, z.files[p.Entry], chUser, chPassword,
				"--query", "INSERT INTO "+target+" FORMAT "+tb.DataFormat)
		}
	}
	// Phase 1: tables + data; phase 2: dictionaries, views, MVs; phase 3: MV inner data.
	for _, n := range m.RestoreOrder {
		tb := tables[n]
		if tb.Kind != KindTable {
			continue
		}
		chq(t, rewrite(string(z.files[tb.SchemaEntry])))
		load("shop_restore."+quoteIdent(tb.Name), tb)
	}
	for _, n := range m.RestoreOrder {
		tb := tables[n]
		if tb.Kind == KindTable {
			continue
		}
		chq(t, rewrite(string(z.files[tb.SchemaEntry])))
	}
	load("shop_restore.mv_daily", inner)

	checksum := func(db, table string) string {
		return chq(t, fmt.Sprintf("SELECT count(), sum(cityHash64(formatRow('RowBinary', *))) FROM %s.%s", db, quoteIdent(table)))
	}
	for _, tb := range []string{"events", "users", "audit", "big", "we/ird name"} {
		orig, got := checksum("shop", tb), checksum("shop_restore", tb)
		if orig != got {
			t.Errorf("%s: original %s, restored %s", tb, orig, got)
		}
	}
	if a, b := chq(t, "SELECT sum(dbl) FROM shop.events"), chq(t, "SELECT sum(dbl) FROM shop_restore.events"); a != b {
		t.Errorf("materialized column: %s vs %s", a, b)
	}
	// uniq states re-serialize in hash-table order, so compare finalized
	// values rather than state bytes.
	aggq := "SELECT count(), sum(cityHash64(k, finalizeAggregation(u), t)) FROM %s.agg"
	if a, b := chq(t, fmt.Sprintf(aggq, "shop")), chq(t, fmt.Sprintf(aggq, "shop_restore")); a != b {
		t.Errorf("agg: %s vs %s", a, b)
	}
	if a, b := chq(t, "SELECT uniqMerge(u) FROM shop.agg"), chq(t, "SELECT uniqMerge(u) FROM shop_restore.agg"); a != b {
		t.Errorf("aggregate states: %s vs %s", a, b)
	}
	mvq := "SELECT count(), sum(c), sum(cityHash64(day, c)) FROM (SELECT day, sum(c) AS c FROM %s.mv_daily GROUP BY day)"
	if a, b := chq(t, fmt.Sprintf(mvq, "shop")), chq(t, fmt.Sprintf(mvq, "shop_restore")); a != b {
		t.Errorf("mv: %s vs %s", a, b)
	}
	if a, b := chq(t, "SELECT count() FROM shop.v_users"), chq(t, "SELECT count() FROM shop_restore.v_users"); a != b {
		t.Errorf("view: %s vs %s", a, b)
	}
	if got := chq(t, "SELECT count() FROM system.columns WHERE database = 'shop_restore' AND table = 'events'"); got != "13" {
		t.Errorf("restored events columns: %s", got)
	}

	// tables allow-list: only users (+ nothing else).
	z2, _ := runBackup(t, env.ec(false, map[string]any{"tables": []string{"shop.users", "shop.mv_daily"}}))
	var objs []string
	for _, tb := range z2.manifest.Databases[0].Tables {
		objs = append(objs, tb.Name)
	}
	if want := "users,mv_daily,.inner_id." + mv.UUID; strings.Join(sortedCopy(objs), ",") != strings.Join(sortedCopy(strings.Split(want, ",")), ",") {
		t.Fatalf("allow-list objects: %v", objs)
	}
	// Missing table is an error.
	var sink bytes.Buffer
	if _, err := (Engine{}).Run(context.Background(), env.ec(false, map[string]any{"tables": []string{"shop.nope"}}), &sink); err == nil {
		t.Fatal("expected error for missing table")
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func testTLS(t *testing.T, env *chEnv) {
	ctx := context.Background()
	ec := env.ec(true, map[string]any{"databases": []string{"shop"}, "ca_pem": env.caPEM})
	ct, err := Engine{}.TestConnection(ctx, ec)
	if err != nil {
		t.Fatal(err)
	}
	if !ct.OK || !ct.TLS {
		t.Fatalf("tls connection test: %+v", ct)
	}
	ec.Test = true
	z, _ := runBackup(t, ec)
	if !z.manifest.Transfer.TLS {
		t.Fatal("manifest should record TLS")
	}
	if _, ok := z.files["schema/shop/events.sql"]; !ok {
		t.Fatal("tls dry run missing schema")
	}

	// Unknown CA (no ca_pem): verification must fail, never skipped.
	noCA := env.ec(true, map[string]any{"databases": []string{"shop"}})
	if ct, _ := (Engine{}).TestConnection(ctx, noCA); ct.OK || !strings.Contains(ct.Error, "no CA is trusted") {
		t.Fatalf("no trusted CA should fail: %+v", ct)
	}
	// System roots only: the private CA is still unknown.
	if err := targettls.Configure("", true); err != nil {
		t.Fatal(err)
	}
	ct, _ = (Engine{}).TestConnection(ctx, noCA)
	_ = targettls.Configure("", false)
	if ct.OK || !strings.Contains(ct.Error, "tls") {
		t.Fatalf("unknown CA should fail: %+v", ct)
	}
	// Wrong server name.
	wrong := env.ec(true, map[string]any{"ca_pem": env.caPEM})
	wrong.TLSServerName = "other.svc"
	if ct, _ := (Engine{}).TestConnection(ctx, wrong); ct.OK || !strings.Contains(ct.Error, "tls") {
		t.Fatalf("wrong server name should fail: %+v", ct)
	}
	// TLS without a server name is refused.
	none := env.ec(true, map[string]any{"ca_pem": env.caPEM})
	none.TLSServerName = ""
	if ct, _ := (Engine{}).TestConnection(ctx, none); ct.OK || !strings.Contains(ct.Error, "server name") {
		t.Fatalf("missing server name should fail: %+v", ct)
	}
	// F1: e2e-tls against the plain native port is refused before the
	// password is sent (no fallback), both in the test and in a run; the
	// run still reports TLS=false so tls.missing opens.
	plain := env.ec(true, map[string]any{"databases": []string{"shop"}, "ca_pem": env.caPEM})
	plainAddr := env.native
	var sent bytes.Buffer
	plain.Dial = func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", plainAddr)
		if err != nil {
			return nil, err
		}
		return &recordConn{Conn: c, w: &sent}, nil
	}
	ct, _ = Engine{}.TestConnection(ctx, plain)
	if ct.OK || ct.TLS || !ct.Reached || !strings.Contains(ct.Error, "no TLS on this port") ||
		!strings.Contains(ct.Error, "compressed") {
		t.Fatalf("plaintext target accepted in e2e-tls: %+v", ct)
	}
	rr, err := Engine{}.Run(ctx, plain, io.Discard)
	if !errors.Is(err, ErrNoTLS) || rr == nil || rr.TLS == nil || *rr.TLS {
		t.Fatalf("run: %+v %v", rr, err)
	}
	if bytes.Contains(sent.Bytes(), []byte(chPassword)) || bytes.Contains(sent.Bytes(), []byte(chUser)) {
		t.Fatal("credentials reached a plaintext target")
	}
	// The same target in compressed mode works.
	comp := env.ec(false, map[string]any{"databases": []string{"shop"}})
	if ct, _ := (Engine{}).TestConnection(ctx, comp); !ct.OK || ct.TLS {
		t.Fatalf("compressed mode: %+v", ct)
	}
}

// recordConn records what the client writes.
type recordConn struct {
	net.Conn
	w *bytes.Buffer
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.w.Write(p)
	return c.Conn.Write(p)
}

// testCerts returns a CA and a server certificate for chTLSName.
func testCerts(t *testing.T) (caPEM, certPEM, keyPEM string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "olympos-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: chTLSName},
		DNSNames:  []string{chTLSName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	enc := func(typ string, b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})) }
	return enc("CERTIFICATE", caDER), enc("CERTIFICATE", der), enc("PRIVATE KEY", kb)
}
