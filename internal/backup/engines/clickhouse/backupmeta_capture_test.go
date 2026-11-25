package clickhouse

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestCaptureNativeTestdata writes testdata/native/<version>/ from real
// native backups: ClickHouse 24.8 and 25.8 in Docker back up the spike
// schema to MinIO, a full and then an incremental, and the test copies each
// run's .backup, its metadata/*.sql objects and one count.txt, and lists
// the objects the run stored (objects.txt).
//
//	go test ./internal/backup/engines/clickhouse/ -run TestCaptureNativeTestdata -update
//
// It runs only with -update, and is skipped without Docker. Every docker
// command has a timeout; the network and containers are removed by
// t.Cleanup, registered before each is created. The images are pinned by
// digest (captureImages) and their version() is checked.
//
// The statements have the form Olympos sends (R26): each run has its own
// MinIO key pair, as each Olympos run has its own credential, and the
// incremental reads its base with its own, through
// use_same_s3_credentials_for_base_backup = 1 and a base URL without
// credentials.
//
// Nothing secret is captured: ClickHouse's default user has no password
// (the dictionary's source names no user), and the MinIO secrets are random
// and checked to appear in no captured file. ClickHouse 24.8 writes the
// incremental's own S3 credentials, secret included, into its .backup
// (<base_backup>); the capture replaces the secret with redactedSecret.

var updateNative = flag.Bool("update", false, "capture testdata/native from Docker (TestCaptureNativeTestdata)")

const (
	captureMinIOUser = "olympos-capture" // MinIO's root, for mc only
	captureFullUser  = "olympos-run-full"
	captureIncrUser  = "olympos-run-incr"
	captureBucket    = "backups"
	// The run prefixes: fixed, so that the captured .backup of an
	// incremental names the same base on every capture.
	captureFullRun = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e60"
	captureIncrRun = "6f1c2a52-0d8e-4b7a-9c1e-1a2b3c4d5e61"
	redactedSecret = "REDACTED-SECRET"
)

// captureImages are the images captured, pinned by digest (the local
// clickhouse/clickhouse-server:24.8 and :25.8 of the capture), with the
// version() each must report.
var captureImages = []struct{ ver, image, server string }{
	{"24.8", "clickhouse/clickhouse-server@sha256:1ffa82edee000a42c09313bd9f1293d94c570aee74babc1b3ca9983a35fa597b", "24.8.14.39"},
	{"25.8", "clickhouse/clickhouse-server@sha256:0152dd511befe6a2c2ef53e930726179669b08116da78500b37c51c96ff5ee77", "25.8.33.6"},
}

// captureSchema is the spike's schema (docs/design/clickhouse-native-spike.md)
// plus a materialized view without TO, whose inner table is in the backup,
// and two Log tables that get the same rows (applog, applog_copy).
const captureSchema = `
CREATE DATABASE spike ENGINE = Atomic;
CREATE TABLE spike.events (
    id UInt64,
    ts DateTime DEFAULT now(),
    user_id UInt32 CODEC(Delta, ZSTD(3)),
    payload String DEFAULT '' CODEC(ZSTD(1)),
    amount Float64 DEFAULT 0,
    INDEX idx_user user_id TYPE minmax GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY id
TTL ts + INTERVAL 5 YEAR;
CREATE TABLE spike.daily (
    day Date,
    users AggregateFunction(uniq, UInt32),
    total AggregateFunction(sum, Float64)
) ENGINE = AggregatingMergeTree ORDER BY day;
CREATE MATERIALIZED VIEW spike.daily_mv TO spike.daily AS
    SELECT toDate(ts) AS day, uniqState(user_id) AS users, sumState(amount) AS total
    FROM spike.events GROUP BY day;
CREATE MATERIALIZED VIEW spike.big_amounts ENGINE = MergeTree ORDER BY id AS
    SELECT id, amount FROM spike.events WHERE amount > 900;
CREATE VIEW spike.recent AS SELECT id, ts, amount FROM spike.events WHERE ts > now() - INTERVAL 1 DAY;
CREATE TABLE spike.countries (id UInt64, name String) ENGINE = MergeTree ORDER BY id;
CREATE DICTIONARY spike.countries_dict (id UInt64, name String)
    PRIMARY KEY id
    SOURCE(CLICKHOUSE(DB 'spike' TABLE 'countries'))
    LIFETIME(MIN 0 MAX 300)
    LAYOUT(HASHED());
CREATE TABLE spike.applog (id UInt64, msg String) ENGINE = Log;
CREATE TABLE spike.applog_copy (id UInt64, msg String) ENGINE = Log;
INSERT INTO spike.countries VALUES (1, 'Turkey'), (2, 'Netherlands'), (3, 'Germany');
INSERT INTO spike.applog VALUES (1, 'started');
INSERT INTO spike.applog_copy VALUES (1, 'started');
INSERT INTO spike.events (id, ts, user_id, payload, amount)
    SELECT number, toDateTime('2026-11-01 00:00:00') + number, number % 1000, toString(number), number % 1000
    FROM numbers(400000);
`

// captureChange runs between the full and the incremental: events gets new
// rows (a new part) and a new column (new DDL), a table is added, the Log
// tables applog and applog_copy grow by the same append, and countries, daily_mv, recent and
// countries_dict are left as they are.
const captureChange = `
INSERT INTO spike.events (id, ts, user_id, payload, amount)
    SELECT 400000 + number, toDateTime('2026-11-20 00:00:00') + number, number % 1000, toString(number), number % 1000
    FROM numbers(1000);
ALTER TABLE spike.events ADD COLUMN note String DEFAULT '';
CREATE TABLE spike.added (id UInt64) ENGINE = Log;
INSERT INTO spike.added VALUES (1), (2);
INSERT INTO spike.applog VALUES (2, 'appended');
INSERT INTO spike.applog_copy VALUES (2, 'appended');
`

func TestCaptureNativeTestdata(t *testing.T) {
	if !*updateNative {
		t.Skip("captures testdata/native only with -update")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := dockerT(t, 20*time.Second, "info", "--format", "{{.ServerVersion}}"); err != nil {
		t.Skipf("docker daemon not available: %v %s", err, out)
	}

	suffix := randHex(t, 4)
	network := "olympos-capture-" + suffix
	minio := "olympos-capture-minio-" + suffix
	password := "pw-" + randHex(t, 16)

	t.Cleanup(func() { _, _ = dockerT(t, time.Minute, "network", "rm", network) })
	mustDocker(t, time.Minute, "network", "create", network)
	t.Cleanup(func() { _, _ = dockerT(t, time.Minute, "rm", "-f", minio) })
	mustDocker(t, 2*time.Minute, "run", "-d", "--pull", "never", "--name", minio, "--network", network,
		"--network-alias", "minio", "-e", "MINIO_ROOT_USER="+captureMinIOUser, "-e", "MINIO_ROOT_PASSWORD="+password,
		"cgr.dev/chainguard/minio:latest", "server", "/data")

	mc := &captureMC{network: network, host: "http://" + captureMinIOUser + ":" + password + "@minio:9000"}
	retry(t, 60*time.Second, "minio bucket", func() (string, error) {
		out, err := mc.run(t, 30*time.Second, "mb", "--ignore-existing", "local/"+captureBucket)
		return string(out), err
	})
	// A key pair per run.
	keys := captureKeys{full: "sk-" + randHex(t, 16), incr: "sk-" + randHex(t, 16)}
	for user, secret := range map[string]string{captureFullUser: keys.full, captureIncrUser: keys.incr} {
		for _, args := range [][]string{{"admin", "user", "add", "local", user, secret},
			{"admin", "policy", "attach", "local", "readwrite", "--user", user}} {
			if out, err := mc.run(t, 30*time.Second, args...); err != nil {
				t.Fatalf("mc admin %s %s: %v %s", args[1], args[2], err, out)
			}
		}
	}
	secrets := []string{password, keys.full, keys.incr}

	for _, img := range captureImages {
		t.Run(img.ver, func(t *testing.T) {
			captureVersion(t, img.ver, img.image, img.server, network, suffix, keys, secrets, mc)
		})
	}
}

type captureKeys struct{ full, incr string }

func captureVersion(t *testing.T, ver, image, wantServer, network, suffix string, keys captureKeys, secrets []string, mc *captureMC) {
	ch := "olympos-capture-ch" + strings.ReplaceAll(ver, ".", "") + "-" + suffix
	t.Cleanup(func() { _, _ = dockerT(t, time.Minute, "rm", "-f", ch) })
	mustDocker(t, 2*time.Minute, "run", "-d", "--pull", "never", "--name", ch, "--network", network,
		"--ulimit", "nofile=262144:262144", image)

	query := func(q string) (string, error) {
		return dockerT(t, 5*time.Minute, "exec", ch, "clickhouse-client", "-n", "-q", q)
	}
	retry(t, 90*time.Second, "clickhouse ready", func() (string, error) { return query("SELECT 1") })
	server, err := query("SELECT version()")
	if err != nil {
		t.Fatalf("version: %v %s", err, server)
	}
	if server != wantServer {
		t.Fatalf("%s is ClickHouse %s, not %s", image, server, wantServer)
	}
	t.Logf("ClickHouse %s", server)

	url := func(run string) string { return "'http://minio:9000/" + captureBucket + "/" + run + "/'" }
	backup := func(run, user, secret, extra string) {
		q := "BACKUP DATABASE spike TO S3(" + url(run) + ", '" + user + "', '" + secret + "')" +
			" SETTINGS allow_s3_native_copy = 0, id = '" + run + "'" + extra
		out, err := query(q)
		if err != nil || !strings.Contains(out, "BACKUP_CREATED") {
			// The statement holds a secret; it is not printed.
			t.Fatalf("BACKUP %s: %v %s", run, err, redact(out, secrets))
		}
	}

	prefix := ver + "-" + suffix
	fullRun, incrRun := prefix+"/"+captureFullRun, prefix+"/"+captureIncrRun
	if out, err := query(captureSchema); err != nil {
		t.Fatalf("schema: %v %s", err, out)
	}
	backup(fullRun, captureFullUser, keys.full, "")
	if out, err := query(captureChange); err != nil {
		t.Fatalf("change: %v %s", err, out)
	}
	backup(incrRun, captureIncrUser, keys.incr, ", base_backup = S3("+url(fullRun)+"), use_same_s3_credentials_for_base_backup = 1")

	dir := filepath.Join("testdata", "native", ver)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	var written []string
	for name, run := range map[string]string{"full": fullRun, "incremental": incrRun} {
		objs := listObjects(t, mc, run)
		// objects.txt: what the run stored, "<size> <key>" per line, for the
		// tests of MetaFile.Written.
		var listing strings.Builder
		var counts []string
		for _, o := range objs {
			fmt.Fprintf(&listing, "%d %s\n", o.size, o.key)
			k := o.key
			switch {
			case k == ".backup" || strings.HasPrefix(k, "metadata/"):
			case path.Base(k) == "count.txt":
				counts = append(counts, k)
				continue
			default:
				continue
			}
			written = append(written, copyObject(t, mc, run, k, filepath.Join(dir, name), secrets))
		}
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		lf := filepath.Join(dir, name, "objects.txt")
		if err := os.WriteFile(lf, []byte(listing.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		written = append(written, lf)
		// One count.txt of the events table, at its own path.
		for _, k := range counts {
			if strings.HasPrefix(k, "data/spike/events/") {
				written = append(written, copyObject(t, mc, run, k, filepath.Join(dir, name), secrets))
				break
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(server+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range written {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatalf("%s holds a MinIO secret", f)
			}
		}
	}
	t.Logf("wrote %d files under %s", len(written), dir)
}

// listObjects returns the objects under run/: key (relative to run/) and size.
func listObjects(t *testing.T, mc *captureMC, run string) []capturedObject {
	t.Helper()
	out, err := mc.run(t, time.Minute, "ls", "--recursive", "--json", "local/"+captureBucket+"/"+run+"/")
	if err != nil {
		t.Fatalf("mc ls: %v %s", err, out)
	}
	var objs []capturedObject
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e struct {
			Key  string `json:"key"`
			Type string `json:"type"`
			Size uint64 `json:"size"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("mc ls line %q: %v", line, err)
		}
		if e.Type == "file" {
			objs = append(objs, capturedObject{key: e.Key, size: e.Size})
		}
	}
	if len(objs) == 0 {
		t.Fatalf("no objects under %s", run)
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].key < objs[j].key })
	return objs
}

type capturedObject struct {
	key  string
	size uint64
}

// copyObject writes run/key to dir/key and returns the local path. In a
// .backup, every MinIO secret is replaced with redactedSecret.
func copyObject(t *testing.T, mc *captureMC, run, key, dir string, secrets []string) string {
	t.Helper()
	b, err := mc.run(t, time.Minute, "cat", "local/"+captureBucket+"/"+run+"/"+key)
	if err != nil {
		t.Fatalf("mc cat %s: %v %s", key, err, b)
	}
	if key == ".backup" {
		if r := redact(string(b), secrets); r != string(b) {
			t.Logf("%s/.backup holds an S3 secret; redacted", run)
			b = []byte(r)
		}
	}
	local := filepath.Join(dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return local
}

// captureMC runs the MinIO client in a container on the capture network.
type captureMC struct{ network, host string }

// run returns mc's stdout (its stderr when it fails): a combined output
// would mix warnings into a file's bytes.
func (m *captureMC) run(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"run", "--rm", "--pull", "never", "--network", m.network,
		"-e", "MC_HOST_local=" + m.host, "cgr.dev/chainguard/minio-client:latest"}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return stderr.Bytes(), err
	}
	return out, nil
}

// redact replaces every secret in s with redactedSecret.
func redact(s string, secrets []string) string {
	for _, secret := range secrets {
		s = strings.ReplaceAll(s, secret, redactedSecret)
	}
	return s
}

func dockerT(t *testing.T, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func mustDocker(t *testing.T, timeout time.Duration, args ...string) string {
	t.Helper()
	out, err := dockerT(t, timeout, args...)
	if err != nil {
		t.Fatalf("docker %s: %v %s", args[0], err, out)
	}
	return out
}

func retry(t *testing.T, within time.Duration, what string, f func() (string, error)) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		out, err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v %s", what, err, out)
		}
		time.Sleep(time.Second)
	}
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
