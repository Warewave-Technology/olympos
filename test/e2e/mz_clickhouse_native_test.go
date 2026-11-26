//go:build e2e

// TestM10ClickHouseNative lives in mz_…: go test runs the tests in file-name
// order, and m10_… would sort before m1_test.go, whose enrollment it needs.

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/minio/minio-go/v7/pkg/signer"
	"gopkg.in/yaml.v3"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// The lab's native ClickHouse servers (test/e2e/manifests/targets.yaml).
const (
	nativeCH        = "native-ch"
	nativeRestoreCH = "restore-native-ch"
	nativeAdminPW   = "CANARY-lab-native-ch-admin-password"
	nativeBackupPW  = "CANARY-lab-native-ch-password"
	nativeRestorePW = "CANARY-lab-restore-native-ch-password"
	// nativeCAFile is where native-ch mounts the Olympos CA (docs/install.md §5).
	nativeCAFile = "/etc/clickhouse-server/olympos-ca/ca.crt"
)

// nativeGrants are the backup user's privileges: exactly what
// docs/clickhouse-backups.md lists, on the databases of the lab's native jobs,
// with select_from_system_db_requires_grant on (targets.yaml).
var nativeGrants = []string{
	"GRANT BACKUP ON m10.* TO backup",
	"GRANT BACKUP ON m10wire.* TO backup",
	"GRANT BACKUP ON shop.* TO backup",
	"GRANT SELECT ON system.backups TO backup",
	"GRANT SELECT ON system.clusters TO backup",
	"GRANT SELECT ON system.parts TO backup",
	"GRANT SELECT ON system.processes TO backup",
}

// nativeSchema is the source: every kind of object #62 names (codecs, a TTL,
// defaults, skip indexes, a dictionary, a view, a materialized view feeding
// an aggregate, a ReplicatedMergeTree), a view with a DEFINER that does not
// exist on the target, and a table the restore allowlist leaves out (URL).
var nativeSchema = []string{
	"DROP DATABASE IF EXISTS m10 SYNC",
	"CREATE DATABASE m10 ENGINE = Atomic",
	`CREATE TABLE m10.events (d Date, ts DateTime CODEC(DoubleDelta, ZSTD(3)), service LowCardinality(String),
		v UInt64 CODEC(T64, ZSTD(1)), note String DEFAULT concat('n', toString(v)),
		INDEX v_minmax v TYPE minmax GRANULARITY 4, INDEX service_bf service TYPE bloom_filter GRANULARITY 1)
		ENGINE = MergeTree PARTITION BY toYYYYMM(d) ORDER BY (service, ts) TTL d + INTERVAL 20 YEAR`,
	`CREATE TABLE m10.daily (d Date, service LowCardinality(String), n AggregateFunction(count), total AggregateFunction(sum, UInt64))
		ENGINE = AggregatingMergeTree ORDER BY (d, service)`,
	`CREATE MATERIALIZED VIEW m10.daily_mv TO m10.daily AS
		SELECT d, service, countState() AS n, sumState(v) AS total FROM m10.events GROUP BY d, service`,
	`CREATE TABLE m10.events_repl (d Date, k UInt64, payload String)
		ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/m10/events_repl', '{replica}') ORDER BY k`,
	"CREATE VIEW m10.events_by_service AS SELECT service, count() AS n FROM m10.events GROUP BY service",
	"CREATE VIEW m10.events_definer DEFINER = admin SQL SECURITY DEFINER AS SELECT service, v FROM m10.events",
	"CREATE TABLE m10.services (service String, team String) ENGINE = MergeTree ORDER BY service",
	`CREATE DICTIONARY m10.service_team (service String, team String) PRIMARY KEY service
		SOURCE(CLICKHOUSE(TABLE 'services')) LIFETIME(0) LAYOUT(COMPLEX_KEY_HASHED())`,
	"CREATE TABLE m10.feed (line String) ENGINE = URL('http://synth-web.lab.svc/health', 'LineAsString')",
	"INSERT INTO m10.services VALUES ('api', 'platform'), ('web', 'storefront'), ('worker', 'platform')",
}

// nativeInsert adds n rows to the source's tables from day off on.
func nativeInsert(t *testing.T, off, n int) {
	t.Helper()
	chQuery(t, nativeCH, "admin", nativeAdminPW, fmt.Sprintf(`INSERT INTO m10.events (d, ts, service, v)
		SELECT toDate('2026-10-01') + %d + number %% 20, toDateTime('2026-10-01 00:00:00') + %d * 86400 + number * 7,
		['api', 'web', 'worker'][1 + number %% 3], number FROM numbers(%d)`, off, off, n))
	chQuery(t, nativeCH, "admin", nativeAdminPW, fmt.Sprintf(
		"INSERT INTO m10.events_repl SELECT toDate('2026-10-01') + %d, %d * 1000000 + number, repeat('x', number %% 50) FROM numbers(%d)", off, off, n/2))
}

// nativeState is what a restore must reproduce: rows and a hash per table
// (the aggregate by its merged values).
func nativeState(t *testing.T, deploy, user, password string) map[string]string {
	t.Helper()
	qs := map[string]string{
		"events":      "SELECT count(), sum(cityHash64(d, ts, service, v, note)) FROM m10.events",
		"events_repl": "SELECT count(), sum(cityHash64(d, k, payload)) FROM m10.events_repl",
		"services":    "SELECT count(), sum(cityHash64(service, team)) FROM m10.services",
		"daily": "SELECT count(), sum(cityHash64(d, service, n, total)) FROM " +
			"(SELECT d, service, countMerge(n) AS n, sumMerge(total) AS total FROM m10.daily GROUP BY d, service)",
	}
	out := map[string]string{}
	for k, q := range qs {
		out[k] = chQuery(t, deploy, user, password, q)
	}
	return out
}

func chQueryOK(t *testing.T, deploy, user, password, sql string) (string, error) {
	t.Helper()
	out, err := runOK(t, "kubectl", "-n", "lab", "exec", "deploy/"+deploy, "-c", "ch", "--", "clickhouse-client",
		"--user", user, "--password", password, "--multiquery", "--query", sql)
	return strings.TrimSpace(out), err
}

func chQuery(t *testing.T, deploy, user, password, sql string) string {
	t.Helper()
	out, err := chQueryOK(t, deploy, user, password, sql)
	if err != nil {
		t.Fatalf("%s: %s: %v\n%s", deploy, sql, err, out)
	}
	return out
}

// syncNativeCA puts the Olympos CA (the agent's olympos-agent-ca, new with
// every reset of Olympos) into lab/olympos-ca and restarts native-ch and
// restore-native-ch when they do not have it yet: ClickHouse loads its
// openSSL.client caConfig when it starts. Returns the CA.
func syncNativeCA(t *testing.T) string {
	t.Helper()
	ca := run(t, "kubectl", "-n", "olympos-system", "get", "configmap", "olympos-agent-ca", "-o", `jsonpath={.data.ca\.crt}`)
	if !strings.Contains(ca, "BEGIN CERTIFICATE") {
		t.Fatalf("olympos-agent-ca: %q", ca)
	}
	if cur, _ := runOK(t, "kubectl", "-n", "lab", "get", "configmap", "olympos-ca", "-o", `jsonpath={.data.ca\.crt}`); cur != ca {
		f := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(f, []byte(ca), 0o600); err != nil {
			t.Fatal(err)
		}
		cm := run(t, "kubectl", "-n", "lab", "create", "configmap", "olympos-ca", "--from-file=ca.crt="+f, "--dry-run=client", "-o", "yaml")
		if out, err := runStdin(t, cm, "kubectl", "apply", "-f", "-"); err != nil {
			t.Fatalf("apply olympos-ca: %v %s", err, out)
		}
	}
	for _, d := range []string{nativeCH, nativeRestoreCH} {
		if got, _ := runOK(t, "kubectl", "-n", "lab", "exec", "deploy/"+d, "-c", "ch", "--", "cat", nativeCAFile); got != ca {
			emptyRestoreTarget(t, d) // a restart; the data is an emptyDir
		}
	}
	for _, d := range []struct{ deploy, user, pw string }{{nativeCH, "admin", nativeAdminPW}, {nativeRestoreCH, "restore", nativeRestorePW}} {
		eventually(t, 2*time.Minute, d.deploy+" reaches Keeper", func() (bool, string) {
			out, err := chQueryOK(t, d.deploy, d.user, d.pw, "SELECT count() FROM system.zookeeper WHERE path = '/'")
			return err == nil, out
		})
	}
	return ca
}

// nativeCheckResult is POST /restores/check's answer for a native copy.
type nativeCheckResult struct {
	OK        bool              `json:"ok"`
	Error     string            `json:"error"`
	Fields    map[string]string `json:"fields"`
	Databases []string          `json:"databases"`
	Native    *struct {
		Objects []nativeDecision `json:"objects"`
	} `json:"native"`
}

type nativeDecision struct {
	Database string `json:"database"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
}

// nativeRequest is the part of GET /restores/{id} a native restore shows.
type nativeRequest struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Error   string `json:"error"`
	Options struct {
		Native *struct {
			Databases []string         `json:"databases"`
			Excluded  []nativeDecision `json:"excluded"`
		} `json:"native"`
	} `json:"options"`
	Result     json.RawMessage `json:"result"`
	Credential *struct {
		Username string `json:"username"`
	} `json:"credential"`
}

func waitNativeRestore(t *testing.T, c *client, id string) nativeRequest {
	t.Helper()
	var rq nativeRequest
	eventually(t, 10*time.Minute, "restore "+id, func() (bool, string) {
		c.must("GET", "/restores/"+id, nil, &rq, 200)
		return rq.Status == "succeeded" || rq.Status == "failed" || rq.Status == "expired", rq.Status
	})
	return rq
}

// copyPaths returns the manifest and the directory of a native run's copy on
// a destination.
func copyPaths(t *testing.T, r backup.Run, destID string) (manifest, dir string) {
	t.Helper()
	for _, c := range r.Copies {
		if c.DestinationID.String() == destID {
			p := c.BlobPath
			if !strings.HasSuffix(p, ".manifest.json") {
				p = strings.TrimSuffix(p, "/") + ".manifest.json"
			}
			return p, strings.TrimSuffix(p, ".manifest.json") + "/"
		}
	}
	t.Fatalf("run %s has no copy on %s: %+v", r.ID, destID, r.Copies)
	return "", ""
}

// flipByte changes one byte of a blob (in place, same size) and returns how
// to put it back, tags included: the destination's SAS cannot overwrite,
// Azurite's account key can.
func flipByte(t *testing.T, az *azblob.Client, path string, at func([]byte) int) (restore func()) {
	t.Helper()
	ctx := context.Background()
	orig := download(t, az, path)
	bc := az.ServiceClient().NewContainerClient("backups").NewBlockBlobClient(path)
	tags, err := bc.GetTags(ctx, nil)
	if err != nil {
		t.Fatalf("tags of %s: %v", path, err)
	}
	keep := map[string]string{}
	for _, tg := range tags.BlobTagSet {
		keep[*tg.Key] = *tg.Value
	}
	changed := bytes.Clone(orig)
	i := at(changed)
	changed[i] ^= 0x01
	if _, err := az.UploadBuffer(ctx, "backups", path, changed, nil); err != nil {
		t.Fatalf("overwrite %s: %v", path, err)
	}
	return func() {
		t.Helper()
		if _, err := az.UploadBuffer(ctx, "backups", path, orig, nil); err != nil {
			t.Fatalf("put back %s: %v", path, err)
		}
		if _, err := bc.SetTags(ctx, keep, nil); err != nil {
			t.Fatalf("tags of %s: %v", path, err)
		}
	}
}

// signedFromClickHouse sends one SigV4-signed request with a run's
// credential from the native-ch pod to the ingest endpoint (wget, verifying
// the endpoint with the Olympos CA ClickHouse trusts) and returns the HTTP
// status line and the body.
func signedFromClickHouse(t *testing.T, method, url, accessKey, secret string) (status, body string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty := sha256.Sum256(nil)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(empty[:]))
	signed := signer.SignV4(*req, accessKey, secret, "", "us-east-1")
	args := []string{"-n", "lab", "exec", "deploy/" + nativeCH, "-c", "ch", "--", "wget", "-S", "-O", "-", "--content-on-error",
		"--tries=1", "--timeout=20", "--method=" + method, "--ca-certificate=" + nativeCAFile}
	for _, h := range []string{"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256"} {
		args = append(args, "--header="+h+": "+signed.Header.Get(h))
	}
	out, _ := runOK(t, "kubectl", append(args, url)...)
	if m := regexp.MustCompile(`HTTP/1\.1 (\d{3}[^\r\n]*)`).FindStringSubmatch(out); m != nil {
		status = m[1]
	}
	return status, out
}

// TestM10ClickHouseNative is #62's done-when in the lab: native full and
// incremental backups of native-ch (every object kind) to a destination
// group of Azurite and MinIO, a restore of each copy into
// restore-native-ch through maker/checker, the source's replicas untouched,
// a changed object or manifest refused, the install.md NetworkPolicy, and
// the run's credential: refused for a DELETE while it lives, refused after
// the run, and nowhere in Olympos's logs and database or ClickHouse's
// system tables.
func TestM10ClickHouseNative(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	var settings struct {
		IngestEnabled bool `json:"ingest_enabled"`
	}
	admin.must("GET", "/backup/settings", nil, &settings, 200)
	if !settings.IngestEnabled {
		t.Fatal("the lab server has no ingest.url: native ClickHouse backups are off (test/e2e/server-values.yaml)")
	}
	maker := grantedUser(t, admin, "native-maker", "operator")
	checker := grantedUser(t, admin, "native-checker", "operator")

	// The lab ClickHouse servers have no TLS on the native port.
	admin.must("PATCH", "/clusters/"+labClusterID, map[string]any{"transfer_mode": "compressed"}, nil, 200)
	t.Cleanup(func() {
		admin.must("PATCH", "/clusters/"+labClusterID, map[string]any{"transfer_mode": "e2e-tls"}, nil, 200)
	})
	syncNativeCA(t)

	// Least privilege: the backup user has exactly the documented grants.
	got := strings.Split(chQuery(t, nativeCH, "admin", nativeAdminPW, "SHOW GRANTS FOR backup"), "\n")
	slices.Sort(got)
	if !slices.Equal(got, nativeGrants) {
		t.Fatalf("grants of backup on native-ch:\n%s\nwant (docs/clickhouse-backups.md):\n%s", strings.Join(got, "\n"), strings.Join(nativeGrants, "\n"))
	}
	if _, err := chQueryOK(t, nativeCH, "backup", nativeBackupPW, "SELECT count() FROM system.query_log"); err == nil {
		t.Fatal("backup reads system.query_log: select_from_system_db_requires_grant is off on native-ch")
	}

	// Destinations: Azurite and MinIO in a group.
	azPort := portForward(t, "olympos", "azurite", 10000)
	cred, _ := azblob.NewSharedKeyCredential(azAccount, azKey)
	az, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("http://127.0.0.1:%d/%s", azPort, azAccount), cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := az.CreateContainer(context.Background(), "backups", nil); err != nil && !strings.Contains(err.Error(), "ContainerAlreadyExists") {
		t.Fatalf("create container: %v", err)
	}
	q, err := sas.BlobSignatureValues{
		Protocol: sas.ProtocolHTTPSandHTTP, ExpiryTime: time.Now().Add(30 * 24 * time.Hour), ContainerName: "backups",
		Permissions: (&sas.ContainerPermissions{Read: true, Create: true, Write: true, Tag: true}).String(),
	}.SignWithSharedKey(cred)
	if err != nil {
		t.Fatal(err)
	}
	azID := ensureDestination(t, admin, map[string]any{
		"name": "m10-azurite", "account": azAccount, "container": "backups", "prefix": "native",
		"auth": "sas_token", "sas": map[string]any{"source": "stored", "value": q.Encode()}, "endpoint_override": azInCluster,
	})["id"].(string)
	s3ID := ensureDestination(t, admin, map[string]any{
		"name": "m10-minio", "kind": "s3", "endpoint_override": "http://minio.olympos.svc:9000", "region": "us-east-1",
		"bucket": "backups", "prefix": "native", "path_style": true, "auth": "access_key",
		"access_key_id": "olympos-backup", "secret_key": map[string]any{"source": "stored", "value": "lab-backup-secret-key"},
	})["id"].(string)
	var groups struct {
		Items []struct{ ID, Name string } `json:"items"`
	}
	admin.must("GET", "/destination-groups", nil, &groups, 200)
	groupID := ""
	for _, g := range groups.Items {
		if g.Name == "m10-copies" {
			groupID = g.ID
		}
	}
	if groupID == "" {
		var g struct{ ID string }
		admin.must("POST", "/destination-groups", map[string]any{"name": "m10-copies", "member_ids": []string{azID, s3ID}}, &g, 201)
		groupID = g.ID
	}

	// The source.
	for _, s := range nativeSchema {
		chQuery(t, nativeCH, "admin", nativeAdminPW, s)
	}
	t.Cleanup(func() { _, _ = chQueryOK(t, nativeCH, "admin", nativeAdminPW, "DROP DATABASE IF EXISTS m10 SYNC") })
	nativeInsert(t, 0, 30000)

	src := labTarget(t, admin, nativeCH)
	backupCred := map[string]any{"source": "stored", "username": "backup", "password": nativeBackupPW}
	var job backup.JobView
	admin.must("POST", "/backup/jobs", map[string]any{"target_id": src.ID, "credential": backupCred, "destination_group_id": groupID,
		"engine_options": map[string]any{"databases": []string{"m10"}, "method": "native", "incremental": "weekly_full_daily"},
		"cron":           "0 2 * * *", "timezone": "UTC", "enabled": false}, &job, 201)
	t.Cleanup(func() {
		if code, raw := admin.do("DELETE", "/backup/jobs/"+job.ID.String(), nil, nil); code != 204 {
			t.Errorf("delete job: %d %s", code, raw)
		}
	})

	dry := runAndWait(t, admin, job.ID.String(), "test")
	t.Logf("dry run: %s, %d steps", dry.Status, len(dry.Steps))
	full := runAndWait(t, admin, job.ID.String(), "manual")
	if full.Method != "native" || full.Objects == nil || *full.Objects == 0 || len(full.Copies) != 2 ||
		full.Copies[0].Status != "succeeded" || full.Copies[1].Status != "succeeded" {
		t.Fatalf("full: %+v", full)
	}
	fullState := nativeState(t, nativeCH, "admin", nativeAdminPW)

	// The NetworkPolicy of docs/install.md ("Egress from the ClickHouse
	// pods", the in-cluster form) plus DNS, which the lab namespace has no
	// other rule for: the incremental goes through it.
	probe := func() error {
		_, err := runOK(t, "kubectl", "-n", "lab", "exec", "deploy/"+nativeCH, "-c", "ch", "--", "wget", "-q", "-T", "5", "--tries=1",
			"-O", "/dev/null", "http://minio.olympos.svc:9000/minio/health/live")
		return err
	}
	if err := probe(); err != nil {
		t.Fatalf("native-ch cannot reach MinIO before the NetworkPolicy: %v", err)
	}
	np := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: clickhouse-to-olympos-ingest, namespace: lab}
spec:
  podSelector:
    matchLabels: {app: native-ch}
  policyTypes: [Egress]
  egress:
  - to:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: olympos}}
      podSelector: {matchLabels: {app.kubernetes.io/name: olympos-server}}
    ports:
    - {protocol: TCP, port: 9444}
  - to:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
      podSelector: {matchLabels: {k8s-app: kube-dns}}
    ports:
    - {protocol: UDP, port: 53}
    - {protocol: TCP, port: 53}
`
	applyStdin(t, np)
	removeNP := func() {
		_, _ = runOK(t, "kubectl", "-n", "lab", "delete", "networkpolicy", "clickhouse-to-olympos-ingest", "--ignore-not-found")
	}
	t.Cleanup(removeNP)
	eventually(t, time.Minute, "the NetworkPolicy is enforced (native-ch cannot reach MinIO)", func() (bool, string) {
		err := probe()
		return err != nil, fmt.Sprint(err)
	})

	nativeInsert(t, 30, 8000)
	incr := runAndWait(t, admin, job.ID.String(), "manual")
	removeNP()
	if incr.Method != "native" || len(incr.Copies) != 2 || incr.Copies[0].Status != "succeeded" || incr.Copies[1].Status != "succeeded" {
		t.Fatalf("incremental: %+v", incr)
	}
	incrState := nativeState(t, nativeCH, "admin", nativeAdminPW)
	manPath, _ := copyPaths(t, incr, azID)
	// The run's manifest holds the signed native manifest (details.native).
	var runManifest struct {
		Details struct {
			Native struct {
				Manifest struct {
					RunID     string `json:"run_id"`
					BaseRunID string `json:"base_run_id"`
				} `json:"manifest"`
			} `json:"native"`
		} `json:"details"`
	}
	if err := json.Unmarshal(download(t, az, manPath), &runManifest); err != nil {
		t.Fatal(err)
	}
	if m := runManifest.Details.Native.Manifest; m.RunID != incr.ID.String() || m.BaseRunID != full.ID.String() {
		t.Fatalf("the second run is not an incremental on the full: %+v (full %s)", m, full.ID)
	}
	t.Logf("full %s (%d objects), incremental %s (%d objects) on it", full.ID, *full.Objects, incr.ID, *incr.Objects)

	srcDDL := map[string]string{}
	for _, o := range []string{"events", "daily", "daily_mv", "events_by_service", "events_definer", "services", "service_team"} {
		srcDDL[o] = chQuery(t, nativeCH, "admin", nativeAdminPW, "SHOW CREATE m10."+o+" FORMAT TSVRaw")
	}
	sourceReplicas := func(t *testing.T) string {
		return chQuery(t, nativeCH, "admin", nativeAdminPW,
			"SELECT arrayStringConcat(groupArray(name), ',') FROM system.zookeeper WHERE path = '/clickhouse/tables/01/m10/events_repl/replicas'")
	}
	if r := sourceReplicas(t); r != "native-ch" {
		t.Fatalf("source replicas before the restores: %q", r)
	}

	dstQ := func(t *testing.T, sql string) string {
		return chQuery(t, nativeRestoreCH, "restore", nativeRestorePW, sql)
	}
	dropTarget := func(t *testing.T) { dstQ(t, "DROP DATABASE IF EXISTS m10 SYNC") }
	target := restoreTargetID(t, admin, nativeRestoreCH)
	restoreIn := func(r backup.Run, destID string) map[string]any {
		return map[string]any{"run_id": r.ID, "copy_destination_id": destID, "target_id": target, "databases": []string{"m10"},
			"credential":    map[string]any{"source": "stored", "username": "restore", "password": nativeRestorePW},
			"justification": "e2e: native-ch lost, restore into restore-native-ch (M10)"}
	}
	check := func(c *client, in map[string]any) nativeCheckResult {
		var ck nativeCheckResult
		c.must("POST", "/restores/check", in, &ck, 200)
		return ck
	}

	for _, tc := range []struct {
		name   string
		run    backup.Run
		destID string
		want   map[string]string
	}{
		{"full-azurite", full, azID, fullState},
		{"full-minio", full, s3ID, fullState},
		{"incremental-azurite", incr, azID, incrState},
		{"incremental-minio", incr, s3ID, incrState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin, maker, checker := admin.in(t), maker.in(t), checker.in(t)
			dropTarget(t)
			in := restoreIn(tc.run, tc.destID)
			var ck nativeCheckResult
			eventually(t, time.Minute, "restore-native-ch answers the check", func() (bool, string) {
				ck = check(maker, in)
				return ck.OK, fmt.Sprintf("%s %v", ck.Error, ck.Fields)
			})
			if ck.Native == nil {
				t.Fatalf("check of a native copy without objects: %+v", ck)
			}
			decided := map[string]nativeDecision{}
			for _, o := range ck.Native.Objects {
				decided[o.Name] = o
			}
			for _, name := range []string{"events", "daily", "daily_mv", "events_repl", "events_by_service", "services", "service_team"} {
				if !decided[name].Allowed {
					t.Errorf("%s left out: %+v", name, decided[name])
				}
			}
			if f := decided["feed"]; f.Allowed || f.Reason == "" {
				t.Errorf("the URL table is not left out with a reason: %+v", f)
			}
			t.Logf("events_definer: %+v", decided["events_definer"])

			rq := openRestore(t, maker, in)
			var seen nativeRequest
			checker.must("GET", "/restores/"+rq.ID, nil, &seen, 200)
			if seen.Options.Native == nil || !slices.ContainsFunc(seen.Options.Native.Excluded, func(d nativeDecision) bool { return d.Name == "feed" }) {
				t.Fatalf("the checker does not see what the restore leaves out: %+v", seen.Options)
			}
			approveRestore(t, maker, checker, rq.ID)
			done := waitNativeRestore(t, admin, rq.ID)
			if done.Status != "succeeded" || done.Credential != nil {
				t.Fatalf("restore %s: %s (%s) %s", rq.ID, done.Status, done.Error, done.Result)
			}

			if got := nativeState(t, nativeRestoreCH, "restore", nativeRestorePW); !mapsEqual(got, tc.want) {
				t.Errorf("restored data %v, source at the run %v", got, tc.want)
			}
			for o, want := range srcDDL {
				if o == "events_definer" && !decided[o].Allowed {
					continue
				}
				if got := dstQ(t, "SHOW CREATE m10."+o+" FORMAT TSVRaw"); got != want {
					t.Errorf("m10.%s on the target:\n%s\nsource:\n%s", o, got, want)
				}
			}
			if n := dstQ(t, "SELECT count() FROM system.tables WHERE database = 'm10' AND name = 'feed'"); n != "0" {
				t.Error("the left-out URL table was created")
			}
			// The view, the dictionary and the materialized view work.
			if got := dstQ(t, "SELECT n FROM m10.events_by_service WHERE service = 'api'"); got == "" || got == "0" {
				t.Errorf("view: %q", got)
			}
			if got := dstQ(t, "SELECT dictGet('m10.service_team', 'team', tuple('web'))"); got != "storefront" {
				t.Errorf("dictionary: %q", got)
			}
			dstQ(t, "INSERT INTO m10.events (d, ts, service, v) SELECT toDate('2030-01-01'), toDateTime('2030-01-01 00:00:00'), 'web', number FROM numbers(123)")
			if got := dstQ(t, "SELECT countMerge(n) FROM m10.daily WHERE d = '2030-01-01'"); got != "123" {
				t.Errorf("materialized view on the target: %q rows for the new day", got)
			}
			// The DEFINER does not exist on the target (it has no user admin).
			if decided["events_definer"].Allowed {
				if out, err := chQueryOK(t, nativeRestoreCH, "restore", nativeRestorePW, "SELECT count() FROM m10.events_definer"); err == nil ||
					!strings.Contains(out, "UNKNOWN_USER") {
					t.Errorf("a view whose DEFINER is missing on the target: %v %s", err, out)
				}
			}
			// The Replicated table has its own Keeper path; the source's
			// replica set is untouched.
			zk := dstQ(t, "SELECT zookeeper_path FROM system.replicas WHERE database = 'm10' AND table = 'events_repl'")
			if !strings.HasPrefix(zk, "/olympos-restore/"+rq.ID+"/") {
				t.Errorf("restored Replicated table's Keeper path %q", zk)
			}
			if r := sourceReplicas(t); r != "native-ch" {
				t.Errorf("source replicas after the restore: %q", r)
			}
			if n := chQuery(t, nativeCH, "admin", nativeAdminPW, "SELECT count() FROM m10.events_repl"); n != strings.Fields(incrState["events_repl"])[0] {
				t.Errorf("source events_repl has %s rows", n)
			}
			t.Logf("restored %s into %s (Keeper %s)", tc.name, nativeRestoreCH, zk)
		})
	}

	t.Run("tampered", func(t *testing.T) {
		admin, maker, checker := admin.in(t), maker.in(t), checker.in(t)
		dropTarget(t)
		_, fullDir := copyPaths(t, full, azID)
		fullMan, _ := copyPaths(t, full, azID)
		// One byte of a data file of the full: the check passes (its
		// manifests verify), the restore fails naming the object.
		var dataKey string
		pager := az.NewListBlobsFlatPager("backups", &container.ListBlobsFlatOptions{Prefix: &fullDir})
		for pager.More() && dataKey == "" {
			page, err := pager.NextPage(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range page.Segment.BlobItems {
				if strings.Contains(*b.Name, "/data/m10/events/") && strings.HasSuffix(*b.Name, ".bin") && *b.Properties.ContentLength > 64 {
					dataKey = *b.Name
					break
				}
			}
		}
		if dataKey == "" {
			t.Fatalf("no data file of m10.events under %s", fullDir)
		}
		putBack := flipByte(t, az, dataKey, func(b []byte) int { return len(b) / 2 })
		in := restoreIn(full, azID)
		if ck := check(maker, in); !ck.OK {
			t.Fatalf("check of a copy with a changed data file: %+v", ck)
		}
		rq := openRestore(t, maker, in)
		approveRestore(t, maker, checker, rq.ID)
		done := waitNativeRestore(t, admin, rq.ID)
		putBack()
		key := strings.TrimPrefix(dataKey, fullDir)
		if done.Status != "failed" || !strings.Contains(done.Error+string(done.Result), key) {
			t.Errorf("restore of a changed object: %s %q %s (want it named: %s)", done.Status, done.Error, done.Result, key)
		}
		t.Logf("changed object: %s %q", done.Status, done.Error)
		dropTarget(t)

		// One byte of the full's signed manifest (an object's SHA-256): neither
		// copy of the chain verifies.
		putBack = flipByte(t, az, fullMan, func(b []byte) int {
			n := bytes.Index(b, []byte(`"native":`))
			i := bytes.Index(b[max(n, 0):], []byte(`"sha256":"`))
			if n < 0 || i < 0 {
				t.Fatal("no object hash in the signed native manifest")
			}
			return n + i + len(`"sha256":"`)
		})
		for _, r := range []backup.Run{full, incr} {
			ck := check(maker, restoreIn(r, azID))
			if ck.OK || ck.Fields["copy_destination_id"] != backup.ErrNativeNotVerified.Error() {
				t.Errorf("check of %s with a changed manifest: %+v", r.ID, ck)
			}
		}
		if code, raw := maker.do("POST", "/restores", restoreIn(incr, azID), nil); code != 422 {
			t.Errorf("open with a changed manifest: %d %s", code, raw)
		}
		putBack()
		if ck := check(maker, restoreIn(incr, azID)); !ck.OK {
			t.Errorf("check after the manifest was put back: %+v", ck)
		}
	})

	t.Run("credential", func(t *testing.T) { nativeCredential(t, admin.in(t), azID) })
}

// in is the session for a subtest: its failures stop the subtest, not the
// parent.
func (c *client) in(t *testing.T) *client {
	cc := *c
	cc.t = t
	return &cc
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// labIngestURL is the server's ingest.url (test/e2e/server-values.yaml), from
// its configuration.
func labIngestURL(t *testing.T) string {
	t.Helper()
	raw := run(t, "kubectl", "-n", "olympos", "get", "configmap", "olympos-config", "-o", `jsonpath={.data.config\.yaml}`)
	var cfg struct {
		Olympos struct {
			Ingest struct {
				URL string `yaml:"url"`
			} `yaml:"ingest"`
		} `yaml:"olympos"`
	}
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil || cfg.Olympos.Ingest.URL == "" {
		t.Fatalf("ingest.url in olympos-config: %v", err)
	}
	return strings.TrimSuffix(cfg.Olympos.Ingest.URL, "/")
}

// nativeCredential: a native run of native-ch through native-ch-wire, which
// records what the agent sends. The run's credential is refused for a
// DELETE while the run goes on, refused after the run, and appears in no
// Olympos log, no column of Olympos's database and no ClickHouse system
// table or log.
func nativeCredential(t *testing.T, admin *client, destID string) {
	run(t, "kubectl", "apply", "-f", "test/e2e/manifests/native-ch-wire.yaml")
	t.Cleanup(func() {
		_, _ = runOK(t, "kubectl", "delete", "-f", "test/e2e/manifests/native-ch-wire.yaml", "--ignore-not-found")
	})
	run(t, "kubectl", "-n", "lab", "rollout", "status", "deploy/native-ch-wire", "--timeout=120s")
	wire := restoreTargetID(t, admin, "native-ch-wire")

	// Enough files that the run lasts a while at 150 PUT a second.
	stmts := []string{"DROP DATABASE IF EXISTS m10wire SYNC", "CREATE DATABASE m10wire",
		"CREATE TABLE m10wire.parts (k UInt64, a String, b String, c String, d String, e String, f String) " +
			"ENGINE = MergeTree ORDER BY k SETTINGS min_bytes_for_wide_part = 0, min_rows_for_wide_part = 0",
		"SYSTEM STOP MERGES m10wire.parts"}
	for i := range 150 {
		stmts = append(stmts, fmt.Sprintf("INSERT INTO m10wire.parts SELECT %d * 1000 + number, 'a', 'b', 'c', 'd', 'e', 'f' FROM numbers(1000)", i))
	}
	chQuery(t, nativeCH, "admin", nativeAdminPW, strings.Join(stmts, ";\n"))
	t.Cleanup(func() { _, _ = chQueryOK(t, nativeCH, "admin", nativeAdminPW, "DROP DATABASE IF EXISTS m10wire SYNC") })

	var job backup.JobView
	admin.must("POST", "/backup/jobs", map[string]any{"target_id": wire,
		"credential":     map[string]any{"source": "stored", "username": "backup", "password": nativeBackupPW},
		"destination_id": destID, "engine_options": map[string]any{"databases": []string{"m10wire"}, "method": "native"},
		"cron": "0 2 * * *", "timezone": "UTC", "enabled": false}, &job, 201)
	t.Cleanup(func() { _, _ = admin.do("DELETE", "/backup/jobs/"+job.ID.String(), nil, nil) })

	run(t, "kubectl", "-n", "lab", "exec", "deploy/native-ch-wire", "--", "sh", "-c", ": > /tmp/c2s")
	var queued backup.Run
	admin.must("POST", "/backup/jobs/"+job.ID.String()+"/run", map[string]any{"trigger": "manual"}, &queued, 202)
	// The S3(url, key, secret) of the run's BACKUP statement.
	s3Args := regexp.MustCompile(`TO S3\('(` + regexp.QuoteMeta(labIngestURL(t)) + `/olympos/[0-9a-f-]+/)', '([^']+)', '([^']+)'\)`)
	var url, accessKey, secret string
	eventually(t, 3*time.Minute, "the run's BACKUP on the wire", func() (bool, string) {
		out, _ := runOK(t, "kubectl", "-n", "lab", "exec", "deploy/native-ch-wire", "--", "cat", "/tmp/c2s")
		m := s3Args.FindStringSubmatch(out)
		if m == nil {
			return false, fmt.Sprintf("%d bytes", len(out))
		}
		url, accessKey, secret = m[1], m[2], m[3]
		return true, ""
	})
	if !strings.Contains(url, queued.ID.String()) || len(secret) < 32 {
		t.Fatalf("captured %s for run %s (secret %d characters)", url, queued.ID, len(secret))
	}

	// While the run goes on, its own credential may not delete.
	for _, key := range []string{"data/m10wire/parts/all_1_1_0/k.bin", ".backup"} {
		status, body := signedFromClickHouse(t, http.MethodDelete, url+key, accessKey, secret)
		if !strings.HasPrefix(status, "403") || !strings.Contains(body, "<Code>AccessDenied</Code>") {
			t.Errorf("DELETE %s with the live credential: %q\n%s", key, status, body)
		}
	}
	var r backup.Run
	admin.must("GET", "/backup/runs/"+queued.ID.String(), nil, &r, 200)
	if r.Status != "running" {
		t.Errorf("the run was %s when the DELETEs were sent: they did not test a live credential", r.Status)
	}
	eventually(t, 5*time.Minute, "the wire run", func() (bool, string) {
		admin.must("GET", "/backup/runs/"+queued.ID.String(), nil, &r, 200)
		return r.Status != "queued" && r.Status != "running", r.Status
	})
	if r.Status != "succeeded" || r.Method != "native" {
		t.Fatalf("wire run: %s %q", r.Status, r.Error)
	}

	// After the run the credential is gone.
	for _, m := range []struct{ method, key string }{{http.MethodGet, ".backup"}, {http.MethodDelete, ".lock"}} {
		status, body := signedFromClickHouse(t, m.method, url+m.key, accessKey, secret)
		if !strings.HasPrefix(status, "403") || !strings.Contains(body, "<Code>InvalidAccessKeyId</Code>") {
			t.Errorf("%s %s after the run: %q\n%s", m.method, m.key, status, body)
		}
	}

	// The secret is nowhere: Olympos's logs and database.
	for _, l := range []struct{ ns, deploy string }{{"olympos", "olympos"}, {"olympos-system", "olympos-agent"}} {
		logs := run(t, "kubectl", "-n", l.ns, "logs", "deploy/"+l.deploy, "--all-containers", "--tail=-1")
		if strings.Contains(logs, secret) {
			t.Errorf("the run's secret is in the %s logs", l.deploy)
		}
	}
	dump := run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--", "pg_dump", "-U", "olympos", "-d", "olympos", "--data-only")
	if len(dump) < 10000 || strings.Contains(dump, secret) {
		t.Errorf("the run's secret in Olympos's database (dump of %d bytes): %v", len(dump), strings.Contains(dump, secret))
	}
	// ClickHouse: every system table that keeps rows, and its log files. The
	// queries name the secret in hex only, so they do not put it there.
	needle := "unhex('" + hex.EncodeToString([]byte(secret)) + "')"
	chQuery(t, nativeCH, "admin", nativeAdminPW, "SYSTEM FLUSH LOGS")
	tables := strings.Fields(chQuery(t, nativeCH, "admin", nativeAdminPW,
		"SELECT name FROM system.tables WHERE database = 'system' AND (engine LIKE '%MergeTree' OR name IN "+
			"('processes', 'backups', 'tables', 'dictionaries', 'query_cache', 'zookeeper_connection', 'user_processes')) ORDER BY name"))
	if !slices.Contains(tables, "query_log") || !slices.Contains(tables, "backups") {
		t.Fatalf("system tables to search: %v", tables)
	}
	for _, tb := range tables {
		n := chQuery(t, nativeCH, "admin", nativeAdminPW, fmt.Sprintf("SELECT count() FROM system.%s WHERE position(formatRow('TSVRaw', *), %s) > 0", tb, needle))
		if n != "0" {
			t.Errorf("the run's secret is in system.%s (%s rows)", tb, n)
		}
	}
	masked := chQuery(t, nativeCH, "admin", nativeAdminPW, fmt.Sprintf(
		"SELECT count() FROM system.query_log WHERE query_kind = 'Backup' AND position(query, '%s') > 0 AND position(query, '[HIDDEN]') > 0", queued.ID))
	if masked == "0" {
		t.Errorf("no masked BACKUP of run %s in system.query_log", queued.ID)
	}
	files, _ := runOK(t, "kubectl", "-n", "lab", "exec", "deploy/"+nativeCH, "-c", "ch", "--", "sh", "-c",
		"cat /var/log/clickhouse-server/*.log 2>/dev/null | grep -c -F -e '"+secret+"' || true")
	if strings.TrimSpace(files) != "0" {
		t.Errorf("the run's secret in native-ch's log files: %s", files)
	}
	if logs := run(t, "kubectl", "-n", "lab", "logs", "deploy/"+nativeCH, "--tail=-1"); strings.Contains(logs, secret) {
		t.Error("the run's secret in native-ch's container log")
	}
	t.Logf("run %s: credential %s… refused for DELETE while live and for every request after the run; its secret is in no log, table or column searched (%d system tables)",
		queued.ID, accessKey[:6], len(tables))
}
