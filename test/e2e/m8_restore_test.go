//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// Lab restore targets (test/e2e/manifests/targets.yaml): new, empty servers.
const (
	restorePGPassword = "CANARY-lab-restore-pg-password"
	restoreCHPassword = "CANARY-lab-restore-ch-password"
)

// restoreReq is the part of a restore request (GET /restores/{id}) the
// tests look at.
type restoreReq struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Error      string `json:"error"`
	BreakGlass bool   `json:"break_glass"`
	Credential *struct {
		Username string `json:"username"`
	} `json:"credential"`
	HasVaultToken bool `json:"has_vault_token"`
	CanApprove    bool `json:"can_approve"`
	Options       struct {
		Superuser *bool    `json:"superuser"`
		Globals   *bool    `json:"globals"`
		Notes     []string `json:"notes"`
	} `json:"options"`
	Result struct {
		Items []struct {
			Name    string   `json:"name"`
			Status  string   `json:"status"`
			Tables  int      `json:"tables"`
			Rows    int64    `json:"rows"`
			Skipped []string `json:"skipped"`
			Error   string   `json:"error"`
		} `json:"items"`
		Notes   []string `json:"notes"`
		Created []string `json:"created"`
	} `json:"result"`
}

// restoreCheck is POST /restores/check's answer.
type restoreCheck struct {
	OK                bool              `json:"ok"`
	Error             string            `json:"error"`
	Fields            map[string]string `json:"fields"`
	Databases         []string          `json:"databases"`
	DatabasesInBackup []string          `json:"databases_in_backup"`
	Options           struct {
		Superuser *bool    `json:"superuser"`
		Notes     []string `json:"notes"`
	} `json:"options"`
	Report *struct {
		Existing         map[string]bool `json:"existing"`
		Superuser        bool            `json:"superuser"`
		Initialized      bool            `json:"initialized"`
		Sealed           bool            `json:"sealed"`
		CanSnapshotForce bool            `json:"can_snapshot_force"`
		ServerVersion    string          `json:"server_version"`
	} `json:"report"`
}

// emptyRestoreTarget restarts a lab restore target (its data is an emptyDir)
// and waits until only the new pod is left and ready.
func emptyRestoreTarget(t *testing.T, deploy string) {
	t.Helper()
	run(t, "kubectl", "-n", "lab", "rollout", "restart", "deploy/"+deploy)
	run(t, "kubectl", "-n", "lab", "rollout", "status", "deploy/"+deploy, "--timeout=240s")
	eventually(t, 2*time.Minute, deploy+": one pod left", func() (bool, string) {
		out := strings.Fields(run(t, "kubectl", "-n", "lab", "get", "pods", "-l", "app="+deploy, "-o", "jsonpath={range .items[*]}{.metadata.name} {end}"))
		return len(out) == 1, strings.Join(out, " ")
	})
}

// restoreTargetID waits until the agent reports the lab restore target.
func restoreTargetID(t *testing.T, c *client, service string) string {
	t.Helper()
	id := ""
	eventually(t, 2*time.Minute, "restore target "+service+" discovered", func() (bool, string) {
		var ts struct {
			Items []struct {
				ID        string `json:"id"`
				Service   string `json:"service"`
				ClusterID string `json:"cluster_id"`
				Status    string `json:"status"`
			} `json:"items"`
		}
		c.must("GET", "/targets", nil, &ts, 200)
		for _, tg := range ts.Items {
			if tg.Service == service && tg.ClusterID == labClusterID && tg.Status != "gone" {
				id = tg.ID
				return true, ""
			}
		}
		return false, fmt.Sprint(len(ts.Items))
	})
	return id
}

// labDestination is the Azurite destination created by TestM2.
func labDestination(t *testing.T, c *client) string {
	t.Helper()
	var dests struct {
		Items []map[string]any `json:"items"`
	}
	c.must("GET", "/destinations", nil, &dests, 200)
	for _, d := range dests.Items {
		if d["name"] == "lab-azurite" {
			return d["id"].(string)
		}
	}
	t.Skip("destination lab-azurite from TestM2BackupsPostgresAndClickHouse missing")
	return ""
}

func jobFor(t *testing.T, c *client, targetID string) string {
	t.Helper()
	var jobs struct{ Items []backup.JobView }
	c.must("GET", "/backup/jobs", nil, &jobs, 200)
	for _, j := range jobs.Items {
		if j.Target.ID == targetID {
			return j.ID.String()
		}
	}
	return ""
}

func checkRestore(t *testing.T, c *client, in map[string]any) restoreCheck {
	t.Helper()
	var res restoreCheck
	c.must("POST", "/restores/check", in, &res, 200)
	return res
}

func openRestore(t *testing.T, c *client, in map[string]any) restoreReq {
	t.Helper()
	var rq restoreReq
	c.must("POST", "/restores", in, &rq, 201)
	return rq
}

// approveRestore: the maker may not approve, the checker does.
func approveRestore(t *testing.T, maker, checker *client, id string) {
	t.Helper()
	var rq restoreReq
	maker.must("GET", "/restores/"+id, nil, &rq, 200)
	if rq.Status != "pending" || rq.CanApprove {
		t.Fatalf("maker's view of a new request: %+v", rq)
	}
	if code, raw := maker.do("POST", "/restores/"+id+"/approve", map[string]any{"comment": "self"}, nil); code != 403 {
		t.Fatalf("maker approved own restore: %d %s", code, raw)
	}
	checker.must("POST", "/restores/"+id+"/approve", map[string]any{"comment": "e2e: target checked"}, &rq, 200)
	if rq.Status != "approved" {
		t.Fatalf("approved request status %s", rq.Status)
	}
}

// waitRestore waits for the backup worker to finish the request; it must
// succeed, and its credential and token must be gone.
func waitRestore(t *testing.T, c *client, id string) restoreReq {
	t.Helper()
	var rq restoreReq
	eventually(t, 10*time.Minute, "restore "+id, func() (bool, string) {
		c.must("GET", "/restores/"+id, nil, &rq, 200)
		return rq.Status == "succeeded" || rq.Status == "failed" || rq.Status == "expired", rq.Status
	})
	if rq.Status != "succeeded" {
		b, _ := json.Marshal(rq.Result)
		t.Fatalf("restore %s: %s (%s) result %s", id, rq.Status, rq.Error, b)
	}
	if rq.Credential != nil || rq.HasVaultToken {
		t.Fatalf("restore %s ended with its secrets kept: credential %+v, token %v", id, rq.Credential, rq.HasVaultToken)
	}
	return rq
}

func olymposSQL(t *testing.T, sql string) string {
	t.Helper()
	return strings.TrimSpace(run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--",
		"psql", "-U", "olympos", "-d", "olympos", "-At", "-c", sql))
}

// TestM8Restores restores a fresh backup of each lab source into its lab
// restore target through maker/checker (docs/restore.md "Restore from the
// UI"), checks the data on the target, refuses a restore over a database
// with data, runs one break-glass restore, and unseals the restored Vault
// with the source's keys.
func TestM8Restores(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	destID := labDestination(t, admin)
	maker := grantedUser(t, admin, "restore-maker", "operator")
	checker := grantedUser(t, admin, "restore-checker", "operator")
	var secrets []string

	t.Run("postgresql", func(t *testing.T) {
		srcSQL := func(sql string) string {
			return strings.TrimSpace(run(t, "kubectl", "-n", "lab", "exec", "statefulset/orders-pg", "--",
				"psql", "-U", "backup", "-d", "orders", "-At", "-v", "ON_ERROR_STOP=1", "-c", sql))
		}
		dstSQL := func(db, sql string) (string, error) {
			out, err := runOK(t, "kubectl", "-n", "lab", "exec", "deploy/restore-pg", "-c", "pg", "--",
				"psql", "-U", "postgres", "-d", db, "-At", "-v", "ON_ERROR_STOP=1", "-c", sql)
			return strings.TrimSpace(out), err
		}
		marker := "m8-" + uuid.NewString()[:8]
		// orders-pg keeps its data across lab resets (the browsable lab too).
		t.Cleanup(func() { srcSQL("DROP TABLE IF EXISTS restore_check") })
		srcSQL("CREATE TABLE IF NOT EXISTS restore_check (id int PRIMARY KEY, marker text NOT NULL)")
		srcSQL("TRUNCATE restore_check")
		srcSQL("INSERT INTO restore_check SELECT g, '" + marker + "' FROM generate_series(1, 2500) g")

		pg := labTarget(t, admin, "orders-pg")
		pgCred := map[string]any{"source": "stored", "username": "backup", "password": "CANARY-lab-pg-password"}
		job := ensureJob(t, admin, pg.ID, destID, pgCred, map[string]any{"databases": []string{"orders"}})
		src := runAndWait(t, admin, job, "manual")

		emptyRestoreTarget(t, "restore-pg")
		target := restoreTargetID(t, admin, "restore-pg")
		cred := map[string]any{"source": "stored", "username": "postgres", "password": restorePGPassword}
		in := map[string]any{"run_id": src.ID, "target_id": target, "credential": cred,
			"justification": "e2e: orders-pg lost, restore into restore-pg (M8)"}

		// The backup's own target is refused.
		own := checkRestore(t, maker, map[string]any{"run_id": src.ID, "target_id": pg.ID, "credential": pgCred})
		if own.OK || !strings.Contains(own.Fields["target_id"], "own target") {
			t.Fatalf("restore into the backup's own target: %+v", own)
		}
		ck := checkRestore(t, maker, in)
		if !ck.OK || ck.Report == nil || !ck.Report.Superuser || !strings.HasPrefix(ck.Report.ServerVersion, "16") ||
			strings.Join(ck.Databases, ",") != "orders" {
			t.Fatalf("check: %+v", ck)
		}
		// Break-glass is for admins on both clusters only.
		bg := map[string]any{"break_glass": true}
		for k, v := range in {
			bg[k] = v
		}
		if code, raw := maker.do("POST", "/restores", bg, nil); code != 403 {
			t.Fatalf("operator break-glass: %d %s", code, raw)
		}

		rq := openRestore(t, maker, in)
		if rq.Status != "pending" || rq.Options.Superuser == nil || !*rq.Options.Superuser || rq.Credential == nil {
			t.Fatalf("opened: %+v", rq)
		}
		if _, raw := checker.do("GET", "/restores/"+rq.ID, nil, nil); strings.Contains(raw, restorePGPassword) {
			t.Fatal("target password in the request")
		}
		approveRestore(t, maker, checker, rq.ID)
		done := waitRestore(t, admin, rq.ID)
		// One item for the roles (globals.sql), one per database.
		items := map[string]string{}
		for _, it := range done.Result.Items {
			items[it.Name] = fmt.Sprintf("%s/%d", it.Status, it.Tables)
		}
		if items["globals.sql"] != "succeeded/0" || items["orders"] != "succeeded/1" || strings.Join(done.Result.Created, ",") != "orders" {
			t.Fatalf("result: %+v", done.Result)
		}
		got, err := dstSQL("orders", "SELECT count(*) || ' ' || min(marker) || ' ' || max(marker) FROM restore_check")
		if err != nil || got != "2500 "+marker+" "+marker {
			t.Fatalf("restored rows: %q %v", got, err)
		}
		// Superuser credential: globals restored and owners kept.
		if got, err := dstSQL("orders", "SELECT tableowner FROM pg_tables WHERE tablename = 'restore_check'"); err != nil || got != "backup" {
			t.Fatalf("owner on the target: %q %v", got, err)
		}

		// A second restore of the same backup is refused: orders now holds data.
		conflict := checkRestore(t, maker, in)
		if conflict.OK || !strings.Contains(conflict.Fields["databases"], "already exist on the target with data") {
			t.Fatalf("conflict check: %+v", conflict)
		}
		if code, raw := maker.do("POST", "/restores", in, nil); code != 422 || !strings.Contains(raw, "nothing is overwritten") {
			t.Fatalf("conflict open: %d %s", code, raw)
		}
		if got, _ := dstSQL("orders", "SELECT count(*) FROM restore_check"); got != "2500" {
			t.Fatalf("target changed by a refused restore: %s rows", got)
		}

		// Break-glass: the operator drops the database by hand, an admin
		// restores it again at once, without a checker. The role backup now
		// exists on the target: it is left alone and listed.
		if _, err := dstSQL("postgres", "DROP DATABASE orders WITH (FORCE)"); err != nil {
			t.Fatal(err)
		}
		bg["justification"] = "e2e: incident M8, no second person available (break-glass)"
		var brq restoreReq
		admin.must("POST", "/restores", bg, &brq, 201)
		if !brq.BreakGlass || brq.Status != "approved" {
			t.Fatalf("break-glass opened: %+v", brq)
		}
		bdone := waitRestore(t, admin, brq.ID)
		if got, err := dstSQL("orders", "SELECT count(*) FROM restore_check WHERE marker = '"+marker+"'"); err != nil || got != "2500" {
			t.Fatalf("break-glass restored rows: %q %v", got, err)
		}
		b, _ := json.Marshal(bdone.Result)
		if !strings.Contains(string(b), "backup") {
			t.Errorf("break-glass result does not list the existing role backup: %s", b)
		}
		if n := olymposSQL(t, "SELECT count(*) FROM outbox WHERE event_type = 'restore.break_glass' AND payload->>'link' LIKE '%"+brq.ID+"'"); n != "1" {
			t.Errorf("restore.break_glass events: %s", n)
		}
		if n := olymposSQL(t, "SELECT count(*) FROM activity_log WHERE action = 'restore.break_glass' AND object_id = '"+brq.ID+"'"); n != "1" {
			t.Errorf("restore.break_glass audit rows: %s", n)
		}
		for _, typ := range []string{"restore.requested", "restore.approved", "restore.started", "restore.succeeded"} {
			if n := olymposSQL(t, "SELECT count(*) FROM outbox WHERE event_type = '"+typ+"' AND payload->>'link' LIKE '%"+rq.ID+"'"); n != "1" {
				t.Errorf("%s events for %s: %s", typ, rq.ID, n)
			}
		}
		secrets = append(secrets, restorePGPassword)
	})

	t.Run("clickhouse", func(t *testing.T) {
		admin.must("PATCH", "/clusters/"+labClusterID, map[string]any{"transfer_mode": "compressed"}, nil, 200)
		t.Cleanup(func() {
			admin.must("PATCH", "/clusters/"+labClusterID, map[string]any{"transfer_mode": "e2e-tls"}, nil, 200)
		})
		count := func(deploy, user, password, sql string) int64 {
			out := run(t, "kubectl", "-n", "lab", "exec", "deploy/"+deploy, "--", "clickhouse-client", "--user", user,
				"--password", password, "--query", sql)
			n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
			if err != nil {
				t.Fatalf("%s: %q", sql, out)
			}
			return n
		}
		// What the conservative scope restores (tables and their rows) and
		// what it reports instead (a view, a column default, a TTL).
		runSQL(t, "metrics-ch", "CREATE DATABASE IF NOT EXISTS metrics")
		runSQL(t, "metrics-ch", "CREATE TABLE IF NOT EXISTS metrics.events (d Date, v UInt64) ENGINE = MergeTree PARTITION BY toYYYYMM(d) ORDER BY d")
		runSQL(t, "metrics-ch", "INSERT INTO metrics.events SELECT toDate('2026-10-01') + number % 60, number FROM numbers(5000)")
		t.Cleanup(func() {
			runSQL(t, "metrics-ch", "DROP VIEW IF EXISTS metrics.events_by_day")
			runSQL(t, "metrics-ch", "DROP TABLE IF EXISTS metrics.sessions")
		})
		runSQL(t, "metrics-ch", "CREATE TABLE IF NOT EXISTS metrics.sessions (d Date, user String, hits UInt32 DEFAULT 1) "+
			"ENGINE = ReplacingMergeTree ORDER BY (d, user) TTL d + INTERVAL 20 YEAR")
		runSQL(t, "metrics-ch", "INSERT INTO metrics.sessions SELECT toDate('2026-10-01') + number % 30, concat('u', toString(number)), number FROM numbers(700)")
		runSQL(t, "metrics-ch", "CREATE VIEW IF NOT EXISTS metrics.events_by_day AS SELECT d, count() AS n FROM metrics.events GROUP BY d")
		events := count("metrics-ch", "backup", "CANARY-lab-ch-password", "SELECT count() FROM metrics.events")
		sessions := count("metrics-ch", "backup", "CANARY-lab-ch-password", "SELECT count() FROM metrics.sessions FINAL")

		ch := labTarget(t, admin, "metrics-ch")
		chCred := map[string]any{"source": "stored", "username": "backup", "password": "CANARY-lab-ch-password"}
		job := ensureJob(t, admin, ch.ID, destID, chCred, map[string]any{"databases": []string{"metrics"}})
		src := runAndWait(t, admin, job, "manual")

		emptyRestoreTarget(t, "restore-ch")
		target := restoreTargetID(t, admin, "restore-ch")
		in := map[string]any{"run_id": src.ID, "target_id": target, "databases": []string{"metrics"},
			"credential":    map[string]any{"source": "stored", "username": "restore", "password": restoreCHPassword},
			"justification": "e2e: metrics-ch lost, restore into restore-ch (M8)"}
		eventually(t, time.Minute, "restore-ch answers the check", func() (bool, string) {
			ck := checkRestore(t, maker, in)
			return ck.OK, ck.Error
		})
		rq := openRestore(t, maker, in)
		approveRestore(t, maker, checker, rq.ID)
		done := waitRestore(t, admin, rq.ID)
		b, _ := json.Marshal(done.Result)
		t.Logf("clickhouse result: %s", b)

		if got := count("restore-ch", "restore", restoreCHPassword, "SELECT count() FROM metrics.events"); got != events {
			t.Errorf("metrics.events: %d rows restored, %d in the source", got, events)
		}
		if got := count("restore-ch", "restore", restoreCHPassword, "SELECT count() FROM metrics.sessions FINAL"); got != sessions {
			t.Errorf("metrics.sessions: %d rows restored, %d in the source", got, sessions)
		}
		// Not created: the view; not restored: the default and the TTL. Both
		// are reported in the result.
		if got := count("restore-ch", "restore", restoreCHPassword, "SELECT count() FROM system.tables WHERE database = 'metrics' AND name = 'events_by_day'"); got != 0 {
			t.Error("a view was created on the target")
		}
		ddl := run(t, "kubectl", "-n", "lab", "exec", "deploy/restore-ch", "--", "clickhouse-client", "--user", "restore",
			"--password", restoreCHPassword, "--query", "SHOW CREATE TABLE metrics.sessions")
		if strings.Contains(ddl, "DEFAULT") || strings.Contains(ddl, "TTL") || !strings.Contains(ddl, "ReplacingMergeTree") {
			t.Errorf("generated DDL: %s", ddl)
		}
		for _, want := range []string{"events_by_day", "sessions"} {
			if !strings.Contains(string(b), want) {
				t.Errorf("result does not report %s: %s", want, b)
			}
		}
		secrets = append(secrets, restoreCHPassword)
	})

	t.Run("vault", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(work(), "vault-init.json"))
		if err != nil {
			t.Skipf("lab vault not initialized: %v", err)
		}
		var source struct {
			Keys      []string `json:"unseal_keys_b64"`
			RootToken string   `json:"root_token"`
		}
		if err := json.Unmarshal(raw, &source); err != nil || len(source.Keys) == 0 {
			t.Fatalf("vault-init.json: %v", err)
		}
		vt := labTarget(t, admin, "vault")
		job := jobFor(t, admin, vt.ID)
		if job == "" {
			t.Skip("needs the lab vault snapshot job (TestM3VaultMakerChecker)")
		}
		marker := "m8-" + uuid.NewString()[:8]
		vaultCLI(t, source.RootToken, "kv", "put", "secret/restore-e2e", "marker="+marker)
		src := runAndWait(t, admin, job, "manual")

		// A new Vault: initialized and unsealed with its own keys.
		emptyRestoreTarget(t, "restore-vault")
		rv := func(token string, args ...string) (string, error) {
			return runOK(t, "kubectl", append([]string{"-n", "lab", "exec", "deploy/restore-vault", "--", "env", "VAULT_TOKEN=" + token, "vault"}, args...)...)
		}
		eventually(t, time.Minute, "restore-vault answers", func() (bool, string) {
			out, _ := rv("", "status", "-format=json")
			return strings.Contains(out, `"initialized"`), out
		})
		out, err := rv("", "operator", "init", "-key-shares=1", "-key-threshold=1", "-format=json")
		if err != nil {
			t.Fatalf("init restore-vault: %v %s", err, out)
		}
		var fresh struct {
			Keys      []string `json:"unseal_keys_b64"`
			RootToken string   `json:"root_token"`
		}
		if err := json.Unmarshal([]byte(out), &fresh); err != nil {
			t.Fatalf("init output: %v", err)
		}
		if out, err := rv("", "operator", "unseal", fresh.Keys[0]); err != nil {
			t.Fatalf("unseal restore-vault: %v %s", err, out)
		}
		secrets = append(secrets, fresh.RootToken, fresh.Keys[0])
		target := restoreTargetID(t, admin, "restore-vault")
		in := map[string]any{"run_id": src.ID, "target_id": target, "vault_token": fresh.RootToken,
			"justification": "e2e: lab vault lost, restore its snapshot into restore-vault (M8)"}
		eventually(t, time.Minute, "restore-vault is active", func() (bool, string) {
			ck := checkRestore(t, maker, in)
			return ck.OK, ck.Error
		})
		// A token with the default policy only may not snapshot-force.
		weak, err := rv(fresh.RootToken, "token", "create", "-policy=default", "-field=token")
		if err != nil {
			t.Fatalf("token create: %v %s", err, weak)
		}
		in["vault_token"] = strings.TrimSpace(weak)
		ck := checkRestore(t, maker, in)
		if ck.OK || !strings.Contains(ck.Fields["vault_token"], "update and sudo") {
			t.Fatalf("default-policy token accepted: %+v", ck)
		}
		in["vault_token"] = fresh.RootToken

		rq := openRestore(t, maker, in)
		if !rq.HasVaultToken {
			t.Fatalf("opened without a token: %+v", rq)
		}
		approveRestore(t, maker, checker, rq.ID)
		done := waitRestore(t, admin, rq.ID)
		b, _ := json.Marshal(done.Result)
		if !strings.Contains(strings.ToLower(string(b)), "unseal") {
			t.Errorf("result has no unseal note: %s", b)
		}

		// The new Vault now holds the source's data, sealed with the source's
		// keys: unseal it with them and read the key with the source's token.
		eventually(t, 2*time.Minute, "restore-vault sealed with the source's keys", func() (bool, string) {
			out, _ := rv("", "status", "-format=json")
			if strings.Contains(out, `"sealed": true`) {
				return true, ""
			}
			// Still unsealed: the old keyring is in memory until Vault reloads.
			got, _ := rv(source.RootToken, "kv", "get", "-field=marker", "secret/restore-e2e")
			return strings.TrimSpace(got) == marker, out
		})
		if out, _ := rv("", "status", "-format=json"); strings.Contains(out, `"sealed": true`) {
			if out, err := rv("", "operator", "unseal", source.Keys[0]); err != nil {
				t.Fatalf("unseal with the source's key: %v %s", err, out)
			}
		}
		eventually(t, time.Minute, "key read from the restored Vault", func() (bool, string) {
			got, _ := rv(source.RootToken, "kv", "get", "-field=marker", "secret/restore-e2e")
			return strings.TrimSpace(got) == marker, got
		})
		// The token given for the request belonged to the new Vault's old data.
		if out, err := rv(fresh.RootToken, "token", "lookup"); err == nil {
			t.Errorf("the new Vault's own root token still works after the restore: %s", out)
		}
	})

	logs := run(t, "kubectl", "-n", "olympos", "logs", "deploy/olympos", "--tail=-1")
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			t.Fatalf("restore secret %q… in the server logs", s[:6])
		}
	}
}
