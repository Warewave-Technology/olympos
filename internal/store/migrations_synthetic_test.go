package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// Migration 00024: synthetic monitoring. Checks the grant role, the scenario
// limits, the allowlist version counter, the append-only runs, the one firing
// alert per scenario and cluster, and the cap on stored response excerpts.
func TestSyntheticMonitoringMigration(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()

	scan := func(q string, args ...any) string {
		t.Helper()
		var id string
		if err := db.QueryRow(ctx, q, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return id
	}
	exec := func(q string, args ...any) error {
		_, err := db.Exec(ctx, q, args...)
		return err
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	principal := scan(`INSERT INTO principals (tenant_id, object_id) VALUES ('t', 'p') RETURNING id::text`)
	cluster := scan(`INSERT INTO clusters (name) VALUES ('c') RETURNING id::text`)
	cluster2 := scan(`INSERT INTO clusters (name) VALUES ('c2') RETURNING id::text`)

	// The new grant role; an unknown one is still refused.
	mustExec(`INSERT INTO grants (principal_id, role) VALUES ($1, 'synthetic-editor')`, principal)
	requireSQLState(t, exec(`INSERT INTO grants (principal_id, role) VALUES ($1, 'bogus')`, principal), "23514")

	// Probe columns of a cluster start as "not installed".
	var probeStatus, probeVersion, probeSerial, probePrevSerial string
	var alerted bool
	if err := db.QueryRow(ctx, `SELECT probe_status, probe_version, probe_cert_serial, probe_prev_cert_serial, probe_offline_alerted FROM clusters WHERE id = $1`, cluster).
		Scan(&probeStatus, &probeVersion, &probeSerial, &probePrevSerial, &alerted); err != nil {
		t.Fatal(err)
	}
	if probeStatus != "not_installed" || probeVersion != "" || probeSerial != "" || probePrevSerial != "" || alerted {
		t.Fatalf("probe defaults: %q %q %q %q %v", probeStatus, probeVersion, probeSerial, probePrevSerial, alerted)
	}
	requireSQLState(t, exec(`UPDATE clusters SET probe_status = 'bogus' WHERE id = $1`, cluster), "23514")
	mustExec(`UPDATE clusters SET probe_status = 'online' WHERE id = $1`, cluster)

	// A new enroll token enrolls the agent and the probe, and neither is used yet.
	var roles []string
	tok := scan(`INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at) VALUES ($1, 'h1', now() + interval '1 hour') RETURNING id::text`, cluster)
	if err := db.QueryRow(ctx, `SELECT roles FROM enroll_tokens WHERE id = $1`, tok).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if strings.Join(roles, ",") != "agent,probe" {
		t.Fatalf("token roles default = %v", roles)
	}
	mustExec(`INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at, roles) VALUES ($1, 'h2', now() + interval '1 hour', '{probe}')`, cluster)
	requireSQLState(t, exec(`INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at, roles) VALUES ($1, 'h3', now(), '{}')`, cluster), "23514")
	requireSQLState(t, exec(`INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at, roles) VALUES ($1, 'h4', now(), '{agent,root}')`, cluster), "23514")

	// The allowlist: one rule per pattern and kind, whatever the case, and a
	// version that moves on every change (insert, update, delete).
	version := func() int64 {
		t.Helper()
		var v int64
		if err := db.QueryRow(ctx, `SELECT version FROM synthetic_allowlist_version WHERE id = 1`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	v0 := version()
	rule := scan(`INSERT INTO synthetic_allowlist (pattern, kind, created_by) VALUES ('Api.Example.com', 'exact', $1) RETURNING id::text`, principal)
	v1 := version()
	if v1 <= v0 {
		t.Fatalf("allowlist version after insert: %d -> %d", v0, v1)
	}
	requireSQLState(t, exec(`INSERT INTO synthetic_allowlist (pattern, kind) VALUES ('api.example.COM', 'exact')`), "23505")
	if v := version(); v != v1 {
		t.Fatalf("a refused insert moved the version: %d -> %d", v1, v)
	}
	mustExec(`INSERT INTO synthetic_allowlist (pattern, kind) VALUES ('api.example.com', 'suffix')`)
	requireSQLState(t, exec(`INSERT INTO synthetic_allowlist (pattern, kind) VALUES ('x', 'regex')`), "23514")
	v2 := version()
	mustExec(`UPDATE synthetic_allowlist SET note = 'n' WHERE id = $1`, rule)
	v3 := version()
	mustExec(`DELETE FROM synthetic_allowlist WHERE id = $1`, rule)
	v4 := version()
	if !(v2 > v1 && v3 > v2 && v4 > v3) {
		t.Fatalf("allowlist version must rise on every change: %d %d %d %d", v1, v2, v3, v4)
	}
	// Only the one row.
	requireSQLState(t, exec(`INSERT INTO synthetic_allowlist_version (id, version) VALUES (2, 1)`), "23514")

	// Credentials: secret material lives in credentials; at least one bound host.
	cred := scan(`INSERT INTO credentials (kind, keyvault_name, secret_name) VALUES ('keyvault_ref', 'kv', 'sec') RETURNING id::text`)
	const insCred = `INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id) VALUES ($1, $2, $3, $4) RETURNING id::text`
	synCred := scan(insCred, "api-token", "bearer", []string{"api.example.com"}, cred)
	requireSQLState(t, exec(`INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id) VALUES ('api-token', 'bearer', '{a}', $1)`, cred), "23505")
	requireSQLState(t, exec(`INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id) VALUES ('empty', 'bearer', '{}', $1)`, cred), "23514")
	requireSQLState(t, exec(`INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id) VALUES ('k', 'cookie', '{a}', $1)`, cred), "23514")
	var scopes string
	if err := db.QueryRow(ctx, `SELECT oauth_scopes FROM synthetic_credentials WHERE id = $1`, synCred).Scan(&scopes); err != nil || scopes != "" {
		t.Fatalf("oauth_scopes default %q, %v", scopes, err)
	}

	// Scenario limits: interval >= 30, timeout 1..60, step retries 0..2.
	const insScn = `INSERT INTO scenarios (name, type, interval_seconds, timeout_seconds, step_retries, run_on) VALUES ($1, 'http', $2, $3, $4, $5) RETURNING id::text`
	scn := scan(insScn, "ok", 30, 60, 2, "all")
	for _, c := range []struct {
		name             string
		interval, to, rt int
		runOn            string
	}{
		{"interval29", 29, 10, 0, "all"},
		{"timeout61", 60, 61, 0, "all"},
		{"timeout0", 60, 0, 0, "all"},
		{"retries3", 60, 10, 3, "all"},
		{"retries-1", 60, 10, -1, "all"},
		{"runon", 60, 10, 0, "some"},
	} {
		requireSQLState(t, exec(strings.Replace(insScn, " RETURNING id::text", "", 1), c.name, c.interval, c.to, c.rt, c.runOn), "23514")
	}
	requireSQLState(t, exec(`INSERT INTO scenarios (name, type) VALUES ('t', 'ftp')`), "23514")
	var storeResp bool
	var enabled bool
	if err := db.QueryRow(ctx, `SELECT store_responses, enabled FROM scenarios WHERE id = $1`, scn).Scan(&storeResp, &enabled); err != nil || !storeResp {
		t.Fatalf("store_responses default %v, %v", storeResp, err)
	}

	// Steps: unique position, and a credential in use cannot go.
	step := scan(`INSERT INTO scenario_steps (scenario_id, position, kind, spec, credential_id) VALUES ($1, 0, 'http', '{"url":"https://api.example.com"}', $2) RETURNING id::text`, scn, synCred)
	requireSQLState(t, exec(`INSERT INTO scenario_steps (scenario_id, position, kind) VALUES ($1, 0, 'dns')`, scn), "23505")
	requireSQLState(t, exec(`INSERT INTO scenario_steps (scenario_id, position, kind) VALUES ($1, 1, 'icmp')`, scn), "23514")
	requireSQLState(t, exec(`DELETE FROM synthetic_credentials WHERE id = $1`, synCred), "23503")
	mustExec(`INSERT INTO scenario_assertions (step_id, position, subject, operator, value) VALUES ($1, 0, 'status', 'equals', '200')`, step)
	requireSQLState(t, exec(`INSERT INTO scenario_assertions (step_id, position, subject, operator, value) VALUES ($1, 1, 'status', 'like', '200')`, step), "23514")
	mustExec(`INSERT INTO scenario_extracts (step_id, name, source, expr) VALUES ($1, 'token', 'json_path', '$.token')`, step)
	requireSQLState(t, exec(`INSERT INTO scenario_extracts (step_id, name, source, expr) VALUES ($1, 'x', 'xpath', '/')`, step), "23514")

	// Alert settings: one row per scenario, defaults from the spec, no channel = routes.
	mustExec(`INSERT INTO scenario_alerts (scenario_id) VALUES ($1)`, scn)
	var failAfter, fleet, recovery int
	var channel *string
	if err := db.QueryRow(ctx, `SELECT cluster_fail_after, fleet_critical_clusters, recovery_after, channel_id::text FROM scenario_alerts WHERE scenario_id = $1`, scn).
		Scan(&failAfter, &fleet, &recovery, &channel); err != nil {
		t.Fatal(err)
	}
	if failAfter != 3 || fleet != 3 || recovery != 2 || channel != nil {
		t.Fatalf("alert defaults: %d %d %d %v", failAfter, fleet, recovery, channel)
	}
	requireSQLState(t, exec(`INSERT INTO scenario_alerts (scenario_id) VALUES ($1)`, scn), "23505")

	// Runs: a scenario run is scheduled once per cluster and slot; a test run
	// needs no scenario; a finished run cannot change.
	const insRun = `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, status, test) VALUES ($1, $2, '2026-01-01T00:00:00Z', $3, $4) RETURNING id::text`
	run := scan(insRun, scn, cluster, "scheduled", false)
	requireSQLState(t, exec(strings.Replace(insRun, " RETURNING id::text", "", 1), scn, cluster, "scheduled", false), "23505")
	mustExec(`INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, status, test) VALUES ($1, $2, '2026-01-01T00:00:00Z', 'scheduled', true)`, scn, cluster)
	mustExec(`INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, status, test) VALUES ($1, $2, '2026-01-01T00:00:00Z', 'scheduled', true)`, scn, cluster)
	testRun := scan(`INSERT INTO synthetic_runs (cluster_id, status, test, test_spec, requested_by) VALUES ($1, 'running', true, '{"steps":[]}', $2) RETURNING id::text`, cluster, principal)
	requireSQLState(t, exec(`INSERT INTO synthetic_runs (cluster_id, status, test) VALUES ($1, 'running', false)`, cluster), "23514")
	requireSQLState(t, exec(strings.Replace(insRun, " RETURNING id::text", "", 1), scn, cluster2, "queued", false), "23514")
	var runIP string
	var allowV int64
	if err := db.QueryRow(ctx, `SELECT remote_ip, probe_ip, allowlist_version FROM synthetic_runs WHERE id = $1`, run).Scan(&runIP, &runIP, &allowV); err != nil {
		t.Fatalf("run columns: %v", err)
	}

	// Not terminal yet: the run may move on, step by step.
	mustExec(`UPDATE synthetic_runs SET status = 'running', started_at = now() WHERE id = $1`, run)
	mustExec(`INSERT INTO synthetic_step_results (run_id, position, status, status_code, error) VALUES ($1, 0, 'passed', 200, '')`, run)
	mustExec(`UPDATE synthetic_runs SET status = 'passed', finished_at = now(), total_ms = 12 WHERE id = $1`, run)
	requireSQLState(t, exec(`UPDATE synthetic_runs SET status = 'failed' WHERE id = $1`, run), "42501")
	requireSQLState(t, exec(`UPDATE synthetic_runs SET failure_reason = 'x' WHERE id = $1`, run), "42501")
	for _, terminal := range []string{"failed", "error", "skipped"} {
		id := scan(`INSERT INTO synthetic_runs (cluster_id, status, test) VALUES ($1, $2, true) RETURNING id::text`, cluster, terminal)
		requireSQLState(t, exec(`UPDATE synthetic_runs SET total_ms = 1 WHERE id = $1`, id), "42501")
	}
	mustExec(`UPDATE synthetic_runs SET status = 'passed' WHERE id = $1`, testRun)

	// Step results: one per position, excerpt at most 2048 bytes.
	requireSQLState(t, exec(`INSERT INTO synthetic_step_results (run_id, position, status) VALUES ($1, 0, 'passed')`, run), "23505")
	requireSQLState(t, exec(`INSERT INTO synthetic_step_results (run_id, position, status) VALUES ($1, 1, 'maybe')`, run), "23514")
	mustExec(`INSERT INTO synthetic_step_results (run_id, position, status, excerpt, extracted_names) VALUES ($1, 1, 'passed', $2, '{token}')`, run, make([]byte, 2048))
	requireSQLState(t, exec(`INSERT INTO synthetic_step_results (run_id, position, status, excerpt) VALUES ($1, 2, 'passed', $2)`, run, make([]byte, 2049)), "23514")

	// Alerts: one firing alert per scenario and cluster, and one for the
	// fleet (no cluster); resolved ones pile up.
	const insAlert = `INSERT INTO synthetic_alerts (scenario_id, cluster_id, state) VALUES ($1, $2, $3)`
	mustExec(insAlert, scn, cluster, "firing")
	requireSQLState(t, exec(insAlert, scn, cluster, "firing"), "23505")
	mustExec(insAlert, scn, cluster2, "firing")
	mustExec(insAlert, scn, nil, "firing")
	requireSQLState(t, exec(insAlert, scn, nil, "firing"), "23505")
	mustExec(insAlert, scn, cluster, "resolved")
	mustExec(insAlert, scn, cluster, "resolved")
	requireSQLState(t, exec(insAlert, scn, cluster, "snoozed"), "23514")
	mustExec(`UPDATE synthetic_alerts SET state = 'resolved', resolved_at = now() WHERE scenario_id = $1 AND cluster_id IS NULL`, scn)
	mustExec(insAlert, scn, nil, "firing")

	// State and hourly roll-ups: one row per pair (and hour).
	mustExec(`INSERT INTO synthetic_state (scenario_id, cluster_id) VALUES ($1, $2)`, scn, cluster)
	requireSQLState(t, exec(`INSERT INTO synthetic_state (scenario_id, cluster_id) VALUES ($1, $2)`, scn, cluster), "23505")
	var blocked string
	var fails, passes int
	if err := db.QueryRow(ctx, `SELECT blocked_reason, consecutive_failures, consecutive_passes FROM synthetic_state WHERE scenario_id = $1`, scn).Scan(&blocked, &fails, &passes); err != nil || blocked != "" || fails != 0 || passes != 0 {
		t.Fatalf("state defaults: %q %d %d %v", blocked, fails, passes, err)
	}
	mustExec(`INSERT INTO synthetic_hourly (scenario_id, cluster_id, hour, runs, passed, failed, p50_ms, p95_ms) VALUES ($1, $2, '2026-01-01T00:00:00Z', 4, 3, 1, 20, 90)`, scn, cluster)
	requireSQLState(t, exec(`INSERT INTO synthetic_hourly (scenario_id, cluster_id, hour, runs, passed, failed, p50_ms, p95_ms) VALUES ($1, $2, '2026-01-01T00:00:00Z', 1, 1, 0, 1, 1)`, scn, cluster), "23505")

	// updated_at moves on update.
	var before, after string
	if err := db.QueryRow(ctx, `SELECT updated_at::text FROM scenarios WHERE id = $1`, scn).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustExec(`UPDATE scenarios SET name = 'renamed' WHERE id = $1`, scn)
	if err := db.QueryRow(ctx, `SELECT updated_at::text FROM scenarios WHERE id = $1`, scn).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("scenarios.updated_at not touched")
	}

	// Removing a scenario removes everything that hangs off it.
	mustExec(`DELETE FROM scenarios WHERE id = $1`, scn)
	for _, tbl := range []string{"scenario_steps", "scenario_assertions", "scenario_extracts", "scenario_alerts", "synthetic_state", "synthetic_hourly", "synthetic_alerts", "synthetic_step_results"} {
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s rows left after deleting the scenario: %d, %v", tbl, n, err)
		}
	}
	mustExec(`DELETE FROM synthetic_credentials WHERE id = $1`, synCred)
}

// Down and up again: the migration is reversible, a token used before it
// reads as the agent's (roles = {agent}), and Down keeps refusing to drop
// synthetic-editor grants.
func TestSyntheticMonitoringMigrationDown(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	goose.SetBaseFS(store.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()

	if err := goose.DownToContext(ctx, sqlDB, "migrations", 23); err != nil {
		t.Fatalf("down to 23: %v", err)
	}
	var cluster, usedTok string
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name) VALUES ('old') RETURNING id::text`).Scan(&cluster); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at, used_at) VALUES ($1, 'used', now() + interval '1 hour', now()) RETURNING id::text`, cluster).Scan(&usedTok); err != nil {
		t.Fatalf("old token: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at) VALUES ($1, 'fresh', now() + interval '1 hour')`, cluster); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpToContext(ctx, sqlDB, "migrations", 24); err != nil {
		t.Fatalf("up to 24: %v", err)
	}
	rows, err := db.Query(ctx, `SELECT token_hash, array_to_string(roles, ','), agent_used_at IS NOT NULL, probe_used_at IS NOT NULL FROM enroll_tokens ORDER BY token_hash`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var hash, roles string
		var agentUsed, probeUsed bool
		if err := rows.Scan(&hash, &roles, &agentUsed, &probeUsed); err != nil {
			t.Fatal(err)
		}
		got = append(got, hash+":"+roles+":"+boolStr(agentUsed)+":"+boolStr(probeUsed))
	}
	rows.Close()
	if g, want := strings.Join(got, " "), "fresh:agent:false:false used:agent:true:false"; g != want {
		t.Fatalf("tokens after up = %q, want %q", g, want)
	}

	// Down refuses while a synthetic-editor grant exists (the old schema
	// cannot hold it), and works once it is gone.
	var principal string
	if err := db.QueryRow(ctx, `INSERT INTO principals (tenant_id, object_id) VALUES ('t', 'p') RETURNING id::text`).Scan(&principal); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO grants (principal_id, role) VALUES ($1, 'synthetic-editor')`, principal); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 23); err == nil {
		t.Fatal("down to 23 with a synthetic-editor grant must be refused")
	}
	if _, err := db.Exec(ctx, `DELETE FROM grants`); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 23); err != nil {
		t.Fatalf("down to 23 again: %v", err)
	}
	var used bool
	if err := db.QueryRow(ctx, `SELECT used_at IS NOT NULL FROM enroll_tokens WHERE token_hash = 'used'`).Scan(&used); err != nil || !used {
		t.Fatalf("used_at after down: %v, %v", used, err)
	}
	// Down drops every probe column of clusters.
	var probeCols string
	if err := db.QueryRow(ctx, `SELECT COALESCE(string_agg(column_name, ','), '') FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'clusters' AND column_name LIKE 'probe\_%'`).Scan(&probeCols); err != nil || probeCols != "" {
		t.Fatalf("probe columns after down: %q, %v", probeCols, err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO grants (principal_id, role) VALUES ($1, 'synthetic-editor')`, principal); err == nil {
		t.Fatal("synthetic-editor must not be a role in the old schema")
	}
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Migration 00024 sends synthetic.allowlist_changed wherever grant.changed
// goes today (the owner's call: both are changes to who may do what, and
// routes are explicit rows with no default). Down removes only those routes.
func TestSyntheticMonitoringMigrationRoutes(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	goose.SetBaseFS(store.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 23); err != nil {
		t.Fatalf("down to 23: %v", err)
	}

	channel := func(name string) string {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO notification_channels (slack_channel_id, name) VALUES ($1, $1) RETURNING id::text`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ops, sec, quiet := channel("ops"), channel("sec"), channel("quiet")
	for _, r := range [][2]string{{"grant.changed", ops}, {"grant.changed", sec}, {"backup.failed", quiet}, {"cr.opened", ops}} {
		if _, err := db.Exec(ctx, `INSERT INTO notification_routes (event_type, channel_id) VALUES ($1, $2)`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	routed := func() string {
		rows, err := db.Query(ctx, `SELECT c.name FROM notification_routes r JOIN notification_channels c ON c.id = r.channel_id
			WHERE r.event_type = 'synthetic.allowlist_changed' ORDER BY c.name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return strings.Join(out, ",")
	}
	if err := goose.UpToContext(ctx, sqlDB, "migrations", 24); err != nil {
		t.Fatalf("up to 24: %v", err)
	}
	if got := routed(); got != "ops,sec" {
		t.Fatalf("synthetic.allowlist_changed routes after up = %q, want ops,sec", got)
	}
	// Down removes the routes of this event and no others.
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 23); err != nil {
		t.Fatalf("down to 23 again: %v", err)
	}
	if got := routed(); got != "" {
		t.Fatalf("synthetic.allowlist_changed routes after down = %q, want none", got)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM notification_routes WHERE event_type IN ('grant.changed', 'backup.failed', 'cr.opened')`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("other routes after down: %d, %v", n, err)
	}
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
	if got := routed(); got != "ops,sec" {
		t.Fatalf("routes after migrating up again = %q, want ops,sec", got)
	}
}
