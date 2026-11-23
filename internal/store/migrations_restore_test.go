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

// Migration 00023: restore requests, the maker-is-not-checker rule, one
// approved or running restore per target, and the scrub of the sealed token
// in every terminal state.
func TestRestoreRequestsMigration(t *testing.T) {
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
	maker := scan(`INSERT INTO principals (tenant_id, object_id) VALUES ('t', 'maker') RETURNING id::text`)
	checker := scan(`INSERT INTO principals (tenant_id, object_id) VALUES ('t', 'checker') RETURNING id::text`)
	cluster := scan(`INSERT INTO clusters (name) VALUES ('c') RETURNING id::text`)
	for _, id := range []string{"src", "dst1", "dst2"} {
		if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine, status) VALUES ($1, $2, 'ns', $1, 5432, 'postgresql', 'configured')`, id, cluster); err != nil {
			t.Fatal(err)
		}
	}
	dest := scan(`INSERT INTO destinations (name, account, container, auth) VALUES ('d', 'acct', 'c', 'managed_identity') RETURNING id::text`)
	job := scan(`INSERT INTO backup_jobs (target_id, destination_id, cron) VALUES ('src', $1, '0 3 * * *') RETURNING id::text`, dest)
	run := scan(`INSERT INTO backup_runs (job_id, trigger, status) VALUES ($1, 'manual', 'succeeded') RETURNING id::text`, job)
	cred := scan(`INSERT INTO credentials (kind, keyvault_name, secret_name) VALUES ('keyvault_ref', 'kv', 'sec') RETURNING id::text`)

	const ins = `INSERT INTO restore_requests (source_run_id, source_destination_id, source_copy_run_id, engine, target_id,
		credential_id, sealed_token, wrapped_dek, maker_principal_id, checker_principal_id, justification, status, expires_at)
		VALUES ($1, $2, $1, 'postgresql', $3, $4, $5, $5, $6, $7, 'because', $8, now() + interval '72 hours') RETURNING id::text`
	open := func(target string, status string, sealed []byte, checkerID any) (string, error) {
		var id string
		err := db.QueryRow(ctx, ins, run, dest, target, cred, sealed, maker, checkerID, status).Scan(&id)
		return id, err
	}

	// Defaults of a freshly opened request.
	var dbs []string
	var status, opts, progress, result, errText, kek, comment string
	var breakGlass bool
	first, err := open("dst1", "pending", []byte("sealed"), nil)
	if err != nil {
		t.Fatalf("insert pending: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT databases, status, options::text, progress::text, result::text, error, kek_version, decision_comment, break_glass
		FROM restore_requests WHERE id = $1`, first).Scan(&dbs, &status, &opts, &progress, &result, &errText, &kek, &comment, &breakGlass); err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 0 || status != "pending" || opts != "{}" || progress != "{}" || result != "{}" || errText != "" || kek != "" || comment != "" || breakGlass {
		t.Fatalf("defaults: %v %q %q %q %q %q %q %q %v", dbs, status, opts, progress, result, errText, kek, comment, breakGlass)
	}

	// Status is one of the eight.
	_, err = open("dst2", "bogus", nil, nil)
	requireSQLState(t, err, "23514")

	// Maker and checker are two principals (23514 check_violation).
	_, err = open("dst2", "pending", nil, maker)
	requireSQLState(t, err, "23514")
	if _, err := open("dst2", "pending", nil, checker); err != nil {
		t.Fatalf("maker <> checker: %v", err)
	}

	// One approved or running restore per target (23505 unique_violation).
	approved, err := open("dst1", "approved", []byte("sealed"), checker)
	if err != nil {
		t.Fatalf("first approved: %v", err)
	}
	_, err = open("dst1", "approved", nil, checker)
	requireSQLState(t, err, "23505")
	_, err = open("dst1", "running", nil, checker)
	requireSQLState(t, err, "23505")
	// Other targets, and pending requests on the same target, are free.
	if _, err := open("dst1", "pending", nil, nil); err != nil {
		t.Fatalf("pending next to approved: %v", err)
	}
	if _, err := open("dst2", "approved", nil, checker); err != nil {
		t.Fatalf("approved on another target: %v", err)
	}
	// Finishing the approved request frees the target.
	if _, err := db.Exec(ctx, `UPDATE restore_requests SET status = 'running' WHERE id = $1`, approved); err != nil {
		t.Fatalf("approved -> running: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE restore_requests SET status = 'succeeded' WHERE id = $1`, approved); err != nil {
		t.Fatalf("running -> succeeded: %v", err)
	}
	if _, err := open("dst1", "approved", nil, checker); err != nil {
		t.Fatalf("approved after the first finished: %v", err)
	}

	// The scrub trigger drops the sealed token and the wrapped key in every
	// terminal state, and leaves the live states alone.
	sealed := func(id string) (token, dek bool) {
		t.Helper()
		if err := db.QueryRow(ctx, `SELECT sealed_token IS NOT NULL, wrapped_dek IS NOT NULL FROM restore_requests WHERE id = $1`, id).Scan(&token, &dek); err != nil {
			t.Fatal(err)
		}
		return
	}
	if tok, dek := sealed(first); !tok || !dek {
		t.Fatal("pending request lost its sealed token")
	}
	if tok, dek := sealed(approved); tok || dek {
		t.Fatalf("succeeded request kept token=%v dek=%v", tok, dek)
	}
	for _, terminal := range []string{"failed", "rejected", "expired", "cancelled"} {
		id, err := open("src", "pending", []byte("sealed"), nil)
		if err != nil {
			t.Fatalf("open for %s: %v", terminal, err)
		}
		if _, err := db.Exec(ctx, `UPDATE restore_requests SET status = $2, error = 'x' WHERE id = $1`, id, terminal); err != nil {
			t.Fatalf("-> %s: %v", terminal, err)
		}
		if tok, dek := sealed(id); tok || dek {
			t.Fatalf("%s kept token=%v dek=%v", terminal, tok, dek)
		}
		// A terminal request cannot be given a token again.
		if _, err := db.Exec(ctx, `UPDATE restore_requests SET sealed_token = 'x'::bytea, wrapped_dek = 'x'::bytea WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if tok, dek := sealed(id); tok || dek {
			t.Fatalf("%s re-sealed token=%v dek=%v", terminal, tok, dek)
		}
	}

	// Deleting the credential row (done by code in a terminal state) leaves
	// the request, with credential_id cleared.
	if _, err := db.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, cred); err != nil {
		t.Fatalf("delete credential: %v", err)
	}
	var credNull bool
	if err := db.QueryRow(ctx, `SELECT credential_id IS NULL FROM restore_requests WHERE id = $1`, first).Scan(&credNull); err != nil {
		t.Fatal(err)
	}
	if !credNull {
		t.Fatal("credential_id not cleared by ON DELETE SET NULL")
	}

	// updated_at follows the convention.
	var before, after string
	if err := db.QueryRow(ctx, `SELECT updated_at::text FROM restore_requests WHERE id = $1`, first).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE restore_requests SET decision_comment = 'x' WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT updated_at::text FROM restore_requests WHERE id = $1`, first).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("updated_at not touched")
	}
}

// Down removes the table and the scrub function, and Up applies again.
func TestRestoreRequestsMigrationDown(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	goose.SetBaseFS(store.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 22); err != nil {
		t.Fatalf("down to 22: %v", err)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE proname = 'olympos_restore_scrub'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("scrub function after down: %d, %v", n, err)
	}
	if _, err := db.Exec(ctx, `SELECT 1 FROM restore_requests`); err == nil {
		t.Fatal("restore_requests still exists after down")
	}
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
}

// Migration 00023 routes restore.failed and restore.break_glass to every
// channel that gets backup.failed (they are not opt-in, and an event with
// no route is dropped), and no other restore event. Down removes the
// restore routes again.
func TestRestoreRequestsMigrationRoutes(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	goose.SetBaseFS(store.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 22); err != nil {
		t.Fatalf("down to 22: %v", err)
	}

	channel := func(name string) string {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO notification_channels (slack_channel_id, name) VALUES ($1, $1) RETURNING id::text`, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ops, sec, approvers := channel("ops"), channel("sec"), channel("approvers")
	for _, r := range [][2]string{{"backup.failed", ops}, {"backup.failed", sec}, {"backup.partial", sec}, {"cr.opened", approvers}} {
		if _, err := db.Exec(ctx, `INSERT INTO notification_routes (event_type, channel_id) VALUES ($1, $2)`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := goose.UpToContext(ctx, sqlDB, "migrations", 23); err != nil {
		t.Fatalf("up to 23: %v", err)
	}
	routes := func() string {
		rows, err := db.Query(ctx, `SELECT r.event_type || ':' || c.name FROM notification_routes r JOIN notification_channels c ON c.id = r.channel_id
			WHERE r.event_type LIKE 'restore.%' ORDER BY 1`)
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
	if got, want := routes(), "restore.break_glass:ops,restore.break_glass:sec,restore.failed:ops,restore.failed:sec"; got != want {
		t.Fatalf("restore routes after up = %q, want %q", got, want)
	}
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 22); err != nil {
		t.Fatalf("down to 22 again: %v", err)
	}
	if got := routes(); got != "" {
		t.Fatalf("restore routes after down = %q, want none", got)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM notification_routes WHERE event_type IN ('backup.failed', 'backup.partial', 'cr.opened')`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("other routes after down: %d, %v", n, err)
	}
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
}
