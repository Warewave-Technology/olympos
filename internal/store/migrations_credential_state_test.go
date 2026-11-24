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

// Migration 00025: the resolution state of a synthetic credential. A row that
// exists before it starts as "ok", the routes of synthetic.credential_expiring
// are copied to the two new events, and down removes both again.
func TestCredentialStateMigration(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	goose.SetBaseFS(store.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 24); err != nil {
		t.Fatalf("down to 24: %v", err)
	}

	scan := func(q string, args ...any) string {
		t.Helper()
		var s string
		if err := db.QueryRow(ctx, q, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return s
	}
	channel := func(name string) string {
		return scan(`INSERT INTO notification_channels (slack_channel_id, name) VALUES ($1, $1) RETURNING id::text`, name)
	}
	ops, quiet := channel("ops"), channel("quiet")
	for _, r := range [][2]string{{"synthetic.credential_expiring", ops}, {"synthetic.failing", quiet}} {
		if _, err := db.Exec(ctx, `INSERT INTO notification_routes (event_type, channel_id) VALUES ($1, $2)`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	secret := scan(`INSERT INTO credentials (kind, keyvault_name, secret_name) VALUES ('keyvault_ref', 'kv', 'sec') RETURNING id::text`)
	cred := scan(`INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id) VALUES ('api-token', 'bearer', '{a}', $1) RETURNING id::text`, secret)

	routed := func(event string) string {
		rows, err := db.Query(ctx, `SELECT c.name FROM notification_routes r JOIN notification_channels c ON c.id = r.channel_id
			WHERE r.event_type = $1 ORDER BY c.name`, event)
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

	if err := goose.UpToContext(ctx, sqlDB, "migrations", 25); err != nil {
		t.Fatalf("up to 25: %v", err)
	}

	// A credential that existed before starts as ok, with nothing else set.
	var state string
	var cause, since, alerted *string
	if err := db.QueryRow(ctx, `SELECT resolve_state, resolve_cause, resolve_failing_since::text, resolve_alerted_at::text FROM synthetic_credentials WHERE id = $1`, cred).
		Scan(&state, &cause, &since, &alerted); err != nil {
		t.Fatal(err)
	}
	if state != "ok" || cause != nil || since != nil || alerted != nil {
		t.Fatalf("defaults: %q %v %v %v", state, cause, since, alerted)
	}
	// Only the three states exist.
	for _, s := range []string{"broken", "unavailable", "ok"} {
		if _, err := db.Exec(ctx, `UPDATE synthetic_credentials SET resolve_state = $2 WHERE id = $1`, cred, s); err != nil {
			t.Fatalf("state %s: %v", s, err)
		}
	}
	_, err := db.Exec(ctx, `UPDATE synthetic_credentials SET resolve_state = 'bogus' WHERE id = $1`, cred)
	requireSQLState(t, err, "23514")

	// The channel that gets credential_expiring gets both new events; the one
	// that does not, does not.
	for _, e := range []string{"synthetic.credential_broken", "synthetic.credential_restored", "synthetic.credential_expiring"} {
		if got := routed(e); got != "ops" {
			t.Fatalf("%s routes after up = %q, want ops", e, got)
		}
	}

	if err := goose.DownToContext(ctx, sqlDB, "migrations", 24); err != nil {
		t.Fatalf("down to 24 again: %v", err)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'synthetic_credentials' AND column_name LIKE 'resolve_%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d resolve_ columns left after down", n)
	}
	for _, e := range []string{"synthetic.credential_broken", "synthetic.credential_restored"} {
		if got := routed(e); got != "" {
			t.Fatalf("%s routes after down = %q, want none", e, got)
		}
	}
	if got := routed("synthetic.credential_expiring"); got != "ops" {
		t.Fatalf("credential_expiring routes after down = %q, want ops", got)
	}
	if got := routed("synthetic.failing"); got != "quiet" {
		t.Fatalf("synthetic.failing routes after down = %q, want quiet", got)
	}
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
}
