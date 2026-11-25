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

// Migration 00026: the audit rows of ingest credentials. The table has no
// column for the secret, refuses unknown kinds, and down drops it.
func TestIngestCredentialsMigration(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()

	columns := func() string {
		t.Helper()
		var s string
		if err := db.QueryRow(ctx, `SELECT coalesce(string_agg(column_name, ',' ORDER BY ordinal_position), '')
			FROM information_schema.columns WHERE table_name = 'ingest_credentials'`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	const want = "access_key,run_id,kind,scope,fingerprint,expires_at,created_at,revoked_at,reason"
	if got := columns(); got != want {
		t.Errorf("columns %s, want %s", got, want)
	}

	const ins = `INSERT INTO ingest_credentials (access_key, run_id, kind, scope, fingerprint, expires_at)
		VALUES ($1, gen_random_uuid(), $2, '{"write":"r/"}', 'hm:0000·0000·0000', now() + interval '1 hour')`
	if _, err := db.Exec(ctx, ins, "OLYAAAAAAAAAAAAAAAAA", "backup"); err != nil {
		t.Fatalf("backup row: %v", err)
	}
	if _, err := db.Exec(ctx, ins, "OLYBBBBBBBBBBBBBBBBB", "restore"); err != nil {
		t.Fatalf("restore row: %v", err)
	}
	if _, err := db.Exec(ctx, ins, "OLYCCCCCCCCCCCCCCCCC", "copy"); err == nil || !strings.Contains(err.Error(), "check") {
		t.Errorf("an unknown kind: %v", err)
	}

	goose.SetBaseFS(store.MigrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDBFromPool(db)
	defer sqlDB.Close()
	if err := goose.DownToContext(ctx, sqlDB, "migrations", 25); err != nil {
		t.Fatalf("down to 25: %v", err)
	}
	if got := columns(); got != "" {
		t.Errorf("down left columns %s", got)
	}
	if err := goose.UpToContext(ctx, sqlDB, "migrations", 26); err != nil {
		t.Fatalf("up to 26: %v", err)
	}
	if got := columns(); got != want {
		t.Errorf("columns after up %s", got)
	}
}
