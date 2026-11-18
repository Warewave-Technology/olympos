// Package testutil provides helpers shared by integration tests.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// DefaultDSN points at the dev Postgres started by `make dev-db`.
const DefaultDSN = "postgres://olympos:olympos@127.0.0.1:55432/postgres?sslmode=disable"

// DB creates a fresh, migrated database for one test and drops it after.
// Tests are skipped when no Postgres is reachable, unless OLYMPOS_REQUIRE_DB=1.
func DB(t testing.TB) *store.DB {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("OLYMPOS_TEST_PG_DSN")
	if dsn == "" {
		dsn = DefaultDSN
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DB") == "1" {
			t.Fatalf("postgres not reachable: %v", err)
		}
		t.Skipf("postgres not reachable (%v); run `make dev-db`", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "olympos_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	u, _ := url.Parse(dsn)
	u.Path = "/" + name
	pool, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name))
		admin.Close(ctx)
	})
	return pool
}
