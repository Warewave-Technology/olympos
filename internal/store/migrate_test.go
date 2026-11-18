package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// A database migrated by a newer Olympos is refused (no downgrade).
func TestMigrateRefusesDowngrade(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (99999, true)`); err != nil {
		t.Fatal(err)
	}
	err := store.Migrate(ctx, db)
	if err == nil || !strings.Contains(err.Error(), "downgrades are not supported") {
		t.Fatalf("downgrade: %v", err)
	}
}
