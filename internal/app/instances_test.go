package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// F5: the newer of two live instances is not ready; it becomes ready when
// the older one is gone; experimental.multiReplica allows both.
func TestInstanceGuard(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first, err := newInstanceGuard(ctx, db, log, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newInstanceGuard(ctx, db, log, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.check(ctx); err != nil || first.Ready() != nil {
		t.Fatalf("older instance must stay ready: %v %v", err, first.Ready())
	}
	if r := second.Ready(); r == nil || !strings.Contains(r.Error(), "single instance") {
		t.Fatalf("newer instance must not be ready: %v", r)
	}
	multi, err := newInstanceGuard(ctx, db, log, true)
	if err != nil || multi.Ready() != nil {
		t.Fatalf("multiReplica: %v %v", err, multi.Ready())
	}
	// The older instance stops heartbeating (crash, pod deleted).
	if _, err := db.Exec(ctx, `UPDATE server_instances SET heartbeat_at = now() - interval '1 minute' WHERE id = $1`, first.id); err != nil {
		t.Fatal(err)
	}
	if err := second.check(ctx); err != nil || second.Ready() != nil {
		t.Fatalf("newer instance must become ready once the older is gone: %v %v", err, second.Ready())
	}
}
