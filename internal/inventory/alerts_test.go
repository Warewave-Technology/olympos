package inventory

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func outboxCount(t *testing.T, db *store.DB, typ string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE event_type = $1`, typ).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// F18: a blip shorter than OfflineAlertAfter sends nothing; a long outage
// sends exactly one agent.offline and one agent.online; repeated
// disconnects send one agent.flapping per window.
func TestAgentAlertDebounce(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	s := &Service{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var id uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, status, last_seen_at) VALUES ('c1', 'online', now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	silent := func(ago string) {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE clusters SET last_seen_at = now() - $2::interval,
			offline_since = CASE WHEN status = 'offline' THEN now() - $2::interval ELSE offline_since END WHERE id = $1`, id, ago); err != nil {
			t.Fatal(err)
		}
	}
	status := func() string {
		var st string
		_ = db.QueryRow(ctx, `SELECT status FROM clusters WHERE id = $1`, id).Scan(&st)
		return st
	}
	hello := &pb.Hello{AgentVersion: "test"}

	// Blip: offline for 2 minutes, then back.
	silent("2 minutes")
	if err := s.CheckOffline(ctx); err != nil || status() != "offline" {
		t.Fatalf("offline: %v %s", err, status())
	}
	if err := s.connected(ctx, id, hello); err != nil || status() != "online" {
		t.Fatalf("back: %v %s", err, status())
	}
	if outboxCount(t, db, "agent.offline")+outboxCount(t, db, "agent.online") != 0 {
		t.Fatal("a short blip must not notify")
	}

	// Long outage.
	silent("2 minutes")
	_ = s.CheckOffline(ctx)
	silent("6 minutes")
	for i := 0; i < 3; i++ {
		if err := s.CheckOffline(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := outboxCount(t, db, "agent.offline"); n != 1 {
		t.Fatalf("agent.offline events: %d", n)
	}
	s.seen(ctx, id) // traffic on a stream that stayed open
	_ = s.connected(ctx, id, hello)
	if n := outboxCount(t, db, "agent.online"); n != 1 || status() != "online" {
		t.Fatalf("agent.online events: %d (%s)", n, status())
	}

	// Flapping: more than 5 disconnects in 30 minutes, once per window.
	for i := 0; i < 8; i++ {
		s.disconnected(id)
	}
	if n := outboxCount(t, db, "agent.flapping"); n != 1 {
		t.Fatalf("agent.flapping events: %d", n)
	}
}
