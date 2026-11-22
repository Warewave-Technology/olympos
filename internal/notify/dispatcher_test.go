package notify_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

type sent struct {
	Channel uuid.UUID
	Msg     notify.Message
}

// fakeSink records sends; fail decides per call whether to fail.
type fakeSink struct {
	mu    sync.Mutex
	sent  []sent
	fail  func(ch notify.Channel, m notify.Message) error
	delay time.Duration
}

func (f *fakeSink) Send(ctx context.Context, ch notify.Channel, m notify.Message) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		if err := f.fail(ch, m); err != nil {
			return err
		}
	}
	f.sent = append(f.sent, sent{ch.ID, m})
	return nil
}

func (f *fakeSink) all() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sent(nil), f.sent...)
}

func (f *fakeSink) reset() {
	f.mu.Lock()
	f.sent = nil
	f.mu.Unlock()
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func mkChannel(t *testing.T, db *store.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(context.Background(), `INSERT INTO notification_channels (slack_channel_id, name) VALUES ('C0TEST'||substr(md5(random()::text),1,6), $1) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func route(t *testing.T, db *store.DB, event string, ch uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `INSERT INTO notification_routes (event_type, channel_id) VALUES ($1, $2)`, event, ch); err != nil {
		t.Fatal(err)
	}
}

func emit(t *testing.T, db *store.DB, e notify.Event) {
	t.Helper()
	if err := notify.Emit(context.Background(), db, e); err != nil {
		t.Fatal(err)
	}
}

type outboxState struct {
	Delivered bool
	Outcome   string
	Attempts  int
	LastError string
	DueIn     time.Duration
	Channels  []uuid.UUID
}

func state(t *testing.T, db *store.DB, key string) outboxState {
	t.Helper()
	var s outboxState
	var secs float64
	if err := db.QueryRow(context.Background(), `SELECT delivered_at IS NOT NULL, outcome, attempts, last_error,
		EXTRACT(EPOCH FROM next_attempt_at - now())::float8, delivered_channels FROM outbox WHERE idempotency_key = $1`, key).
		Scan(&s.Delivered, &s.Outcome, &s.Attempts, &s.LastError, &secs, &s.Channels); err != nil {
		t.Fatal(err)
	}
	s.DueIn = time.Duration(secs * float64(time.Second))
	return s
}

func makeDue(t *testing.T, db *store.DB) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `UPDATE outbox SET next_attempt_at = now() WHERE delivered_at IS NULL`); err != nil {
		t.Fatal(err)
	}
}

func TestBackoff(t *testing.T) {
	d := &notify.Dispatcher{}
	for attempts, want := range map[int]time.Duration{0: 30 * time.Second, 1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute,
		7: 32 * time.Minute, 8: time.Hour, 100: time.Hour} {
		if got := d.Backoff(attempts); got != want {
			t.Errorf("Backoff(%d) = %s, want %s", attempts, got, want)
		}
	}
}

func TestCatalog(t *testing.T) {
	entries := notify.CatalogEntries()
	if len(entries) != len(notify.Catalog) {
		t.Fatal("catalog size")
	}
	for _, e := range entries {
		if e.Description == "" {
			t.Errorf("%s has no description", e.EventType)
		}
		if e.OptIn != (e.EventType == notify.BackupSucceeded) {
			t.Errorf("%s opt_in = %v", e.EventType, e.OptIn)
		}
	}
	// backup.partial is listed next to backup.failed.
	if notify.BackupPartial != "backup.partial" || entries[1].EventType != notify.BackupPartial || entries[0].EventType != notify.BackupFailed ||
		entries[1].Description != "A backup was written to some of its destinations but not all." || !notify.Known(notify.BackupPartial) {
		t.Errorf("backup.partial entry: %+v", entries[1])
	}
	// Restore events (docs/design/ui-restore.md): all in the catalog, none
	// opt-in (restore.failed and restore.break_glass must never be missed).
	listed := map[string]bool{}
	for _, e := range entries {
		listed[e.EventType] = true
	}
	for _, ev := range []string{"restore.requested", "restore.approved", "restore.rejected", "restore.started", "restore.succeeded",
		"restore.failed", "restore.break_glass"} {
		if !listed[ev] || !notify.Known(ev) || notify.IsOptIn(ev) {
			t.Errorf("%s: listed %v, known %v, opt-in %v", ev, listed[ev], notify.Known(ev), notify.IsOptIn(ev))
		}
	}
}

func TestDispatchRouting(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	a, b, c := mkChannel(t, db, "#a"), mkChannel(t, db, "#b"), mkChannel(t, db, "#c")
	route(t, db, notify.BackupFailed, a)
	route(t, db, notify.BackupFailed, b)
	sink := &fakeSink{}
	d := &notify.Dispatcher{DB: db, Sinks: map[string]notify.Sink{"slack": sink}, Log: quiet,
		Link: func(p string) string { return "https://olympos.example" + p }}

	emit(t, db, notify.Event{Type: notify.BackupFailed, Key: "k-routed", Title: "orders-pg backup failed", Link: "/backups/runs/1",
		Fields: map[string]string{"cluster": "prod"}})
	emit(t, db, notify.Event{Type: notify.AgentOffline, Key: "k-noroute", Title: "agent offline"})
	emit(t, db, notify.Event{Type: notify.BackupFailed, Key: "k-override", Title: "override", ChannelID: &c})
	gone := uuid.New()
	emit(t, db, notify.Event{Type: notify.BackupFailed, Key: "k-gone-override", Title: "override gone", ChannelID: &gone})
	// Opt-in: no route for backup.succeeded, so even an override channel does not deliver.
	emit(t, db, notify.Event{Type: notify.BackupSucceeded, Key: "k-optin", Title: "ok", ChannelID: &c})
	// Idempotent emit: same key twice is one row.
	emit(t, db, notify.Event{Type: notify.BackupFailed, Key: "k-routed", Title: "dup"})

	if n, err := d.DispatchOnce(ctx); err != nil || n != 5 {
		t.Fatalf("dispatch: n=%d err=%v", n, err)
	}
	byKey := map[string][]uuid.UUID{}
	for _, s := range sink.all() {
		byKey[s.Msg.Key] = append(byKey[s.Msg.Key], s.Channel)
		if s.Msg.Key == "k-routed" {
			if s.Msg.Link != "https://olympos.example/backups/runs/1" || s.Msg.Title != "orders-pg backup failed" || s.Msg.Fields["cluster"] != "prod" {
				t.Errorf("message: %+v", s.Msg)
			}
		}
	}
	sortIDs := func(ids []uuid.UUID) []uuid.UUID {
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		return ids
	}
	if got, want := sortIDs(byKey["k-routed"]), sortIDs([]uuid.UUID{a, b}); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("routed to %v, want %v", got, want)
	}
	if got := byKey["k-override"]; len(got) != 1 || got[0] != c {
		t.Errorf("override delivered to %v, want only %s", got, c)
	}
	if got := byKey["k-gone-override"]; len(got) != 2 {
		t.Errorf("missing override channel should fall back to routes, got %v", got)
	}
	if len(byKey["k-noroute"]) != 0 || len(byKey["k-optin"]) != 0 {
		t.Errorf("unrouted events were sent: %v", byKey)
	}
	if s := state(t, db, "k-noroute"); !s.Delivered || s.Outcome != "no_route" {
		t.Errorf("no route: %+v", s)
	}
	if s := state(t, db, "k-optin"); !s.Delivered || s.Outcome != "no_route" {
		t.Errorf("opt-in: %+v", s)
	}
	if s := state(t, db, "k-routed"); !s.Delivered || s.Outcome != "delivered" || s.Attempts != 1 || len(s.Channels) != 2 {
		t.Errorf("routed: %+v", s)
	}

	// Once routed, backup.succeeded is delivered (to the override channel).
	route(t, db, notify.BackupSucceeded, a)
	sink.reset()
	emit(t, db, notify.Event{Type: notify.BackupSucceeded, Key: "k-optin-2", Title: "ok", ChannelID: &c})
	emit(t, db, notify.Event{Type: notify.BackupSucceeded, Key: "k-optin-3", Title: "ok"})
	if _, err := d.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got := map[string]uuid.UUID{}
	for _, s := range sink.all() {
		got[s.Msg.Key] = s.Channel
	}
	if got["k-optin-2"] != c || got["k-optin-3"] != a {
		t.Errorf("opt-in after routing: %v", got)
	}
	// Nothing left; delivered rows are not resent.
	sink.reset()
	if n, _ := d.DispatchOnce(ctx); n != 0 || len(sink.all()) != 0 {
		t.Fatalf("redelivered: n=%d sent=%d", n, len(sink.all()))
	}
}

func TestDispatchRetryBackoff(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	a, b := mkChannel(t, db, "#a"), mkChannel(t, db, "#b")
	route(t, db, notify.BackupMissed, a)
	route(t, db, notify.BackupMissed, b)
	failB := 2
	sink := &fakeSink{fail: func(ch notify.Channel, m notify.Message) error {
		if ch.ID == b && failB > 0 {
			failB--
			return errors.New("Post \"https://hooks.example/x?sv=1&sig=SECRETSIG123\": channel_not_found")
		}
		return nil
	}}
	d := &notify.Dispatcher{DB: db, Sinks: map[string]notify.Sink{"slack": sink}, Log: quiet}
	emit(t, db, notify.Event{Type: notify.BackupMissed, Key: "k1", Title: "missed"})

	if _, err := d.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s := state(t, db, "k1")
	if s.Delivered || s.Attempts != 1 || s.DueIn < 25*time.Second || s.DueIn > 35*time.Second || len(s.Channels) != 1 || s.Channels[0] != a {
		t.Fatalf("after first failure: %+v", s)
	}
	if s.LastError == "" || strings.Contains(s.LastError, "SECRETSIG123") {
		t.Fatalf("last_error must be set and redacted: %q", s.LastError)
	}
	// F10: each channel records its last delivery (time + result, redacted).
	var okA, okB bool
	var errB string
	_ = db.QueryRow(ctx, `SELECT last_delivery_ok FROM notification_channels WHERE id = $1`, a).Scan(&okA)
	_ = db.QueryRow(ctx, `SELECT last_delivery_ok, last_delivery_error FROM notification_channels WHERE id = $1`, b).Scan(&okB, &errB)
	if !okA || okB || errB == "" || strings.Contains(errB, "SECRETSIG123") {
		t.Fatalf("last delivery: a=%v b=%v %q", okA, okB, errB)
	}
	// Not due yet: nothing claimed.
	if n, _ := d.DispatchOnce(ctx); n != 0 {
		t.Fatalf("claimed %d events before next_attempt_at", n)
	}
	makeDue(t, db)
	if _, err := d.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s = state(t, db, "k1"); s.Delivered || s.Attempts != 2 || s.DueIn < 55*time.Second || s.DueIn > 65*time.Second {
		t.Fatalf("after second failure: %+v", s)
	}
	makeDue(t, db)
	if _, err := d.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s = state(t, db, "k1"); !s.Delivered || s.Attempts != 3 || s.LastError != "" || len(s.Channels) != 2 {
		t.Fatalf("after success: %+v", s)
	}
	// Channel a got exactly one message: retries only went to b.
	var toA, toB int
	for _, x := range sink.all() {
		if x.Channel == a {
			toA++
		} else if x.Channel == b {
			toB++
		}
	}
	if toA != 1 || toB != 1 {
		t.Fatalf("sends a=%d b=%d", toA, toB)
	}
}

func TestDispatchSinkNotConfiguredKeepsPending(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	a := mkChannel(t, db, "#a")
	route(t, db, notify.AgentOffline, a)
	unconfigured := true
	sink := &fakeSink{fail: func(notify.Channel, notify.Message) error {
		if unconfigured {
			return notify.ErrSinkNotConfigured
		}
		return nil
	}}
	d := &notify.Dispatcher{DB: db, Sinks: map[string]notify.Sink{"slack": sink}, Log: quiet}
	emit(t, db, notify.Event{Type: notify.AgentOffline, Key: "k", Title: "offline"})
	for i := 0; i < 3; i++ {
		makeDue(t, db)
		if _, err := d.DispatchOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if s := state(t, db, "k"); s.Delivered || s.Attempts != 0 || s.DueIn < 50*time.Second {
		t.Fatalf("pending: %+v", s)
	}
	unconfigured = false
	makeDue(t, db)
	if _, err := d.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := state(t, db, "k"); !s.Delivered {
		t.Fatalf("not delivered once configured: %+v", s)
	}
}

// TestDispatchConcurrentNoDoubleSend runs several dispatchers (replicas) on
// the same outbox: SKIP LOCKED means every event is sent exactly once.
func TestDispatchConcurrentNoDoubleSend(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	a := mkChannel(t, db, "#a")
	route(t, db, notify.GrantChanged, a)
	const n = 60
	for i := 0; i < n; i++ {
		emit(t, db, notify.Event{Type: notify.GrantChanged, Key: "k-" + uuid.NewString(), Title: "grant"})
	}
	sink := &fakeSink{delay: 3 * time.Millisecond}
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		d := &notify.Dispatcher{DB: db, Sinks: map[string]notify.Sink{"slack": sink}, Log: quiet, Batch: 5}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, err := d.DispatchOnce(ctx); err != nil {
					t.Error(err)
					return
				}
				var left int
				_ = db.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE delivered_at IS NULL`).Scan(&left)
				if left == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	counts := map[string]int{}
	for _, s := range sink.all() {
		counts[s.Msg.Key]++
	}
	if len(counts) != n {
		t.Fatalf("delivered %d distinct events, want %d", len(counts), n)
	}
	for k, c := range counts {
		if c != 1 {
			t.Errorf("%s sent %d times", k, c)
		}
	}
}

// TestDispatchAtLeastOnce: a crash after the send but before the commit
// (simulated by a failing context mid-batch) resends; the idempotency key
// stays the same so receivers can de-duplicate.
func TestDispatchAtLeastOnce(t *testing.T) {
	db := testutil.DB(t)
	a := mkChannel(t, db, "#a")
	route(t, db, notify.CROpened, a)
	emit(t, db, notify.Event{Type: notify.CROpened, Key: "cr-1", Title: "cr"})
	cctx, cancel := context.WithCancel(context.Background())
	sink := &fakeSink{fail: func(notify.Channel, notify.Message) error {
		cancel() // "crash" right after the message went out
		return nil
	}}
	d := &notify.Dispatcher{DB: db, Sinks: map[string]notify.Sink{"slack": sink}, Log: quiet}
	if _, err := d.DispatchOnce(cctx); err == nil {
		t.Fatal("expected the commit to fail with a cancelled context")
	}
	if s := state(t, db, "cr-1"); s.Delivered {
		t.Fatal("must not be marked delivered when the transaction did not commit")
	}
	sink.fail = nil
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := sink.all()
	if len(all) != 2 || all[0].Msg.Key != "cr-1" || all[1].Msg.Key != "cr-1" {
		t.Fatalf("expected the same key twice (at-least-once), got %+v", all)
	}
	if s := state(t, db, "cr-1"); !s.Delivered {
		t.Fatal("not delivered on retry")
	}
}
