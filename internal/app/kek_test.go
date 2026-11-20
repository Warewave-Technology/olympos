package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRecovery struct {
	mu    sync.Mutex
	ok    bool
	level string
	err   error
}

func (f *fakeRecovery) set(ok bool, level string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ok, f.level, f.err = ok, level, err
}

func (f *fakeRecovery) KEKRecoverable(context.Context) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ok, f.level, f.err
}

func kinds(w *kekWatch) string {
	var out []string
	for _, it := range w.Items() {
		out = append(out, it.Kind+"/"+it.Severity)
	}
	return strings.Join(out, ",")
}

// F17: the Key Vault items follow the vault without a restart, and the
// server logs only when the result changes.
func TestKEKWatch(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	fake := &fakeRecovery{level: "Recoverable+Purgeable"}
	w := &kekWatch{rc: fake, log: slog.New(slog.NewTextHandler(&buf, nil)), every: time.Hour}
	lines := func() int { return strings.Count(buf.String(), "\n") }

	w.check(ctx)
	if got := kinds(w); got != "kek_purgeable/crit" {
		t.Fatalf("purge protection off: %q", got)
	}
	if l := w.Items()[0].Link; l != "/backups?self=1" {
		t.Fatalf("link: %s", l)
	}
	if lines() != 1 || !strings.Contains(buf.String(), "Key Vault purge protection is off") {
		t.Fatalf("log: %s", buf.String())
	}
	w.check(ctx)
	if lines() != 1 {
		t.Fatalf("unchanged result logged again: %s", buf.String())
	}

	fake.set(false, "", errors.New("read KEK attributes: 403 Forbidden"))
	w.check(ctx)
	if got := kinds(w); got != "kek_recovery_unknown/warn" {
		t.Fatalf("check failed: %q", got)
	}
	if lines() != 2 || !strings.Contains(buf.String(), "could not check Key Vault purge protection") {
		t.Fatalf("log: %s", buf.String())
	}

	fake.set(true, "Recoverable", nil)
	w.check(ctx)
	if got := kinds(w); got != "" {
		t.Fatalf("vault fixed, items left: %q", got)
	}
	if lines() != 3 || !strings.Contains(buf.String(), "purge protection is on") {
		t.Fatalf("log: %s", buf.String())
	}

	// A check cut short by shutdown keeps the last result.
	fake.set(false, "", context.Canceled)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	w.check(cctx)
	if got := kinds(w); got != "" || lines() != 3 {
		t.Fatalf("cancelled check changed the result: %q %s", got, buf.String())
	}
}

// The periodic loop picks up a fixed vault.
func TestKEKWatchRuns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeRecovery{level: "Purgeable"}
	w := &kekWatch{rc: fake, log: slog.New(slog.NewTextHandler(io.Discard, nil)), every: 10 * time.Millisecond}
	w.check(ctx)
	if kinds(w) != "kek_purgeable/crit" {
		t.Fatalf("start: %q", kinds(w))
	}
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	fake.set(true, "Recoverable+ProtectedSubscription", nil)
	deadline := time.Now().Add(5 * time.Second)
	for kinds(w) != "" {
		if time.Now().After(deadline) {
			t.Fatalf("item not cleared by the periodic check: %q", kinds(w))
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	// A key vault without a recovery check (local, dev) has no items.
	none := newKEKWatch(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	none.check(ctx)
	none.run(ctx)
	if none.Items() != nil {
		t.Fatal("items without a recovery checker")
	}
}
