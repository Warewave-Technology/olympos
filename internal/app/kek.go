package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// KEK recovery check (F17): how often it runs and how long one check may take.
const (
	kekCheckEvery   = time.Hour
	kekCheckTimeout = 15 * time.Second
)

// kekWatch warns when the KEK could be purged (F17): the Olympos database
// dump is useless without it. It checks at startup and then every
// kekCheckEvery, so the Needs-attention item clears once the vault is fixed.
// It logs only when the result changes.
type kekWatch struct {
	rc    secrets.RecoveryChecker
	log   *slog.Logger
	every time.Duration

	mu    sync.Mutex
	state string // "" before the first check, then "ok" or the item kind and level
	items []inventory.AttentionItem
}

func newKEKWatch(kv secrets.KeyVault, log *slog.Logger) *kekWatch {
	rc, _ := kv.(secrets.RecoveryChecker)
	return &kekWatch{rc: rc, log: log, every: kekCheckEvery}
}

// Items is the latest result, for the Needs-attention strip.
func (w *kekWatch) Items() []inventory.AttentionItem {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.items
}

func (w *kekWatch) run(ctx context.Context) {
	if w.rc == nil {
		return
	}
	t := time.NewTicker(w.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		w.check(ctx)
	}
}

func (w *kekWatch) check(ctx context.Context) {
	if w.rc == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, kekCheckTimeout)
	defer cancel()
	okRec, level, err := w.rc.KEKRecoverable(cctx)
	if ctx.Err() != nil {
		return // shutting down: keep the last result
	}
	var state string
	var items []inventory.AttentionItem
	switch {
	case err != nil:
		state = "kek_recovery_unknown"
		items = []inventory.AttentionItem{{Kind: "kek_recovery_unknown", Severity: "warn", Label: "Key Vault",
			Detail: "could not check purge protection of the KEK (needs keys/get)", Link: "/backups?self=1"}}
	case !okRec:
		state = "kek_purgeable " + level
		items = []inventory.AttentionItem{{Kind: "kek_purgeable", Severity: "crit", Label: "Key Vault",
			Detail: "purge protection is off (" + level + "): enable soft delete and purge protection", Link: "/backups?self=1"}}
	default:
		state = "ok"
	}
	w.mu.Lock()
	prev := w.state
	w.state, w.items = state, items
	w.mu.Unlock()
	if state == prev {
		return
	}
	switch {
	case err != nil:
		w.log.Warn("could not check Key Vault purge protection", "err", err)
	case !okRec:
		w.log.Error("Key Vault purge protection is off: the KEK can be purged and every Olympos backup of its own database becomes useless",
			"recovery_level", level)
	case prev != "":
		w.log.Info("Key Vault purge protection is on: the KEK is recoverable", "recovery_level", level)
	}
}
