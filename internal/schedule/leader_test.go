package schedule

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// Leaders hold their locks outside the pool: several leaders on a pool of one
// connection still tick, and the pool stays usable (a 4-CPU host stalled
// with one pinned pool connection per leader).
func TestLeadersDoNotPinPoolConnections(t *testing.T) {
	base := testutil.DB(t)
	dsn := base.Config().ConnString()
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, dsn+sep+"pool_max_conns=1")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// Stop the leaders before closing: Close waits for every connection.
	defer db.Close()
	defer cancel()
	if db.Config().MaxConns != 1 {
		t.Fatalf("pool_max_conns ignored: %d", db.Config().MaxConns)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var ticks [3]atomic.Int32
	for i := range ticks {
		go RunLeader(ctx, db, 0x7e570000+int64(i), 50*time.Millisecond, log, func(ctx context.Context) error {
			var one int
			if err := db.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
				return err
			}
			ticks[i].Add(1)
			return nil
		})
	}
	deadline := time.Now().Add(10 * time.Second)
	for i := range ticks {
		for ticks[i].Load() < 2 {
			if time.Now().After(deadline) {
				t.Fatalf("leader %d did not tick (ticks %d %d %d)", i, ticks[0].Load(), ticks[1].Load(), ticks[2].Load())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
	defer pcancel()
	if err := db.Ping(pctx); err != nil {
		t.Fatalf("pool exhausted by leaders: %v", err)
	}
}

func TestPoolMinimum(t *testing.T) {
	db := testutil.DB(t)
	if got := db.Config().MaxConns; got < 16 {
		t.Fatalf("MaxConns = %d, want >= 16 (store.minPoolConns)", got)
	}
}
