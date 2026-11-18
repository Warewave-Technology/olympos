package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/version"
)

const (
	instanceHeartbeat = 10 * time.Second
	// instanceLive: an instance whose heartbeat is older is considered gone.
	instanceLive = 30 * time.Second
)

// instanceGuard enforces the v0.1 single-instance rule (F5): tunnels only
// open on the instance an agent is connected to, so a second instance on
// the same database would "work sometimes". Each instance registers in
// server_instances and heartbeats; the newer of two live instances logs an
// error and reports not ready, unless experimental.multiReplica is set.
// The check is evaluated on every heartbeat, so after the older instance
// stops (rolling restart, crash) the newer one becomes ready.
type instanceGuard struct {
	db    *store.DB
	log   *slog.Logger
	id    uuid.UUID
	multi bool

	mu      sync.Mutex
	blocked error
}

func newInstanceGuard(ctx context.Context, db *store.DB, log *slog.Logger, multi bool) (*instanceGuard, error) {
	host, _ := os.Hostname()
	g := &instanceGuard{db: db, log: log, id: uuid.New(), multi: multi}
	if _, err := db.Exec(ctx, `INSERT INTO server_instances (id, hostname, version) VALUES ($1, $2, $3)`, g.id, host, version.Version); err != nil {
		return nil, err
	}
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// Ready is part of /readyz.
func (g *instanceGuard) Ready() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.blocked
}

func (g *instanceGuard) check(ctx context.Context) error {
	if _, err := g.db.Exec(ctx, `UPDATE server_instances SET heartbeat_at = now() WHERE id = $1`, g.id); err != nil {
		return err
	}
	var host, ver string
	var started time.Time
	err := g.db.QueryRow(ctx, `SELECT o.hostname, o.version, o.started_at FROM server_instances o, server_instances me
		WHERE me.id = $1 AND o.id <> me.id AND o.heartbeat_at > now() - $2::interval
		  AND (o.started_at, o.id) < (me.started_at, me.id)
		ORDER BY o.started_at LIMIT 1`, g.id, fmt.Sprintf("%d seconds", int(instanceLive.Seconds()))).Scan(&host, &ver, &started)
	var blocked error
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	case g.multi:
		// Allowed explicitly; nothing to report.
	default:
		blocked = fmt.Errorf("another olympos-server instance (%s, %s, started %s) uses this database; v0.1 supports a single instance "+
			"(see docs/install.md, or set experimental.multiReplica)", host, ver, started.UTC().Format(time.RFC3339))
	}
	g.mu.Lock()
	changed := (blocked == nil) != (g.blocked == nil)
	g.blocked = blocked
	g.mu.Unlock()
	if changed && blocked != nil {
		g.log.Error("not ready: more than one live server instance", "err", blocked)
	} else if changed {
		g.log.Info("ready: this is the only live server instance")
	}
	return nil
}

// run heartbeats until ctx ends, then deregisters.
func (g *instanceGuard) run(ctx context.Context) {
	t := time.NewTicker(instanceHeartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = g.db.Exec(dctx, `DELETE FROM server_instances WHERE id = $1`, g.id)
			cancel()
			return
		case <-t.C:
		}
		if err := g.check(ctx); err != nil && ctx.Err() == nil {
			g.log.Warn("server instance heartbeat", "err", err)
		}
		_, _ = g.db.Exec(ctx, `DELETE FROM server_instances WHERE heartbeat_at < now() - interval '1 hour'`)
	}
}
