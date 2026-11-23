package app

import (
	"context"
	"fmt"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/synthetic"
)

// Synthetic monitoring (docs/design/synthetic-monitoring.md): probe state,
// the scheduler, dispatch of runs to the probe streams on this replica,
// result ingestion, the alert state machine and its messages, credential
// expiry, and the API under /api/v1/synthetic.
func init() {
	Register(func(d *Deps) (Wiring, error) {
		svc := &synthetic.Service{
			DB: d.DB, Log: d.Log.With("component", "synthetic"), Probes: d.Gateway,
			Creds: &backup.Credentials{KV: d.KV, Envelope: d.Envelope},
			Cfg:   d.Cfg.Synthetic, Started: time.Now(),
		}
		svc.OnResult = svc.ApplyOutcome
		// Ruling P25: a restored database starts ahead of every allowlist
		// version a probe has seen. Before any run is sent.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		v, err := svc.AdvanceAllowlistVersion(ctx)
		if err != nil {
			return Wiring{}, fmt.Errorf("advance the synthetic allowlist version: %w", err)
		}
		svc.Log.Info("synthetic allowlist version", "version", v)
		svc.InstallHooks(&d.Gateway.ProbeHooks)
		api := &synthetic.API{Svc: svc, Log: d.Log.With("component", "synthetic-api")}
		return Wiring{
			Modules: []server.Module{api},
			// The dispatcher runs on every replica (each sends the runs of
			// the probes connected to it); the scheduler, the alert loop
			// and maintenance on the leader of their locks.
			Workers: []Worker{svc.RunDispatcher, svc.RunScheduler, svc.RunAlerts, svc.RunMaintenance},
		}, nil
	})
}
