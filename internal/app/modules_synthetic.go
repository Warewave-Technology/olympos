package app

import (
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/synthetic"
)

// Synthetic monitoring (docs/design/synthetic-monitoring.md): probe state,
// dispatch of runs to the probe streams on this replica, result ingestion.
func init() {
	Register(func(d *Deps) (Wiring, error) {
		svc := &synthetic.Service{
			DB: d.DB, Log: d.Log.With("component", "synthetic"), Probes: d.Gateway,
			Creds: &backup.Credentials{KV: d.KV, Envelope: d.Envelope},
			Cfg:   d.Cfg.Synthetic, Started: time.Now(),
		}
		svc.InstallHooks(&d.Gateway.ProbeHooks)
		return Wiring{
			// The dispatcher runs on every replica (each sends the runs of
			// the probes connected to it); the alert loop on the leader.
			Workers: []Worker{svc.RunDispatcher, svc.RunAlerts},
		}, nil
	})
}
