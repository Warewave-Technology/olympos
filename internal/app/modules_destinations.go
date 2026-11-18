package app

import (
	"github.com/Warewave-Technology/olympos/internal/destinations"
	"github.com/Warewave-Technology/olympos/internal/server"
)

// Backup destinations (SPEC §10.3): API + daily sas.expiring job (leader).
func init() {
	Register(func(d *Deps) (Wiring, error) {
		log := d.Log.With("component", "destinations")
		api := &destinations.API{DB: d.DB, Log: log, KV: d.KV, Env: d.Envelope, Cred: d.Cred}
		job := &destinations.ExpiryJob{DB: d.DB, KV: d.KV, Env: d.Envelope, Log: log}
		return Wiring{Modules: []server.Module{api}, Workers: []Worker{job.Run}}, nil
	})
}
