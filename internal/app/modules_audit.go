package app

import (
	"github.com/Warewave-Technology/olympos/internal/audit"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/server"
)

// M4 — Audit: kubescape/polaris over the read-only API proxy, kube-bench on
// agents, findings diff (SPEC §12).
func init() {
	Register(func(d *Deps) (Wiring, error) {
		log := d.Log.With("component", "audit")
		storage, err := storageOptions(d.Cfg)
		if err != nil {
			return Wiring{}, err
		}
		svc := &audit.Service{
			DB: d.DB, Log: log, Gateway: d.Gateway,
			Blob:         blob.NewResolver(d.DB, d.KV, d.Envelope, d.Cred, blob.WithStorage(storage)),
			KubescapeBin: d.Cfg.Audit.KubescapeBin, KubescapeArtifacts: d.Cfg.Audit.KubescapeArtifacts,
			PolarisBin: d.Cfg.Audit.PolarisBin,
		}
		svc.InstallHooks(&d.Gateway.Hooks)
		return Wiring{
			Modules: []server.Module{&audit.API{DB: d.DB, Log: log}},
			Workers: []Worker{svc.RunScheduler, svc.RunWorker},
		}, nil
	})
}
