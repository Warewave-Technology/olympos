package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/approvals"
	_ "github.com/Warewave-Technology/olympos/internal/backup/engines/vault" // registers the "vault" snapshot engine
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/vaults"
)

// M3: Vaults (HashiCorp Vault & OpenBao), change requests with maker/checker,
// drift detection, raft snapshot backups (SPEC §10.2, §11).
func init() {
	Register(func(d *Deps) (Wiring, error) {
		log := d.Log.With("component", "vaults")
		svc := &vaults.Service{DB: d.DB, Log: log, KV: d.KV, KeyVaultName: d.Cfg.KeyVault.Name, Dial: vaults.GatewayDial(d.Gateway)}
		svc.RegisterBackup()
		cr := &approvals.API{DB: d.DB, Log: d.Log.With("component", "approvals"), Envelope: d.Envelope, HMAC: d.HMAC,
			Applier: svc, TTL: d.Cfg.ChangeRequests.TTL,
			OnApplied: func(id uuid.UUID) {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					if err := svc.Refresh(ctx, id); err != nil {
						log.Error("vault index refresh after apply", "vault_id", id, "err", err)
					}
				}()
			}}
		api := &vaults.API{Svc: svc, Log: log, RequireTLS: !d.Cfg.DevMode}
		expire := func(ctx context.Context) error { _, err := cr.ExpireDue(ctx); return err }
		return Wiring{
			Modules: []server.Module{api, cr},
			Workers: []Worker{svc.Maintenance(expire)},
		}, nil
	})
}
