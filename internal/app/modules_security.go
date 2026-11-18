package app

import (
	"context"
	"errors"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/security"
	"github.com/Warewave-Technology/olympos/internal/server"
)

// M5 security: Kyverno/NetworkPolicy/image ingest, trivy scanner, API.
func init() {
	Register(func(d *Deps) (Wiring, error) {
		log := d.Log.With("component", "security")
		sc := &security.Scanner{
			DB: d.DB, Log: log.With("worker", "scanner"), KV: d.KV, Envelope: d.Envelope,
			Runner: &security.TrivyCLI{Bin: d.Cfg.Security.TrivyBin, CacheDir: d.Cfg.Security.TrivyCacheDir, DBRepo: d.Cfg.Security.TrivyDBRepo},
			Link:   d.PublicLink,
		}
		ing := &security.Ingester{DB: d.DB, Log: log, SystemNamespaces: d.Cfg.Security.SystemNamespaces, OnNewImages: sc.Poke,
			ReportUnmanaged: d.Cfg.Security.SecretsInventory.ReportUnmanaged == nil || *d.Cfg.Security.SecretsInventory.ReportUnmanaged}
		// Chain any Report hook installed by another module.
		prev := d.Gateway.Hooks.Report
		d.Gateway.Hooks.Report = func(ctx context.Context, clusterID uuid.UUID, r *pb.ResourceReport) error {
			err := ing.Report(ctx, clusterID, r)
			if prev != nil {
				err = errors.Join(err, prev(ctx, clusterID, r))
			}
			return err
		}
		api := &security.API{DB: d.DB, Log: log, Envelope: d.Envelope, Scanner: sc}
		return Wiring{Modules: []server.Module{api}, Workers: []Worker{sc.Run}}, nil
	})
}
