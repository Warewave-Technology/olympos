package vaults

import (
	"context"
	"errors"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

// BackupCredential supplies the Olympos AppRole to the vault snapshot
// engine: role_id as Username, secret_id (from Key Vault) as Secret. The
// worker zeroes Secret after the run.
func (s *Service) BackupCredential(ctx context.Context, t backup.TargetInfo) (backup.Credential, error) {
	r, err := loadRowByTarget(ctx, s.DB, t.ID)
	if errors.Is(err, store.ErrNotFound) {
		return backup.Credential{}, errors.New("no vault is registered for this target")
	}
	if err != nil {
		return backup.Credential{}, err
	}
	if r.Status != "configured" || r.RoleID == "" || r.SecretIDRef == "" {
		return backup.Credential{}, errors.New("configure this vault on the Vaults page first (Olympos AppRole is missing)")
	}
	sid, err := secrets.Resolve(ctx, s.KV, r.SecretIDRef)
	if err != nil {
		return backup.Credential{}, errors.New("could not read the AppRole secret_id from Key Vault")
	}
	return backup.Credential{Username: r.RoleID, Secret: sid}, nil
}

// RegisterBackup installs the AppRole credential provider for engine
// "vault" and the CA bundle lookup used by the snapshot engine.
func (s *Service) RegisterBackup() {
	backup.RegisterCredentialProvider("vault", s.BackupCredential)
	vclient.CABundleFor = s.CABundleFor
}

// Maintenance runs on the leader every minute: extra (change request expiry),
// the index refresh + drift detection every IndexInterval, and secret_id
// rotation checks every RotateCheck.
func (s *Service) Maintenance(extra func(ctx context.Context) error) func(ctx context.Context) {
	return func(ctx context.Context) {
		var lastIndex, lastRotate time.Time
		schedule.RunLeader(ctx, s.DB, LockVaults, time.Minute, s.Log, func(ctx context.Context) error {
			if extra != nil {
				if err := extra(ctx); err != nil && ctx.Err() == nil {
					s.Log.Error("change request expiry", "err", err)
				}
			}
			now := time.Now()
			if now.Sub(lastIndex) >= IndexInterval {
				lastIndex = now
				if err := s.RefreshAll(ctx); err != nil && ctx.Err() == nil {
					s.Log.Error("vault index", "err", err)
				}
			}
			if now.Sub(lastRotate) >= RotateCheck {
				lastRotate = now
				if err := s.RotateDue(ctx); err != nil && ctx.Err() == nil {
					s.Log.Error("vault secret_id rotation", "err", err)
				}
			}
			return nil
		})
	}
}
