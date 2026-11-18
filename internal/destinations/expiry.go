package destinations

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// LockSASExpiry is the advisory lock key of the sas.expiring job (single
// active replica).
const LockSASExpiry int64 = 0x4f4c5910

// ExpiryThresholds are the days-before-expiry at which sas.expiring fires
// (SPEC §10.3). 0 means "has expired".
var ExpiryThresholds = []int{14, 3, 0}

// ExpiryJob emits sas.expiring for SAS destinations. For Key Vault
// references it re-reads the secret so a rotated token updates the stored
// expiry.
type ExpiryJob struct {
	DB       *store.DB
	KV       secrets.KeyVault
	Env      *secrets.Envelope
	Log      *slog.Logger
	Now      func() time.Time
	Interval time.Duration // default 24h
}

// Run ticks while holding the leader lock.
func (j *ExpiryJob) Run(ctx context.Context) {
	iv := j.Interval
	if iv == 0 {
		iv = 24 * time.Hour
	}
	schedule.RunLeader(ctx, j.DB, LockSASExpiry, iv, j.Log, j.Tick)
}

// threshold returns the smallest threshold that applies to remaining, or
// -1 when none does yet.
func threshold(remaining time.Duration) int {
	if remaining <= 0 {
		return 0
	}
	t := -1
	for _, d := range ExpiryThresholds {
		if d > 0 && remaining <= time.Duration(d)*24*time.Hour {
			t = d
		}
	}
	return t
}

// ExpiryKey is the idempotency key of one notification: one per
// destination, threshold and expiry (a rotated SAS starts a new series).
func ExpiryKey(destID uuid.UUID, thresholdDays int, expiresAt time.Time) string {
	return fmt.Sprintf("sas.expiring:%s:%dd:%d", destID, thresholdDays, expiresAt.Unix())
}

// Tick checks every SAS destination once.
func (j *ExpiryJob) Tick(ctx context.Context) error {
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	type dest struct {
		id      uuid.UUID
		name    string
		credID  uuid.UUID
		kind    string
		expires *time.Time
		perms   string
	}
	rows, err := j.DB.Query(ctx, `SELECT d.id, d.name, d.sas_credential_id, c.kind, d.sas_expires_at, d.sas_permissions
		FROM destinations d JOIN credentials c ON c.id = d.sas_credential_id WHERE d.auth = 'sas_token'`)
	if err != nil {
		return err
	}
	var ds []dest
	for rows.Next() {
		var d dest
		if err := rows.Scan(&d.id, &d.name, &d.credID, &d.kind, &d.expires, &d.perms); err != nil {
			rows.Close()
			return err
		}
		ds = append(ds, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range ds {
		if d.kind == "keyvault_ref" {
			// The referenced secret may have been rotated: refresh expiry.
			if b, err := blob.LoadSAS(ctx, j.DB, j.KV, j.Env, d.credID); err != nil {
				j.Log.Warn("sas.expiring: cannot read SAS from Key Vault; using stored expiry", "destination", d.id.String(), "err", err)
			} else {
				info, perr := ParseSAS(string(b))
				secrets.Zero(b)
				if perr == nil && info.ExpiresAt != nil && (d.expires == nil || !d.expires.Equal(*info.ExpiresAt) || d.perms != info.Permissions) {
					if _, err := j.DB.Exec(ctx, `UPDATE destinations SET sas_expires_at = $2, sas_permissions = $3 WHERE id = $1`,
						d.id, info.ExpiresAt, info.Permissions); err != nil {
						return err
					}
					d.expires = info.ExpiresAt
				}
			}
		}
		if d.expires == nil {
			continue
		}
		th := threshold(d.expires.Sub(now))
		if th < 0 {
			continue
		}
		days := int(d.expires.Sub(now).Hours() / 24)
		title := fmt.Sprintf("SAS token of destination %s expires in %d days", d.name, days)
		switch {
		case th == 0:
			title = fmt.Sprintf("SAS token of destination %s has expired: backups to it fail", d.name)
		case days < 1:
			title = fmt.Sprintf("SAS token of destination %s expires within a day", d.name)
		}
		err := store.Tx(ctx, j.DB, func(tx pgx.Tx) error {
			return notify.Emit(ctx, tx, notify.Event{
				Type:  notify.SASExpiring,
				Key:   ExpiryKey(d.id, th, *d.expires),
				Title: title,
				Link:  "/settings/destinations?id=" + d.id.String(),
				Fields: map[string]string{
					"destination": d.name,
					"expires":     d.expires.UTC().Format(time.RFC3339),
				},
				Payload: map[string]any{
					"destination_id": d.id.String(),
					"threshold_days": th,
					"expires_at":     d.expires.UTC().Format(time.RFC3339),
					"days_left":      days,
				},
			})
		})
		if err != nil {
			return err
		}
	}
	return nil
}
