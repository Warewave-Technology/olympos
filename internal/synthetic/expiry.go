package synthetic

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// ExpiryInterval is how often the leader of LockSyntheticMaintenance checks
// credential expiry (RunMaintenance, retention.go).
const ExpiryInterval = 24 * time.Hour

// ExpiryThresholds are the days before a credential's expires_at at which
// synthetic.credential_expiring fires (§5). An expired credential gets no
// message of its own: its runs end in error (credential_expired) and alert
// like any failure.
var ExpiryThresholds = []int{14, 3}

// expiryThreshold is the smallest threshold that remaining is within, or -1
// when none is (yet, or any more: expired).
func expiryThreshold(remaining time.Duration) int {
	t := -1
	if remaining <= 0 {
		return t
	}
	for _, d := range ExpiryThresholds {
		if remaining <= time.Duration(d)*24*time.Hour && (t < 0 || d < t) {
			t = d
		}
	}
	return t
}

// CredentialExpiryKey is the idempotency key of one message: one per
// credential, threshold and expiry, so that a rotated credential (a new
// expires_at) starts a new series.
func CredentialExpiryKey(credID uuid.UUID, thresholdDays int, expiresAt time.Time) string {
	return fmt.Sprintf("%s:%s:%dd:%d", notify.SyntheticCredentialExpiring, credID, thresholdDays, expiresAt.Unix())
}

// CheckCredentialExpiry sends synthetic.credential_expiring for every
// synthetic credential within 14 or 3 days of its expires_at, once per
// threshold (the outbox's idempotency key). The message names the
// credential, its expiry and the scenarios that use it; never its value.
func (s *Service) CheckCredentialExpiry(ctx context.Context) error {
	now := s.now()
	type cred struct {
		id        uuid.UUID
		name      string
		expires   time.Time
		scenarios []string
	}
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.name, c.expires_at,
			COALESCE((SELECT array_agg(DISTINCT sc.name ORDER BY sc.name) FROM scenario_steps st JOIN scenarios sc ON sc.id = st.scenario_id
				WHERE st.credential_id = c.id), '{}')
		FROM synthetic_credentials c
		WHERE c.expires_at IS NOT NULL AND c.expires_at > $1 AND c.expires_at <= $2
		ORDER BY c.expires_at, c.id`, now, now.Add(time.Duration(ExpiryThresholds[0])*24*time.Hour))
	if err != nil {
		return err
	}
	creds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cred, error) {
		var c cred
		return c, r.Scan(&c.id, &c.name, &c.expires, &c.scenarios)
	})
	if err != nil {
		return err
	}
	return store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, c := range creds {
			th := expiryThreshold(c.expires.Sub(now))
			if th < 0 {
				continue
			}
			days := int(c.expires.Sub(now).Hours() / 24)
			title := fmt.Sprintf("Synthetic credential %s expires in %d days", c.name, days)
			if days < 1 {
				title = fmt.Sprintf("Synthetic credential %s expires within a day", c.name)
			}
			used := "none"
			if len(c.scenarios) > 0 {
				used = topList(c.scenarios)
			}
			expires := c.expires.UTC().Format(time.RFC3339)
			if err := notify.Emit(ctx, tx, notify.Event{
				Type:   notify.SyntheticCredentialExpiring,
				Key:    CredentialExpiryKey(c.id, th, c.expires),
				Title:  title,
				Link:   "/settings/synthetic?credential=" + c.id.String(),
				Fields: map[string]string{"credential": c.name, "expires": expires, "used by": used},
				Payload: map[string]any{"credential_id": c.id.String(), "threshold_days": th, "expires_at": expires, "days_left": days,
					"scenario_count": len(c.scenarios)},
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
