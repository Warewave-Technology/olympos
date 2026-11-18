// Package notify implements the transactional outbox, the dispatcher and the
// Slack sink (SPEC §14).
package notify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// Event types (v1 catalog).
const (
	BackupFailed        = "backup.failed"
	BackupMissed        = "backup.missed"
	BackupSucceeded     = "backup.succeeded"
	CROpened            = "cr.opened"
	CRApproved          = "cr.approved"
	CRRejected          = "cr.rejected"
	CRExpired           = "cr.expired"
	CRFailed            = "cr.failed"
	VaultUnmanagedWrite = "vault.unmanaged_write"
	AuditNewFindings    = "audit.new_findings"
	VulnCritical        = "vuln.critical"
	AgentOffline        = "agent.offline"
	AgentOnline         = "agent.online"
	GrantChanged        = "grant.changed"
	GrantStale          = "grant.stale"
	SASExpiring         = "sas.expiring"
)

// Catalog lists every event type, in display order. backup.succeeded is
// opt-in: it has no default route.
var Catalog = []string{
	BackupFailed, BackupMissed, BackupSucceeded, CROpened, CRApproved, CRRejected, CRExpired, CRFailed,
	VaultUnmanagedWrite, AuditNewFindings, VulnCritical, AgentOffline, AgentOnline, GrantChanged, GrantStale, SASExpiring,
}

// Event is what modules emit. Payload MUST NOT contain secret values;
// HMAC fingerprints are fine.
type Event struct {
	Type string
	// Key makes delivery idempotent: emitting the same key twice is a no-op.
	// Default: random.
	Key string
	// ChannelID overrides routing (jobs/schedules with their own channel).
	ChannelID *uuid.UUID
	// Title is the one-line message; Link is a path under publicURL.
	Title   string
	Link    string
	Fields  map[string]string
	Payload map[string]any
}

// Emit writes the event to the outbox in the caller's transaction.
func Emit(ctx context.Context, q store.Querier, e Event) error {
	if e.Type == "" {
		return fmt.Errorf("event type required")
	}
	if e.Key == "" {
		e.Key = e.Type + ":" + uuid.NewString()
	}
	body := map[string]any{"title": e.Title, "link": e.Link, "fields": e.Fields}
	for k, v := range e.Payload {
		body[k] = v
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO outbox (event_type, payload, channel_id, idempotency_key)
		VALUES ($1, $2, $3, $4) ON CONFLICT (idempotency_key) DO NOTHING`, e.Type, b, e.ChannelID, e.Key)
	return err
}
