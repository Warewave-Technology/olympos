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
	BackupPartial       = "backup.partial"
	BackupMissed        = "backup.missed"
	BackupSucceeded     = "backup.succeeded"
	CROpened            = "cr.opened"
	CRApproved          = "cr.approved"
	CRRejected          = "cr.rejected"
	CRExpired           = "cr.expired"
	CRFailed            = "cr.failed"
	RestoreRequested    = "restore.requested"
	RestoreApproved     = "restore.approved"
	RestoreRejected     = "restore.rejected"
	RestoreStarted      = "restore.started"
	RestoreSucceeded    = "restore.succeeded"
	RestoreFailed       = "restore.failed"
	RestoreBreakGlass   = "restore.break_glass"
	VaultUnmanagedWrite = "vault.unmanaged_write"
	AuditNewFindings    = "audit.new_findings"
	VulnCritical        = "vuln.critical"
	SensitiveDataFound  = "sensitive_data.found"
	SecretFindings      = "secret.new_findings"
	AgentOffline        = "agent.offline"
	AgentOnline         = "agent.online"
	AgentFlapping       = "agent.flapping"
	GrantChanged        = "grant.changed"
	GrantStale          = "grant.stale"
	SASExpiring         = "sas.expiring"

	// Synthetic monitoring (docs/design/synthetic-monitoring.md §5, §6.1).
	SyntheticFailing            = "synthetic.failing"
	SyntheticCritical           = "synthetic.critical"
	SyntheticRecovered          = "synthetic.recovered"
	ProbeOffline                = "probe.offline"
	ProbeOnline                 = "probe.online"
	SyntheticCredentialExpiring = "synthetic.credential_expiring"
	SyntheticCredentialBroken   = "synthetic.credential_broken"
	SyntheticCredentialRestored = "synthetic.credential_restored"
	SyntheticAllowlistChanged   = "synthetic.allowlist_changed"
)

// Catalog lists every event type, in display order. backup.succeeded is
// opt-in: it has no default route.
var Catalog = []string{
	BackupFailed, BackupPartial, BackupMissed, BackupSucceeded, CROpened, CRApproved, CRRejected, CRExpired, CRFailed,
	RestoreRequested, RestoreApproved, RestoreRejected, RestoreStarted, RestoreSucceeded, RestoreFailed, RestoreBreakGlass,
	VaultUnmanagedWrite, AuditNewFindings, VulnCritical, SensitiveDataFound, SecretFindings, AgentOffline, AgentOnline, AgentFlapping, GrantChanged, GrantStale, SASExpiring,
	SyntheticFailing, SyntheticCritical, SyntheticRecovered, ProbeOffline, ProbeOnline, SyntheticCredentialExpiring,
	SyntheticCredentialBroken, SyntheticCredentialRestored, SyntheticAllowlistChanged,
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
	// Seq orders the events one transaction emits: the row's created_at
	// and next_attempt_at are now() plus Seq microseconds, so that the
	// dispatcher delivers them in that order (now() is the same for the
	// whole transaction). Zero: now().
	Seq int
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
	_, err = q.Exec(ctx, `INSERT INTO outbox (event_type, payload, channel_id, idempotency_key, created_at, next_attempt_at)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5), now() + make_interval(secs => $5))
		ON CONFLICT (idempotency_key) DO NOTHING`, e.Type, b, e.ChannelID, e.Key, float64(e.Seq)/1e6)
	return err
}
