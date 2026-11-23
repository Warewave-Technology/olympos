// Package restore implements restore requests: a successful backup copy
// restored into a new, discovered target after a second person's approval
// or through the recorded break-glass path (docs/design/ui-restore.md).
package restore

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/backup"
)

// Status is a restore request's lifecycle state.
type Status string

const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusRejected  Status = "rejected"
	StatusExpired   Status = "expired"
	StatusCancelled Status = "cancelled"
)

// AllStatuses lists every status (the CHECK of restore_requests.status).
var AllStatuses = []Status{StatusPending, StatusApproved, StatusRunning, StatusSucceeded, StatusFailed,
	StatusRejected, StatusExpired, StatusCancelled}

// Terminal reports whether the request is over: its credential and Vault
// token are gone and nothing happens to it any more.
func (s Status) Terminal() bool {
	switch s {
	case StatusPending, StatusApproved, StatusRunning:
		return false
	}
	return true
}

// ApprovedTTL is how long an approved request may wait for the backup
// worker to start it (agent offline, for example). After that it expires,
// which frees the target and wipes the credential and the token.
const ApprovedTTL = 24 * time.Hour

// Input opens a request (POST /restores) or checks one (POST
// /restores/check). Credential.Password and VaultToken are write-only.
type Input struct {
	RunID uuid.UUID `json:"run_id"`
	// CopyDestinationID picks the copy (group runs); nil takes the copy the
	// run's restore guide selects by default.
	CopyDestinationID *uuid.UUID `json:"copy_destination_id"`
	TargetID          string     `json:"target_id"`
	// Databases to restore (PostgreSQL, ClickHouse); empty means all the
	// databases in the backup.
	Databases []string `json:"databases"`
	// Globals: PostgreSQL roles from globals.sql (default on; only with a
	// superuser credential).
	Globals *bool `json:"globals"`
	// TLSCAPEM verifies the target's certificate (a new target has no job
	// whose options carry one).
	TLSCAPEM string `json:"tls_ca_pem"`
	// Credential is the target's admin login (PostgreSQL, ClickHouse).
	Credential *backup.CredentialInput `json:"credential"`
	// VaultToken is a token of the new Vault allowed to snapshot-force.
	VaultToken    string `json:"vault_token"`
	Justification string `json:"justification"`
	// BreakGlass starts the request at once (admins on both clusters).
	BreakGlass bool `json:"break_glass"`
}

// Options are restore_requests.options: what the checker sees and the
// executor uses besides the databases.
type Options struct {
	// Globals: restore PostgreSQL roles (false when the credential is not a
	// superuser).
	Globals *bool `json:"globals,omitempty"`
	// Superuser: the PostgreSQL credential is a superuser (owners and
	// privileges are kept); nil for other engines.
	Superuser *bool  `json:"superuser,omitempty"`
	TLSCAPEM  string `json:"tls_ca_pem,omitempty"`
	// Notes are the open-time check's findings shown with the request (an
	// existing empty database restored into, no superuser).
	Notes []string `json:"notes,omitempty"`
	// ServerVersion of the target when the request was opened.
	ServerVersion string `json:"server_version,omitempty"`
}

// EngineOptions are the engine options of the target's EngineContext for a
// request: only the CA bundle, under each engine's own key.
func EngineOptions(engine string, o Options) json.RawMessage {
	m := map[string]any{}
	if o.TLSCAPEM != "" {
		switch engine {
		case "postgresql":
			m["tls_ca_pem"] = o.TLSCAPEM
		case "clickhouse":
			m["ca_pem"] = o.TLSCAPEM
		case "vault":
			m["ca_bundle"] = o.TLSCAPEM
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// TargetReport is what an engine's inspector finds on a restore target,
// without writing anything.
type TargetReport struct {
	// Existing: selected databases that exist on the target, true when the
	// database holds user objects (tables, views, functions, sequences).
	Existing map[string]bool `json:"existing"`
	// Superuser: the PostgreSQL credential is a superuser.
	Superuser bool `json:"superuser"`
	// Vault: initialized, sealed, and whether the token may call
	// sys/storage/raft/snapshot-force (update and sudo, or root).
	Initialized      bool `json:"initialized"`
	Sealed           bool `json:"sealed"`
	CanSnapshotForce bool `json:"can_snapshot_force"`
	// Standby (Vault): the target is an HA node that is not the active
	// node (sys/leader: ha_enabled and not is_self).
	Standby bool `json:"standby"`
	// CapabilitiesDenied (Vault): sys/capabilities-self refused the token
	// (HTTP 401/403), so its capabilities could not be read.
	CapabilitiesDenied bool   `json:"capabilities_denied"`
	ServerVersion      string `json:"server_version"`
}

// TargetInspector checks a restore target over its tunnel with the request's
// credential (which also tests it). Implemented per engine.
type TargetInspector interface {
	InspectRestoreTarget(ctx context.Context, ec backup.EngineContext, databases []string) (*TargetReport, error)
}

// BackupChecker is optionally implemented by a TargetInspector: it compares
// the backup's engine metadata (the manifest's details) with what the
// inspector found and returns why the target cannot take this backup ("":
// it can). Its finding is shown on the target_id field when a request is
// checked or opened (PostgreSQL: a dump of a newer major than the server).
type BackupChecker interface {
	CheckBackup(details map[string]any, r *TargetReport) string
}

// checkBackup runs the engine inspector's BackupChecker, if any.
func checkBackup(engine string, details map[string]any, r *TargetReport) string {
	insp, ok := InspectorFor(engine)
	if !ok || details == nil || r == nil {
		return ""
	}
	if c, ok := insp.(BackupChecker); ok {
		return c.CheckBackup(details, r)
	}
	return ""
}

var (
	inspectorsMu sync.RWMutex
	inspectors   = map[string]TargetInspector{}
)

// RegisterInspector makes restores of engine possible (call from init()).
func RegisterInspector(engine string, i TargetInspector) {
	inspectorsMu.Lock()
	defer inspectorsMu.Unlock()
	inspectors[engine] = i
}

// InspectorFor returns the inspector registered for engine.
func InspectorFor(engine string) (TargetInspector, bool) {
	inspectorsMu.RLock()
	defer inspectorsMu.RUnlock()
	i, ok := inspectors[engine]
	return i, ok
}

// ---------------------------------------------------------------- views

// SourceRef is the backup a request restores.
type SourceRef struct {
	RunID       uuid.UUID `json:"run_id"`
	CopyRunID   uuid.UUID `json:"copy_run_id"`
	TargetID    string    `json:"target_id"`
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	Namespace   string    `json:"namespace"`
	Service     string    `json:"service"`
	// Destination holding the copy.
	DestinationID   uuid.UUID `json:"destination_id"`
	DestinationName string    `json:"destination_name"`
	DestinationKind string    `json:"destination_kind"`
}

// TargetRef is the target a request restores into.
type TargetRef struct {
	ID            string    `json:"id"`
	ClusterID     uuid.UUID `json:"cluster_id"`
	ClusterName   string    `json:"cluster_name"`
	Namespace     string    `json:"namespace"`
	Service       string    `json:"service"`
	Port          int       `json:"port"`
	VaultProvider string    `json:"vault_provider,omitempty"`
}

// CredentialRef is the public part of the request's target credential
// (never the password); nil once the request is over.
type CredentialRef struct {
	Source   string `json:"source"`
	Ref      string `json:"ref,omitempty"`
	Username string `json:"username"`
}

// Request is a restore request as the API shows it. It never carries a
// password or a token.
type Request struct {
	ID         uuid.UUID      `json:"id"`
	Status     Status         `json:"status"`
	Engine     string         `json:"engine"`
	Source     SourceRef      `json:"source"`
	Target     TargetRef      `json:"target"`
	Databases  []string       `json:"databases"`
	Options    Options        `json:"options"`
	Credential *CredentialRef `json:"credential"`
	// HasVaultToken: a Vault token is held for this request (until it ends).
	HasVaultToken bool `json:"has_vault_token"`

	Maker         authz.Principal  `json:"maker"`
	Checker       *authz.Principal `json:"checker"`
	Justification string           `json:"justification"`
	// BreakGlass: the maker started the request without a checker (the
	// maker is the decider; Checker stays null).
	BreakGlass        bool       `json:"break_glass"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	DecidedAt         *time.Time `json:"decided_at"`
	DecisionComment   string     `json:"decision_comment"`
	ApprovedExpiresAt *time.Time `json:"approved_expires_at"`
	StartedAt         *time.Time `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at"`
	// Progress and Result are written by the executor.
	Progress json.RawMessage `json:"progress"`
	Result   json.RawMessage `json:"result"`
	Error    string          `json:"error"`

	CanApprove            bool   `json:"can_approve"`
	ApproveDisabledReason string `json:"approve_disabled_reason"`
	CanCancel             bool   `json:"can_cancel"`

	makerID   uuid.UUID
	checkerID *uuid.UUID
	clusters  Clusters
}

// Link is the UI path of a restore request (notifications carry links only).
func Link(id uuid.UUID) string { return "/approvals?restore=" + id.String() }
