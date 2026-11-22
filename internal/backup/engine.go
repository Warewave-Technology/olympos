// Package backup implements backup jobs, the scheduler, workers and engines
// (SPEC §10). Engines never see Blob credentials and the cluster never sees
// database credentials: the server connects through the agent tunnel.
package backup

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// TargetInfo is what an engine knows about its target.
type TargetInfo struct {
	ID            string
	ClusterID     string
	ClusterName   string
	Namespace     string
	Service       string
	Port          int
	Engine        string // postgresql | clickhouse | vault
	VaultProvider string
	TLSServerName string // SNI / verify name (default <service>.<namespace>.svc)
}

// Credential is the resolved login for a run. Secret MUST be zeroed by the
// caller after use (the worker does this).
type Credential struct {
	Username string
	Secret   []byte
}

// EngineContext is passed to every engine call.
type EngineContext struct {
	Target TargetInfo
	// Dial opens a new tunnel to the target. Engines that need several
	// connections (pg_dump per database) call it repeatedly.
	Dial func(ctx context.Context) (net.Conn, error)
	// UseTLS is true in transfer mode e2e-tls (default): the engine MUST
	// speak verified TLS end-to-end with the target whenever the target
	// supports it. Without TLS on the target a password MUST NOT cross the
	// connection: PostgreSQL only logs in with SCRAM-SHA-256, ClickHouse and
	// Vault are refused. The engine reports RunResult.TLS=false (also with
	// the error) so the tls.missing finding opens.
	// False in "compressed" mode (plaintext inside the cluster).
	UseTLS bool
	// TLSServerName to verify; InsecureSkipVerify is never used. RootCAs is
	// left to the engine: the configured target bundle, plus the system pool
	// with targetTLS.systemRoots or TrustSystemRoots.
	TLSServerName string
	// TrustSystemRoots: the target was configured by an admin, not
	// discovered (Olympos' own database), so public CAs may vouch for it.
	TrustSystemRoots bool
	// Credential returns the login (database user, or AppRole for Vault).
	Credential func(ctx context.Context) (Credential, error)
	Options    json.RawMessage
	// Test is a dry run: produce a small artifact (e.g. schema only).
	Test bool
}

// RunResult is engine metadata stored in the manifest.
type RunResult struct {
	ServerVersion string `json:"server_version"`
	ToolVersion   string `json:"tool_version,omitempty"`
	// TLS reports whether the run spoke TLS with the target (nil = unknown).
	// false opens the tls.missing finding (SPEC §7, §13.4).
	TLS     *bool          `json:"tls,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// Privilege is one line of the connection test.
type Privilege struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// ConnectionTest is the result of TestConnection (API shape).
type ConnectionTest struct {
	OK            bool        `json:"ok"`
	ServerVersion string      `json:"server_version"`
	TLS           bool        `json:"tls"`
	Privileges    []Privilege `json:"privileges"`
	Databases     []string    `json:"databases"`
	Error         string      `json:"error,omitempty"`
	// Reached: the target answered (TLS is known) even if the test failed,
	// so the tls.missing finding is opened or resolved.
	Reached bool `json:"-"`
}

// Engine is a backup engine.
type Engine interface {
	Name() string
	// Ext is the blob extension, e.g. "tar" or "snap".
	Ext() string
	ContentType() string
	TestConnection(ctx context.Context, ec EngineContext) (*ConnectionTest, error)
	// Run streams the backup into w (single blob). The worker hashes and
	// counts bytes; engines must not buffer whole backups in memory or disk.
	Run(ctx context.Context, ec EngineContext, w io.Writer) (*RunResult, error)
}

var (
	enginesMu sync.RWMutex
	engines   = map[string]Engine{}
)

// RegisterEngine makes an engine available (call from init()).
func RegisterEngine(e Engine) {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	engines[e.Name()] = e
}

// EngineFor returns the engine registered for name.
func EngineFor(name string) (Engine, bool) {
	enginesMu.RLock()
	defer enginesMu.RUnlock()
	e, ok := engines[name]
	return e, ok
}

// CredentialProvider supplies credentials for engines whose login is not a
// user-entered credential (Vault: the Olympos AppRole). Registered by the
// vaults module.
type CredentialProvider func(ctx context.Context, t TargetInfo) (Credential, error)

var (
	credProvMu sync.RWMutex
	credProvs  = map[string]CredentialProvider{}
)

// RegisterCredentialProvider sets the provider for an engine name.
func RegisterCredentialProvider(engine string, p CredentialProvider) {
	credProvMu.Lock()
	defer credProvMu.Unlock()
	credProvs[engine] = p
}

// CredentialProviderFor returns the provider for engine, if any.
func CredentialProviderFor(engine string) (CredentialProvider, bool) {
	credProvMu.RLock()
	defer credProvMu.RUnlock()
	p, ok := credProvs[engine]
	return p, ok
}

// ---------------------------------------------------------------- restore

// Progress is what a restore reports while it runs; the restore executor
// stores the latest one (restore_requests.progress, throttled).
type Progress struct {
	// Phase: "verify" (the checksum pass), "check" (the target re-check),
	// "globals" (PostgreSQL roles) or "restore".
	Phase    string `json:"phase,omitempty"`
	Database string `json:"database,omitempty"`
	Table    string `json:"table,omitempty"`
	// Bytes of the backup read so far, of Total.
	Bytes int64 `json:"bytes"`
	Total int64 `json:"total,omitempty"`
	// Done lists the databases restored so far. Created lists the
	// databases the restore created on the target so far, cumulatively:
	// after a failure (or a stopped server) they stay and are listed, never
	// dropped. Report a database here right after creating it.
	Done    []string `json:"done,omitempty"`
	Created []string `json:"created,omitempty"`
}

// RestoreContext is passed to Restorer.Restore. The embedded EngineContext
// dials the restore target (not a job's) with the request's credential;
// its Options are the target's engine options (the CA bundle).
type RestoreContext struct {
	EngineContext
	// Archive is the backup copy for random reads (PostgreSQL, ClickHouse
	// zip archives; each entry's CRC-32 is checked by archive/zip); nil for
	// Vault. Its SHA-256 was verified before Restore is called. Small reads
	// are served from a read-ahead window; the executor closes it.
	Archive blob.Object
	// Snapshot is the Vault/OpenBao snapshot, front to back; nil otherwise.
	Snapshot io.Reader
	// Databases to restore (empty for Vault).
	Databases []string
	// Options are the request's restore options (restore.Options as JSON:
	// globals, superuser, tls_ca_pem, notes).
	Options json.RawMessage
	// Superuser: the PostgreSQL credential is a superuser (owners,
	// privileges and globals are kept).
	Superuser bool
	// Progress reports progress; never nil. Cheap to call often.
	Progress func(Progress)
}

// RestoreItem is the result for one database (or the snapshot).
type RestoreItem struct {
	Name string `json:"name"`
	// Status: succeeded | failed | skipped.
	Status string `json:"status"`
	// Bytes of the backup restored for this item.
	Bytes int64 `json:"bytes"`
	// Duration in seconds.
	Duration float64 `json:"duration_seconds"`
	Tables   int     `json:"tables"`
	// Rows written (ClickHouse).
	Rows int64 `json:"rows"`
	// Skipped lists what was not restored, with the reason (roles that
	// exist, external tables with their DDL, ...).
	Skipped []string `json:"skipped,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// RestoreResult is what a restore did. A restorer returns it also with an
// error, filled as far as it got: Created always lists the databases it
// created (they are left in place after a failure).
type RestoreResult struct {
	Items   []RestoreItem `json:"items"`
	Notes   []string      `json:"notes"`
	Created []string      `json:"created"`
}

// Restorer is the restore direction of an engine (docs/design/ui-restore.md
// "Engines"). It never drops or replaces anything on the target.
type Restorer interface {
	Restore(ctx context.Context, rc RestoreContext) (*RestoreResult, error)
}

var (
	restorersMu sync.RWMutex
	restorers   = map[string]Restorer{}
)

// RegisterRestorer makes restores of engine possible (call from init()).
func RegisterRestorer(engine string, r Restorer) {
	restorersMu.Lock()
	defer restorersMu.Unlock()
	restorers[engine] = r
}

// RestorerFor returns the restorer registered for engine.
func RestorerFor(engine string) (Restorer, bool) {
	restorersMu.RLock()
	defer restorersMu.RUnlock()
	r, ok := restorers[engine]
	return r, ok
}
