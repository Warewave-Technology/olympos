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
	// speak TLS end-to-end with the target. False in "compressed" mode.
	UseTLS bool
	// TLSServerName to verify; InsecureSkipVerify is never used. RootCAs is
	// left to the engine (system pool + optional configured bundle).
	TLSServerName string
	// Credential returns the login (database user, or AppRole for Vault).
	Credential func(ctx context.Context) (Credential, error)
	Options    json.RawMessage
	// Test is a dry run: produce a small artifact (e.g. schema only).
	Test bool
}

// RunResult is engine metadata stored in the manifest.
type RunResult struct {
	ServerVersion string         `json:"server_version"`
	ToolVersion   string         `json:"tool_version,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
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
