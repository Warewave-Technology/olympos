// Package vaults manages HashiCorp Vault and OpenBao instances discovered in
// clusters (SPEC §11): one-time configure with a root token (never stored),
// AppRole access, the secret index (keys only, never values), drift
// detection, and applying approved change requests.
//
// The Olympos policy cannot read secret values: key names come from the KV v2
// subkeys endpoint, and writes are JSON merge PATCHes.
package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

// Intervals (§11.2, §11.5, §11.1).
const (
	IndexInterval = 10 * time.Minute
	// RotateAfter: the secret_id is rotated monthly; secret_id_ttl is 720h,
	// so rotation starts well before expiry.
	RotateAfter   = 25 * 24 * time.Hour
	RotateCheck   = time.Hour
	requestTimout = 30 * time.Second

	// LockVaults is the advisory lock of the vaults maintenance leader.
	LockVaults int64 = 0x4f4c5931

	// AppRole / policy names created by configure.
	PolicyName = "olympos"
	RoleName   = "olympos"
)

// DialFunc opens a connection to a target. Production uses the agent tunnel
// (gateway.Dial); tests dial the container directly.
type DialFunc func(ctx context.Context, clusterID uuid.UUID, targetID string, opt gateway.DialOptions) (net.Conn, error)

// GatewayDial adapts gateway.Dial.
func GatewayDial(g *gateway.Gateway) DialFunc {
	return func(ctx context.Context, clusterID uuid.UUID, targetID string, opt gateway.DialOptions) (net.Conn, error) {
		return g.Dial(ctx, clusterID, targetID, opt)
	}
}

// Service holds the vault operations. It implements approvals.Applier.
type Service struct {
	DB  *store.DB
	Log *slog.Logger
	KV  secrets.KeyVault
	// KeyVaultName is the Key Vault that stores AppRole secret_ids.
	KeyVaultName string
	Dial         DialFunc
	Now          func() time.Time

	mu         sync.Mutex
	refreshing map[uuid.UUID]*sync.Mutex
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// KVMount is one secrets engine mount as stored in vaults.kv_mounts.
type KVMount struct {
	Path        string `json:"path"`
	Version     int    `json:"version"`
	Managed     bool   `json:"managed"`
	Description string `json:"description"`
}

// row is a vault joined with its target and cluster.
type row struct {
	ID               uuid.UUID
	TargetID         string
	ClusterID        uuid.UUID
	ClusterName      string
	Labels           map[string]string
	ClusterStatus    string
	TransferMode     string
	Namespace        string
	Service          string
	Port             int
	PortName         string
	Engine           string
	TLSServerName    string
	DetectedVersion  string
	TLSOK            *bool
	TargetStatus     string
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	Provider         string
	Version          string
	Status           string
	Mounts           []KVMount
	RoleID           string
	SecretIDRef      string
	SecretIDAccessor string
	RotatedAt        *time.Time
	ConfiguredByName string
	ConfiguredAt     *time.Time
	LastIndexAt      *time.Time
	LastError        string
	CABundle         string
	IndexedMounts    []string
}

const rowSelect = `SELECT v.id, v.target_id, t.cluster_id, c.name, c.labels, c.status, c.transfer_mode,
	t.namespace, t.service, t.port, t.port_name, t.engine, t.tls_server_name, t.detected_version, t.tls_ok, t.status,
	t.first_seen_at, t.last_seen_at,
	v.provider, v.version, v.status, v.kv_mounts, v.role_id, v.secret_id_ref, v.secret_id_accessor, v.secret_id_rotated_at,
	COALESCE(NULLIF(p.display_name_snapshot,''), p.upn_snapshot, ''), v.configured_at, v.last_index_at, v.last_error,
	v.ca_bundle, v.indexed_mounts
	FROM vaults v JOIN targets t ON t.id = v.target_id JOIN clusters c ON c.id = t.cluster_id
	LEFT JOIN principals p ON p.id = v.configured_by`

type scanner interface{ Scan(dest ...any) error }

func scanRow(sc scanner) (*row, error) {
	r := &row{}
	var mounts []byte
	err := sc.Scan(&r.ID, &r.TargetID, &r.ClusterID, &r.ClusterName, &r.Labels, &r.ClusterStatus, &r.TransferMode,
		&r.Namespace, &r.Service, &r.Port, &r.PortName, &r.Engine, &r.TLSServerName, &r.DetectedVersion, &r.TLSOK, &r.TargetStatus,
		&r.FirstSeenAt, &r.LastSeenAt,
		&r.Provider, &r.Version, &r.Status, &mounts, &r.RoleID, &r.SecretIDRef, &r.SecretIDAccessor, &r.RotatedAt,
		&r.ConfiguredByName, &r.ConfiguredAt, &r.LastIndexAt, &r.LastError, &r.CABundle, &r.IndexedMounts)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(mounts, &r.Mounts)
	return r, nil
}

func loadRow(ctx context.Context, q store.Querier, id uuid.UUID) (*row, error) {
	r, err := scanRow(q.QueryRow(ctx, rowSelect+` WHERE v.id = $1 AND c.status <> 'revoked'`, id))
	return r, store.NotFound(err)
}

func loadRowByTarget(ctx context.Context, q store.Querier, targetID string) (*row, error) {
	r, err := scanRow(q.QueryRow(ctx, rowSelect+` WHERE v.target_id = $1 AND c.status <> 'revoked'`, targetID))
	return r, store.NotFound(err)
}

func (r *row) serverName() string {
	if r.TLSServerName != "" {
		return r.TLSServerName
	}
	return vclient.DefaultServerName(r.Service, r.Namespace)
}

func (r *row) managedMounts() []string {
	var out []string
	for _, m := range r.Mounts {
		if m.Managed && m.Version == 2 {
			out = append(out, m.Path)
		}
	}
	return out
}

// client returns an unauthenticated client to the vault through the tunnel.
// caBundle overrides the stored bundle when non-nil.
func (s *Service) client(r *row, caBundle *string, timeout time.Duration) (*vclient.Client, error) {
	if s.Dial == nil {
		return nil, errors.New("no tunnel dialer configured")
	}
	bundle := r.CABundle
	if caBundle != nil {
		bundle = *caBundle
	}
	compressed := r.TransferMode == "compressed"
	return vclient.New(vclient.Options{
		Dial: func(ctx context.Context) (net.Conn, error) {
			return s.Dial(ctx, r.ClusterID, r.TargetID, gateway.DialOptions{Compressed: compressed})
		},
		TLS:        !compressed,
		ServerName: r.serverName(),
		CABundle:   []byte(bundle),
		Timeout:    timeout,
	})
}

// approle returns a client logged in with the Olympos AppRole. The caller
// must call done() (revokes the token, closes tunnels).
func (s *Service) approle(ctx context.Context, r *row, timeout time.Duration) (*vclient.Client, func(), error) {
	if r.Status != "configured" || r.RoleID == "" || r.SecretIDRef == "" {
		return nil, nil, errors.New("vault is not configured")
	}
	c, err := s.client(r, nil, timeout)
	if err != nil {
		return nil, nil, err
	}
	sid, err := secrets.Resolve(ctx, s.KV, r.SecretIDRef)
	if err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("read AppRole secret_id from Key Vault: %w", err)
	}
	err = vclient.AppRoleLogin(ctx, c, r.RoleID, sid)
	secrets.Zero(sid)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, func() { vclient.RevokeSelf(c); c.Close() }, nil
}

// SecretIDName is the Key Vault secret holding a vault's AppRole secret_id.
func SecretIDName(vaultID uuid.UUID) string {
	return "olympos-vault-" + vaultID.String() + "-secret-id"
}

// CABundleFor returns the configured CA bundle of the vault at targetID.
func (s *Service) CABundleFor(ctx context.Context, targetID string) ([]byte, error) {
	r, err := loadRowByTarget(ctx, s.DB, targetID)
	if err != nil {
		return nil, err
	}
	return []byte(r.CABundle), nil
}

func (s *Service) setError(ctx context.Context, id uuid.UUID, msg string) {
	if _, err := s.DB.Exec(ctx, `UPDATE vaults SET last_error = $2 WHERE id = $1`, id, msg); err != nil {
		s.Log.Error("update vault error", "vault_id", id, "err", err)
	}
}
