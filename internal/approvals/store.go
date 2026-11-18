package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// VaultInfo is what change requests need to know about a vault.
type VaultInfo struct {
	ID          uuid.UUID
	ClusterID   uuid.UUID
	ClusterName string
	Labels      map[string]string
	Name        string // <namespace>/<service>
	Provider    string
	Status      string
	Mounts      map[string]bool // managed KV v2 mounts
}

type kvMount struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
	Managed bool   `json:"managed"`
}

// LoadVault returns the vault with its cluster labels.
func LoadVault(ctx context.Context, q store.Querier, id uuid.UUID) (VaultInfo, error) {
	var v VaultInfo
	var ns, svc string
	var mounts []byte
	err := q.QueryRow(ctx, `SELECT v.id, t.cluster_id, c.name, c.labels, t.namespace, t.service, v.provider, v.status, v.kv_mounts
		FROM vaults v JOIN targets t ON t.id = v.target_id JOIN clusters c ON c.id = t.cluster_id
		WHERE v.id = $1 AND c.status <> 'revoked'`, id).
		Scan(&v.ID, &v.ClusterID, &v.ClusterName, &v.Labels, &ns, &svc, &v.Provider, &v.Status, &mounts)
	if err != nil {
		return v, store.NotFound(err)
	}
	v.Name = ns + "/" + svc
	var ms []kvMount
	_ = json.Unmarshal(mounts, &ms)
	v.Mounts = map[string]bool{}
	for _, m := range ms {
		if m.Managed && m.Version == 2 {
			v.Mounts[NormalizeMount(m.Path)] = true
		}
	}
	return v, nil
}

// VaultLockKey is the transaction-level advisory lock taken while a change
// request writes to a vault and while drift is evaluated, so a version
// produced by Olympos is never mistaken for an unmanaged write.
const VaultLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended('olympos-vault:' || $1::text, 0))`

// Session-level form of VaultLockSQL (same key).
const (
	vaultSessionLockSQL = `SELECT pg_advisory_lock(hashtextextended('olympos-vault:' || $1::text, 0))`
	vaultUnlockSQL      = `SELECT pg_advisory_unlock(hashtextextended('olympos-vault:' || $1::text, 0))`
)

// lockVaultSession holds the vault lock on a dedicated connection across the
// two apply transactions and the Vault call (session-level and transaction-
// level advisory locks on the same key exclude each other). A lost server
// drops the connection and with it the lock.
func lockVaultSession(ctx context.Context, db *store.DB, vaultID uuid.UUID) (func(), error) {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, vaultSessionLockSQL, vaultID); err != nil {
		conn.Release()
		return nil, err
	}
	return func() {
		uctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := conn.Exec(uctx, vaultUnlockSQL, vaultID); err != nil {
			// Do not return a connection that may still hold the lock.
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}, nil
}

// LockVault takes VaultLockSQL in tx.
func LockVault(ctx context.Context, tx pgx.Tx, vaultID uuid.UUID) error {
	_, err := tx.Exec(ctx, VaultLockSQL, vaultID)
	return err
}

// ---------------------------------------------------------------- views

// VaultRef is the vault summary embedded in a change request.
type VaultRef struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"` // namespace/service
	Namespace   string    `json:"namespace"`
	ClusterName string    `json:"cluster_name"`
	Provider    string    `json:"provider"`
}

// ItemView is a change item as shown to anyone. It never carries a value:
// only the HMAC fingerprint.
type ItemView struct {
	ID          uuid.UUID `json:"id"`
	Mount       string    `json:"mount"`
	Path        string    `json:"path"`
	Key         *string   `json:"key"`
	Op          Op        `json:"op"`
	BaseVersion int       `json:"base_version"`
	Versions    []int     `json:"versions"`
	Fingerprint string    `json:"fingerprint"`
}

// EventView is one entry of the trail.
type EventView struct {
	At        time.Time      `json:"at"`
	Kind      string         `json:"kind"`
	ActorName string         `json:"actor_name"`
	Details   map[string]any `json:"details"`
}

// ChangeRequest is the API shape.
type ChangeRequest struct {
	ID                    uuid.UUID        `json:"id"`
	Vault                 VaultRef         `json:"vault"`
	Maker                 authz.Principal  `json:"maker"`
	Checker               *authz.Principal `json:"checker"`
	Justification         string           `json:"justification"`
	Status                Status           `json:"status"`
	CreatedAt             time.Time        `json:"created_at"`
	ExpiresAt             time.Time        `json:"expires_at"`
	DecidedAt             *time.Time       `json:"decided_at"`
	DecisionComment       string           `json:"decision_comment"`
	AppliedAt             *time.Time       `json:"applied_at"`
	Failure               string           `json:"failure"`
	FailureCode           string           `json:"failure_code"`
	CanApprove            bool             `json:"can_approve"`
	ApproveDisabledReason string           `json:"approve_disabled_reason"`
	CanCancel             bool             `json:"can_cancel"`
	Items                 []ItemView       `json:"items"`
	Events                []EventView      `json:"events,omitempty"`

	makerID   uuid.UUID
	checkerID *uuid.UUID
	labels    map[string]string
}

// Filter narrows ListRequests.
type Filter struct {
	VaultID      *uuid.UUID
	Status       string
	MakerID      *uuid.UUID
	WaitingForMe bool
	Limit        int
}

const crSelect = `SELECT cr.id, cr.vault_id, t.namespace || '/' || t.service, c.name, c.labels, v.provider,
	cr.maker_principal_id, cr.checker_principal_id, cr.justification, cr.status, cr.created_at, cr.expires_at,
	cr.decided_at, cr.decision_comment, cr.applied_at, cr.failure, cr.failure_code
	FROM change_requests cr JOIN vaults v ON v.id = cr.vault_id JOIN targets t ON t.id = v.target_id
	JOIN clusters c ON c.id = t.cluster_id`

func scanCR(row pgx.Row) (*ChangeRequest, error) {
	cr := &ChangeRequest{}
	var st string
	err := row.Scan(&cr.ID, &cr.Vault.ID, &cr.Vault.Name, &cr.Vault.ClusterName, &cr.labels, &cr.Vault.Provider,
		&cr.makerID, &cr.checkerID, &cr.Justification, &st, &cr.CreatedAt, &cr.ExpiresAt,
		&cr.DecidedAt, &cr.DecisionComment, &cr.AppliedAt, &cr.Failure, &cr.FailureCode)
	cr.Status = Status(st)
	cr.Vault.Namespace, _, _ = strings.Cut(cr.Vault.Name, "/")
	return cr, err
}

// ListRequests returns change requests visible to sub (read scope on the
// vault's cluster), newest first.
func ListRequests(ctx context.Context, q store.Querier, sub *authz.Subject, f Filter, now time.Time) ([]*ChangeRequest, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}
	rows, err := q.Query(ctx, crSelect+`
		WHERE c.status <> 'revoked' AND ($1::uuid IS NULL OR cr.vault_id = $1) AND ($2 = '' OR cr.status = $2)
		  AND ($3::uuid IS NULL OR cr.maker_principal_id = $3)
		ORDER BY cr.created_at DESC LIMIT $4`, f.VaultID, f.Status, f.MakerID, f.Limit*4)
	if err != nil {
		return nil, err
	}
	var all []*ChangeRequest
	for rows.Next() {
		cr, err := scanCR(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if sub.Can(authz.PermRead, cr.labels) {
			all = append(all, cr)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []*ChangeRequest{}
	for _, cr := range all {
		if err := fill(ctx, q, cr, sub, now, false); err != nil {
			return nil, err
		}
		if f.WaitingForMe && !cr.CanApprove {
			continue
		}
		out = append(out, cr)
		if len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

// GetRequest loads one change request with items and trail. Returns
// store.ErrNotFound when it does not exist or is outside sub's scope.
func GetRequest(ctx context.Context, q store.Querier, sub *authz.Subject, id uuid.UUID, now time.Time) (*ChangeRequest, error) {
	cr, err := scanCR(q.QueryRow(ctx, crSelect+` WHERE cr.id = $1 AND c.status <> 'revoked'`, id))
	if err != nil {
		return nil, store.NotFound(err)
	}
	if !sub.Can(authz.PermRead, cr.labels) {
		return nil, store.ErrNotFound
	}
	if err := fill(ctx, q, cr, sub, now, true); err != nil {
		return nil, err
	}
	return cr, nil
}

func fill(ctx context.Context, q store.Querier, cr *ChangeRequest, sub *authz.Subject, now time.Time, events bool) error {
	var err error
	if cr.Maker, err = authz.GetPrincipal(ctx, q, cr.makerID); err != nil {
		return err
	}
	if cr.checkerID != nil {
		p, err := authz.GetPrincipal(ctx, q, *cr.checkerID)
		if err != nil {
			return err
		}
		cr.Checker = &p
	}
	if err := CheckDecide(sub, cr.Maker, cr.labels, cr.Status, cr.ExpiresAt, now); err != nil {
		cr.ApproveDisabledReason = err.Error()
	} else {
		cr.CanApprove = true
	}
	cr.CanCancel = CheckCancel(sub, cr.Maker, cr.Status) == nil
	// Values are never selected here: only the fingerprint.
	rows, err := q.Query(ctx, `SELECT id, mount, path, key, op, base_version, versions, hmac_fingerprint
		FROM change_items WHERE cr_id = $1 ORDER BY created_at, id`, cr.ID)
	if err != nil {
		return err
	}
	cr.Items = []ItemView{}
	for rows.Next() {
		var it ItemView
		var op string
		if err := rows.Scan(&it.ID, &it.Mount, &it.Path, &it.Key, &op, &it.BaseVersion, &it.Versions, &it.Fingerprint); err != nil {
			rows.Close()
			return err
		}
		it.Op = Op(op)
		if it.Versions == nil {
			it.Versions = []int{}
		}
		cr.Items = append(cr.Items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !events {
		return nil
	}
	rows, err = q.Query(ctx, `SELECT e.at, e.kind, COALESCE(NULLIF(p.display_name_snapshot,''), p.upn_snapshot, ''), e.details
		FROM change_events e LEFT JOIN principals p ON p.id = e.actor_principal_id WHERE e.cr_id = $1 ORDER BY e.at, e.id`, cr.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	cr.Events = []EventView{}
	for rows.Next() {
		var ev EventView
		var d []byte
		if err := rows.Scan(&ev.At, &ev.Kind, &ev.ActorName, &d); err != nil {
			return err
		}
		_ = json.Unmarshal(d, &ev.Details)
		if ev.ActorName == "" {
			ev.ActorName = "Olympos"
		}
		cr.Events = append(cr.Events, ev)
	}
	return rows.Err()
}

// lockedCR is the state read under FOR UPDATE.
type lockedCR struct {
	ID        uuid.UUID
	VaultID   uuid.UUID
	MakerID   uuid.UUID
	Status    Status
	ExpiresAt time.Time
}

var errNotFound = errors.New("not found")

func lockCR(ctx context.Context, tx pgx.Tx, id uuid.UUID) (lockedCR, error) {
	var c lockedCR
	var st string
	err := tx.QueryRow(ctx, `SELECT id, vault_id, maker_principal_id, status, expires_at FROM change_requests WHERE id = $1 FOR UPDATE`, id).
		Scan(&c.ID, &c.VaultID, &c.MakerID, &st, &c.ExpiresAt)
	c.Status = Status(st)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, errNotFound
	}
	return c, err
}

// scrub drops sealed values of a request (terminal states). The migration
// trigger does the same; this is explicit so the code does not rely on it.
func scrub(ctx context.Context, q store.Querier, crID uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE change_items SET sealed_value = NULL, wrapped_dek = NULL WHERE cr_id = $1`, crID)
	return err
}

func addEvent(ctx context.Context, q store.Querier, crID uuid.UUID, actor *uuid.UUID, kind string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	d, err := json.Marshal(details)
	if err != nil {
		return err
	}
	// clock_timestamp(): several events of one transaction keep their order.
	_, err = q.Exec(ctx, `INSERT INTO change_events (cr_id, at, actor_principal_id, kind, details) VALUES ($1, clock_timestamp(), $2, $3, $4)`, crID, actor, kind, d)
	return err
}
