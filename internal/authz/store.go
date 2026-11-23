package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// UpsertPrincipal creates or refreshes the snapshot fields of a principal.
func UpsertPrincipal(ctx context.Context, q store.Querier, p Principal) (Principal, error) {
	err := q.QueryRow(ctx, `
		INSERT INTO principals (tenant_id, object_id, upn_snapshot, display_name_snapshot, user_type, account_enabled, synced_at)
		VALUES (lower($1), lower($2), $3, $4, COALESCE(NULLIF($5,''),'Member'), $6, now())
		ON CONFLICT (tenant_id, object_id) DO UPDATE SET
		  upn_snapshot = CASE WHEN EXCLUDED.upn_snapshot <> '' THEN EXCLUDED.upn_snapshot ELSE principals.upn_snapshot END,
		  display_name_snapshot = CASE WHEN EXCLUDED.display_name_snapshot <> '' THEN EXCLUDED.display_name_snapshot ELSE principals.display_name_snapshot END,
		  user_type = CASE WHEN $5 <> '' THEN EXCLUDED.user_type ELSE principals.user_type END,
		  account_enabled = EXCLUDED.account_enabled,
		  synced_at = now()
		RETURNING id, tenant_id, object_id, upn_snapshot, display_name_snapshot, user_type, account_enabled`,
		p.TenantID, p.ObjectID, p.UPN, p.DisplayName, p.UserType, p.AccountEnabled,
	).Scan(&p.ID, &p.TenantID, &p.ObjectID, &p.UPN, &p.DisplayName, &p.UserType, &p.AccountEnabled)
	return p, err
}

// GetPrincipal loads a principal by ID.
func GetPrincipal(ctx context.Context, q store.Querier, id uuid.UUID) (Principal, error) {
	var p Principal
	err := q.QueryRow(ctx, `SELECT id, tenant_id, object_id, upn_snapshot, display_name_snapshot, user_type, account_enabled
		FROM principals WHERE id = $1`, id).
		Scan(&p.ID, &p.TenantID, &p.ObjectID, &p.UPN, &p.DisplayName, &p.UserType, &p.AccountEnabled)
	return p, store.NotFound(err)
}

// LoadSubject loads a principal with its active (non-revoked) grants.
func LoadSubject(ctx context.Context, q store.Querier, principalID uuid.UUID) (*Subject, error) {
	p, err := GetPrincipal(ctx, q, principalID)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT id, role, scope_selector, stale FROM grants
		WHERE principal_id = $1 AND revoked_at IS NULL`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	s := &Subject{Principal: p}
	for rows.Next() {
		var g Grant
		var role, scope string
		if err := rows.Scan(&g.ID, &role, &scope, &g.Stale); err != nil {
			return nil, err
		}
		g.PrincipalID = principalID
		g.Role = Role(role)
		if g.Scope, err = ParseScope(scope); err != nil {
			continue // a malformed scope never authorizes
		}
		s.Grants = append(s.Grants, g)
	}
	return s, rows.Err()
}

// GrantRow is a grant joined with its principal, for listing.
type GrantRow struct {
	ID            uuid.UUID  `json:"id"`
	Principal     Principal  `json:"principal"`
	Role          Role       `json:"role"`
	Scope         string     `json:"scope"`
	GrantedBy     *uuid.UUID `json:"granted_by"`
	GrantedByName string     `json:"granted_by_name"`
	GrantedAt     time.Time  `json:"granted_at"`
	Stale         bool       `json:"stale"`
}

// ListGrants returns active grants.
func ListGrants(ctx context.Context, q store.Querier) ([]GrantRow, error) {
	rows, err := q.Query(ctx, `
		SELECT g.id, p.id, p.tenant_id, p.object_id, p.upn_snapshot, p.display_name_snapshot, p.user_type, p.account_enabled,
		       g.role, g.scope_selector, g.granted_by, COALESCE(gb.display_name_snapshot, ''), g.granted_at, g.stale
		FROM grants g JOIN principals p ON p.id = g.principal_id
		LEFT JOIN principals gb ON gb.id = g.granted_by
		WHERE g.revoked_at IS NULL ORDER BY p.display_name_snapshot, g.role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrantRow
	for rows.Next() {
		var r GrantRow
		var role string
		if err := rows.Scan(&r.ID, &r.Principal.ID, &r.Principal.TenantID, &r.Principal.ObjectID, &r.Principal.UPN,
			&r.Principal.DisplayName, &r.Principal.UserType, &r.Principal.AccountEnabled,
			&role, &r.Scope, &r.GrantedBy, &r.GrantedByName, &r.GrantedAt, &r.Stale); err != nil {
			return nil, err
		}
		r.Role = Role(role)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrGuestApprover is returned when vault-approver is granted to a guest.
var ErrGuestApprover = errors.New("vault-approver cannot be granted to guest accounts")

// ErrGuestSyntheticEditor is returned when synthetic-editor is granted to a
// guest (ruling P18): the role attaches admin-made credentials to requests
// and sees the headers of credentialed steps.
var ErrGuestSyntheticEditor = errors.New("synthetic-editor cannot be granted to guest accounts")

// CreateGrant inserts a grant after validating the role/guest rules.
func CreateGrant(ctx context.Context, q store.Querier, principal Principal, role Role, scope Scope, grantedBy *uuid.UUID) (uuid.UUID, error) {
	if (role == RoleVaultApprover || role == RoleAdmin || role == RoleSyntheticEditor) && principal.IsGuest() {
		switch role {
		case RoleVaultApprover:
			return uuid.Nil, ErrGuestApprover
		case RoleSyntheticEditor:
			return uuid.Nil, ErrGuestSyntheticEditor
		}
		// Admin implies approve; approval is refused for guests at check time,
		// but granting admin to a guest is refused too to keep it obvious.
		return uuid.Nil, errors.New("admin cannot be granted to guest accounts")
	}
	var id uuid.UUID
	err := q.QueryRow(ctx, `INSERT INTO grants (principal_id, role, scope_selector, granted_by)
		VALUES ($1, $2, $3, $4) RETURNING id`, principal.ID, string(role), scope.String(), grantedBy).Scan(&id)
	return id, err
}

// RevokeGrant marks a grant revoked. Returns the revoked row's principal and role.
func RevokeGrant(ctx context.Context, q store.Querier, id uuid.UUID, by *uuid.UUID) (uuid.UUID, Role, error) {
	var pid uuid.UUID
	var role string
	err := q.QueryRow(ctx, `UPDATE grants SET revoked_at = now(), revoked_by = $2
		WHERE id = $1 AND revoked_at IS NULL RETURNING principal_id, role`, id, by).Scan(&pid, &role)
	return pid, Role(role), store.NotFound(err)
}

// BootstrapAdmins grants admin (scope all) to the configured object IDs, but
// only when the grants table is completely empty (SPEC §3.2).
func BootstrapAdmins(ctx context.Context, db *store.DB, tenantID string, objectIDs []string) (int, error) {
	if len(objectIDs) == 0 {
		return 0, nil
	}
	n := 0
	err := store.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE grants IN EXCLUSIVE MODE`); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM grants`).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return nil
		}
		all, _ := ParseScope("all")
		for _, oid := range objectIDs {
			p, err := UpsertPrincipal(ctx, tx, Principal{TenantID: tenantID, ObjectID: oid, AccountEnabled: true})
			if err != nil {
				return fmt.Errorf("bootstrap principal %s: %w", oid, err)
			}
			if _, err := CreateGrant(ctx, tx, p, RoleAdmin, all, nil); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
