package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// DirectoryUser is a user as seen in Entra (Graph).
type DirectoryUser struct {
	ObjectID       string `json:"object_id"`
	DisplayName    string `json:"display_name"`
	UPN            string `json:"upn"`
	Mail           string `json:"mail"`
	UserType       string `json:"user_type"`
	AccountEnabled bool   `json:"account_enabled"`
}

// Directory looks users up in Entra.
type Directory interface {
	Search(ctx context.Context, q string) ([]DirectoryUser, error)
	// Get returns ErrUserNotFound for deleted users.
	Get(ctx context.Context, objectID string) (DirectoryUser, error)
}

// ErrUserNotFound means the user does not exist (deleted) in Entra.
var ErrUserNotFound = errors.New("user not found in directory")

// Graph is a Microsoft Graph client using app permissions (User.ReadBasic.All).
type Graph struct {
	BaseURL string // https://graph.microsoft.com
	Cred    azcore.TokenCredential
	HTTP    *http.Client
}

type graphUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	UserType          string `json:"userType"`
	AccountEnabled    *bool  `json:"accountEnabled"`
}

func (u graphUser) toDirectory() DirectoryUser {
	enabled := true
	if u.AccountEnabled != nil {
		enabled = *u.AccountEnabled
	}
	return DirectoryUser{ObjectID: u.ID, DisplayName: u.DisplayName, UPN: u.UserPrincipalName, Mail: u.Mail,
		UserType: u.UserType, AccountEnabled: enabled}
}

const graphSelect = "id,displayName,userPrincipalName,mail,userType,accountEnabled"

func (g *Graph) do(ctx context.Context, path string, out any) (int, error) {
	tok, err := g.Cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{strings.TrimRight(g.BaseURL, "/") + "/.default"}})
	if err != nil {
		return 0, fmt.Errorf("graph token: %w", err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.BaseURL, "/")+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("ConsistencyLevel", "eventual")
	c := g.HTTP
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("graph %s: %s", path, resp.Status)
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

// Search finds users by display name, UPN or mail prefix.
func (g *Graph) Search(ctx context.Context, q string) ([]DirectoryUser, error) {
	q = strings.ReplaceAll(strings.TrimSpace(q), `"`, "")
	if len(q) < 2 {
		return nil, nil
	}
	search := fmt.Sprintf(`"displayName:%s" OR "userPrincipalName:%s" OR "mail:%s"`, q, q, q)
	var out struct {
		Value []graphUser `json:"value"`
	}
	if _, err := g.do(ctx, "/v1.0/users?$top=15&$select="+graphSelect+"&$search="+url.QueryEscape(search), &out); err != nil {
		return nil, err
	}
	res := make([]DirectoryUser, 0, len(out.Value))
	for _, u := range out.Value {
		res = append(res, u.toDirectory())
	}
	return res, nil
}

// Get loads one user by object ID.
func (g *Graph) Get(ctx context.Context, oid string) (DirectoryUser, error) {
	if _, err := uuid.Parse(oid); err != nil {
		return DirectoryUser{}, ErrUserNotFound
	}
	var u graphUser
	code, err := g.do(ctx, "/v1.0/users/"+oid+"?$select="+graphSelect, &u)
	if code == http.StatusNotFound {
		return DirectoryUser{}, ErrUserNotFound
	}
	if err != nil {
		return DirectoryUser{}, err
	}
	return u.toDirectory(), nil
}

// LocalDirectory searches only principals already known to Olympos. Used in
// devMode where no Graph access exists.
type LocalDirectory struct{ DB *store.DB }

func (l LocalDirectory) Search(ctx context.Context, q string) ([]DirectoryUser, error) {
	rows, err := l.DB.Query(ctx, `SELECT object_id, display_name_snapshot, upn_snapshot, user_type, account_enabled FROM principals
		WHERE display_name_snapshot ILIKE '%' || $1 || '%' OR upn_snapshot ILIKE '%' || $1 || '%' OR object_id = $1 LIMIT 15`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryUser
	for rows.Next() {
		var u DirectoryUser
		if err := rows.Scan(&u.ObjectID, &u.DisplayName, &u.UPN, &u.UserType, &u.AccountEnabled); err != nil {
			return nil, err
		}
		u.Mail = u.UPN
		out = append(out, u)
	}
	return out, rows.Err()
}

func (l LocalDirectory) Get(ctx context.Context, oid string) (DirectoryUser, error) {
	var u DirectoryUser
	var deleted bool
	err := l.DB.QueryRow(ctx, `SELECT object_id, display_name_snapshot, upn_snapshot, user_type, account_enabled, deleted FROM principals WHERE object_id = $1`, oid).
		Scan(&u.ObjectID, &u.DisplayName, &u.UPN, &u.UserType, &u.AccountEnabled, &deleted)
	if errors.Is(err, pgx.ErrNoRows) || deleted {
		return u, ErrUserNotFound
	}
	return u, err
}

// SyncPrincipals refreshes snapshots daily and marks grants of disabled or
// deleted users stale (SPEC §3.2). Stale grants do not authorize.
func SyncPrincipals(ctx context.Context, db *store.DB, dir Directory, log *slog.Logger) error {
	rows, err := db.Query(ctx, `SELECT DISTINCT p.id, p.object_id FROM principals p JOIN grants g ON g.principal_id = p.id WHERE g.revoked_at IS NULL`)
	if err != nil {
		return err
	}
	type pr struct {
		id  uuid.UUID
		oid string
	}
	var list []pr
	for rows.Next() {
		var x pr
		if err := rows.Scan(&x.id, &x.oid); err != nil {
			rows.Close()
			return err
		}
		list = append(list, x)
	}
	rows.Close()
	for _, p := range list {
		u, err := dir.Get(ctx, p.oid)
		gone := errors.Is(err, ErrUserNotFound)
		if err != nil && !gone {
			log.Warn("principal sync", "object_id", p.oid, "err", err)
			continue
		}
		err = store.Tx(ctx, db, func(tx pgx.Tx) error {
			if gone {
				if _, err := tx.Exec(ctx, `UPDATE principals SET deleted = true, account_enabled = false, synced_at = now() WHERE id = $1`, p.id); err != nil {
					return err
				}
			} else if _, err := tx.Exec(ctx, `UPDATE principals SET upn_snapshot = $2, display_name_snapshot = $3, user_type = COALESCE(NULLIF($4,''), user_type),
				account_enabled = $5, deleted = false, synced_at = now() WHERE id = $1`, p.id, u.UPN, u.DisplayName, u.UserType, u.AccountEnabled); err != nil {
				return err
			}
			stale := gone || !u.AccountEnabled
			if !stale {
				_, err := tx.Exec(ctx, `UPDATE grants SET stale = false WHERE principal_id = $1 AND revoked_at IS NULL AND stale`, p.id)
				return err
			}
			r, err := tx.Query(ctx, `UPDATE grants SET stale = true WHERE principal_id = $1 AND revoked_at IS NULL AND NOT stale RETURNING id, role`, p.id)
			if err != nil {
				return err
			}
			type g struct{ id, role string }
			var marked []g
			for r.Next() {
				var x g
				if err := r.Scan(&x.id, &x.role); err != nil {
					r.Close()
					return err
				}
				marked = append(marked, x)
			}
			r.Close()
			name := u.DisplayName
			if name == "" {
				name = p.oid
			}
			reason := "account disabled"
			if gone {
				reason = "deleted in Entra"
			}
			for _, x := range marked {
				if err := notify.Emit(ctx, tx, notify.Event{Type: notify.GrantStale, Key: "grant.stale:" + x.id,
					Title: fmt.Sprintf("Grant marked stale: %s (%s) — %s", name, x.role, reason), Link: "/settings",
					Fields: map[string]string{"principal": name, "role": x.role, "reason": reason}}); err != nil {
					return err
				}
				if err := activity.Record(ctx, tx, activity.Entry{Action: "grant.stale", ObjectType: "grant", ObjectID: x.id,
					Details: map[string]any{"principal_object_id": p.oid, "role": x.role, "reason": reason}}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
