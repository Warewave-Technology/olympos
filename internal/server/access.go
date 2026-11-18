package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/store"
)

type meGrant struct {
	Role  authz.Role `json:"role"`
	Scope string     `json:"scope"`
}

// Me is GET /api/v1/me. Permissions drive which controls the SPA renders
// (controls a role does not allow are hidden, SPEC §15).
type Me struct {
	Principal   authz.Principal `json:"principal"`
	IsGuest     bool            `json:"is_guest"`
	Roles       []authz.Role    `json:"roles"`
	Grants      []meGrant       `json:"grants"`
	Permissions map[string]any  `json:"permissions"`
	CSRFToken   string          `json:"csrf_token"`
	DevMode     bool            `json:"dev_mode"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	subj := httpx.Subject(r)
	me := Me{Principal: subj.Principal, IsGuest: subj.Principal.IsGuest(), Roles: subj.Roles(), Grants: []meGrant{}, DevMode: s.DevMode}
	for _, g := range subj.Grants {
		if !g.Stale {
			me.Grants = append(me.Grants, meGrant{Role: g.Role, Scope: g.Scope.String()})
		}
	}
	me.Permissions = map[string]any{
		"read":                   subj.CanAny(authz.PermRead),
		"operate":                subj.CanAny(authz.PermOperate),
		"operate_global":         subj.CanGlobal(authz.PermOperate),
		"vault_make":             subj.CanAny(authz.PermVaultMake),
		"vault_approve":          subj.CanAny(authz.PermVaultApprove),
		"admin":                  subj.CanAny(authz.PermAdmin),
		"admin_global":           subj.CanGlobal(authz.PermAdmin),
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.DB.QueryRow(r.Context(), `SELECT csrf_token FROM sessions WHERE id = $1`, hashSession(c.Value)).Scan(&me.CSRFToken)
	}
	httpx.JSON(w, http.StatusOK, me)
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	gs, err := authz.ListGrants(r.Context(), s.DB)
	if err != nil {
		httpx.Internal(w, r, s.Log, err)
		return
	}
	type row struct {
		authz.GrantRow
		IsGuest bool `json:"is_guest"`
	}
	out := make([]row, 0, len(gs))
	for _, g := range gs {
		out = append(out, row{GrantRow: g, IsGuest: g.Principal.IsGuest()})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

type createGrantReq struct {
	ObjectID string   `json:"object_id"`
	Roles    []string `json:"roles"`
	Scope    string   `json:"scope"`
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	subj := httpx.Subject(r)
	if !subj.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	var req createGrantReq
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := uuid.Parse(req.ObjectID); err != nil {
		httpx.FieldErrors(w, "invalid grant", map[string]string{"object_id": "Pick a person from the directory search."})
		return
	}
	if len(req.Roles) == 0 {
		httpx.FieldErrors(w, "invalid grant", map[string]string{"roles": "Select at least one role."})
		return
	}
	roles := make([]authz.Role, 0, len(req.Roles))
	for _, rs := range req.Roles {
		ro, err := authz.ParseRole(rs)
		if err != nil {
			httpx.FieldErrors(w, "invalid grant", map[string]string{"roles": err.Error()})
			return
		}
		roles = append(roles, ro)
	}
	scope, err := authz.ParseScope(req.Scope)
	if err != nil {
		httpx.FieldErrors(w, "invalid grant", map[string]string{"scope": err.Error()})
		return
	}
	// Always resolve the person from the directory: object ID is the key,
	// and userType decides the guest rule. Never trust client-sent names.
	du, err := s.Directory.Get(r.Context(), req.ObjectID)
	if errors.Is(err, ErrUserNotFound) {
		httpx.FieldErrors(w, "invalid grant", map[string]string{"object_id": "This person was not found in Entra ID."})
		return
	}
	if err != nil {
		httpx.Internal(w, r, s.Log, err)
		return
	}
	if !du.AccountEnabled {
		httpx.FieldErrors(w, "invalid grant", map[string]string{"object_id": "This account is disabled in Entra ID."})
		return
	}
	var ids []uuid.UUID
	err = store.Tx(r.Context(), s.DB, func(tx pgx.Tx) error {
		p, err := authz.UpsertPrincipal(r.Context(), tx, authz.Principal{TenantID: s.TenantID, ObjectID: du.ObjectID, UPN: du.UPN,
			DisplayName: du.DisplayName, UserType: du.UserType, AccountEnabled: du.AccountEnabled})
		if err != nil {
			return err
		}
		for _, ro := range roles {
			id, err := authz.CreateGrant(r.Context(), tx, p, ro, scope, httpx.ActorID(r))
			if err != nil {
				return err
			}
			ids = append(ids, id)
			if err := httpx.Record(r, tx, "grant.created", "grant", id.String(), nil, map[string]any{
				"principal_object_id": p.ObjectID, "principal": p.DisplayName, "role": ro, "scope": scope.String()}); err != nil {
				return err
			}
			if err := notify.Emit(r.Context(), tx, notify.Event{Type: notify.GrantChanged, Key: "grant.changed:created:" + id.String(),
				Title: fmt.Sprintf("Access granted: %s → %s (%s)", p.DisplayName, ro, scope.String()), Link: "/settings",
				Fields: map[string]string{"principal": p.DisplayName, "role": string(ro), "scope": scope.String(), "by": subj.Principal.DisplayName}}); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, authz.ErrGuestApprover) || (err != nil && strings.Contains(err.Error(), "guest")) {
		httpx.FieldErrors(w, "invalid grant", map[string]string{"roles": err.Error()})
		return
	}
	if err != nil {
		httpx.Internal(w, r, s.Log, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"ids": ids})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	subj := httpx.Subject(r)
	if !subj.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	err := store.Tx(r.Context(), s.DB, func(tx pgx.Tx) error {
		pid, role, err := authz.RevokeGrant(r.Context(), tx, id, httpx.ActorID(r))
		if err != nil {
			return err
		}
		// Never leave Olympos without an admin.
		var admins int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM grants g JOIN principals p ON p.id = g.principal_id
			WHERE g.role = 'admin' AND g.scope_selector = 'all' AND g.revoked_at IS NULL AND NOT g.stale AND p.account_enabled`).Scan(&admins); err != nil {
			return err
		}
		if admins == 0 {
			return errLastAdmin
		}
		p, err := authz.GetPrincipal(r.Context(), tx, pid)
		if err != nil {
			return err
		}
		if err := httpx.Record(r, tx, "grant.revoked", "grant", id.String(), nil, map[string]any{
			"principal_object_id": p.ObjectID, "principal": p.DisplayName, "role": role}); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE principal_id = $1 AND NOT EXISTS
			(SELECT 1 FROM grants WHERE principal_id = $1 AND revoked_at IS NULL)`, pid); err != nil {
			return err
		}
		return notify.Emit(r.Context(), tx, notify.Event{Type: notify.GrantChanged, Key: "grant.changed:revoked:" + id.String(),
			Title: fmt.Sprintf("Access revoked: %s (%s)", p.DisplayName, role), Link: "/settings",
			Fields: map[string]string{"principal": p.DisplayName, "role": string(role), "by": subj.Principal.DisplayName}})
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.Is(err, errLastAdmin):
		httpx.Error(w, http.StatusConflict, "this is the last admin grant with scope all; grant admin to someone else first")
	case err != nil:
		httpx.Internal(w, r, s.Log, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

var errLastAdmin = errors.New("last admin")

func (s *Server) handlePrincipalSearch(w http.ResponseWriter, r *http.Request) {
	if !httpx.Subject(r).CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		httpx.JSON(w, http.StatusOK, map[string]any{"items": []DirectoryUser{}})
		return
	}
	users, err := s.Directory.Search(r.Context(), q)
	if err != nil {
		s.Log.Warn("directory search", "err", err)
		httpx.Error(w, http.StatusBadGateway, "Entra ID directory search failed; check the Graph permission User.ReadBasic.All")
		return
	}
	type item struct {
		DirectoryUser
		IsGuest bool `json:"is_guest"`
	}
	out := make([]item, 0, len(users))
	for _, u := range users {
		out = append(out, item{DirectoryUser: u, IsGuest: strings.EqualFold(u.UserType, "Guest") || strings.Contains(strings.ToUpper(u.UPN), "#EXT#")})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	subj := httpx.Subject(r)
	q := r.URL.Query()
	f := activity.Filter{Action: q.Get("action"), ObjectType: q.Get("object_type"), Query: q.Get("q"), Limit: httpx.IntQuery(r, "limit", 100)}
	if v := q.Get("actor"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.ActorID = &id
		}
	}
	if v := q.Get("before"); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			f.Before = &t
		}
	}
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			t := time.Now().Add(-d)
			f.Since = &t
		}
	}
	if !subj.CanGlobal(authz.PermRead) {
		ids, err := httpx.ScopedClusters(r.Context(), s.DB, subj, authz.PermRead)
		if err != nil {
			httpx.Internal(w, r, s.Log, err)
			return
		}
		f.ClusterIDs = ids
	}
	es, err := activity.List(r.Context(), s.DB, f)
	if err != nil {
		httpx.Internal(w, r, s.Log, err)
		return
	}
	if es == nil {
		es = []activity.Entry{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": es})
}
