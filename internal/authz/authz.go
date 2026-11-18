// Package authz implements principals, grants and scope checks (SPEC §3.2).
// Grants are stored in Olympos by Entra object ID; group claims are ignored.
package authz

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/labels"
)

// Role is one of the five Olympos roles.
type Role string

const (
	RoleViewer        Role = "viewer"
	RoleOperator      Role = "operator"
	RoleVaultMaker    Role = "vault-maker"
	RoleVaultApprover Role = "vault-approver"
	RoleAdmin         Role = "admin"
)

// Roles lists every valid role.
var Roles = []Role{RoleViewer, RoleOperator, RoleVaultMaker, RoleVaultApprover, RoleAdmin}

// ParseRole validates a role string.
func ParseRole(s string) (Role, error) {
	for _, r := range Roles {
		if string(r) == s {
			return r, nil
		}
	}
	return "", fmt.Errorf("unknown role %q", s)
}

// Permission is a capability derived from roles.
type Permission int

const (
	// PermRead: read everything except secret values.
	PermRead Permission = iota
	// PermOperate: run/configure backups, audits, scans, notification routing.
	PermOperate
	// PermVaultMake: open change requests.
	PermVaultMake
	// PermVaultApprove: approve/reject change requests opened by someone else.
	PermVaultApprove
	// PermAdmin: grants, clusters, destinations, vault configure.
	PermAdmin
)

var rolePerms = map[Role][]Permission{
	RoleViewer:        {PermRead},
	RoleOperator:      {PermRead, PermOperate},
	RoleVaultMaker:    {PermRead, PermVaultMake},
	RoleVaultApprover: {PermRead, PermVaultApprove},
	RoleAdmin:         {PermRead, PermOperate, PermVaultMake, PermVaultApprove, PermAdmin},
}

// Principal is an Entra user identified by (tenant_id, object_id).
type Principal struct {
	ID             uuid.UUID `json:"id"`
	TenantID       string    `json:"tenant_id"`
	ObjectID       string    `json:"object_id"`
	UPN            string    `json:"upn"`
	DisplayName    string    `json:"display_name"`
	UserType       string    `json:"user_type"`
	AccountEnabled bool      `json:"account_enabled"`
}

// IsGuest reports whether the principal is an Entra B2B guest.
func (p Principal) IsGuest() bool {
	return strings.EqualFold(p.UserType, "Guest") || strings.Contains(strings.ToUpper(p.UPN), "#EXT#")
}

// SameAs compares principals by tenant + object ID (maker/checker rule).
func (p Principal) SameAs(o Principal) bool {
	return strings.EqualFold(p.TenantID, o.TenantID) && strings.EqualFold(p.ObjectID, o.ObjectID)
}

// Scope is a parsed scope selector: "all" or a Kubernetes label selector over
// cluster labels set in Olympos.
type Scope struct {
	raw string
	all bool
	sel labels.Selector
}

// ParseScope parses "all" or a label selector such as "env=prod,team in (a,b)".
func ParseScope(s string) (Scope, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return Scope{raw: "all", all: true}, nil
	}
	sel, err := labels.Parse(s)
	if err != nil {
		return Scope{}, fmt.Errorf("invalid scope selector: %w", err)
	}
	if sel.Empty() {
		return Scope{}, fmt.Errorf("empty scope selector; use \"all\"")
	}
	return Scope{raw: sel.String(), sel: sel}, nil
}

func (s Scope) String() string { return s.raw }

// All reports whether the scope covers every cluster.
func (s Scope) All() bool { return s.all }

// Matches reports whether a cluster with the given labels is in scope.
func (s Scope) Matches(clusterLabels map[string]string) bool {
	if s.all {
		return true
	}
	return s.sel.Matches(labels.Set(clusterLabels))
}

// Grant is an active role assignment.
type Grant struct {
	ID          uuid.UUID `json:"id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	Role        Role      `json:"role"`
	Scope       Scope     `json:"-"`
	Stale       bool      `json:"stale"`
}

// Subject is an authenticated principal with its active grants.
type Subject struct {
	Principal Principal
	Grants    []Grant
}

func (s *Subject) usable(g Grant) bool {
	if g.Stale || !s.Principal.AccountEnabled {
		return false
	}
	return true
}

func hasPerm(r Role, p Permission) bool {
	for _, x := range rolePerms[r] {
		if x == p {
			return true
		}
	}
	return false
}

// permAllowed applies principal-level restrictions on top of roles.
func (s *Subject) permAllowed(p Permission) bool {
	// vault-approver MUST NOT apply to guests, even via admin.
	if p == PermVaultApprove && s.Principal.IsGuest() {
		return false
	}
	return true
}

// Can reports whether the subject has p on a cluster with the given labels.
func (s *Subject) Can(p Permission, clusterLabels map[string]string) bool {
	if s == nil || !s.permAllowed(p) {
		return false
	}
	for _, g := range s.Grants {
		if s.usable(g) && hasPerm(g.Role, p) && g.Scope.Matches(clusterLabels) {
			return true
		}
	}
	return false
}

// CanGlobal reports whether the subject has p with scope "all". Used for
// objects that are not tied to a cluster (destinations, grants, channels).
func (s *Subject) CanGlobal(p Permission) bool {
	if s == nil || !s.permAllowed(p) {
		return false
	}
	for _, g := range s.Grants {
		if s.usable(g) && hasPerm(g.Role, p) && g.Scope.All() {
			return true
		}
	}
	return false
}

// CanAny reports whether the subject has p on at least one scope. Used to
// decide whether to show a page or control at all.
func (s *Subject) CanAny(p Permission) bool {
	if s == nil || !s.permAllowed(p) {
		return false
	}
	for _, g := range s.Grants {
		if s.usable(g) && hasPerm(g.Role, p) {
			return true
		}
	}
	return false
}

// Roles returns distinct usable roles (for /me).
func (s *Subject) Roles() []Role {
	seen := map[Role]bool{}
	var out []Role
	for _, g := range s.Grants {
		if s.usable(g) && !seen[g.Role] {
			seen[g.Role] = true
			out = append(out, g.Role)
		}
	}
	return out
}
