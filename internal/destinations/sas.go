// Package destinations implements backup destinations (SPEC §10.3): the
// REST API, SAS token inspection, the "Test destination" probe and the
// sas.expiring notifications.
package destinations

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Warewave-Technology/olympos/internal/blob"
)

// RequiredPermissions are what the server needs: read, create, write, tag.
const RequiredPermissions = "rcwt"

// SAS scopes.
const (
	ScopeContainer = "container" // service SAS with sr=c (what we ask for)
	ScopeAccount   = "account"   // account SAS (ss/srt)
	ScopeService   = "service"   // service SAS on a single blob/version/directory: unusable
	ScopeUnknown   = "unknown"
)

// SASInfo is what a SAS token grants, as far as its query string tells.
type SASInfo struct {
	Permissions string     `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Missing     []string   `json:"missing"`
	Extra       []string   `json:"extra"`
	Scope       string     `json:"scope"`
	// UserDelegation is true for a user delegation SAS (signed with an Entra
	// key, skoid present): it works with allowSharedKeyAccess=false.
	UserDelegation bool `json:"user_delegation"`
	// StoredPolicy is set when the SAS references a stored access policy
	// (si): permissions/expiry may live in the policy and are not visible.
	StoredPolicy string   `json:"stored_policy,omitempty"`
	Notes        []string `json:"notes"`
}

// CanDelete reports whether the SAS grants a delete-like permission
// (d = delete, x = delete version, y = permanent delete).
func (s SASInfo) CanDelete() bool { return strings.ContainsAny(s.Permissions, "dxy") }

// Expired reports whether the SAS is past its expiry at now.
func (s SASInfo) Expired(now time.Time) bool { return s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) }

var permNames = map[rune]string{
	'r': "read", 'a': "add", 'c': "create", 'w': "write", 'd': "delete", 'x': "delete version", 'y': "permanent delete",
	'l': "list", 't': "tag", 'f': "filter by tag", 'm': "move", 'e': "execute", 'o': "ownership", 'p': "permissions / process",
	'i': "set immutability policy", 'u': "update",
}

// PermissionName returns a human name for a SAS permission letter.
func PermissionName(p string) string {
	if len(p) == 1 {
		if n, ok := permNames[rune(p[0])]; ok {
			return n
		}
	}
	return p
}

// ParseSAS inspects a SAS token (bare, with '?', or a full SAS URL). It
// never returns or logs the signature.
func ParseSAS(token string) (SASInfo, error) {
	raw := blob.NormalizeSAS(token)
	if raw == "" {
		return SASInfo{}, errors.New("SAS token is empty")
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return SASInfo{}, errors.New("SAS token is not a valid query string")
	}
	if q.Get("sig") == "" {
		return SASInfo{}, errors.New("not a SAS token: no signature (sig)")
	}
	info := SASInfo{Permissions: q.Get("sp"), Missing: []string{}, Extra: []string{}, Notes: []string{}, StoredPolicy: q.Get("si")}
	if info.Permissions == "" && info.StoredPolicy == "" {
		return SASInfo{}, errors.New("SAS token has no permissions (sp)")
	}
	if se := q.Get("se"); se != "" {
		t, err := blob.ParseSASTime(se)
		if err != nil {
			return SASInfo{}, errors.New("SAS token has an invalid expiry (se)")
		}
		info.ExpiresAt = &t
	} else if info.StoredPolicy != "" {
		info.Notes = append(info.Notes, "expiry is defined by stored access policy "+info.StoredPolicy+" and cannot be checked; sas.expiring notifications are not sent")
	} else {
		return SASInfo{}, errors.New("SAS token has no expiry (se)")
	}

	info.UserDelegation = q.Get("skoid") != ""
	ss, srt, sr := q.Get("ss"), q.Get("srt"), q.Get("sr")
	switch {
	case ss != "" || srt != "":
		info.Scope = ScopeAccount
		info.Notes = append(info.Notes, "account SAS: requires shared key access on the storage account (allowSharedKeyAccess=true) and reaches every container; prefer a container-scoped SAS or Managed Identity")
		if ss != "" && !strings.Contains(ss, "b") {
			info.Notes = append(info.Notes, "account SAS does not include the blob service (ss lacks b)")
		}
		if srt != "" && !strings.Contains(srt, "o") {
			info.Notes = append(info.Notes, "account SAS does not include object-level access (srt lacks o)")
		}
	case sr == "c":
		info.Scope = ScopeContainer
		if !info.UserDelegation {
			info.Notes = append(info.Notes, "service SAS signed with the account key: requires shared key access on the storage account; a user delegation SAS or Managed Identity avoids that")
		}
	case sr == "b" || sr == "bv" || sr == "bs" || sr == "d":
		info.Scope = ScopeService
		info.Notes = append(info.Notes, "SAS is scoped to a single blob or directory (sr="+sr+"); use a container-scoped SAS (sr=c)")
	default:
		info.Scope = ScopeUnknown
	}

	for _, p := range RequiredPermissions {
		if !strings.ContainsRune(info.Permissions, p) {
			info.Missing = append(info.Missing, string(p))
		}
	}
	if info.StoredPolicy != "" && info.Permissions == "" {
		info.Missing = []string{} // defined by the policy; the probe tells
	}
	seen := map[rune]bool{}
	for _, p := range info.Permissions {
		if strings.ContainsRune(RequiredPermissions, p) || seen[p] {
			continue
		}
		seen[p] = true
		info.Extra = append(info.Extra, string(p))
	}
	return info, nil
}
