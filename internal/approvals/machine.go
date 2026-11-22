// Package approvals implements change requests on vault secrets with the
// maker/checker rule (SPEC §11.3, §11.4).
//
// This file is the pure part: the state machine, the authorization rules
// and the write plan. It has no I/O and is unit-tested exhaustively.
//
//	pending ──approve──▶ approved ──start──▶ applying ──apply ok──▶ applied
//	   │                                          └──apply err──▶ failed
//
//	'approved' and 'applying' are entered in one transaction (committed
//	before Vault is called); a request left in 'applying' is settled by the
//	reconciler from the KV metadata (applied or failed).
//	   ├──reject──▶ rejected
//	   ├──cancel──▶ cancelled (maker only)
//	   └──ttl─────▶ expired
package approvals

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Warewave-Technology/olympos/internal/authz"
)

// Status of a change request.
type Status string

const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusApplying  Status = "applying"
	StatusApplied   Status = "applied"
	StatusRejected  Status = "rejected"
	StatusExpired   Status = "expired"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Terminal reports whether no further transition is possible. Sealed values
// MUST be NULL in every terminal state.
func (s Status) Terminal() bool {
	switch s {
	case StatusApplied, StatusRejected, StatusExpired, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Event drives a transition.
type Event string

const (
	EvApprove    Event = "approve"
	EvReject     Event = "reject"
	EvCancel     Event = "cancel"
	EvExpire     Event = "expire"
	EvApplyStart Event = "apply_start"
	EvApplyOK    Event = "apply_ok"
	EvApplyErr   Event = "apply_err"
)

var transitions = map[Status]map[Event]Status{
	StatusPending:  {EvApprove: StatusApproved, EvReject: StatusRejected, EvCancel: StatusCancelled, EvExpire: StatusExpired},
	StatusApproved: {EvApplyStart: StatusApplying},
	StatusApplying: {EvApplyOK: StatusApplied, EvApplyErr: StatusFailed},
}

// Failure codes (change_requests.failure_code).
const (
	FailApplyError   = "apply_error"   // Vault refused or was unreachable
	FailApplyUnknown = "apply_unknown" // reconciled: Vault has no trace of the write; open a new request
	FailConflict     = "conflict"      // reconciled: the secret changed in a way Olympos did not write
	FailUnverified   = "unverified"    // the outcome could not be read for applyGiveUp; values discarded
)

// ErrInvalidTransition is returned for a transition the machine does not allow
// (e.g. a second decision on an already decided request).
var ErrInvalidTransition = errors.New("invalid change request transition")

// Next returns the state after e, or ErrInvalidTransition.
func Next(s Status, e Event) (Status, error) {
	if to, ok := transitions[s][e]; ok {
		return to, nil
	}
	return s, fmt.Errorf("%w: %s on %s", ErrInvalidTransition, e, s)
}

// EventKind is the change_events.kind recorded for the state entered.
func EventKind(to Status) string {
	switch to {
	case StatusPending:
		return "opened"
	default:
		return string(to)
	}
}

// ---------------------------------------------------------------- rules

// Reasons shown to the user (approve_disabled_reason).
const (
	ReasonOwnRequest = "You opened this request"
	ReasonGuest      = "Guest accounts cannot approve change requests"
	ReasonNoRole     = "Your role does not allow approving change requests on this vault"
	ReasonExpired    = "This request has expired"
	ReasonNotMaker   = "Only the maker can cancel a request"
	ReasonNoMakeRole = "Your role does not allow opening change requests on this vault"
)

// DenyError is a rule violation (HTTP 403 for role rules, 409 for state).
type DenyError struct {
	Reason string
	// Conflict is true when the request is in the wrong state (HTTP 409)
	// rather than the caller lacking the right (HTTP 403).
	Conflict bool
}

func (e *DenyError) Error() string { return e.Reason }

func deny(reason string) error     { return &DenyError{Reason: reason} }
func conflict(reason string) error { return &DenyError{Reason: reason, Conflict: true} }

func statusReason(s Status) string { return "This request is " + string(s) }

// CheckOpen: the maker needs vault-maker in scope of the vault's cluster.
func CheckOpen(sub *authz.Subject, clusterLabels map[string]string) error {
	if !sub.Can(authz.PermVaultMake, clusterLabels) {
		return deny(ReasonNoMakeRole)
	}
	return nil
}

// vaultMsgs keep the texts change requests have always shown.
func vaultMsgs(st Status) ruleMsgs {
	return ruleMsgs{
		notPending: func() string { return statusReason(st) },
		expired:    ReasonExpired,
		own:        ReasonOwnRequest,
		guest:      ReasonGuest,
		noRole:     ReasonNoRole,
		notMaker:   ReasonNotMaker,
	}
}

// CheckDecide applies the maker/checker rule (DecideRule) to approve and
// reject a change request; the checker needs vault-approver in scope of the
// vault's cluster.
func CheckDecide(sub *authz.Subject, maker authz.Principal, clusterLabels map[string]string, st Status, expiresAt, now time.Time) error {
	allowed := sub != nil && sub.Can(authz.PermVaultApprove, clusterLabels)
	return decideRule(sub, maker, st == StatusPending, expiresAt, now, allowed, vaultMsgs(st))
}

// CheckCancel: only the maker withdraws a pending request (CancelRule).
func CheckCancel(sub *authz.Subject, maker authz.Principal, st Status) error {
	return cancelRule(sub, maker, st == StatusPending, vaultMsgs(st))
}

// ---------------------------------------------------------------- input

// Op is a change item operation (§11.3).
type Op string

const (
	OpCreate         Op = "create"
	OpReplace        Op = "replace"
	OpDelete         Op = "delete"
	OpDestroyHistory Op = "destroy_history"
)

// Limits.
const (
	MinJustification = 10
	MaxJustification = 2000
	MaxItems         = 50
	MaxValueBytes    = 64 << 10
	MaxVersions      = 100
)

// Item is one validated change item. Value is plaintext and only present
// between decode and sealing (create/replace) or between unsealing and the
// Vault write; callers zero it.
type Item struct {
	Mount       string
	Path        string
	Key         string
	Op          Op
	BaseVersion int
	Versions    []int
	Value       []byte
}

// NormalizeMount returns the mount with exactly one trailing slash.
func NormalizeMount(m string) string {
	m = strings.Trim(strings.TrimSpace(m), "/")
	if m == "" {
		return ""
	}
	return m + "/"
}

// ValidMountName reports whether m (normalized) is safe to embed in a Vault
// path and in the HCL policy.
func ValidMountName(m string) bool {
	if m == "" || !strings.HasSuffix(m, "/") || len(m) > 256 {
		return false
	}
	for _, seg := range strings.Split(strings.TrimSuffix(m, "/"), "/") {
		if !validSegment(seg) {
			return false
		}
	}
	return true
}

func validSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	for _, c := range seg {
		if !(c == '-' || c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// NormalizePath validates a secret path below its mount ("app/db").
func NormalizePath(p string) (string, bool) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" || len(p) > 512 || path.Clean(p) != p {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if !validSegment(seg) {
			return "", false
		}
	}
	return p, true
}

// ValidKey reports whether k is an acceptable KV key name.
func ValidKey(k string) bool {
	if k == "" || len(k) > 256 || strings.TrimSpace(k) != k {
		return false
	}
	for _, c := range k {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// ValidateJustification returns a field error or "".
func ValidateJustification(j string) string {
	n := len([]rune(strings.TrimSpace(j)))
	if n < MinJustification {
		return fmt.Sprintf("at least %d characters", MinJustification)
	}
	if n > MaxJustification {
		return fmt.Sprintf("at most %d characters", MaxJustification)
	}
	return ""
}

// ValidateItems checks every item and normalizes mount/path in place.
// managedMounts are the vault's managed KV v2 mounts. Field errors are keyed
// "items[i].field".
func ValidateItems(items []Item, managedMounts map[string]bool) map[string]string {
	fields := map[string]string{}
	if len(items) == 0 {
		fields["items"] = "at least one item is required"
		return fields
	}
	if len(items) > MaxItems {
		fields["items"] = fmt.Sprintf("at most %d items", MaxItems)
		return fields
	}
	type pk struct{ mount, path, key string }
	seenKey := map[pk]bool{}
	baseByPath := map[[2]string]int{}
	destroyByPath := map[[2]string]bool{}
	for i := range items {
		it := &items[i]
		f := func(name, msg string) { fields[fmt.Sprintf("items[%d].%s", i, name)] = msg }
		it.Mount = NormalizeMount(it.Mount)
		if !ValidMountName(it.Mount) || !managedMounts[it.Mount] {
			f("mount", "not a managed KV v2 mount of this vault")
			continue
		}
		p, ok := NormalizePath(it.Path)
		if !ok {
			f("path", "invalid secret path")
			continue
		}
		it.Path = p
		if it.BaseVersion < 0 {
			f("base_version", "must be >= 0")
			continue
		}
		pp := [2]string{it.Mount, it.Path}
		switch it.Op {
		case OpCreate, OpReplace, OpDelete:
			if !ValidKey(it.Key) {
				f("key", "a key name is required")
				continue
			}
			if it.Op == OpDelete {
				if len(it.Value) > 0 {
					f("value", "a value is not allowed for delete")
					continue
				}
			} else {
				if len(it.Value) == 0 {
					f("value", "a value is required")
					continue
				}
				if len(it.Value) > MaxValueBytes {
					f("value", "value too large")
					continue
				}
			}
			if len(it.Versions) > 0 {
				f("versions", "versions are only allowed for destroy_history")
				continue
			}
			if it.Op != OpCreate && it.BaseVersion == 0 {
				f("base_version", "the version you saw is required")
				continue
			}
			k := pk{it.Mount, it.Path, it.Key}
			if seenKey[k] {
				f("key", "this key appears twice in the request")
				continue
			}
			seenKey[k] = true
			if b, ok := baseByPath[pp]; ok && b != it.BaseVersion {
				f("base_version", "all items on one path must use the same base version")
				continue
			}
			baseByPath[pp] = it.BaseVersion
		case OpDestroyHistory:
			if it.Key != "" {
				f("key", "destroy_history destroys whole versions; no key")
				continue
			}
			if len(it.Value) > 0 {
				f("value", "a value is not allowed for destroy_history")
				continue
			}
			if len(it.Versions) == 0 || len(it.Versions) > MaxVersions {
				f("versions", "list the versions to destroy")
				continue
			}
			bad := false
			seen := map[int]bool{}
			for _, v := range it.Versions {
				if v < 1 || seen[v] {
					bad = true
				}
				seen[v] = true
			}
			if bad {
				f("versions", "versions must be distinct positive numbers")
				continue
			}
			if destroyByPath[pp] {
				f("op", "one destroy_history item per path")
				continue
			}
			destroyByPath[pp] = true
			sort.Ints(it.Versions)
		default:
			f("op", "must be create, replace, delete or destroy_history")
		}
	}
	return fields
}

// ---------------------------------------------------------------- plan

// WriteKind is how a write reaches Vault.
type WriteKind string

const (
	// WriteCreate: POST <mount>/data/<path> with options.cas = 0 (new path).
	WriteCreate WriteKind = "create"
	// WritePatch: PATCH <mount>/data/<path>, merge-patch+json, options.cas = base.
	WritePatch WriteKind = "patch"
	// WriteDestroy: POST <mount>/destroy/<path> {"versions": [...]}.
	WriteDestroy WriteKind = "destroy"
)

// Write is one Vault call. Items on the same path are merged into ONE write,
// i.e. one new version.
type Write struct {
	Kind        WriteKind
	Mount       string
	Path        string
	BaseVersion int
	// Set holds keys to set (create/replace); values are plaintext and MUST
	// be zeroed by the caller after the call. Delete holds keys to remove
	// (merge patch null).
	Set      map[string][]byte
	Delete   []string
	Versions []int
}

// Ref is "<mount><path>".
func (w Write) Ref() string { return w.Mount + w.Path }

// Plan merges items into writes: data writes first (in first-seen path
// order), then destroys.
func Plan(items []Item) ([]Write, error) {
	var data, destroys []Write
	idx := map[[2]string]int{}
	for _, it := range items {
		pp := [2]string{it.Mount, it.Path}
		if it.Op == OpDestroyHistory {
			destroys = append(destroys, Write{Kind: WriteDestroy, Mount: it.Mount, Path: it.Path, Versions: append([]int(nil), it.Versions...)})
			continue
		}
		i, ok := idx[pp]
		if !ok {
			kind := WritePatch
			if it.BaseVersion == 0 {
				kind = WriteCreate
			}
			data = append(data, Write{Kind: kind, Mount: it.Mount, Path: it.Path, BaseVersion: it.BaseVersion, Set: map[string][]byte{}})
			i = len(data) - 1
			idx[pp] = i
		}
		w := &data[i]
		if w.BaseVersion != it.BaseVersion {
			return nil, fmt.Errorf("items on %s use different base versions", w.Ref())
		}
		switch it.Op {
		case OpCreate, OpReplace:
			w.Set[it.Key] = it.Value
		case OpDelete:
			if w.Kind == WriteCreate {
				return nil, fmt.Errorf("cannot delete a key of a new secret %s", w.Ref())
			}
			w.Delete = append(w.Delete, it.Key)
		default:
			return nil, fmt.Errorf("unknown op %q", it.Op)
		}
	}
	return append(data, destroys...), nil
}

// Applied is a write that reached Vault. Version is the new KV version (0 for
// destroy).
type Applied struct {
	Mount   string
	Path    string
	Kind    WriteKind
	Version int
}

// SafeError is an apply failure whose message is safe to store and show
// (never contains values, tokens or raw Vault responses).
type SafeError struct {
	Msg string
	// Unknown: the write may or may not have reached Vault (timeout,
	// transport error, 5xx). The request stays 'applying' and the
	// reconciler settles it from the KV metadata (security review #5).
	Unknown bool
}

func (e *SafeError) Error() string { return e.Msg }

// OutcomeUnknown reports whether err leaves the Vault state unknown.
func OutcomeUnknown(err error) bool {
	var se *SafeError
	return errors.As(err, &se) && se.Unknown
}

// SafeMessage returns the user-visible failure text for err.
func SafeMessage(err error) string {
	var se *SafeError
	if errors.As(err, &se) {
		return se.Msg
	}
	return "apply failed"
}
