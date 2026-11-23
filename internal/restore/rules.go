package restore

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/authz"
)

// What is the noun of the shared maker/checker messages.
const What = "restore request"

// Reasons shown to the user.
const (
	ReasonNoOpenRole      = "Your role does not allow restoring this backup into this target: you need read on the backup's cluster and operate on the target's cluster"
	ReasonBreakGlassRole  = "Break-glass needs the admin role on both the backup's and the target's cluster"
	ReasonBreakGlassGuest = "Guest accounts cannot use break-glass"
	ReasonExpired         = "This restore request has expired"
)

// Clusters are the labels of the two clusters a request touches: the
// backup's (the run's target) and the restore target's.
type Clusters struct {
	Run, Target map[string]string
}

func denyErr(reason string) error     { return &approvals.DenyError{Reason: reason} }
func conflictErr(reason string) error { return &approvals.DenyError{Reason: reason, Conflict: true} }

// CheckOpen: the maker needs read on the run's cluster and operate on the
// target's cluster; break-glass needs admin on both and is not for guests
// (it is a self-approval, and guests never approve).
func CheckOpen(sub *authz.Subject, c Clusters, breakGlass bool) error {
	if !sub.Can(authz.PermRead, c.Run) || !sub.Can(authz.PermOperate, c.Target) {
		return denyErr(ReasonNoOpenRole)
	}
	if !breakGlass {
		return nil
	}
	if sub.Principal.IsGuest() {
		return denyErr(ReasonBreakGlassGuest)
	}
	if !sub.Can(authz.PermAdmin, c.Run) || !sub.Can(authz.PermAdmin, c.Target) {
		return denyErr(ReasonBreakGlassRole)
	}
	return nil
}

// CheckDecide applies the shared maker/checker rule to approve and reject:
// another person (by tenant + object id), not a guest, with operate on both
// clusters, while the request is pending and not past expiresAt.
func CheckDecide(sub *authz.Subject, maker authz.Principal, c Clusters, st Status, expiresAt, now time.Time) error {
	allowed := sub != nil && sub.Can(authz.PermOperate, c.Run) && sub.Can(authz.PermOperate, c.Target)
	return approvals.DecideRule(sub, maker, st == StatusPending, expiresAt, now, allowed, What)
}

// CheckCancel: only the maker withdraws a request, while it is pending or
// approved and not started (which frees the target at once).
func CheckCancel(sub *authz.Subject, maker authz.Principal, st Status) error {
	if st != StatusPending && st != StatusApproved {
		return conflictErr("This restore request is " + string(st))
	}
	return approvals.CancelRule(sub, maker, true, What)
}

// Due reports whether a request expires now: pending past its TTL, or
// approved and not started within ApprovedTTL of the approval.
func Due(st Status, expiresAt time.Time, approvedExpiresAt *time.Time, now time.Time) bool {
	switch st {
	case StatusPending:
		return !now.Before(expiresAt)
	case StatusApproved:
		return approvedExpiresAt != nil && !now.Before(*approvedExpiresAt)
	}
	return false
}

// hasDatabases reports whether engine restores databases (not a snapshot).
func hasDatabases(engine string) bool { return engine == "postgresql" || engine == "clickhouse" }

// CheckDatabases validates the selected databases against the backup's:
// empty selects all of them, every name must be in the backup, once. Vault
// restores a snapshot and takes none. It returns the list to restore, or a
// message for the databases field.
func CheckDatabases(engine string, selected, inBackup []string) ([]string, string) {
	if !hasDatabases(engine) {
		if len(selected) > 0 {
			return nil, "a " + engine + " restore loads the whole snapshot; no databases are selected"
		}
		return []string{}, ""
	}
	if len(inBackup) == 0 {
		return nil, "the backup lists no databases"
	}
	if len(selected) == 0 {
		return append([]string{}, inBackup...), ""
	}
	known := map[string]bool{}
	for _, d := range inBackup {
		known[d] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(selected))
	var missing []string
	for _, d := range selected {
		d = strings.TrimSpace(d)
		switch {
		case d == "":
			return nil, "a database name is empty"
		case seen[d]:
			return nil, fmt.Sprintf("%s is selected twice", d)
		case !known[d]:
			missing = append(missing, d)
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(missing) > 0 {
		return nil, "not in the backup: " + strings.Join(missing, ", ")
	}
	return out, ""
}

// CheckReport applies the open-time (and start-time) checks to what the
// target's inspector found: no selected database may exist with user
// objects in it (an existing empty one is restored into), and a Vault must
// be initialized, unsealed, the active node, and let the token
// snapshot-force. It returns
// field errors and notes for the request.
func CheckReport(engine string, databases []string, r *TargetReport) (map[string]string, []string) {
	f := map[string]string{}
	var notes []string
	if engine == "vault" {
		switch {
		case !r.Initialized:
			f["target_id"] = "the target Vault is not initialized"
		case r.Sealed:
			f["target_id"] = "the target Vault is sealed; unseal it before the restore"
		case r.Standby:
			f["target_id"] = "the target is a standby node of an HA Vault, not the active node; point the target at the active " +
				"node (a Service that selects only the active pod) and check again; if it was just unsealed, wait for it to " +
				"become the active node and check again"
		case r.CapabilitiesDenied:
			f["vault_token"] = "the target refused to show this token's capabilities (sys/capabilities-self refused it, HTTP 401/403): the token " +
				"needs the default policy (or access to sys/capabilities-self) plus update and sudo on sys/storage/raft/snapshot-force"
		case !r.CanSnapshotForce:
			f["vault_token"] = "this token needs both update and sudo on sys/storage/raft/snapshot-force on the target"
		}
		return f, notes
	}
	var full, empty []string
	for _, d := range databases {
		data, ok := r.Existing[d]
		switch {
		case ok && data:
			full = append(full, d)
		case ok:
			empty = append(empty, d)
		}
	}
	sort.Strings(full)
	if len(full) > 0 {
		f["databases"] = "already exist on the target with data in them (nothing is overwritten): " + strings.Join(full, ", ")
	}
	if len(empty) > 0 {
		notes = append(notes, "Exist on the target without user objects and are restored into: "+strings.Join(empty, ", "))
	}
	if engine == "postgresql" && !r.Superuser {
		notes = append(notes, "The credential is not a superuser: owners, privileges and globals (roles) are not restored (pg_restore --no-owner --no-privileges)")
	}
	return f, notes
}
