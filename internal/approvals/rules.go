package approvals

import (
	"time"

	"github.com/Warewave-Technology/olympos/internal/authz"
)

// The maker/checker rules shared by every kind of request that needs a second
// person: Vault change requests and restore requests. They are pure; the
// caller supplies its own permission result and the noun used in messages.

// ruleMsgs are the reasons a rule reports. Vault change requests keep their
// historical texts (the Reason* constants); other kinds derive theirs from the
// noun with msgsFor.
type ruleMsgs struct {
	notPending func() string // the request is no longer pending (409)
	expired    string        // past its TTL (409)
	own        string        // the checker is the maker (403)
	guest      string        // guests never approve (403)
	noRole     string        // the caller lacks the permission (403)
	notMaker   string        // someone other than the maker cancels (403)
}

func msgsFor(what string) ruleMsgs {
	return ruleMsgs{
		notPending: func() string { return "This " + what + " is no longer pending" },
		expired:    "This " + what + " has expired",
		own:        ReasonOwnRequest,
		guest:      "Guest accounts cannot approve " + what + "s",
		noRole:     "Your role does not allow approving " + what + "s",
		notMaker:   "Only the maker can cancel a " + what,
	}
}

// DecideRule applies the maker/checker rule to approve and reject a request
// of kind what (e.g. "change request", "restore request"):
//   - the request must be pending and not past expiresAt;
//   - the checker MUST NOT be the maker, compared by (tenant_id, object_id).
//     No role bypasses this, admin included;
//   - guests never approve, whatever allowed says;
//   - allowed, the caller's own permission check, must hold.
//
// State violations are Conflict errors (409), the rest are 403.
func DecideRule(sub *authz.Subject, maker authz.Principal, pending bool, expiresAt, now time.Time, allowed bool, what string) error {
	return decideRule(sub, maker, pending, expiresAt, now, allowed, msgsFor(what))
}

func decideRule(sub *authz.Subject, maker authz.Principal, pending bool, expiresAt, now time.Time, allowed bool, m ruleMsgs) error {
	if !pending {
		return conflict(m.notPending())
	}
	if !now.Before(expiresAt) {
		return conflict(m.expired)
	}
	if sub == nil {
		return deny(m.noRole)
	}
	if sub.Principal.SameAs(maker) {
		return deny(m.own)
	}
	if sub.Principal.IsGuest() {
		return deny(m.guest)
	}
	if !allowed {
		return deny(m.noRole)
	}
	return nil
}

// CancelRule: only the maker withdraws a pending request of kind what.
func CancelRule(sub *authz.Subject, maker authz.Principal, pending bool, what string) error {
	return cancelRule(sub, maker, pending, msgsFor(what))
}

func cancelRule(sub *authz.Subject, maker authz.Principal, pending bool, m ruleMsgs) error {
	if !pending {
		return conflict(m.notPending())
	}
	if sub == nil || !sub.Principal.SameAs(maker) {
		return deny(m.notMaker)
	}
	return nil
}
