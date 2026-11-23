package approvals

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/authz"
)

func denyOf(t *testing.T, err error) *DenyError {
	t.Helper()
	var de *DenyError
	if !errors.As(err, &de) {
		t.Fatalf("want *DenyError, got %v", err)
	}
	return de
}

func TestDecideRule(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour)
	maker := principal("ada", "Member")
	checker := principal("bob", "Member")
	guest := principal("eve", "Guest")
	extGuest := principal("mallory", "Member")
	extGuest.UPN = "mallory_fabrikam.com#EXT#@contoso.onmicrosoft.com"
	const what = "restore request"

	if err := DecideRule(subject(checker), maker, true, exp, now, true, what); err != nil {
		t.Fatalf("another member with permission should decide: %v", err)
	}

	// Not pending: conflict naming the noun.
	de := denyOf(t, DecideRule(subject(checker), maker, false, exp, now, true, what))
	if !de.Conflict || !strings.Contains(de.Reason, what) {
		t.Fatalf("not pending: %+v", de)
	}
	// Past expiry (the boundary included): conflict naming the noun.
	for _, at := range []time.Time{now, now.Add(-time.Minute)} {
		de = denyOf(t, DecideRule(subject(checker), maker, true, at, now, true, what))
		if !de.Conflict || !strings.Contains(de.Reason, what) || !strings.Contains(de.Reason, "expired") {
			t.Fatalf("expired: %+v", de)
		}
	}
	// The maker never decides, even with the permission.
	de = denyOf(t, DecideRule(subject(maker), maker, true, exp, now, true, what))
	if de.Conflict || de.Reason != ReasonOwnRequest {
		t.Fatalf("maker: %+v", de)
	}
	// Guests never decide, by user type or by #EXT# UPN, even when allowed.
	for _, g := range []authz.Principal{guest, extGuest} {
		de = denyOf(t, DecideRule(subject(g), maker, true, exp, now, true, what))
		if de.Conflict || !strings.Contains(de.Reason, "Guest") || !strings.Contains(de.Reason, what) {
			t.Fatalf("guest %s: %+v", g.UPN, de)
		}
	}
	// The caller's permission result gates the rest.
	de = denyOf(t, DecideRule(subject(checker), maker, true, exp, now, false, what))
	if de.Conflict || !strings.Contains(de.Reason, what) {
		t.Fatalf("not allowed: %+v", de)
	}
	// No subject: no right.
	de = denyOf(t, DecideRule(nil, maker, true, exp, now, true, what))
	if de.Conflict {
		t.Fatalf("nil subject: %+v", de)
	}
	// State is reported before the caller's identity.
	if de = denyOf(t, DecideRule(subject(maker), maker, false, exp, now, true, what)); !de.Conflict {
		t.Fatalf("state first: %+v", de)
	}
}

func TestCancelRule(t *testing.T) {
	maker := principal("ada", "Member")
	other := principal("bob", "Member")
	const what = "restore request"

	if err := CancelRule(subject(maker), maker, true, what); err != nil {
		t.Fatalf("maker should cancel: %v", err)
	}
	de := denyOf(t, CancelRule(subject(maker), maker, false, what))
	if !de.Conflict || !strings.Contains(de.Reason, what) {
		t.Fatalf("not pending: %+v", de)
	}
	de = denyOf(t, CancelRule(subject(other, "admin"), maker, true, what))
	if de.Conflict || !strings.Contains(de.Reason, what) {
		t.Fatalf("other principal: %+v", de)
	}
	if de = denyOf(t, CancelRule(nil, maker, true, what)); de.Conflict {
		t.Fatalf("nil subject: %+v", de)
	}
}
