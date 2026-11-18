package approvals

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
)

func subject(p authz.Principal, grants ...string) *authz.Subject {
	s := &authz.Subject{Principal: p}
	for _, g := range grants {
		role, scope := g, "all"
		for i := range g {
			if g[i] == '@' {
				role, scope = g[:i], g[i+1:]
			}
		}
		sc, err := authz.ParseScope(scope)
		if err != nil {
			panic(err)
		}
		s.Grants = append(s.Grants, authz.Grant{ID: uuid.New(), PrincipalID: p.ID, Role: authz.Role(role), Scope: sc})
	}
	return s
}

func principal(name, userType string) authz.Principal {
	return authz.Principal{ID: uuid.New(), TenantID: "tenant-a", ObjectID: uuid.NewString(), UPN: name + "@contoso.com",
		DisplayName: name, UserType: userType, AccountEnabled: true}
}

func TestTransitions(t *testing.T) {
	cases := []struct {
		from Status
		ev   Event
		to   Status
		ok   bool
	}{
		{StatusPending, EvApprove, StatusApproved, true},
		{StatusPending, EvReject, StatusRejected, true},
		{StatusPending, EvCancel, StatusCancelled, true},
		{StatusPending, EvExpire, StatusExpired, true},
		{StatusApproved, EvApplyOK, StatusApplied, true},
		{StatusApproved, EvApplyErr, StatusFailed, true},
		// No double decisions, no skipping approval.
		{StatusPending, EvApplyOK, StatusPending, false},
		{StatusApproved, EvApprove, StatusApproved, false},
		{StatusApproved, EvReject, StatusApproved, false},
		{StatusApproved, EvExpire, StatusApproved, false},
	}
	for _, s := range []Status{StatusApplied, StatusRejected, StatusExpired, StatusFailed, StatusCancelled} {
		if !s.Terminal() {
			t.Errorf("%s should be terminal", s)
		}
		for _, ev := range []Event{EvApprove, EvReject, EvCancel, EvExpire, EvApplyOK, EvApplyErr} {
			cases = append(cases, struct {
				from Status
				ev   Event
				to   Status
				ok   bool
			}{s, ev, s, false})
		}
	}
	for _, c := range cases {
		got, err := Next(c.from, c.ev)
		if c.ok != (err == nil) || got != c.to {
			t.Errorf("Next(%s, %s) = %s, %v; want %s ok=%v", c.from, c.ev, got, err, c.to, c.ok)
		}
		if !c.ok && !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("Next(%s, %s): want ErrInvalidTransition, got %v", c.from, c.ev, err)
		}
	}
	if StatusPending.Terminal() || StatusApproved.Terminal() {
		t.Error("pending/approved are not terminal")
	}
}

func reason(err error) string {
	var de *DenyError
	if errors.As(err, &de) {
		return de.Reason
	}
	return ""
}

func TestMakerCannotApproveOwnRequestAdminIncluded(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour)
	prod := map[string]string{"env": "prod"}
	maker := principal("ada", "Member")
	// The same person signing in again (new principal row id is irrelevant:
	// identity is tenant+object id, case-insensitive).
	again := maker
	again.ID = uuid.New()
	again.TenantID = "TENANT-A"
	for _, sub := range []*authz.Subject{
		subject(maker, "admin"),
		subject(maker, "vault-approver", "vault-maker"),
		subject(again, "admin", "vault-approver"),
	} {
		err := CheckDecide(sub, maker, prod, StatusPending, exp, now)
		if reason(err) != ReasonOwnRequest {
			t.Fatalf("maker approving own request: got %v, want %q", err, ReasonOwnRequest)
		}
		var de *DenyError
		if errors.As(err, &de) && de.Conflict {
			t.Fatal("own request must be 403, not 409")
		}
	}
}

func TestCheckDecideRules(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour)
	prod := map[string]string{"env": "prod"}
	maker := principal("ada", "Member")
	checker := principal("bob", "Member")
	guest := principal("eve", "Guest")
	extGuest := principal("mallory", "Member")
	extGuest.UPN = "mallory_fabrikam.com#EXT#@contoso.onmicrosoft.com"

	if err := CheckDecide(subject(checker, "vault-approver"), maker, prod, StatusPending, exp, now); err != nil {
		t.Fatalf("approver should decide: %v", err)
	}
	if err := CheckDecide(subject(checker, "admin"), maker, prod, StatusPending, exp, now); err != nil {
		t.Fatalf("admin (not maker) should decide: %v", err)
	}
	if err := CheckDecide(subject(checker, "vault-approver@env=prod"), maker, prod, StatusPending, exp, now); err != nil {
		t.Fatalf("scoped approver should decide: %v", err)
	}
	// Out of scope.
	if r := reason(CheckDecide(subject(checker, "vault-approver@env=dev"), maker, prod, StatusPending, exp, now)); r != ReasonNoRole {
		t.Fatalf("out of scope: %q", r)
	}
	// Wrong roles.
	for _, g := range []string{"viewer", "operator", "vault-maker"} {
		if r := reason(CheckDecide(subject(checker, g), maker, prod, StatusPending, exp, now)); r != ReasonNoRole {
			t.Fatalf("%s must not decide: %q", g, r)
		}
	}
	// Guests never approve, even as admin.
	for _, g := range []authz.Principal{guest, extGuest} {
		if r := reason(CheckDecide(subject(g, "admin", "vault-approver"), maker, prod, StatusPending, exp, now)); r != ReasonGuest {
			t.Fatalf("guest %s: %q", g.UPN, r)
		}
	}
	// Stale grant / disabled account.
	st := subject(checker, "vault-approver")
	st.Grants[0].Stale = true
	if CheckDecide(st, maker, prod, StatusPending, exp, now) == nil {
		t.Fatal("stale grant must not authorize")
	}
	// Double decision impossible.
	for _, s := range []Status{StatusApproved, StatusApplied, StatusRejected, StatusExpired, StatusFailed, StatusCancelled} {
		err := CheckDecide(subject(checker, "vault-approver"), maker, prod, s, exp, now)
		var de *DenyError
		if !errors.As(err, &de) || !de.Conflict {
			t.Fatalf("decide on %s: %v (want conflict)", s, err)
		}
	}
	// Expired by TTL.
	if r := reason(CheckDecide(subject(checker, "vault-approver"), maker, prod, StatusPending, now, now)); r != ReasonExpired {
		t.Fatalf("expired: %q", r)
	}
	if CheckDecide(nil, maker, prod, StatusPending, exp, now) == nil {
		t.Fatal("nil subject must not decide")
	}
}

func TestCheckCancelAndOpen(t *testing.T) {
	maker := principal("ada", "Member")
	other := principal("bob", "Member")
	if err := CheckCancel(subject(maker, "vault-maker"), maker, StatusPending); err != nil {
		t.Fatal(err)
	}
	if reason(CheckCancel(subject(other, "admin"), maker, StatusPending)) != ReasonNotMaker {
		t.Fatal("only the maker cancels, admin included")
	}
	if CheckCancel(subject(maker, "vault-maker"), maker, StatusApplied) == nil {
		t.Fatal("cannot cancel a decided request")
	}
	prod := map[string]string{"env": "prod"}
	if CheckOpen(subject(maker, "vault-maker@env=prod"), prod) != nil || CheckOpen(subject(maker, "admin"), prod) != nil {
		t.Fatal("maker/admin may open")
	}
	for _, g := range []string{"viewer", "operator", "vault-approver", "vault-maker@env=dev"} {
		if CheckOpen(subject(maker, g), prod) == nil {
			t.Fatalf("%s must not open", g)
		}
	}
}

func TestValidateItems(t *testing.T) {
	mounts := map[string]bool{"secret/": true}
	ok := []Item{
		{Mount: "secret", Path: "/app/db/", Key: "PASSWORD", Op: OpReplace, BaseVersion: 3, Value: []byte("x")},
		{Mount: "secret/", Path: "app/db", Key: "OLD", Op: OpDelete, BaseVersion: 3},
		{Mount: "secret/", Path: "app/new", Key: "K", Op: OpCreate, Value: []byte("v")},
		{Mount: "secret/", Path: "app/db", Op: OpDestroyHistory, Versions: []int{2, 1}},
	}
	if f := ValidateItems(ok, mounts); len(f) != 0 {
		t.Fatalf("valid items rejected: %v", f)
	}
	if ok[0].Mount != "secret/" || ok[0].Path != "app/db" || ok[3].Versions[0] != 1 {
		t.Fatalf("not normalized: %+v", ok)
	}
	bad := map[string][]Item{
		"unmanaged mount":      {{Mount: "legacy/", Path: "a", Key: "k", Op: OpCreate, Value: []byte("v")}},
		"path traversal":       {{Mount: "secret/", Path: "a/../b", Key: "k", Op: OpCreate, Value: []byte("v")}},
		"value on delete":      {{Mount: "secret/", Path: "a", Key: "k", Op: OpDelete, BaseVersion: 1, Value: []byte("v")}},
		"value on destroy":     {{Mount: "secret/", Path: "a", Op: OpDestroyHistory, Versions: []int{1}, Value: []byte("v")}},
		"key on destroy":       {{Mount: "secret/", Path: "a", Key: "k", Op: OpDestroyHistory, Versions: []int{1}}},
		"no versions":          {{Mount: "secret/", Path: "a", Op: OpDestroyHistory}},
		"bad versions":         {{Mount: "secret/", Path: "a", Op: OpDestroyHistory, Versions: []int{0}}},
		"missing value":        {{Mount: "secret/", Path: "a", Key: "k", Op: OpReplace, BaseVersion: 1}},
		"replace without base": {{Mount: "secret/", Path: "a", Key: "k", Op: OpReplace, Value: []byte("v")}},
		"missing key":          {{Mount: "secret/", Path: "a", Op: OpCreate, Value: []byte("v")}},
		"unknown op":           {{Mount: "secret/", Path: "a", Key: "k", Op: "read"}},
		"negative base":        {{Mount: "secret/", Path: "a", Key: "k", Op: OpCreate, BaseVersion: -1, Value: []byte("v")}},
		"duplicate key":        {{Mount: "secret/", Path: "a", Key: "k", Op: OpReplace, BaseVersion: 1, Value: []byte("v")}, {Mount: "secret/", Path: "a", Key: "k", Op: OpDelete, BaseVersion: 1}},
		"mixed base on a path": {{Mount: "secret/", Path: "a", Key: "k", Op: OpReplace, BaseVersion: 1, Value: []byte("v")}, {Mount: "secret/", Path: "a", Key: "j", Op: OpReplace, BaseVersion: 2, Value: []byte("v")}},
		"versions on data op":  {{Mount: "secret/", Path: "a", Key: "k", Op: OpReplace, BaseVersion: 1, Value: []byte("v"), Versions: []int{1}}},
		"quote in mount (HCL)": {{Mount: `se"cret/`, Path: "a", Key: "k", Op: OpCreate, Value: []byte("v")}},
		"no items":             {},
	}
	for name, items := range bad {
		if f := ValidateItems(items, mounts); len(f) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if ValidateJustification("too short") == "" || ValidateJustification("  rotate db password  ") != "" {
		t.Fatal("justification >= 10 chars")
	}
}

func TestPlanMergesItemsOnSamePath(t *testing.T) {
	items := []Item{
		{Mount: "secret/", Path: "app/db", Key: "PASSWORD", Op: OpReplace, BaseVersion: 3, Value: []byte("p")},
		{Mount: "secret/", Path: "app/db", Op: OpDestroyHistory, Versions: []int{1}},
		{Mount: "secret/", Path: "app/new", Key: "A", Op: OpCreate, Value: []byte("a")},
		{Mount: "secret/", Path: "app/db", Key: "USER", Op: OpDelete, BaseVersion: 3},
		{Mount: "secret/", Path: "app/db", Key: "NEW", Op: OpCreate, BaseVersion: 3, Value: []byte("n")},
		{Mount: "secret/", Path: "app/new", Key: "B", Op: OpCreate, Value: []byte("b")},
	}
	plan, err := Plan(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 {
		t.Fatalf("want 3 writes (db patch, new create, destroy), got %d: %+v", len(plan), plan)
	}
	db, nw, ds := plan[0], plan[1], plan[2]
	if db.Kind != WritePatch || db.Ref() != "secret/app/db" || db.BaseVersion != 3 || len(db.Set) != 2 || len(db.Delete) != 1 || db.Delete[0] != "USER" {
		t.Fatalf("db patch: %+v", db)
	}
	if nw.Kind != WriteCreate || nw.BaseVersion != 0 || len(nw.Set) != 2 {
		t.Fatalf("new path create: %+v", nw)
	}
	if ds.Kind != WriteDestroy || len(ds.Versions) != 1 || ds.Versions[0] != 1 {
		t.Fatalf("destroy last: %+v", ds)
	}
	if _, err := Plan([]Item{{Mount: "secret/", Path: "x", Key: "k", Op: OpDelete, BaseVersion: 0}}); err == nil {
		t.Fatal("delete on a new path must fail")
	}
}

func TestSafeMessage(t *testing.T) {
	if SafeMessage(errors.New("raw vault body with secret")) != "apply failed" {
		t.Fatal("unsafe errors must not be shown")
	}
	if SafeMessage(&SafeError{Msg: "check-and-set conflict"}) != "check-and-set conflict" {
		t.Fatal("safe message")
	}
}
