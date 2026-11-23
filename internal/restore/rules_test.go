package restore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/authz"
)

func subject(p authz.Principal, grants ...string) *authz.Subject {
	s := &authz.Subject{Principal: p}
	for _, g := range grants {
		role, scope, ok := strings.Cut(g, "@")
		if !ok {
			scope = "all"
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

func deny(t *testing.T, err error) *approvals.DenyError {
	t.Helper()
	var de *approvals.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("want *approvals.DenyError, got %v", err)
	}
	return de
}

var (
	prod  = map[string]string{"env": "prod"}
	stage = map[string]string{"env": "stage"}
	two   = Clusters{Run: prod, Target: stage}
)

func TestCheckOpen(t *testing.T) {
	p := principal("ada", "Member")
	ok := []*authz.Subject{
		subject(p, "viewer@env=prod", "operator@env=stage"),
		subject(p, "operator"),
	}
	for _, s := range ok {
		if err := CheckOpen(s, two, false); err != nil {
			t.Fatalf("maker with read+operate: %v", err)
		}
	}
	for _, s := range []*authz.Subject{
		subject(p, "operator@env=stage"),                    // no read on the run's cluster
		subject(p, "viewer@env=prod", "viewer@env=stage"),   // no operate on the target's cluster
		subject(p, "operator@env=prod", "viewer@env=stage"), // operate on the wrong cluster
		nil,
	} {
		if de := deny(t, CheckOpen(s, two, false)); de.Conflict || de.Reason != ReasonNoOpenRole {
			t.Fatalf("open refused: %+v", de)
		}
	}

	// Break-glass: admin on both clusters, members only.
	if err := CheckOpen(subject(p, "admin"), two, true); err != nil {
		t.Fatalf("admin break-glass: %v", err)
	}
	if err := CheckOpen(subject(p, "admin@env=prod", "admin@env=stage"), two, true); err != nil {
		t.Fatalf("scoped admin on both: %v", err)
	}
	for _, s := range []*authz.Subject{
		subject(p, "operator"),
		subject(p, "admin@env=prod", "operator@env=stage"),
		subject(p, "operator@env=prod", "admin@env=stage"),
	} {
		if de := deny(t, CheckOpen(s, two, true)); de.Reason != ReasonBreakGlassRole {
			t.Fatalf("break-glass by a non-admin: %+v", de)
		}
	}
	if de := deny(t, CheckOpen(subject(principal("eve", "Guest"), "admin"), two, true)); de.Reason != ReasonBreakGlassGuest {
		t.Fatalf("break-glass by a guest: %+v", de)
	}
}

func TestCheckDecide(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour)
	maker := principal("ada", "Member")
	checker := principal("bob", "Member")

	if err := CheckDecide(subject(checker, "operator@env=prod", "operator@env=stage"), maker, two, StatusPending, exp, now); err != nil {
		t.Fatalf("checker with operate on both: %v", err)
	}
	// The maker never decides, admin included.
	if de := deny(t, CheckDecide(subject(maker, "admin"), maker, two, StatusPending, exp, now)); de.Reason != approvals.ReasonOwnRequest {
		t.Fatalf("maker = checker: %+v", de)
	}
	// Same person, another principal row (compared by tenant + object id).
	alias := maker
	alias.ID = uuid.New()
	if de := deny(t, CheckDecide(subject(alias, "admin"), maker, two, StatusPending, exp, now)); de.Reason != approvals.ReasonOwnRequest {
		t.Fatalf("maker under another row: %+v", de)
	}
	// operate on one cluster only is not enough, read is not enough.
	for _, s := range []*authz.Subject{
		subject(checker, "operator@env=prod", "viewer@env=stage"),
		subject(checker, "viewer@env=prod", "operator@env=stage"),
		subject(checker, "viewer"),
	} {
		if de := deny(t, CheckDecide(s, maker, two, StatusPending, exp, now)); de.Conflict || !strings.Contains(de.Reason, "restore request") {
			t.Fatalf("checker lacking operate on a cluster: %+v", de)
		}
	}
	// Guests never approve.
	if de := deny(t, CheckDecide(subject(principal("eve", "Guest"), "admin"), maker, two, StatusPending, exp, now)); !strings.Contains(de.Reason, "Guest") {
		t.Fatalf("guest: %+v", de)
	}
	// State: not pending, expired.
	if de := deny(t, CheckDecide(subject(checker, "operator"), maker, two, StatusApproved, exp, now)); !de.Conflict {
		t.Fatalf("approved: %+v", de)
	}
	if de := deny(t, CheckDecide(subject(checker, "operator"), maker, two, StatusPending, now, now)); !de.Conflict || !strings.Contains(de.Reason, "expired") {
		t.Fatalf("expired: %+v", de)
	}
}

func TestCheckCancel(t *testing.T) {
	maker := principal("ada", "Member")
	other := principal("bob", "Member")
	for _, st := range []Status{StatusPending, StatusApproved} {
		if err := CheckCancel(subject(maker, "viewer"), maker, st); err != nil {
			t.Fatalf("maker cancels %s: %v", st, err)
		}
	}
	if de := deny(t, CheckCancel(subject(other, "admin"), maker, StatusPending)); de.Conflict {
		t.Fatalf("someone else cancels: %+v", de)
	}
	for _, st := range []Status{StatusRunning, StatusSucceeded, StatusFailed, StatusRejected, StatusExpired, StatusCancelled} {
		if de := deny(t, CheckCancel(subject(maker), maker, st)); !de.Conflict || !strings.Contains(de.Reason, string(st)) {
			t.Fatalf("cancel %s: %+v", st, de)
		}
	}
}

func TestDue(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	cases := []struct {
		st       Status
		exp      time.Time
		approved *time.Time
		due      bool
	}{
		{StatusPending, past, nil, true},
		{StatusPending, now, nil, true},
		{StatusPending, future, nil, false},
		{StatusApproved, past, &future, false}, // the pending TTL no longer applies
		{StatusApproved, future, &past, true},
		{StatusApproved, future, nil, false},
		{StatusRunning, past, &past, false},
		{StatusSucceeded, past, &past, false},
	}
	for _, c := range cases {
		if got := Due(c.st, c.exp, c.approved, now); got != c.due {
			t.Errorf("Due(%s, exp %v, approved %v) = %v", c.st, c.exp.Sub(now), c.approved, got)
		}
	}
}

func TestStatusTerminal(t *testing.T) {
	for _, s := range AllStatuses {
		want := s != StatusPending && s != StatusApproved && s != StatusRunning
		if s.Terminal() != want {
			t.Errorf("%s terminal = %v", s, s.Terminal())
		}
	}
	if len(AllStatuses) != 8 {
		t.Fatalf("statuses: %v", AllStatuses)
	}
}

func TestCheckDatabases(t *testing.T) {
	inBackup := []string{"postgres", "shop", "billing"}
	got, msg := CheckDatabases("postgresql", nil, inBackup)
	if msg != "" || strings.Join(got, ",") != "postgres,shop,billing" {
		t.Fatalf("default all: %v %q", got, msg)
	}
	got, msg = CheckDatabases("postgresql", []string{"shop", " billing "}, inBackup)
	if msg != "" || strings.Join(got, ",") != "shop,billing" {
		t.Fatalf("subset: %v %q", got, msg)
	}
	for _, sel := range [][]string{{"shop", "nope"}, {"shop", "shop"}, {""}} {
		if _, msg := CheckDatabases("clickhouse", sel, inBackup); msg == "" {
			t.Fatalf("%v accepted", sel)
		}
	}
	if _, msg := CheckDatabases("postgresql", nil, nil); msg == "" {
		t.Fatal("a backup without databases accepted")
	}
	// Vault: a snapshot, no databases.
	if got, msg := CheckDatabases("vault", nil, nil); msg != "" || len(got) != 0 {
		t.Fatalf("vault: %v %q", got, msg)
	}
	if _, msg := CheckDatabases("vault", []string{"x"}, nil); msg == "" {
		t.Fatal("vault with databases accepted")
	}
}

func TestCheckReport(t *testing.T) {
	r := &TargetReport{Existing: map[string]bool{"postgres": false, "shop": true}, Superuser: true}
	f, notes := CheckReport("postgresql", []string{"postgres", "billing"}, r)
	if len(f) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "postgres") {
		t.Fatalf("empty existing database is restored into: %v %v", f, notes)
	}
	f, _ = CheckReport("postgresql", []string{"shop", "billing"}, r)
	if !strings.Contains(f["databases"], "shop") {
		t.Fatalf("existing database with data: %v", f)
	}
	f, notes = CheckReport("postgresql", []string{"billing"}, &TargetReport{})
	if len(f) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "superuser") {
		t.Fatalf("not a superuser: %v %v", f, notes)
	}
	// Vault: initialized, unsealed, token allowed to snapshot-force.
	if f, _ := CheckReport("vault", nil, &TargetReport{Initialized: true, CanSnapshotForce: true}); len(f) != 0 {
		t.Fatalf("ready vault: %v", f)
	}
	for _, rep := range []*TargetReport{
		{Initialized: false, CanSnapshotForce: true},
		{Initialized: true, Sealed: true, CanSnapshotForce: true},
		{Initialized: true},
		{Initialized: true, Standby: true, CanSnapshotForce: true},
		{Initialized: true, CapabilitiesDenied: true},
	} {
		if f, _ := CheckReport("vault", nil, rep); len(f) == 0 {
			t.Fatalf("vault %+v accepted", rep)
		}
	}
	for _, c := range []struct {
		rep        TargetReport
		key, words string
	}{
		{TargetReport{Initialized: true, Standby: true, CanSnapshotForce: true}, "target_id", "active node"},
		{TargetReport{Initialized: true, CapabilitiesDenied: true}, "vault_token", "default policy"},
		{TargetReport{Initialized: true}, "vault_token", "update and sudo"},
	} {
		f, _ := CheckReport("vault", nil, &c.rep)
		if !strings.Contains(f[c.key], c.words) {
			t.Errorf("vault %+v: %v, want %q on %s", c.rep, f, c.words, c.key)
		}
	}
}

func TestEngineOptions(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
	for engine, key := range map[string]string{"postgresql": "tls_ca_pem", "clickhouse": "ca_pem", "vault": "ca_bundle"} {
		raw := string(EngineOptions(engine, Options{TLSCAPEM: pem}))
		if !strings.Contains(raw, `"`+key+`"`) {
			t.Errorf("%s: %s", engine, raw)
		}
		if raw := string(EngineOptions(engine, Options{})); raw != "{}" {
			t.Errorf("%s without a CA: %s", engine, raw)
		}
	}
}
