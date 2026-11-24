package authz

import "testing"

func mustScope(t *testing.T, s string) Scope {
	t.Helper()
	sc, err := ParseScope(s)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestScopeAndPermissions(t *testing.T) {
	prod := map[string]string{"env": "prod"}
	dev := map[string]string{"env": "dev"}
	s := &Subject{Principal: Principal{AccountEnabled: true}, Grants: []Grant{
		{Role: RoleOperator, Scope: mustScope(t, "env=prod")},
		{Role: RoleViewer, Scope: mustScope(t, "all")},
	}}
	if !s.Can(PermOperate, prod) || s.Can(PermOperate, dev) {
		t.Fatal("operator scope not applied")
	}
	if !s.Can(PermRead, dev) || s.CanGlobal(PermOperate) || !s.CanGlobal(PermRead) {
		t.Fatal("global checks wrong")
	}
	if s.CanAny(PermAdmin) {
		t.Fatal("no admin expected")
	}
}

func TestStaleAndDisabledGrantsDoNotAuthorize(t *testing.T) {
	s := &Subject{Principal: Principal{AccountEnabled: true}, Grants: []Grant{{Role: RoleAdmin, Scope: mustScope(t, "all"), Stale: true}}}
	if s.CanAny(PermRead) {
		t.Fatal("stale grant authorized")
	}
	s = &Subject{Principal: Principal{AccountEnabled: false}, Grants: []Grant{{Role: RoleAdmin, Scope: mustScope(t, "all")}}}
	if s.CanAny(PermRead) {
		t.Fatal("disabled account authorized")
	}
}

func TestGuestNeverApproves(t *testing.T) {
	g := &Subject{Principal: Principal{AccountEnabled: true, UPN: "bob_contoso.com#EXT#@tenant.onmicrosoft.com"},
		Grants: []Grant{{Role: RoleAdmin, Scope: mustScope(t, "all")}}}
	if g.CanAny(PermVaultApprove) {
		t.Fatal("guest can approve")
	}
	if !g.CanAny(PermAdmin) {
		t.Fatal("other admin permissions should remain")
	}
}

func TestGuestNeverEditsSynthetic(t *testing.T) {
	const guestUPN = "bob_contoso.com#EXT#@tenant.onmicrosoft.com"
	for _, role := range []Role{RoleSyntheticEditor, RoleAdmin} {
		g := &Subject{Principal: Principal{AccountEnabled: true, UPN: guestUPN}, Grants: []Grant{{Role: role, Scope: mustScope(t, "all")}}}
		if g.CanAny(PermSyntheticEdit) {
			t.Fatalf("guest with %s can edit synthetic scenarios", role)
		}
		if !g.CanAny(PermRead) {
			t.Fatalf("guest with %s lost read", role)
		}
		m := &Subject{Principal: Principal{AccountEnabled: true, UPN: "alice@tenant.onmicrosoft.com"}, Grants: []Grant{{Role: role, Scope: mustScope(t, "all")}}}
		if !m.CanAny(PermSyntheticEdit) {
			t.Fatalf("member with %s cannot edit synthetic scenarios", role)
		}
	}
}

func TestParseScope(t *testing.T) {
	if _, err := ParseScope("env in (prod,staging),team=payments"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseScope("env==="); err == nil {
		t.Fatal("bad selector accepted")
	}
	if !mustScope(t, "").All() {
		t.Fatal("empty means all")
	}
}

func TestSyntheticEditor(t *testing.T) {
	if r, err := ParseRole("synthetic-editor"); err != nil || r != RoleSyntheticEditor {
		t.Fatalf("ParseRole: %v %v", r, err)
	}
	prod := map[string]string{"env": "prod"}
	dev := map[string]string{"env": "dev"}
	ed := &Subject{Principal: Principal{AccountEnabled: true}, Grants: []Grant{{Role: RoleSyntheticEditor, Scope: mustScope(t, "env=dev")}}}
	if !ed.Can(PermSyntheticEdit, dev) || ed.Can(PermSyntheticEdit, prod) || ed.CanGlobal(PermSyntheticEdit) {
		t.Fatal("synthetic-editor scope not applied")
	}
	if !ed.Can(PermRead, dev) || ed.CanAny(PermOperate) || ed.CanAny(PermAdmin) {
		t.Fatal("synthetic-editor has read only besides editing scenarios")
	}
	admin := &Subject{Principal: Principal{AccountEnabled: true}, Grants: []Grant{{Role: RoleAdmin, Scope: mustScope(t, "all")}}}
	if !admin.CanGlobal(PermSyntheticEdit) {
		t.Fatal("admin edits scenarios")
	}
	for _, r := range []Role{RoleViewer, RoleOperator, RoleVaultMaker, RoleVaultApprover} {
		s := &Subject{Principal: Principal{AccountEnabled: true}, Grants: []Grant{{Role: r, Scope: mustScope(t, "all")}}}
		if s.CanAny(PermSyntheticEdit) {
			t.Fatalf("%s edits scenarios", r)
		}
	}
}
