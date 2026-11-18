package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/authz"
)

func TestLoginRequiresGrant(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	nobody := e.Principal("nobody", "Member")
	c := e.Login(nobody)
	if code := c.Do("GET", "/api/v1/me", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("principal without grants got a session: %d", code)
	}
}

func TestBootstrapAdminsOnlyWhenEmpty(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	ctx := context.Background()
	n, err := authz.BootstrapAdmins(ctx, e.DB, apitest.TenantID, []string{"aaaaaaaa-0000-0000-0000-000000000001"})
	if err != nil || n != 1 {
		t.Fatalf("bootstrap: %d %v", n, err)
	}
	n, _ = authz.BootstrapAdmins(ctx, e.DB, apitest.TenantID, []string{"aaaaaaaa-0000-0000-0000-000000000002"})
	if n != 0 {
		t.Fatal("bootstrap applied with non-empty grants table")
	}
}

func TestCSRFRequired(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	csrf := admin.CSRF
	admin.CSRF = ""
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "c1"}, nil); code != http.StatusForbidden {
		t.Fatalf("POST without CSRF: %d", code)
	}
	admin.CSRF = "wrong"
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "c1"}, nil); code != http.StatusForbidden {
		t.Fatalf("POST with wrong CSRF: %d", code)
	}
	admin.CSRF = csrf
	if code := admin.Do("POST", "/api/v1/clusters", map[string]any{"name": "c1"}, nil); code != http.StatusCreated {
		t.Fatalf("POST with CSRF: %d", code)
	}
}

func TestIdleSessionExpires(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	c := e.Login(e.Principal("v", "Member", "viewer"))
	if code := c.Do("GET", "/api/v1/me", nil, nil); code != 200 {
		t.Fatal(code)
	}
	_, _ = e.DB.Exec(context.Background(), `UPDATE sessions SET last_seen_at = now() - interval '31 minutes'`)
	if code := c.Do("GET", "/api/v1/me", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("idle session still valid: %d", code)
	}
}

func TestGrantRules(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	admin := e.Login(e.Principal("admin", "Member", "admin"))
	guest := e.Principal("guest_ext", "Guest")
	member := e.Principal("member", "Member")

	code, body := admin.Raw("POST", "/api/v1/grants", map[string]any{"object_id": guest.ObjectID, "roles": []string{"vault-approver"}, "scope": "all"})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "guest") {
		t.Fatalf("guest approver: %d %s", code, body)
	}
	if code := admin.Do("POST", "/api/v1/grants", map[string]any{"object_id": guest.ObjectID, "roles": []string{"viewer"}, "scope": "env=dev"}, nil); code != http.StatusCreated {
		t.Fatalf("guest viewer: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/grants", map[string]any{"object_id": member.ObjectID, "roles": []string{"operator", "vault-maker"}, "scope": "env=prod"}, nil); code != http.StatusCreated {
		t.Fatalf("member grant: %d", code)
	}
	var n int
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE event_type = 'grant.changed'`).Scan(&n)
	if n != 3 {
		t.Fatalf("grant.changed events: %d", n)
	}
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM activity_log WHERE action = 'grant.created'`).Scan(&n)
	if n != 3 {
		t.Fatalf("grant audit rows: %d", n)
	}
	viewer := e.Login(e.Principal("viewer", "Member", "viewer"))
	if code := viewer.Do("POST", "/api/v1/grants", map[string]any{"object_id": member.ObjectID, "roles": []string{"admin"}}, nil); code != http.StatusForbidden {
		t.Fatalf("viewer created grant: %d", code)
	}
	// Last admin cannot be revoked.
	var gs struct {
		Items []struct {
			ID        string `json:"id"`
			Role      string `json:"role"`
			Principal struct {
				DisplayName string `json:"display_name"`
			} `json:"principal"`
		} `json:"items"`
	}
	admin.Do("GET", "/api/v1/grants", nil, &gs)
	for _, g := range gs.Items {
		if g.Role == "admin" && g.Principal.DisplayName == "admin" {
			if code := admin.Do("DELETE", "/api/v1/grants/"+g.ID, nil, nil); code != http.StatusConflict {
				t.Fatalf("last admin revoked: %d", code)
			}
		}
	}
}

func TestActivityLogIsAppendOnly(t *testing.T) {
	e := apitest.New(t, apitest.Options{})
	e.Login(e.Principal("a", "Member", "viewer"))
	if _, err := e.DB.Exec(context.Background(), `UPDATE activity_log SET action = 'x'`); err == nil {
		t.Fatal("activity_log update allowed")
	}
	if _, err := e.DB.Exec(context.Background(), `DELETE FROM activity_log`); err == nil {
		t.Fatal("activity_log delete allowed")
	}
}
