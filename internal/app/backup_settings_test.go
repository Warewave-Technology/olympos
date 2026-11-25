//go:build dev

package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// The wizard defaults new ClickHouse jobs to native when the endpoint is on,
// and it is on only with ingest.url (R14).
func TestBackupSettingsIngestEnabled(t *testing.T) {
	db := testutil.DB(t)
	p, err := authz.UpsertPrincipal(context.Background(), db, authz.Principal{TenantID: matrixTenant, ObjectID: uuid.NewString(),
		UPN: "vic@contoso.com", DisplayName: "vic", UserType: "Member", AccountEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO grants (principal_id, role, scope_selector) VALUES ($1,'viewer','')`, p.ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, yaml string
		want       bool
	}{
		{"no ingest.url", "", false},
		{"ingest.url set", "  ingest: {url: \"http://ingest.test:9444\"}\n", true},
	} {
		ts := httptest.NewServer(wiredHandlerYAML(t, db, c.yaml))
		jar, _ := cookiejar.New(nil)
		cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := cl.Get(ts.URL + "/auth/dev-login?oid=" + p.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		resp, err = cl.Get(ts.URL + "/api/v1/backup/settings")
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			IngestEnabled *bool `json:"ingest_enabled"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		ts.Close()
		if err != nil || resp.StatusCode != http.StatusOK || out.IngestEnabled == nil || *out.IngestEnabled != c.want {
			t.Errorf("%s: %d %+v %v, want ingest_enabled=%v", c.name, resp.StatusCode, out, err, c.want)
		}
	}
}
