//go:build dev

package destinations_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/destinations"
	"github.com/Warewave-Technology/olympos/internal/server"
)

func TestDestinationsAPI(t *testing.T) {
	ep := azurite(t)
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&destinations.API{DB: e.DB, Log: e.Log, KV: e.KV, Env: e.Envelope}}
	}})
	ctx := context.Background()
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	scopedAdmin := e.Login(e.Principal("sam", "Member", "admin@env=prod"))
	op := e.Login(e.Principal("olga", "Member", "operator"))
	viewer := e.Login(e.Principal("vic", "Member", "viewer"))

	c := newContainer(t, ep)
	good := containerSAS(t, c, permsRCWT, time.Now().Add(60*24*time.Hour))
	withDelete := containerSAS(t, c, permsRCWTD, time.Now().Add(60*24*time.Hour))
	weak := containerSAS(t, c, permsRW, time.Now().Add(60*24*time.Hour))
	canaries := []string{sigOf(good), sigOf(withDelete), sigOf(weak)}
	for _, s := range canaries[:2] {
		if dec, err := url.QueryUnescape(s); err == nil {
			canaries = append(canaries, dec)
		}
	}
	checkNoSecret := func(where, s string) {
		t.Helper()
		for _, c := range canaries {
			if c != "" && strings.Contains(s, c) {
				t.Fatalf("SAS signature leaked in %s", where)
			}
		}
	}
	input := func(name, token string) map[string]any {
		return map[string]any{"name": name, "account": devAccount, "container": c, "prefix": "olympos", "auth": "sas_token",
			"endpoint_override": ep, "sas": map[string]any{"source": "stored", "value": token}}
	}

	// Permissions: admin with scope all only.
	for _, cl := range []*apitest.Client{viewer, op, scopedAdmin} {
		if code := cl.Do("POST", "/api/v1/destinations", input("x", good), nil); code != 403 {
			t.Fatalf("%s create: %d", cl.P.DisplayName, code)
		}
		if code := cl.Do("POST", "/api/v1/destinations/test", input("x", good), nil); code != 403 {
			t.Fatalf("%s test: %d", cl.P.DisplayName, code)
		}
	}

	// Create with a correct SAS.
	code, body := admin.Raw("POST", "/api/v1/destinations", input("primary", good))
	checkNoSecret("create response", body)
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	var d destinations.View
	admin.Do("GET", "/api/v1/destinations", nil, nil)
	var list struct{ Items []destinations.View }
	if code, body := viewer.Raw("GET", "/api/v1/destinations", nil); code != 200 {
		t.Fatalf("viewer list: %d", code)
	} else {
		checkNoSecret("list", body)
	}
	viewer.Do("GET", "/api/v1/destinations", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: %+v", list)
	}
	d = list.Items[0]
	if d.SASSource != "stored" || d.SASRef != "" || d.SASPermissions != "rcwt" || d.SASExpiresAt == nil || d.LastTestOK == nil || !*d.LastTestOK ||
		d.LastTest == nil || d.LastTest.CanDelete || d.Prefix != "olympos" || d.Auth != "sas_token" {
		t.Fatalf("destination: %+v", d)
	}

	// Duplicate name → 409 before probing.
	if code := admin.Do("POST", "/api/v1/destinations", input("primary", good), nil); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}

	// SAS with d: saved, but never silently.
	var risky destinations.View
	code, body = admin.Raw("POST", "/api/v1/destinations", input("risky", withDelete))
	checkNoSecret("risky create", body)
	if code != 201 {
		t.Fatalf("risky create: %d %s", code, body)
	}
	admin.Do("GET", "/api/v1/destinations", nil, &list)
	for _, x := range list.Items {
		if x.Name == "risky" {
			risky = x
		}
	}
	if !risky.LastTest.CanDelete || !strings.Contains(body, "can delete blobs") {
		t.Fatalf("missing can-delete warning: %s", body)
	}

	// SAS without c/t: 422 with the report, nothing saved.
	var failed destinations.TestFailed
	if code := admin.Do("POST", "/api/v1/destinations", input("weak", weak), &failed); code != 422 || failed.Test == nil || failed.Test.OK ||
		strings.Join(failed.Test.SAS.Missing, ",") != "c,t" {
		t.Fatalf("weak: %d %+v", code, failed)
	}
	// Managed identity without a server credential: 422.
	if code := admin.Do("POST", "/api/v1/destinations", map[string]any{"name": "mi", "account": "stolympos", "container": "backups",
		"auth": "managed_identity"}, &failed); code != 422 || !strings.Contains(failed.Error, "managed identity") {
		t.Fatalf("mi: %d %+v", code, failed)
	}
	// Validation.
	if code, body := admin.Raw("POST", "/api/v1/destinations", map[string]any{"name": "", "account": "Bad_Account", "container": "x",
		"auth": "sas_token", "prefix": "../etc"}); code != 422 || !strings.Contains(body, "account") || !strings.Contains(body, "prefix") ||
		!strings.Contains(body, "container") || !strings.Contains(body, "\"sas\"") {
		t.Fatalf("validation: %d %s", code, body)
	}

	// Key Vault reference.
	if err := e.KV.SetSecret(ctx, "kv-weu", "backup-sas", []byte(good)); err != nil {
		t.Fatal(err)
	}
	var kvd destinations.View
	in := input("kvref", "")
	in["sas"] = map[string]any{"source": "keyvault_ref", "ref": "kv://kv-weu/backup-sas"}
	if code, body := admin.Raw("POST", "/api/v1/destinations", in); code != 201 {
		t.Fatalf("kv create: %d %s", code, body)
	} else {
		checkNoSecret("kv create", body)
	}
	admin.Do("GET", "/api/v1/destinations", nil, &list)
	for _, x := range list.Items {
		if x.Name == "kvref" {
			kvd = x
		}
	}
	if kvd.SASSource != "keyvault_ref" || kvd.SASRef != "kv://kv-weu/backup-sas" {
		t.Fatalf("kv destination: %+v", kvd)
	}
	in["sas"] = map[string]any{"source": "keyvault_ref", "ref": "kv://kv-weu/missing"}
	in["name"] = "kvmissing"
	if code := admin.Do("POST", "/api/v1/destinations", in, nil); code != 422 {
		t.Fatalf("kv missing: %d", code)
	}

	// PATCH: 403 / 404, rename re-tests with the stored SAS, new SAS replaces the credential.
	if code := viewer.Do("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"name": "p2"}, nil); code != 403 {
		t.Fatalf("viewer patch: %d", code)
	}
	if code := admin.Do("PATCH", "/api/v1/destinations/"+uuid.NewString(), map[string]any{"name": "p2"}, nil); code != 404 {
		t.Fatalf("patch missing: %d", code)
	}
	var patched destinations.View
	if code := admin.Do("PATCH", "/api/v1/destinations/"+d.ID.String(), map[string]any{"name": "primary-2"}, &patched); code != 200 ||
		patched.Name != "primary-2" || patched.SASSource != "stored" {
		t.Fatalf("rename: %d %+v", code, patched)
	}
	var oldCred uuid.UUID
	_ = e.DB.QueryRow(ctx, `SELECT sas_credential_id FROM destinations WHERE id = $1`, risky.ID).Scan(&oldCred)
	code, body = admin.Raw("PATCH", "/api/v1/destinations/"+risky.ID.String(), map[string]any{"sas": map[string]any{"source": "stored", "value": good}})
	checkNoSecret("patch", body)
	if code != 200 || strings.Contains(body, "can delete blobs") {
		t.Fatalf("replace SAS: %d %s", code, body)
	}
	var n int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id = $1`, oldCred).Scan(&n)
	if n != 0 {
		t.Fatal("replaced SAS credential must be removed")
	}
	if code := admin.Do("PATCH", "/api/v1/destinations/"+risky.ID.String(), map[string]any{"sas": map[string]any{"source": "stored", "value": weak}}, nil); code != 422 {
		t.Fatalf("patch to weak SAS: %d", code)
	}

	// Saved and unsaved tests.
	var rep destinations.Report
	if code := viewer.Do("POST", "/api/v1/destinations/"+d.ID.String()+"/test", nil, nil); code != 403 {
		t.Fatalf("viewer test: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/destinations/"+uuid.NewString()+"/test", nil, nil); code != 404 {
		t.Fatalf("test missing: %d", code)
	}
	if code := admin.Do("POST", "/api/v1/destinations/"+kvd.ID.String()+"/test", nil, &rep); code != 200 || !rep.OK {
		t.Fatalf("saved test: %d %+v", code, rep)
	}
	if code, body := admin.Raw("POST", "/api/v1/destinations/test", input("", withDelete)); code != 200 || !strings.Contains(body, `"can_delete":true`) {
		t.Fatalf("unsaved test: %d %s", code, body)
	} else {
		checkNoSecret("unsaved test", body)
	}

	// DELETE: 409 when a job references it, 204 otherwise (credential removed too).
	var cl uuid.UUID
	if err := e.DB.QueryRow(ctx, `INSERT INTO clusters (name) VALUES ('prod') RETURNING id`).Scan(&cl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port) VALUES ('t1', $1, 'db', 'pg', 5432)`, cl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(ctx, `INSERT INTO backup_jobs (target_id, destination_id, cron) VALUES ('t1', $1, '@daily')`, d.ID); err != nil {
		t.Fatal(err)
	}
	if code := viewer.Do("DELETE", "/api/v1/destinations/"+d.ID.String(), nil, nil); code != 403 {
		t.Fatalf("viewer delete: %d", code)
	}
	if code := admin.Do("DELETE", "/api/v1/destinations/"+d.ID.String(), nil, nil); code != 409 {
		t.Fatalf("delete in use: %d", code)
	}
	var kvCred uuid.UUID
	_ = e.DB.QueryRow(ctx, `SELECT sas_credential_id FROM destinations WHERE id = $1`, kvd.ID).Scan(&kvCred)
	if code := admin.Do("DELETE", "/api/v1/destinations/"+kvd.ID.String(), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id = $1`, kvCred).Scan(&n)
	if n != 0 {
		t.Fatal("credential of deleted destination must be removed")
	}
	if code := admin.Do("DELETE", "/api/v1/destinations/"+kvd.ID.String(), nil, nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}

	// Activity log and no secrets anywhere.
	rows, _ := e.DB.Query(ctx, `SELECT action, details::text FROM activity_log WHERE object_type = 'destination' ORDER BY at`)
	var actions []string
	for rows.Next() {
		var a, det string
		_ = rows.Scan(&a, &det)
		checkNoSecret("activity "+a, det)
		actions = append(actions, a)
	}
	rows.Close()
	want := "destination.created,destination.created,destination.created,destination.updated,destination.updated,destination.tested,destination.tested,destination.deleted"
	if strings.Join(actions, ",") != want {
		t.Fatalf("activity: %v", actions)
	}
	var reports string
	_ = e.DB.QueryRow(ctx, `SELECT string_agg(last_test_report::text, ' ') FROM destinations`).Scan(&reports)
	checkNoSecret("last_test_report", reports)
	checkNoSecret("logs", e.LogBuf.String())
	if strings.Contains(e.LogBuf.String(), "sig=") && !strings.Contains(e.LogBuf.String(), "sig=[REDACTED]") {
		t.Fatal("SAS query in logs")
	}
}
