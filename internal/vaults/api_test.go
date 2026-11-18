package vaults_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/targetid"
	"github.com/Warewave-Technology/olympos/internal/vaults"
)

func TestPolicyHasNoReadOnData(t *testing.T) {
	p := vaults.Policy([]string{"secret/", "team-a/kv/"})
	for _, line := range strings.Split(p, "\n") {
		if strings.Contains(line, "/data/*") && (strings.Contains(line, `"read"`) || strings.Contains(line, `"update"`) || strings.Contains(line, `"list"`)) {
			t.Fatalf("policy grants more than create/patch on data: %s", line)
		}
	}
	for _, want := range []string{
		`path "secret/metadata/*" { capabilities = ["list", "read"] }`,
		`path "secret/subkeys/*" { capabilities = ["read"] }`,
		`path "secret/data/*" { capabilities = ["create", "patch"] }`,
		`path "secret/destroy/*" { capabilities = ["update"] }`,
		`path "team-a/kv/data/*" { capabilities = ["create", "patch"] }`,
		`path "sys/mounts" { capabilities = ["read"] }`,
		`path "sys/storage/raft/snapshot" { capabilities = ["read"] }`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("policy misses %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "sudo") || strings.Contains(p, `"delete"`) {
		t.Fatalf("policy too broad:\n%s", p)
	}
}

type fixture struct {
	clusterID uuid.UUID
	targetID  string
	vaultID   uuid.UUID
}

func seed(t *testing.T, db *store.DB, name string, labels map[string]string, mode string) fixture {
	t.Helper()
	ctx := context.Background()
	var f fixture
	lb, _ := json.Marshal(labels)
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, labels, status, transfer_mode) VALUES ($1, $2, 'online', $3) RETURNING id`,
		name, lb, mode).Scan(&f.clusterID); err != nil {
		t.Fatal(err)
	}
	f.targetID = targetid.Compute(f.clusterID.String(), "vault", "vault", 8200)
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine, vault_provider)
		VALUES ($1, $2, 'vault', 'vault', 8200, 'vault', 'hashicorp')`, f.targetID, f.clusterID); err != nil {
		t.Fatal(err)
	}
	// As inventory ingest does for a Service annotated olympos.io/vault.
	if err := db.QueryRow(ctx, `INSERT INTO vaults (target_id, provider) VALUES ($1, 'hashicorp') RETURNING id`, f.targetID).Scan(&f.vaultID); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestVaultAPIScopeAndRoles(t *testing.T) {
	var svc *vaults.Service
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		svc = &vaults.Service{DB: e.DB, Log: e.Log, KV: e.KV, KeyVaultName: "local",
			Dial: func(context.Context, uuid.UUID, string, gateway.DialOptions) (net.Conn, error) {
				return nil, gateway.ErrAgentOffline
			}}
		return []server.Module{&vaults.API{Svc: svc, Log: e.Log}}
	}})
	prod := seed(t, e.DB, "prod-1", map[string]string{"env": "prod"}, "e2e-tls")
	dev := seed(t, e.DB, "dev-1", map[string]string{"env": "dev"}, "e2e-tls")
	ctx := context.Background()
	_, _ = e.DB.Exec(ctx, `UPDATE vaults SET status = 'configured', kv_mounts = '[{"path":"secret/","version":2,"managed":true}]' WHERE id = $1`, prod.vaultID)
	_, _ = e.DB.Exec(ctx, `INSERT INTO vault_secret_index (vault_id, mount, path, keys, current_version, versions)
		VALUES ($1, 'secret/', 'app/db', '{PASSWORD,USER}', 2, '[{"version":1},{"version":2}]')`, prod.vaultID)
	_, _ = e.DB.Exec(ctx, `INSERT INTO vault_managed_versions (vault_id, mount, path, version, cr_id) VALUES ($1, 'secret/', 'app/db', 2, $2)`,
		prod.vaultID, uuid.New())

	prodViewer := e.Login(e.Principal("vic", "Member", "viewer@env=prod"))
	devAdmin := e.Login(e.Principal("dee", "Member", "admin@env=dev"))
	prodOperator := e.Login(e.Principal("opa", "Member", "operator@env=prod"))

	var list struct{ Items []vaults.View }
	if code := prodViewer.Do("GET", "/api/v1/vaults", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].ID != prod.vaultID {
		t.Fatalf("list in scope: %d %+v", code, list.Items)
	}
	if list.Items[0].Secrets != 1 || list.Items[0].TLSServerName != "vault.vault.svc" || list.Items[0].Target.ID != prod.targetID {
		t.Fatalf("view: %+v", list.Items[0])
	}
	devAdmin.Do("GET", "/api/v1/vaults", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != dev.vaultID {
		t.Fatalf("dev admin list: %+v", list.Items)
	}
	paths := []string{
		"/api/v1/vaults/" + prod.vaultID.String(),
		"/api/v1/vaults/" + prod.vaultID.String() + "/tree",
		"/api/v1/vaults/" + prod.vaultID.String() + "/secrets/app/db?mount=secret/",
	}
	for _, p := range paths {
		if code, body := prodViewer.Raw("GET", p, nil); code != 200 {
			t.Fatalf("GET %s in scope: %d %s", p, code, body)
		}
		if code, _ := devAdmin.Raw("GET", p, nil); code != http.StatusNotFound {
			t.Fatalf("GET %s outside scope: %d (want 404)", p, code)
		}
	}
	var d vaults.SecretDetail
	prodViewer.Do("GET", paths[2], nil, &d)
	if strings.Join(d.Keys, ",") != "PASSWORD,USER" || d.CurrentVersion != 2 || len(d.Versions) != 2 || !d.Versions[1].ByOlympos || d.Versions[0].ByOlympos {
		t.Fatalf("secret detail: %+v", d)
	}
	for _, p := range []string{"/inspect", "/configure"} {
		body := map[string]any{"root_token": "hvs.rootTokenCanary0000000000000000", "mounts": []string{"secret/"}}
		if p == "/inspect" {
			delete(body, "mounts")
		}
		if code, _ := devAdmin.Raw("POST", "/api/v1/vaults/"+prod.vaultID.String()+p, body); code != http.StatusNotFound {
			t.Fatalf("%s outside scope: %d", p, code)
		}
		if code, _ := prodOperator.Raw("POST", "/api/v1/vaults/"+prod.vaultID.String()+p, body); code != http.StatusForbidden {
			t.Fatalf("%s as operator: %d", p, code)
		}
	}
	if code, _ := prodViewer.Raw("POST", "/api/v1/vaults/"+prod.vaultID.String()+"/refresh", nil); code != http.StatusForbidden {
		t.Fatalf("refresh as viewer: %d", code)
	}
	if code, _ := prodOperator.Raw("POST", "/api/v1/vaults/"+prod.vaultID.String()+"/refresh", nil); code != http.StatusAccepted {
		t.Fatalf("refresh as operator: %d", code)
	}
	if strings.Contains(e.LogBuf.String(), "rootTokenCanary") {
		t.Fatal("root token in logs")
	}
	// The API never exposes the AppRole identifiers.
	_, raw := prodViewer.Raw("GET", paths[0], nil)
	if strings.Contains(raw, "role_id") || strings.Contains(raw, "secret_id_ref") {
		t.Fatalf("vault view leaks AppRole details: %s", raw)
	}
}

func TestRootTokenRequiresTLS(t *testing.T) {
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		svc := &vaults.Service{DB: e.DB, Log: e.Log, KV: e.KV, KeyVaultName: "local"}
		return []server.Module{&vaults.API{Svc: svc, Log: e.Log, RequireTLS: true}}
	}})
	f := seed(t, e.DB, "prod-1", map[string]string{"env": "prod"}, "e2e-tls")
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	if code, _ := admin.Raw("POST", "/api/v1/vaults/"+f.vaultID.String()+"/inspect", map[string]any{"root_token": "x"}); code != http.StatusBadRequest {
		t.Fatalf("root token over plain HTTP: %d", code)
	}
}

func TestVaultSearch(t *testing.T) {
	e := apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		svc := &vaults.Service{DB: e.DB, Log: e.Log, KV: e.KV, KeyVaultName: "local"}
		return []server.Module{&vaults.API{Svc: svc, Log: e.Log}}
	}})
	prod := seed(t, e.DB, "prod-weu", map[string]string{"env": "prod", "team": "payments"}, "e2e-tls")
	dev := seed(t, e.DB, "dev-weu", map[string]string{"env": "dev"}, "e2e-tls")
	ctx := context.Background()
	for _, v := range []uuid.UUID{prod.vaultID, dev.vaultID} {
		_, _ = e.DB.Exec(ctx, `INSERT INTO vault_secret_index (vault_id, mount, path, keys, current_version)
			VALUES ($1, 'secret/', 'payments/db', '{PASSWORD,USER}', 1)`, v)
	}
	c := e.Login(e.Principal("vic", "Member", "viewer@env=prod"))
	var res struct{ Items []vaults.SearchHit }
	if code := c.Do("GET", "/api/v1/vaults/search?q=payments", nil, &res); code != 200 {
		t.Fatalf("search: %d", code)
	}
	vaultHits, pathHits := 0, 0
	for _, h := range res.Items {
		if h.ClusterName != "prod-weu" {
			t.Fatalf("result outside scope: %+v", h)
		}
		switch h.Match {
		case "vault":
			vaultHits++ // matched by the cluster label team=payments
		case "path":
			pathHits++
			if h.Path != "payments/db" || h.Keys != 2 {
				t.Fatalf("path hit: %+v", h)
			}
		}
	}
	if vaultHits != 1 || pathHits != 1 {
		t.Fatalf("hits: %+v", res.Items)
	}
	if code := c.Do("GET", "/api/v1/vaults/search?q=p", nil, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("short query: %d", code)
	}
}
