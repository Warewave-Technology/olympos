//go:build dev

package vaults_test

// End-to-end tests against real HashiCorp Vault and OpenBao servers in
// Docker (SPEC §11, §18). Each server runs with integrated (raft) storage
// from a config passed through VAULT_LOCAL_CONFIG / BAO_LOCAL_CONFIG, is
// initialized + unsealed through the API by the test, and gets a KV v2 mount
// "secret/" and a KV v1 mount "legacy/". Dev mode is not used because its
// in-memory storage has no raft snapshot endpoint.
//
// The agent tunnel is replaced by a direct dial to the container port
// (transfer mode "compressed" → plain HTTP). Skipped without Docker unless
// OLYMPOS_REQUIRE_DOCKER=1.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/backup"
	_ "github.com/Warewave-Technology/olympos/internal/backup/engines/vault" // registers engine "vault"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/vaults"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

type provider struct {
	name      string // hashicorp | openbao
	container string
	image     string
	envVar    string
	dataDir   string
}

var providers = []provider{
	{"hashicorp", "olympos-m3-vault", "hashicorp/vault:1.18", "VAULT_LOCAL_CONFIG", "/vault/file"},
	{"openbao", "olympos-m3-bao", "openbao/openbao:latest", "BAO_LOCAL_CONFIG", "/openbao/file"},
}

func requireDocker(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker not available: %v", err)
		}
		t.Skipf("docker not available (%v); set OLYMPOS_REQUIRE_DOCKER=1 to fail instead", err)
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

type server_ struct {
	addr      string
	root      string
	unsealKey string
	admin     *vaultapi.Client // root client for setup and assertions only
}

func startServer(t *testing.T, p provider) *server_ {
	t.Helper()
	_ = exec.Command("docker", "rm", "-f", "-v", p.container).Run()
	cfg := map[string]any{
		"storage":       map[string]any{"raft": map[string]any{"path": p.dataDir, "node_id": "n1"}},
		"listener":      []any{map[string]any{"tcp": map[string]any{"address": "0.0.0.0:8200", "tls_disable": true}}},
		"api_addr":      "http://127.0.0.1:8200",
		"cluster_addr":  "http://127.0.0.1:8201",
		"disable_mlock": true,
		"ui":            false,
	}
	cb, _ := json.Marshal(cfg)
	docker(t, "run", "-d", "--name", p.container, "-p", "127.0.0.1::8200", "-e", p.envVar+"="+string(cb), p.image, "server")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "40", p.container).CombinedOutput()
			t.Logf("%s logs:\n%s", p.container, out)
		}
		_ = exec.Command("docker", "rm", "-f", "-v", p.container).Run()
	})
	port := docker(t, "port", p.container, "8200/tcp")
	port = strings.Split(port, "\n")[0]
	s := &server_{addr: port}
	c, err := vaultapi.NewClient(&vaultapi.Config{Address: "http://" + s.addr, HttpClient: &http.Client{Timeout: 90 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	c.ClearToken()
	ctx := context.Background()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := c.Sys().SealStatusWithContext(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not start", p.container)
		}
		time.Sleep(300 * time.Millisecond)
	}
	init, err := c.Sys().InitWithContext(ctx, &vaultapi.InitRequest{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.root, s.unsealKey = init.RootToken, init.KeysB64[0]
	if _, err := c.Sys().UnsealWithContext(ctx, s.unsealKey); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	c.SetToken(s.root)
	for {
		h, err := c.Sys().HealthWithContext(ctx)
		if err == nil && !h.Sealed && !h.Standby {
			if _, err := c.Sys().ListMountsWithContext(ctx); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become active", p.container)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err := c.Sys().MountWithContext(ctx, "secret", &vaultapi.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Sys().MountWithContext(ctx, "legacy", &vaultapi.MountInput{Type: "kv", Options: map[string]string{"version": "1"}}); err != nil {
		t.Fatal(err)
	}
	s.admin = c
	return s
}

// Canary values: never in API responses, logs or the database.
const (
	canaryPre   = "CANARY-pre-existing-7f3e"
	canaryNew   = "CANARY-rotated-pw-91ab"
	canaryKey2  = "CANARY-new-key-55cd"
	canaryPath  = "CANARY-new-path-0d0d"
	canaryCas   = "CANARY-cas-loser-ee11"
	canaryDrift = "CANARY-direct-write-aa77"
)

var canaries = []string{canaryPre, canaryNew, canaryKey2, canaryPath, canaryCas, canaryDrift}

type e2e struct {
	t       *testing.T
	env     *apitest.Env
	svc     *vaults.Service
	cr      *approvals.API
	faults  *approvals.Faults
	srv     *server_
	fx      fixture
	admin   *apitest.Client
	maker   *apitest.Client
	checker *apitest.Client
	bodies  []string
}

func (x *e2e) call(c *apitest.Client, method, path string, body, out any) int {
	x.t.Helper()
	code, raw := c.Raw(method, path, body)
	x.bodies = append(x.bodies, raw)
	if out != nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), out); err != nil {
			x.t.Fatalf("decode %s: %v", raw, err)
		}
	}
	return code
}

func (x *e2e) kv(path string) *vaultapi.KVSecret {
	x.t.Helper()
	s, err := x.srv.admin.KVv2("secret").Get(context.Background(), path)
	if err != nil {
		x.t.Fatalf("root read %s: %v", path, err)
	}
	return s
}

// changeRequest opens a CR as maker and approves it as checker.
func (x *e2e) changeRequest(items ...map[string]any) approvals.ChangeRequest {
	x.t.Helper()
	var cr approvals.ChangeRequest
	if code := x.call(x.maker, "POST", "/api/v1/change-requests", map[string]any{"vault_id": x.fx.vaultID,
		"justification": "e2e change request for " + x.t.Name(), "items": items}, &cr); code != 201 {
		x.t.Fatalf("open: %d %s", code, x.bodies[len(x.bodies)-1])
	}
	var out approvals.ChangeRequest
	if code := x.call(x.checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{"comment": "lgtm"}, &out); code != 200 {
		x.t.Fatalf("approve: %d %s", code, x.bodies[len(x.bodies)-1])
	}
	var sealed int
	_ = x.env.DB.QueryRow(context.Background(), `SELECT count(*) FROM change_items WHERE cr_id = $1 AND (sealed_value IS NOT NULL OR wrapped_dek IS NOT NULL)`, cr.ID).Scan(&sealed)
	if sealed != 0 {
		x.t.Fatalf("sealed values remain after %s", out.Status)
	}
	return out
}

func (x *e2e) refresh() {
	x.t.Helper()
	if err := x.svc.Refresh(context.Background(), x.fx.vaultID); err != nil {
		x.t.Fatalf("refresh: %v", err)
	}
}

func (x *e2e) secret(path string) vaults.SecretDetail {
	x.t.Helper()
	var d vaults.SecretDetail
	if code := x.call(x.admin, "GET", "/api/v1/vaults/"+x.fx.vaultID.String()+"/secrets/"+path+"?mount=secret/", nil, &d); code != 200 {
		x.t.Fatalf("secret %s: %d", path, code)
	}
	return d
}

func TestE2EVaultAndOpenBao(t *testing.T) {
	requireDocker(t)
	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			runE2E(t, p)
		})
	}
}

func runE2E(t *testing.T, p provider) {
	ctx := context.Background()
	srv := startServer(t, p)
	// Pre-existing data (baseline, not drift).
	// A fresh KV v2 mount upgrades its storage in the background: retry.
	for i := 0; ; i++ {
		_, err := srv.admin.KVv2("secret").Put(ctx, "app/db", map[string]any{"USER": "svc", "PASSWORD": canaryPre})
		if err == nil {
			break
		}
		if i > 100 {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := srv.admin.Logical().WriteWithContext(ctx, "legacy/old", map[string]any{"K": canaryPre}); err != nil {
		t.Fatal(err)
	}

	x := &e2e{t: t, srv: srv, faults: &approvals.Faults{}}
	x.env = apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		x.svc = &vaults.Service{DB: e.DB, Log: e.Log, KV: e.KV, KeyVaultName: "local",
			Dial: func(ctx context.Context, _ uuid.UUID, targetID string, opt gateway.DialOptions) (net.Conn, error) {
				if !opt.Compressed || targetID != x.fx.targetID {
					return nil, errors.New("unexpected dial")
				}
				var d net.Dialer
				return d.DialContext(ctx, "tcp", srv.addr)
			}}
		x.cr = &approvals.API{DB: e.DB, Log: e.Log, Envelope: e.Envelope, HMAC: e.HMAC, Applier: x.svc, Inspector: x.svc, Faults: x.faults}
		return []server.Module{&vaults.API{Svc: x.svc, Log: e.Log}, x.cr}
	}})
	x.fx = seed(t, x.env.DB, "prod-"+p.name, map[string]string{"env": "prod"}, "compressed")
	if p.name == "openbao" {
		_, _ = x.env.DB.Exec(ctx, `UPDATE vaults SET provider = 'openbao' WHERE id = $1`, x.fx.vaultID)
	}
	x.svc.RegisterBackup()
	x.admin = x.env.Login(x.env.Principal("root-admin", "Member", "admin"))
	x.maker = x.env.Login(x.env.Principal("mia", "Member", "vault-maker@env=prod"))
	x.checker = x.env.Login(x.env.Principal("carl", "Member", "vault-approver@env=prod"))
	viewer := x.env.Login(x.env.Principal("vic", "Member", "viewer@env=prod"))
	vid := x.fx.vaultID.String()

	// ---- inspect (root token, nothing stored)
	var ins vaults.InspectResult
	if code := x.call(viewer, "POST", "/api/v1/vaults/"+vid+"/inspect", map[string]any{"root_token": srv.root}, nil); code != 403 {
		t.Fatalf("inspect as viewer: %d", code)
	}
	if code := x.call(x.admin, "POST", "/api/v1/vaults/"+vid+"/inspect", map[string]any{"root_token": srv.root}, &ins); code != 200 {
		t.Fatalf("inspect: %d %s", code, x.bodies[len(x.bodies)-1])
	}
	mv := map[string]int{}
	for _, m := range ins.Mounts {
		mv[m.Path] = m.Version
	}
	if ins.Sealed || ins.Version == "" || mv["secret/"] != 2 || mv["legacy/"] != 1 || ins.Storage != "raft" {
		t.Fatalf("inspect result: %+v", ins)
	}
	t.Logf("%s version %s, storage %s", p.name, ins.Version, ins.Storage)

	// ---- configure
	if code := x.call(x.admin, "POST", "/api/v1/vaults/"+vid+"/configure", map[string]any{"root_token": srv.root, "mounts": []string{"secret/", "legacy/"}}, nil); code != 422 {
		t.Fatalf("configure with a KV v1 mount: %d", code)
	}
	var view vaults.View
	if code := x.call(x.admin, "POST", "/api/v1/vaults/"+vid+"/configure", map[string]any{"root_token": "hvs.not-a-valid-token-at-all", "mounts": []string{"secret/"}}, nil); code != 422 {
		t.Fatalf("configure with a bad token: %d", code)
	}
	if code := x.call(x.admin, "POST", "/api/v1/vaults/"+vid+"/configure", map[string]any{"root_token": srv.root, "mounts": []string{"secret"}}, &view); code != 200 {
		t.Fatalf("configure: %d %s", code, x.bodies[len(x.bodies)-1])
	}
	if view.Status != "configured" || view.Version == "" {
		t.Fatalf("configured view: %+v", view)
	}
	pol, err := srv.admin.Sys().GetPolicyWithContext(ctx, "olympos")
	if err != nil || strings.TrimSpace(pol) != strings.TrimSpace(vaults.Policy([]string{"secret/"})) {
		t.Fatalf("policy olympos: %v\n%s", err, pol)
	}
	role, err := srv.admin.Logical().ReadWithContext(ctx, "auth/approle/role/olympos")
	if err != nil || role == nil {
		t.Fatalf("approle: %v", err)
	}
	if ttl(role.Data["secret_id_ttl"]) != 720*3600 || ttl(role.Data["token_ttl"]) != 3600 || ttl(role.Data["token_max_ttl"]) != 86400 ||
		!strings.Contains(fmt.Sprint(role.Data["token_policies"]), "olympos") {
		t.Fatalf("approle settings: %v", role.Data)
	}

	// ---- browse: keys via subkeys, values never
	x.refresh()
	d := x.secret("app/db")
	if strings.Join(d.Keys, ",") != "PASSWORD,USER" || d.CurrentVersion != 1 || !d.Managed {
		t.Fatalf("indexed secret: %+v", d)
	}
	var tree struct{ Items []vaults.SecretSummary }
	x.call(viewer, "GET", "/api/v1/vaults/"+vid+"/tree", nil, &tree)
	if len(tree.Items) != 1 || tree.Items[0].Path != "app/db" || tree.Items[0].Keys != 2 {
		t.Fatalf("tree: %+v", tree.Items)
	}

	// ---- SPEC §18: the Olympos token cannot read a value (403)
	olympos := approleClient(t, x, srv)
	for _, path := range []string{"secret/data/app/db", "legacy/old"} {
		_, err := olympos.Logical().ReadWithContext(ctx, path)
		if vclient.StatusCode(err) != 403 {
			t.Fatalf("reading %s with the Olympos token: %v (want 403)", path, err)
		}
	}
	if sk, err := olympos.Logical().ReadWithDataWithContext(ctx, "secret/subkeys/app/db", map[string][]string{"depth": {"1"}}); err != nil {
		t.Fatalf("subkeys: %v", err)
	} else if b, _ := json.Marshal(sk.Data); strings.Contains(string(b), canaryPre) {
		t.Fatalf("subkeys returned a value: %s", b)
	}
	vclient.RevokeSelf(olympos)

	// ---- create / replace via one merged PATCH, new path via POST cas=0
	cr := x.changeRequest(
		map[string]any{"mount": "secret/", "path": "app/db", "key": "PASSWORD", "op": "replace", "base_version": 1, "value": canaryNew},
		map[string]any{"mount": "secret/", "path": "app/db", "key": "API_KEY", "op": "create", "base_version": 1, "value": canaryKey2},
		map[string]any{"mount": "secret/", "path": "app/new", "key": "TOKEN", "op": "create", "base_version": 0, "value": canaryPath},
	)
	if cr.Status != approvals.StatusApplied {
		t.Fatalf("cr 1: %s %s", cr.Status, cr.Failure)
	}
	s := x.kv("app/db")
	if s.VersionMetadata.Version != 2 || s.Data["PASSWORD"] != canaryNew || s.Data["API_KEY"] != canaryKey2 || s.Data["USER"] != "svc" {
		t.Fatalf("app/db after cr 1: v%d keys %d", s.VersionMetadata.Version, len(s.Data))
	}
	if s := x.kv("app/new"); s.VersionMetadata.Version != 1 || s.Data["TOKEN"] != canaryPath {
		t.Fatalf("app/new after cr 1: v%d", s.VersionMetadata.Version)
	}

	// ---- delete a key (merge patch null)
	cr = x.changeRequest(map[string]any{"mount": "secret/", "path": "app/db", "key": "USER", "op": "delete", "base_version": 2})
	if cr.Status != approvals.StatusApplied {
		t.Fatalf("cr delete: %s %s", cr.Status, cr.Failure)
	}
	s = x.kv("app/db")
	if _, ok := s.Data["USER"]; ok || s.VersionMetadata.Version != 3 || s.Data["PASSWORD"] != canaryNew {
		t.Fatalf("app/db after delete: v%d %v", s.VersionMetadata.Version, keysOf(s.Data))
	}

	// ---- destroy_history
	cr = x.changeRequest(map[string]any{"mount": "secret/", "path": "app/db", "op": "destroy_history", "versions": []int{1}})
	if cr.Status != approvals.StatusApplied {
		t.Fatalf("cr destroy: %s %s", cr.Status, cr.Failure)
	}
	md, err := srv.admin.KVv2("secret").GetMetadata(ctx, "app/db")
	if err != nil || !md.Versions["1"].Destroyed || md.Versions["2"].Destroyed || md.CurrentVersion != 3 {
		t.Fatalf("metadata after destroy: %v %+v", err, md)
	}

	x.refresh()
	d = x.secret("app/db")
	if d.CurrentVersion != 3 || !d.Managed || strings.Join(d.Keys, ",") != "API_KEY,PASSWORD" {
		t.Fatalf("index after changes: %+v", d)
	}
	byOlympos := map[int]bool{}
	for _, v := range d.Versions {
		byOlympos[v.Version] = v.ByOlympos
		if v.Version == 1 && !v.Destroyed {
			t.Fatal("version 1 must show destroyed")
		}
	}
	if byOlympos[1] || !byOlympos[2] || !byOlympos[3] {
		t.Fatalf("by_olympos: %v", byOlympos)
	}
	var open int
	_ = x.env.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE source = 'vault-drift' AND status = 'open'`).Scan(&open)
	if open != 0 {
		t.Fatalf("no drift expected yet, got %d", open)
	}

	// ---- cas conflict → failed with a safe message
	var pending approvals.ChangeRequest
	if code := x.call(x.maker, "POST", "/api/v1/change-requests", map[string]any{"vault_id": x.fx.vaultID, "justification": "this one loses the race",
		"items": []map[string]any{{"mount": "secret/", "path": "app/db", "key": "PASSWORD", "op": "replace", "base_version": 3, "value": canaryCas}}}, &pending); code != 201 {
		t.Fatalf("open cas cr: %d", code)
	}
	// Someone writes directly (break-glass) in the meantime: version 4.
	if _, err := srv.admin.KVv2("secret").Patch(ctx, "app/db", map[string]any{"PASSWORD": canaryDrift}); err != nil {
		t.Fatal(err)
	}
	var failed approvals.ChangeRequest
	if code := x.call(x.checker, "POST", "/api/v1/change-requests/"+pending.ID.String()+"/approve", map[string]any{}, &failed); code != 200 {
		t.Fatalf("approve cas cr: %d", code)
	}
	if failed.Status != approvals.StatusFailed || !strings.Contains(failed.Failure, "check-and-set") {
		t.Fatalf("cas conflict: %s %q", failed.Status, failed.Failure)
	}
	if x.kv("app/db").Data["PASSWORD"] != canaryDrift {
		t.Fatal("failed request must not have written")
	}

	// ---- drift: version 4 was not written by Olympos
	x.refresh()
	x.refresh() // reported once per version
	var ref, title string
	_ = x.env.DB.QueryRow(ctx, `SELECT resource_ref, title FROM findings WHERE source = 'vault-drift' AND status = 'open'`).Scan(&ref, &title)
	if ref != "secret/app/db" || title != "Unmanaged change" {
		t.Fatalf("drift finding: %q %q", ref, title)
	}
	var events int
	_ = x.env.DB.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type = 'vault.unmanaged_write'`).Scan(&events)
	if events != 1 {
		t.Fatalf("vault.unmanaged_write events: %d (want 1)", events)
	}
	if d := x.secret("app/db"); d.Managed || d.CurrentVersion != 4 {
		t.Fatalf("index after drift: %+v", d)
	}
	x.call(x.admin, "GET", "/api/v1/vaults/"+vid, nil, &view)
	if view.Drift != 1 {
		t.Fatalf("vault drift count: %d", view.Drift)
	}
	// Olympos writes over it → back under management, finding resolved.
	cr = x.changeRequest(map[string]any{"mount": "secret/", "path": "app/db", "key": "PASSWORD", "op": "replace", "base_version": 4, "value": canaryNew})
	if cr.Status != approvals.StatusApplied {
		t.Fatalf("re-take: %s %s", cr.Status, cr.Failure)
	}
	x.refresh()
	_ = x.env.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE source = 'vault-drift' AND status = 'open'`).Scan(&open)
	if open != 0 || !x.secret("app/db").Managed {
		t.Fatalf("drift should resolve after an Olympos write (open=%d)", open)
	}

	// ---- raft snapshot through the engine, with the AppRole credential provider
	eng, ok := backup.EngineFor("vault")
	if !ok || eng.Ext() != "snap" {
		t.Fatal("vault engine not registered")
	}
	if _, ok := backup.CredentialProviderFor("vault"); !ok {
		t.Fatal("vault credential provider not registered")
	}
	// The registry is global and the providers' subtests run in parallel:
	// use this subtest's service directly (it is what RegisterBackup installs).
	prov := x.svc.BackupCredential
	ti := backup.TargetInfo{ID: x.fx.targetID, ClusterID: x.fx.clusterID.String(), Namespace: "vault", Service: "vault", Port: 8200,
		Engine: "vault", VaultProvider: p.name}
	ec := backup.EngineContext{Target: ti, UseTLS: false,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srv.addr)
		},
		Credential: func(ctx context.Context) (backup.Credential, error) { return prov(ctx, ti) }}
	ct, err := eng.TestConnection(ctx, ec)
	if err != nil || !ct.OK {
		t.Fatalf("test connection: %v %+v", err, ct)
	}
	cw := &countingWriter{}
	pr, pw := io.Pipe()
	files := make(chan []string, 1)
	go func() { files <- tarNames(pr) }()
	res, err := eng.Run(ctx, ec, io.MultiWriter(cw, pw))
	pw.Close()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	names := <-files
	if cw.n < 1024 || !slices.Contains(names, "SHA256SUMS.sealed") || res.ServerVersion == "" {
		t.Fatalf("snapshot: %d bytes, files %v, %+v", cw.n, names, res)
	}
	t.Logf("%s raft snapshot: %d bytes, files %v", p.name, cw.n, names)

	// ---- secret_id rotation (generate new → store → destroy old)
	var oldAcc string
	_ = x.env.DB.QueryRow(ctx, `SELECT secret_id_accessor FROM vaults WHERE id = $1`, x.fx.vaultID).Scan(&oldAcc)
	oldSID, _ := x.env.KV.GetSecret(ctx, "local", vaults.SecretIDName(x.fx.vaultID))
	if err := x.svc.RotateSecretID(ctx, x.fx.vaultID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	var newAcc, roleID string
	_ = x.env.DB.QueryRow(ctx, `SELECT secret_id_accessor, role_id FROM vaults WHERE id = $1`, x.fx.vaultID).Scan(&newAcc, &roleID)
	if newAcc == oldAcc || newAcc == "" {
		t.Fatal("accessor not rotated")
	}
	probe, _ := vclient.New(vclient.Options{Dial: ec.Dial, ServerName: "vault.vault.svc"})
	if err := vclient.AppRoleLogin(ctx, probe, roleID, oldSID); err == nil {
		t.Fatal("old secret_id must be destroyed")
	}
	probe.Close()
	x.refresh() // new secret_id works

	// ---- root token and values never persisted or logged
	// Positive control: the grep does find what is stored (role_id in the
	// vaults table, the secret_id in the key vault directory).
	if where := occurrences(t, x, roleID); !slices.Contains(where, "table vaults") {
		t.Fatalf("grep control: role_id not found (%v)", where)
	}
	newSID, _ := x.env.KV.GetSecret(ctx, "local", vaults.SecretIDName(x.fx.vaultID))
	if where := occurrences(t, x, string(newSID)); len(where) != 1 || !strings.HasPrefix(where[0], "key vault") {
		t.Fatalf("grep control: secret_id must live only in Key Vault (%v)", where)
	}
	assertAbsent(t, x, srv.root, "root token")
	for _, c := range canaries {
		assertAbsent(t, x, c, "secret value")
	}

	applyFaults(t, x)
}

// applyFaults (F4): the outcome of a Vault write is lost (commit fails after
// the write, or the server dies before the call). The request stays
// 'applying', drift never reports Olympos' own write, and the reconciler
// settles it from the KV metadata.
func applyFaults(t *testing.T, x *e2e) {
	ctx := context.Background()
	lost := errors.New("injected: server killed")
	openApprove := func(path string) approvals.ChangeRequest {
		t.Helper()
		var cr, out approvals.ChangeRequest
		if code := x.call(x.maker, "POST", "/api/v1/change-requests", map[string]any{"vault_id": x.fx.vaultID, "justification": "fault injection " + path,
			"items": []map[string]any{{"mount": "secret/", "path": path, "key": "K", "op": "create", "base_version": 0, "value": canaryNew}}}, &cr); code != 201 {
			t.Fatalf("open %s: %d", path, code)
		}
		if code := x.call(x.checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, &out); code != 200 {
			t.Fatalf("approve %s: %d", path, code)
		}
		if out.Status != approvals.StatusApplying {
			t.Fatalf("%s: status %s, want applying", path, out.Status)
		}
		return out
	}
	backdate := func(id uuid.UUID) {
		t.Helper()
		if _, err := x.env.DB.Exec(ctx, `UPDATE change_requests SET applying_at = now() - interval '3 minutes' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	status := func(id uuid.UUID) (approvals.Status, string) {
		t.Helper()
		var st, code string
		_ = x.env.DB.QueryRow(ctx, `SELECT status, failure_code FROM change_requests WHERE id = $1`, id).Scan(&st, &code)
		return approvals.Status(st), code
	}
	driftOpen := func(ref string) int {
		var n int
		_ = x.env.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE source = 'vault-drift' AND status = 'open' AND resource_ref = $1`, ref).Scan(&n)
		return n
	}

	// Commit lost after Vault wrote v1.
	x.faults.AfterVault = func() error { return lost }
	written := openApprove("app/f4-written")
	x.faults.AfterVault = nil
	if s := x.kv("app/f4-written"); s.VersionMetadata.Version != 1 {
		t.Fatalf("vault write: v%d", s.VersionMetadata.Version)
	}
	x.refresh()
	if driftOpen("secret/app/f4-written") != 0 {
		t.Fatal("Olympos' own write reported as drift while applying")
	}
	if n, _ := x.cr.ReconcileApplying(ctx); n != 0 {
		t.Fatal("reconciled before 2 minutes")
	}
	backdate(written.ID)

	// Server died before the Vault call.
	x.faults.BeforeVault = func() error { return lost }
	unwritten := openApprove("app/f4-unwritten")
	x.faults.BeforeVault = nil
	backdate(unwritten.ID)

	if n, err := x.cr.ReconcileApplying(ctx); err != nil || n != 2 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if st, _ := status(written.ID); st != approvals.StatusApplied {
		t.Fatalf("written: %s", st)
	}
	if st, code := status(unwritten.ID); st != approvals.StatusFailed || code != approvals.FailApplyUnknown {
		t.Fatalf("unwritten: %s %s", st, code)
	}
	var acts, sealed int
	_ = x.env.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE action = 'cr.applied_reconciled' AND object_id = $1`, written.ID.String()).Scan(&acts)
	_ = x.env.DB.QueryRow(ctx, `SELECT count(*) FROM change_items WHERE cr_id = ANY($1) AND (sealed_value IS NOT NULL OR wrapped_dek IS NOT NULL)`,
		[]uuid.UUID{written.ID, unwritten.ID}).Scan(&sealed)
	if acts != 1 || sealed != 0 {
		t.Fatalf("reconciled activity %d, sealed left %d", acts, sealed)
	}
	x.refresh()
	if driftOpen("secret/app/f4-written") != 0 {
		t.Fatal("reconciled write reported as drift")
	}
	if d := x.secret("app/f4-written"); !d.Managed {
		t.Fatalf("reconciled write not managed: %+v", d)
	}
}

func approleClient(t *testing.T, x *e2e, srv *server_) *vclient.Client {
	t.Helper()
	var roleID string
	_ = x.env.DB.QueryRow(context.Background(), `SELECT role_id FROM vaults WHERE id = $1`, x.fx.vaultID).Scan(&roleID)
	sid, err := x.env.KV.GetSecret(context.Background(), "local", vaults.SecretIDName(x.fx.vaultID))
	if err != nil {
		t.Fatalf("secret_id not in key vault: %v", err)
	}
	c, err := vclient.New(vclient.Options{ServerName: "vault.vault.svc",
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srv.addr)
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := vclient.AppRoleLogin(context.Background(), c, roleID, sid); err != nil {
		t.Fatalf("approle login: %v", err)
	}
	return c
}

// occurrences greps the whole database (text, and hex for bytea), the
// captured logs, every API response and the local Key Vault directory for s.
func occurrences(t *testing.T, x *e2e, s string) []string {
	t.Helper()
	ctx := context.Background()
	rows, err := x.env.DB.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	var where []string
	hexed := hex.EncodeToString([]byte(s))
	for _, tbl := range tables {
		var n int
		if err := x.env.DB.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %q t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0`, tbl),
			s, hexed).Scan(&n); err != nil {
			t.Fatalf("grep %s: %v", tbl, err)
		}
		if n > 0 {
			where = append(where, "table "+tbl)
		}
	}
	if strings.Contains(x.env.LogBuf.String(), s) {
		where = append(where, "logs")
	}
	for _, b := range x.bodies {
		if strings.Contains(b, s) {
			where = append(where, "api response")
			break
		}
	}
	_ = filepath.WalkDir(x.env.KV.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(s)) {
			where = append(where, "key vault "+p)
		}
		return nil
	})
	return where
}

func assertAbsent(t *testing.T, x *e2e, s, what string) {
	t.Helper()
	if where := occurrences(t, x, s); len(where) > 0 {
		t.Fatalf("%s found in %v", what, where)
	}
}

func ttl(v any) int {
	switch x := v.(type) {
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case float64:
		return int(x)
	}
	return -1
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func tarNames(r io.Reader) []string {
	defer io.Copy(io.Discard, r) //nolint:errcheck
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			return names
		}
		names = append(names, h.Name)
	}
}
