package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
)

// Integration test against real single-node raft servers in Docker (dev
// mode has inmem storage and no raft snapshots). The images are the lab's
// (test/e2e/manifests/targets.yaml). Skipped without Docker unless
// OLYMPOS_REQUIRE_DOCKER=1.

type itProvider struct {
	name, image, envVar, dataDir string
}

var itProviders = []itProvider{
	{"hashicorp", "hashicorp/vault:1.20", "VAULT_LOCAL_CONFIG", "/vault/file"},
	{"openbao", "openbao/openbao:2.4.1", "BAO_LOCAL_CONFIG", "/openbao/file"},
}

const itCanary = "CANARY-restored-secret-3d7a"

func itRequireDocker(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatal("docker not found")
		}
		t.Skip("docker not available")
	}
	if out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("docker info: %v %s", err, out)
		}
		t.Skipf("docker daemon not available (%v); set OLYMPOS_REQUIRE_DOCKER=1 to fail instead", err)
	}
}

func itDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

type itServer struct {
	addr      string // host:port
	root      string
	unsealKey string
	admin     *vaultapi.Client
}

// itStart runs a raft server, initializes it (one key share) and unseals it.
func itStart(t *testing.T, p itProvider, container string) *itServer {
	t.Helper()
	_ = exec.Command("docker", "rm", "-f", container).Run()
	cfg := map[string]any{
		"storage":       map[string]any{"raft": map[string]any{"path": p.dataDir, "node_id": "n1"}},
		"listener":      []any{map[string]any{"tcp": map[string]any{"address": "0.0.0.0:8200", "tls_disable": true}}},
		"api_addr":      "http://127.0.0.1:8200",
		"cluster_addr":  "http://127.0.0.1:8201",
		"disable_mlock": true,
		"ui":            false,
	}
	cb, _ := json.Marshal(cfg)
	itDocker(t, "run", "-d", "--name", container, "-p", "127.0.0.1::8200", "-e", "SKIP_SETCAP=true",
		"-e", p.envVar+"="+string(cb), p.image, "server")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "40", container).CombinedOutput()
			t.Logf("%s logs:\n%s", container, out)
		}
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})
	addr := strings.Split(itDocker(t, "port", container, "8200/tcp"), "\n")[0]
	s := &itServer{addr: addr}
	s.admin = itClient(t, addr, "")
	ctx := context.Background()
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := s.admin.Sys().SealStatusWithContext(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not start", container)
		}
		time.Sleep(300 * time.Millisecond)
	}
	init, err := s.admin.Sys().InitWithContext(ctx, &vaultapi.InitRequest{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.root, s.unsealKey = init.RootToken, init.KeysB64[0]
	s.unseal(t, s.unsealKey)
	s.admin.SetToken(s.root)
	s.waitActive(t, s.admin)
	return s
}

func itClient(t *testing.T, addr, token string) *vaultapi.Client {
	t.Helper()
	c, err := vaultapi.NewClient(&vaultapi.Config{Address: "http://" + addr, HttpClient: &http.Client{Timeout: 90 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	c.ClearNamespace()
	if token == "" {
		c.ClearToken()
	} else {
		c.SetToken(token)
	}
	return c
}

func (s *itServer) unseal(t *testing.T, key string) {
	t.Helper()
	st, err := s.admin.Sys().UnsealWithContext(context.Background(), key)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if st.Sealed {
		t.Fatal("still sealed after unseal")
	}
}

// waitActive waits until c's token can list mounts (the node is active).
func (s *itServer) waitActive(t *testing.T, c *vaultapi.Client) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		h, err := c.Sys().HealthWithContext(ctx)
		if err == nil && !h.Sealed && !h.Standby {
			if _, err = c.Sys().ListMountsWithContext(ctx); err == nil {
				return
			}
		}
		last = err
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("not active: %v", last)
}

func (s *itServer) engineContext(token string) backup.EngineContext {
	return backup.EngineContext{
		Target: backup.TargetInfo{ID: "restore-target", Namespace: "lab", Service: "vault-new"},
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", s.addr)
		},
		Credential: func(context.Context) (backup.Credential, error) {
			return backup.Credential{Secret: []byte(token)}, nil
		},
	}
}

// token creates a token with policy (and the default policy unless
// noDefault: without it a token cannot call sys/capabilities-self).
func (s *itServer) token(t *testing.T, policy, hcl string, noDefault bool) string {
	t.Helper()
	ctx := context.Background()
	if err := s.admin.Sys().PutPolicyWithContext(ctx, policy, hcl); err != nil {
		t.Fatal(err)
	}
	sec, err := s.admin.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{Policies: []string{policy}, NoDefaultPolicy: noDefault, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	return sec.Auth.ClientToken
}

func TestRestoreIntegration(t *testing.T) {
	itRequireDocker(t)
	for _, p := range itProviders {
		t.Run(p.name, func(t *testing.T) {
			ctx := context.Background()
			src := itStart(t, p, "olympos-t9-"+p.name+"-src")
			if err := src.admin.Sys().MountWithContext(ctx, "secret", &vaultapi.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := src.admin.KVv2("secret").Put(ctx, "app/db", map[string]any{"password": itCanary}); err != nil {
				t.Fatal(err)
			}
			var snap bytes.Buffer
			if err := src.admin.Sys().RaftSnapshotWithContext(ctx, &snap); err != nil {
				t.Fatalf("snapshot: %v", err)
			}

			dst := itStart(t, p, "olympos-t9-"+p.name+"-dst")
			forceHCL := `path "sys/storage/raft/snapshot-force" { capabilities = ["update", "sudo"] }`
			weak := dst.token(t, "olympos-weak", `path "sys/storage/raft/snapshot" { capabilities = ["read"] }`, false)
			// Without the default policy capabilities-self answers 403:
			// refused, as the inspector cannot show the token may restore.
			noDefault := dst.token(t, "olympos-restore", forceHCL, true)
			tok := dst.token(t, "olympos-restore", forceHCL, false)
			// Vault requires both update and sudo on snapshot-force.
			updateOnly := dst.token(t, "olympos-update-only", `path "sys/storage/raft/snapshot-force" { capabilities = ["update"] }`, false)
			sudoOnly := dst.token(t, "olympos-sudo-only", `path "sys/storage/raft/snapshot-force" { capabilities = ["sudo"] }`, false)

			// The inspector: a token without the capability is refused.
			for name, bad := range map[string]string{"weak": weak, "no default policy": noDefault, "update only": updateOnly, "sudo only": sudoOnly} {
				r, err := Engine{}.InspectRestoreTarget(ctx, dst.engineContext(bad), nil)
				if err != nil {
					t.Fatalf("inspect (%s): %v", name, err)
				}
				if fields, _ := restore.CheckReport("vault", nil, r); fields["vault_token"] == "" {
					t.Fatalf("%s token not refused: %+v", name, r)
				}
			}
			r, err := Engine{}.InspectRestoreTarget(ctx, dst.engineContext(tok), nil)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			if fields, _ := restore.CheckReport("vault", nil, r); len(fields) > 0 || !r.Initialized || r.Sealed || !r.CanSnapshotForce {
				t.Fatalf("report %+v, refusals %v", r, fields)
			}
			t.Logf("target %s %s: initialized, unsealed, token may snapshot-force", p.name, r.ServerVersion)

			// The restore.
			rc := backup.RestoreContext{EngineContext: dst.engineContext(tok), RequestID: "it", Snapshot: bytes.NewReader(snap.Bytes()),
				Databases: []string{}, Progress: func(backup.Progress) {}}
			res, err := Engine{}.Restore(ctx, rc)
			if res != nil {
				for _, n := range res.Notes {
					t.Logf("note: %s", n)
				}
			}
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
			if len(res.Items) != 1 || res.Items[0].Status != "succeeded" || res.Items[0].Bytes != int64(snap.Len()) {
				t.Fatalf("items %+v (snapshot %d bytes)", res.Items, snap.Len())
			}
			for _, s := range append(append([]string{}, res.Notes...), res.Items[0].Error) {
				if strings.Contains(s, tok) {
					t.Fatalf("token in the result: %s", s)
				}
			}

			// The target now holds the source's keyring: unseal it with
			// the source's key if it resealed, then read the source's
			// secret with the source's root token.
			deadline := time.Now().Add(60 * time.Second)
			var st *vaultapi.SealStatusResponse
			for time.Now().Before(deadline) {
				if st, err = dst.admin.Sys().SealStatusWithContext(ctx); err == nil {
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
			if st == nil {
				t.Fatalf("seal status after the restore: %v", err)
			}
			t.Logf("after the restore: sealed=%v", st.Sealed)
			if st.Sealed {
				dst.unseal(t, src.unsealKey)
			}
			restored := itClient(t, dst.addr, src.root)
			dst.waitActive(t, restored)
			kv, err := restored.KVv2("secret").Get(ctx, "app/db")
			if err != nil {
				t.Fatalf("read the restored secret: %v", err)
			}
			if kv.Data["password"] != itCanary {
				t.Fatalf("restored secret %v", kv.Data)
			}
			// The target's own root token and the request's token are gone.
			for name, old := range map[string]string{"target root": dst.root, "request": tok} {
				if _, err := itClient(t, dst.addr, old).Auth().Token().LookupSelfWithContext(ctx); err == nil {
					t.Errorf("the %s token still works after the restore", name)
				}
			}
		})
	}
}
