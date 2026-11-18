//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/targetid"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// labCluster is shared by later milestone tests (enrolled once).
var labClusterID string

// TestM1EnrollInventoryDiscovery installs the agent from the UI-generated
// command and checks enrollment, inventory, discovery and agent RBAC.
func TestM1EnrollInventoryDiscovery(t *testing.T) {
	admin := login(t, devAdminOID, "Lab Admin")
	var clusters struct {
		Items []inventory.Cluster `json:"items"`
	}
	admin.must("GET", "/clusters", nil, &clusters, 200)
	for _, c := range clusters.Items {
		if c.Name == "lab" && c.Status != "revoked" {
			labClusterID = c.ID.String()
		}
	}
	if labClusterID == "" {
		var created inventory.InstallResponse
		admin.must("POST", "/clusters", map[string]any{"name": "lab", "labels": map[string]string{"env": "lab", "team": "platform"}}, &created, 201)
		labClusterID = created.Cluster.ID.String()
		sets := helmSets(created.Command)
		for _, k := range []string{"server", "bootstrapToken", "serverCA", "clusterName"} {
			if sets[k] == "" {
				t.Fatalf("install command lacks %s:\n%s", k, created.Command)
			}
		}
		sets["providerOverride"] = "onprem"
		installAgent(t, "olympos-agent", "olympos-system", sets)
	}

	var c inventory.Cluster
	eventually(t, 3*time.Minute, "agent online with inventory", func() (bool, string) {
		admin.must("GET", "/clusters/"+labClusterID, nil, &c, 200)
		return c.Status == "online" && c.Nodes == 2 && c.APIVersion != "", fmt.Sprintf("%s nodes=%d api=%s", c.Status, c.Nodes, c.APIVersion)
	})
	if c.Provider != "onprem" {
		t.Errorf("provider %q, want onprem", c.Provider)
	}

	var targets struct {
		Items []inventory.Target `json:"items"`
	}
	want := map[string]string{"orders-pg": "postgresql", "vault": "vault", "metrics-ch": "clickhouse", "openbao": ""}
	eventually(t, 2*time.Minute, "targets discovered", func() (bool, string) {
		admin.must("GET", "/targets", nil, &targets, 200)
		got := map[string]string{}
		for _, tg := range targets.Items {
			if tg.ClusterID.String() == labClusterID && tg.Status != "gone" {
				got[tg.Service] = tg.Engine
			}
		}
		for svc, eng := range want {
			if e, ok := got[svc]; !ok || e != eng {
				return false, fmt.Sprintf("%v", got)
			}
		}
		if _, ok := got["not-a-target"]; ok {
			t.Fatal("unannotated service discovered")
		}
		return true, ""
	})
	for _, tg := range targets.Items {
		if tg.Service == "metrics-ch" && tg.Port != 9000 {
			t.Errorf("olympos.io/port=native not honored: port %d", tg.Port)
		}
		if tg.Service == "openbao" && tg.VaultProvider != "openbao" {
			t.Errorf("openbao vault provider %q", tg.VaultProvider)
		}
	}

	// Agent RBAC (SPEC §4.2): no Secrets, no writes, no exec.
	sa := "system:serviceaccount:olympos-system:olympos-agent"
	for _, chk := range []struct {
		args []string
		want string
	}{
		{[]string{"get", "secrets", "-A"}, "no"},
		{[]string{"list", "secrets", "-n", "lab"}, "no"},
		{[]string{"list", "secrets", "-n", "olympos-system"}, "no"},
		{[]string{"get", "secret/olympos-agent-identity", "-n", "olympos-system"}, "yes"},
		{[]string{"get", "secret/other", "-n", "olympos-system"}, "no"},
		{[]string{"create", "pods", "-n", "lab"}, "no"},
		{[]string{"create", "pods/exec", "-n", "lab"}, "no"},
		{[]string{"update", "configmaps", "-n", "lab"}, "no"},
		{[]string{"list", "pods", "-A"}, "yes"},
		{[]string{"create", "jobs", "-n", "olympos-bench"}, "no"}, // bench disabled in this release
	} {
		out, _ := runOK(t, "kubectl", append([]string{"auth", "can-i", "--as", sa}, chk.args...)...)
		if strings.TrimSpace(out) != chk.want {
			t.Errorf("can-i %v = %q, want %q", chk.args, strings.TrimSpace(out), chk.want)
		}
	}

	// Bootstrap token is gone from the identity Secret after enrollment.
	keys := run(t, "kubectl", "-n", "olympos-system", "get", "secret", "olympos-agent-identity", "-o", "jsonpath={.data}")
	if strings.Contains(keys, "bootstrap-token") || !strings.Contains(keys, "tls.crt") {
		t.Errorf("identity secret keys: %s", keys)
	}
	// Agent container exposes no ports and runs read-only, non-root.
	spec := run(t, "kubectl", "-n", "olympos-system", "get", "deploy", "olympos-agent", "-o", "jsonpath={.spec.template.spec}")
	if strings.Contains(spec, "containerPort") || !strings.Contains(spec, `"readOnlyRootFilesystem":true`) || !strings.Contains(spec, `"runAsNonRoot":true`) {
		t.Errorf("agent pod spec not hardened: %s", spec)
	}

	// Dashboard reflects the cluster.
	var d inventory.Dashboard
	admin.must("GET", "/dashboard", nil, &d, 200)
	if d.Totals.Clusters < 1 || d.Totals.AgentsOnline < 1 || d.Totals.Nodes < 2 {
		t.Errorf("dashboard totals: %+v", d.Totals)
	}
}

// TestM1TunnelRealAgent runs a gateway in-process and points a second, real
// agent at it. The gateway can ask for any target_id; the agent must only
// open tunnels to targets it discovered itself (SPEC §0.3, §18).
func TestM1TunnelRealAgent(t *testing.T) {
	kubeconfig(t)
	db := testutil.DB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ca := pki.NewForTest()
	gw := gateway.New(db, ca, log)
	svc := &inventory.Service{DB: db, Log: log}
	svc.Hooks(&gw.Hooks)

	der, key, err := ca.IssueServerCert([]string{"host.docker.internal"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := gw.GRPCServer(gw.TLSConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}))
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer srv.Stop()
	port := l.Addr().(*net.TCPAddr).Port

	var clusterID uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name) VALUES ('lab-inproc') RETURNING id`).Scan(&clusterID); err != nil {
		t.Fatal(err)
	}
	token := "olyb_e2e_" + uuid.NewString()
	if _, err := db.Exec(ctx, `INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		clusterID, gateway.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	ns := "olympos-e2e"
	_, _ = runOK(t, "kubectl", "delete", "namespace", ns, "--wait=true")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	installAgent(t, "olympos-agent-e2e", ns, map[string]string{
		"server":         fmt.Sprintf("host.docker.internal:%d", port),
		"bootstrapToken": token,
		"serverCA":       base64.StdEncoding.EncodeToString(caPEM),
		"clusterName":    "lab-inproc",
	})
	defer func() {
		_, _ = runOK(t, "helm", "uninstall", "olympos-agent-e2e", "-n", ns)
		_, _ = runOK(t, "kubectl", "delete", "namespace", ns, "--wait=false")
	}()

	eventually(t, 2*time.Minute, "in-process agent connected", func() (bool, string) { return gw.Connected(clusterID), "" })
	pgTarget := targetid.Compute(clusterID.String(), "lab", "orders-pg", 5432)
	eventually(t, time.Minute, "orders-pg discovered", func() (bool, string) {
		var n int
		_ = db.QueryRow(ctx, `SELECT count(*) FROM targets WHERE id = $1`, pgTarget).Scan(&n)
		return n == 1, ""
	})

	// Unknown and undiscovered targets are rejected by the agent.
	for _, id := range []string{
		strings.Repeat("ab", 16),
		targetid.Compute(clusterID.String(), "lab", "not-a-target", 5432),
		targetid.Compute(clusterID.String(), "kube-system", "kube-dns", 53),
		"10.96.0.1:443",
	} {
		if _, err := gw.Dial(ctx, clusterID, id, gateway.DialOptions{}); !errors.Is(err, gateway.ErrTunnelRejected) {
			t.Errorf("target %q: want rejection, got %v", id, err)
		}
	}

	// A discovered target works, TLS end-to-end, verified against the lab CA.
	caBytes, err := os.ReadFile(filepath.Join(work(), "lab-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caBytes)
	cfg, err := pgx.ParseConfig("postgres://backup@orders-pg.lab.svc:5432/orders?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = "CANARY-lab-pg-password"
	cfg.TLSConfig = &tls.Config{ServerName: "orders-pg.lab.svc", RootCAs: roots, MinVersion: tls.VersionTLS12}
	var wire gateway.Conn
	// The name only exists inside the cluster; the tunnel does the routing.
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := gw.Dial(ctx, clusterID, pgTarget, gateway.DialOptions{})
		wire = c
		return c, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("postgres through tunnel: %v", err)
	}
	var ver string
	var ssl bool
	if err := conn.QueryRow(ctx, `SELECT version(), ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&ver, &ssl); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	if !ssl || !strings.Contains(ver, "PostgreSQL 16") {
		t.Fatalf("expected TLS to PostgreSQL 16, got ssl=%v %s", ssl, ver)
	}
	if wire.WireBytes() == 0 {
		t.Error("wire bytes not counted")
	}

	// Revocation drops the stream and the agent cannot come back.
	if err := gw.Revoke(ctx, db, clusterID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if gw.Connected(clusterID) {
		t.Fatal("revoked agent still connected")
	}
	time.Sleep(20 * time.Second) // agent backoff + retry
	if gw.Connected(clusterID) {
		t.Fatal("revoked agent reconnected")
	}
}
