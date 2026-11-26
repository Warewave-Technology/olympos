package postgres_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/postgres"
)

const (
	container  = "olympos-m2b-pg"
	serverName = "orders-pg.db.svc"
	superPW    = "super-Secret-pw-1"
	// backupPW contains ':' and '\' to exercise passfile escaping, and is a
	// canary that must never appear in errors.
	backupPW = `canary:b\ckup-PW-7f3a`
)

var (
	pgAddr  string // 127.0.0.1:port of the container
	caPEM   string
	pgBin   string // directory with pg_dump, pg_dumpall, pg_restore
	skipMsg string
)

func TestMain(m *testing.M) {
	code := func() int {
		if err := setup(); err != nil {
			skipMsg = err.Error()
			fmt.Fprintln(os.Stderr, "postgres engine tests skipped:", skipMsg)
		}
		defer func() { _ = exec.Command("docker", "rm", "-f", "-v", container).Run() }()
		return m.Run()
	}()
	os.Exit(code)
}

func need(t *testing.T) {
	t.Helper()
	if skipMsg != "" {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatal(skipMsg)
		}
		t.Skip(skipMsg)
	}
}

func findPgBin() string {
	for _, d := range []string{os.Getenv("OLYMPOS_PG_BIN"), "/opt/homebrew/opt/libpq/bin", "/usr/lib/postgresql/17/bin", "/usr/lib/postgresql/16/bin"} {
		if d == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(d, "pg_dump")); err == nil {
			return d
		}
	}
	if p, err := exec.LookPath("pg_dump"); err == nil {
		return filepath.Dir(p)
	}
	return ""
}

func setup() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found")
	}
	if pgBin = findPgBin(); pgBin == "" {
		return fmt.Errorf("pg_dump not found (set OLYMPOS_PG_BIN)")
	}
	certPEM, keyPEM, ca, err := makeCerts()
	if err != nil {
		return err
	}
	caPEM = ca
	_ = exec.Command("docker", "rm", "-f", "-v", container).Run()
	script := `set -e
printf '%s' "$SSL_CERT" > /var/lib/postgresql/server.crt
printf '%s' "$SSL_KEY" > /var/lib/postgresql/server.key
chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key
chmod 600 /var/lib/postgresql/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key`
	out, err := exec.Command("docker", "run", "-d", "--name", container, "-e", "POSTGRES_PASSWORD="+superPW,
		"-e", "SSL_CERT="+certPEM, "-e", "SSL_KEY="+keyPEM, "-p", "127.0.0.1::5432",
		"--entrypoint", "sh", "postgres:16-alpine", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker run: %v: %s", err, out)
	}
	out, err = exec.Command("docker", "port", container, "5432/tcp").Output()
	if err != nil {
		return fmt.Errorf("docker port: %v", err)
	}
	pgAddr = strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
	ctx := context.Background()
	var conn *pgx.Conn
	deadline := time.Now().Add(90 * time.Second)
	for {
		conn, err = pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:%s@%s/postgres?sslmode=disable", superPW, pgAddr))
		if err == nil {
			// The entrypoint restarts the server after init; make sure we
			// talk to the final one.
			if err = conn.Ping(ctx); err == nil {
				var inRecovery bool
				if err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err == nil {
					break
				}
			}
			conn.Close(ctx)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("postgres container not ready: %v", err)
		}
		time.Sleep(time.Second)
	}
	time.Sleep(time.Second)
	conn.Close(ctx)
	conn, err = pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:%s@%s/postgres?sslmode=disable", superPW, pgAddr))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	for _, q := range []string{
		`CREATE DATABASE shop`,
		fmt.Sprintf(`CREATE ROLE backup LOGIN PASSWORD '%s'`, strings.ReplaceAll(backupPW, "'", "''")),
		`GRANT pg_read_all_data TO backup`,
		`CREATE ROLE limited LOGIN PASSWORD 'limited-pw-123'`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	shop, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:%s@%s/shop?sslmode=disable", superPW, pgAddr))
	if err != nil {
		return err
	}
	defer shop.Close(ctx)
	for _, q := range []string{
		`CREATE TABLE orders (id serial PRIMARY KEY, item text NOT NULL)`,
		`INSERT INTO orders (item) SELECT 'item-' || g FROM generate_series(1, 500) g`,
		`REVOKE ALL ON orders FROM PUBLIC`,
	} {
		if _, err := shop.Exec(ctx, q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	return nil
}

func makeCerts() (certPEM, keyPEM, caOut string, err error) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "olympos test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), nil
}

// dumpDir builds the PgDumpDir layout <major>/bin/{pg_dump,pg_dumpall}.
func dumpDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command(filepath.Join(pgBin, "pg_dump"), "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	var major int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)[strings.Index(string(out), ")")+1:]), "%d", &major); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	if major < 16 {
		t.Skipf("pg_dump %d < server 16", major)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, fmt.Sprint(major), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"pg_dump", "pg_dumpall"} {
		if err := os.Symlink(filepath.Join(pgBin, tool), filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	// A lower major must never be chosen.
	_ = os.MkdirAll(filepath.Join(dir, "9", "bin"), 0o755)
	return dir
}

// countingConn tracks bytes like a tunnel.
type ec struct {
	dials int
}

func engineContext(t *testing.T, user, pw string, useTLS bool, opts map[string]any, test bool) (backup.EngineContext, *ec) {
	t.Helper()
	counter := &ec{}
	raw, _ := json.Marshal(opts)
	return backup.EngineContext{
		Target:        backup.TargetInfo{ID: "t1", Namespace: "db", Service: "orders-pg", Port: 5432, Engine: "postgresql", TLSServerName: serverName},
		TLSServerName: serverName,
		UseTLS:        useTLS,
		Options:       raw,
		Test:          test,
		Dial: func(ctx context.Context) (net.Conn, error) {
			counter.dials++
			var d net.Dialer
			return d.DialContext(ctx, "tcp", pgAddr)
		},
		Credential: func(ctx context.Context) (backup.Credential, error) {
			return backup.Credential{Username: user, Secret: []byte(pw)}, nil
		},
	}, counter
}

func readZip(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		if f.Method != zip.Store {
			t.Errorf("%s: method %d, want store", f.Name, f.Method)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		out[f.Name] = data
	}
	return out
}

func restoreList(t *testing.T, dump []byte) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "x.dump")
	if err := os.WriteFile(f, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(pgBin, "pg_restore"), "--list", f).CombinedOutput()
	if err != nil {
		t.Fatalf("pg_restore --list: %v: %s", err, out)
	}
	return string(out)
}

func TestRunPlainAllDatabases(t *testing.T) {
	need(t)
	e := &postgres.Engine{DumpDir: dumpDir(t)}
	ectx, _ := engineContext(t, "backup", backupPW, false, nil, false)
	var buf bytes.Buffer
	res, err := e.Run(context.Background(), ectx, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.ServerVersion, "16.") || res.TLS == nil || *res.TLS || !strings.Contains(res.ToolVersion, "pg_dump") {
		t.Fatalf("result: %+v", res)
	}
	files := readZip(t, buf.Bytes())
	for _, want := range []string{"globals.sql", "postgres.dump", "shop.dump"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("zip lacks %s: %v", want, keys(files))
		}
	}
	if !strings.Contains(string(files["globals.sql"]), "CREATE ROLE backup") {
		t.Fatalf("globals: %s", files["globals.sql"])
	}
	list := restoreList(t, files["shop.dump"])
	if !strings.Contains(list, "TABLE DATA public orders") {
		t.Fatalf("pg_restore --list: %s", list)
	}
	// pg_read_all_data includes SELECT on pg_authid, so role passwords are kept.
	if res.Details["globals"] != "full" {
		t.Fatalf("globals=%v", res.Details["globals"])
	}
}

func TestRunTLSVerified(t *testing.T) {
	need(t)
	e := &postgres.Engine{DumpDir: dumpDir(t)}
	ectx, _ := engineContext(t, "backup", backupPW, true, map[string]any{"databases": []string{"shop"}, "tls_ca_pem": caPEM}, false)
	var buf bytes.Buffer
	res, err := e.Run(context.Background(), ectx, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if res.TLS == nil || !*res.TLS {
		t.Fatal("expected TLS")
	}
	files := readZip(t, buf.Bytes())
	if len(files) != 2 || files["shop.dump"] == nil {
		t.Fatalf("files: %v", keys(files))
	}
	if !strings.Contains(restoreList(t, files["shop.dump"]), "TABLE DATA public orders") {
		t.Fatal("no data in dump")
	}

	// Wrong name: verify-full must refuse (no InsecureSkipVerify anywhere).
	bad, _ := engineContext(t, "backup", backupPW, true, map[string]any{"databases": []string{"shop"}, "tls_ca_pem": caPEM}, false)
	bad.TLSServerName = "other.db.svc"
	_, err = e.Run(context.Background(), bad, io.Discard)
	if err == nil || strings.Contains(err.Error(), backupPW) {
		t.Fatalf("wrong server name accepted or password leaked: %v", err)
	}
	// Untrusted CA (system roots): refused too.
	untrusted, _ := engineContext(t, "backup", backupPW, true, map[string]any{"databases": []string{"shop"}}, false)
	if _, err := e.Run(context.Background(), untrusted, io.Discard); err == nil {
		t.Fatal("self-signed cert accepted with system roots")
	}
}

func TestRunDryRunSchemaOnly(t *testing.T) {
	need(t)
	e := &postgres.Engine{DumpDir: dumpDir(t)}
	ectx, _ := engineContext(t, "backup", backupPW, false, map[string]any{"databases": []string{"shop", "postgres"}, "globals": true}, true)
	var buf bytes.Buffer
	if _, err := e.Run(context.Background(), ectx, &buf); err != nil {
		t.Fatal(err)
	}
	files := readZip(t, buf.Bytes())
	if len(files) != 2 || files["shop.dump"] == nil || files["globals.sql"] == nil {
		t.Fatalf("dry run files: %v", keys(files))
	}
	list := restoreList(t, files["shop.dump"])
	if strings.Contains(list, "TABLE DATA") || !strings.Contains(list, "TABLE public orders") {
		t.Fatalf("not schema-only: %s", list)
	}
}

func TestRunErrors(t *testing.T) {
	need(t)
	e := &postgres.Engine{DumpDir: dumpDir(t)}
	ectx, _ := engineContext(t, "backup", "wrong-password-xyz", false, nil, false)
	_, err := e.Run(context.Background(), ectx, io.Discard)
	if err == nil || strings.Contains(err.Error(), "wrong-password-xyz") {
		t.Fatalf("bad password: %v", err)
	}
	ectx, _ = engineContext(t, "backup", backupPW, false, map[string]any{"databases": []string{"nope"}}, false)
	if _, err := e.Run(context.Background(), ectx, io.Discard); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("missing db: %v", err)
	}
	// The limited role cannot read orders: pg_dump fails clearly.
	ectx, _ = engineContext(t, "limited", "limited-pw-123", false, map[string]any{"databases": []string{"shop"}, "globals": false}, false)
	if _, err := e.Run(context.Background(), ectx, io.Discard); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("limited role: %v", err)
	}
	// No suitable pg_dump.
	t.Setenv("PATH", "")
	e2 := &postgres.Engine{DumpDir: t.TempDir()}
	ectx, _ = engineContext(t, "backup", backupPW, false, nil, false)
	if _, err := e2.Run(context.Background(), ectx, io.Discard); err == nil || !strings.Contains(err.Error(), "no pg_dump with major version >= 16") {
		t.Fatalf("missing tool: %v", err)
	}
}

func TestTestConnection(t *testing.T) {
	need(t)
	e := &postgres.Engine{DumpDir: dumpDir(t)}
	ectx, _ := engineContext(t, "backup", backupPW, true, map[string]any{"tls_ca_pem": caPEM}, false)
	ct, err := e.TestConnection(context.Background(), ectx)
	if err != nil {
		t.Fatal(err)
	}
	if !ct.OK || !ct.TLS || !strings.HasPrefix(ct.ServerVersion, "16.") || !contains(ct.Databases, "shop") || !contains(ct.Databases, "postgres") {
		t.Fatalf("connection test: %+v", ct)
	}
	lim, _ := engineContext(t, "limited", "limited-pw-123", false, map[string]any{"databases": []string{"shop"}}, false)
	ct, err = e.TestConnection(context.Background(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if ct.OK {
		t.Fatalf("limited role should fail privileges: %+v", ct)
	}
	found := false
	for _, p := range ct.Privileges {
		if p.Name == "select:shop" && !p.OK && strings.Contains(p.Detail, "public.orders") {
			found = true
		}
	}
	if !found {
		t.Fatalf("privileges: %+v", ct.Privileges)
	}
	bad, _ := engineContext(t, "backup", "nope-"+backupPW, false, nil, false)
	ct, _ = e.TestConnection(context.Background(), bad)
	if ct.OK || ct.Error == "" || strings.Contains(ct.Error, backupPW) || !ct.TLS {
		t.Fatalf("bad password: %+v", ct)
	}
}

func TestProbeTLSNoTLS(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		b := make([]byte, 8)
		_, _ = io.ReadFull(c, b)
		_, _ = c.Write([]byte{'N'})
		c.Close()
	}()
	ok, err := postgres.ProbeTLS(context.Background(), func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", l.Addr().String()) })
	if err != nil || ok {
		t.Fatalf("probe: %v %v", ok, err)
	}
}

func TestFindToolLayout(t *testing.T) {
	if pgBin = findPgBin(); pgBin == "" {
		t.Skip("pg_dump not found")
	}
	dir := dumpDir(t)
	tool, err := postgres.FindTool(context.Background(), dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tool.PgDump, dir) || tool.Major < 16 {
		t.Fatalf("tool: %+v", tool)
	}
	// RHEL PGDG layout (/usr/pgsql-{major}/bin) in a ':' list.
	rhel := t.TempDir()
	m := strconv.Itoa(tool.Major)
	if err := os.MkdirAll(filepath.Join(rhel, "pgsql-"+m, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"pg_dump", "pg_dumpall"} {
		_ = os.Symlink(filepath.Join(pgBin, b), filepath.Join(rhel, "pgsql-"+m, "bin", b))
	}
	t.Setenv("PATH", "")
	got, err := postgres.FindTool(context.Background(), "/nonexistent:"+filepath.Join(rhel, "pgsql-{major}", "bin"), 16)
	if err != nil || !strings.HasPrefix(got.PgDump, rhel) {
		t.Fatalf("{major} layout: %+v %v", got, err)
	}
	if _, err := postgres.FindTool(context.Background(), dir, 99); err == nil {
		t.Fatal("expected no tool for major 99")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// noTLSConn hides the server's TLS support: it answers the SSLRequest with
// 'N' itself, so the real server sees a plain startup.
type noTLSConn struct {
	net.Conn
	pending []byte
}

func (c *noTLSConn) Write(p []byte) (int, error) {
	if bytes.Equal(p, []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}) {
		c.pending = []byte{'N'}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *noTLSConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// F1: e2e-tls mode, target without TLS, server asks for SCRAM-SHA-256: the
// backup runs (the password never crosses the wire) and reports TLS=false so
// the tls.missing finding opens.
func TestRunNoTLSScramAllowed(t *testing.T) {
	need(t)
	e := &postgres.Engine{DumpDir: dumpDir(t)}
	ectx, _ := engineContext(t, "backup", backupPW, true, map[string]any{"databases": []string{"shop"}}, false)
	dial := ectx.Dial
	ectx.Dial = func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return &noTLSConn{Conn: c}, nil
	}
	var buf bytes.Buffer
	res, err := e.Run(context.Background(), ectx, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if res.TLS == nil || *res.TLS {
		t.Fatalf("expected TLS=false: %+v", res)
	}
	if !strings.Contains(restoreList(t, readZip(t, buf.Bytes())["shop.dump"]), "TABLE DATA public orders") {
		t.Fatal("no data in dump")
	}
	ct, err := e.TestConnection(context.Background(), ectx)
	if err != nil || !ct.OK || ct.TLS {
		t.Fatalf("connection test: %+v %v", ct, err)
	}
}
