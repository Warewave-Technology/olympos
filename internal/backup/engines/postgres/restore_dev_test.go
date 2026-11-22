//go:build dev

package postgres_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/postgres"
	"github.com/Warewave-Technology/olympos/internal/restore"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// The restore tests back a seeded database of the dev Postgres (`make
// dev-db`, PostgreSQL 16) up with the engine and restore it into a new
// PostgreSQL 17 server in a container, over verified TLS like a new target
// in e2e-tls mode. pg_restore 17 (CI's and the image's newest) cannot
// restore into 16, which is tested too.

func devDSN() string {
	if dsn := os.Getenv("OLYMPOS_TEST_PG_DSN"); dsn != "" {
		return dsn
	}
	return testutil.DefaultDSN
}

// devAdmin connects to the dev Postgres, or skips (fails with
// OLYMPOS_REQUIRE_DB=1).
func devAdmin(t *testing.T) (*pgx.Conn, *url.URL) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, devDSN())
	if err != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DB") == "1" {
			t.Fatalf("postgres not reachable: %v", err)
		}
		t.Skipf("postgres not reachable (%v); run `make dev-db`", err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	u, _ := url.Parse(devDSN())
	return c, u
}

// restoreToolDir is a <major>/bin layout with pg_dump, pg_dumpall and
// pg_restore.
func restoreToolDir(t *testing.T) string {
	t.Helper()
	bin := findPgBin()
	if bin == "" {
		t.Skip("pg_dump not found (set OLYMPOS_PG_BIN)")
	}
	pgBin = bin
	dir := dumpDir(t)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "9" {
			continue
		}
		if err := os.Symlink(filepath.Join(bin, "pg_restore"), filepath.Join(dir, e.Name(), "bin", "pg_restore")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func devContext(u *url.URL, user, pw string, opts map[string]any) backup.EngineContext {
	raw, _ := json.Marshal(opts)
	return backup.EngineContext{
		Target:  backup.TargetInfo{ID: "t-restore", Namespace: "db", Service: "dev-pg", Port: 5432, Engine: "postgresql"},
		Options: raw,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", u.Host)
		},
		Credential: func(ctx context.Context) (backup.Credential, error) {
			return backup.Credential{Username: user, Secret: []byte(pw)}, nil
		},
	}
}

// memObject is a blob.Object over a backup in memory.
type memObject struct{ *bytes.Reader }

func (memObject) Close() error { return nil }

// progressLog records what a restore reported.
type progressLog struct {
	mu      sync.Mutex
	phases  []string
	created []string
}

func (p *progressLog) report(pr backup.Progress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.phases) == 0 || p.phases[len(p.phases)-1] != pr.Phase {
		p.phases = append(p.phases, pr.Phase)
	}
	p.created = append([]string{}, pr.Created...)
}

func randSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func execAll(t *testing.T, c *pgx.Conn, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := c.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func connectDB(t *testing.T, u *url.URL, db, user, pw string) *pgx.Conn {
	t.Helper()
	v := *u
	v.Path = "/" + db
	v.User = url.UserPassword(user, pw)
	c, err := pgx.Connect(context.Background(), v.String())
	if err != nil {
		t.Fatalf("connect %s: %v", db, err)
	}
	return c
}

func queryOne[T any](t *testing.T, c *pgx.Conn, q string, args ...any) T {
	t.Helper()
	var v T
	if err := c.QueryRow(context.Background(), q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

func item(t *testing.T, res *backup.RestoreResult, name string) backup.RestoreItem {
	t.Helper()
	for _, it := range res.Items {
		if it.Name == name {
			return it
		}
	}
	t.Fatalf("no item %s in %+v", name, res.Items)
	return backup.RestoreItem{}
}

// target17 is a PostgreSQL 17 server in a container.
type target17 struct {
	u  *url.URL // superuser, no TLS (test queries)
	ca string   // CA of its certificate (for serverName)
}

// startTarget17 runs a PostgreSQL 17 server with TLS in a container.
func startTarget17(t *testing.T) target17 {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv("OLYMPOS_REQUIRE_DOCKER") == "1" {
			t.Fatal("docker not found")
		}
		t.Skip("docker not found")
	}
	certPEM, keyPEM, ca, err := makeCerts()
	if err != nil {
		t.Fatal(err)
	}
	name := "olympos-restore-pg17-" + randSuffix()
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	script := `set -e
printf '%s' "$SSL_CERT" > /var/lib/postgresql/server.crt
printf '%s' "$SSL_KEY" > /var/lib/postgresql/server.key
chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key
chmod 600 /var/lib/postgresql/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key`
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD="+superPW,
		"-e", "SSL_CERT="+certPEM, "-e", "SSL_KEY="+keyPEM, "-p", "127.0.0.1::5432",
		"--entrypoint", "sh", "postgres:17-alpine", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	out, err = exec.Command("docker", "port", name, "5432/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	addr := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
	u, _ := url.Parse(fmt.Sprintf("postgres://postgres:%s@%s/postgres?sslmode=disable", url.QueryEscape(superPW), addr))
	ctx := context.Background()
	deadline := time.Now().Add(90 * time.Second)
	for {
		c, err := pgx.Connect(ctx, u.String())
		if err == nil {
			var inRecovery bool
			err = c.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery)
			c.Close(ctx)
			if err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("postgres 17 container not ready: %v", err)
		}
		time.Sleep(time.Second)
	}
	// The entrypoint restarts the server after init; make sure the final
	// one answers.
	time.Sleep(time.Second)
	for {
		c, err := pgx.Connect(ctx, u.String())
		if err == nil {
			c.Close(ctx)
			return target17{u: u, ca: ca}
		}
		if time.Now().After(deadline) {
			t.Fatalf("postgres 17 container not ready: %v", err)
		}
		time.Sleep(time.Second)
	}
}

// targetContext dials the container in e2e-tls mode, verifying its
// certificate with the request's CA.
func targetContext(tg target17, user, pw string) backup.EngineContext {
	ec := devContext(tg.u, user, pw, map[string]any{"tls_ca_pem": tg.ca})
	ec.UseTLS = true
	ec.TLSServerName = serverName
	ec.Target.TLSServerName = serverName
	return ec
}

func TestRestoreDev(t *testing.T) {
	admin, du := devAdmin(t)
	devUser := du.User.Username()
	devPW, _ := du.User.Password()
	dir := restoreToolDir(t)
	tg := startTarget17(t)
	tu := tg.u
	target := connectDB(t, tu, "postgres", "postgres", superPW)
	t.Cleanup(func() { target.Close(context.Background()) })
	ctx := context.Background()
	e := &postgres.Engine{DumpDir: dir}

	sfx := randSuffix()
	src, owner, reader, plain := "rs_shop_"+sfx, "rs_owner_"+sfx, "rs_reader_"+sfx, "rs_cdb_"+sfx
	const plainPW = "rs-plain-PW-1"
	t.Cleanup(func() {
		for _, db := range []string{src, src + "_orig"} {
			_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, db))
		}
		for _, r := range []string{owner, reader} {
			_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+r)
		}
	})

	// Seed the source: a database owned by a role of its own, with a grant
	// to another role and a membership between them.
	execAll(t, admin,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'rs-owner-pw'`, owner),
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN`, reader),
		fmt.Sprintf(`GRANT %s TO %s`, reader, owner),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, src, owner),
		fmt.Sprintf(`ALTER DATABASE %s SET work_mem = '8MB'`, src),
		fmt.Sprintf(`COMMENT ON DATABASE %s IS 'restore test'`, src),
	)
	sc := connectDB(t, du, src, devUser, devPW)
	execAll(t, sc,
		fmt.Sprintf(`CREATE SCHEMA shop AUTHORIZATION %s`, owner),
		`CREATE TABLE shop.orders (id serial PRIMARY KEY, item text NOT NULL)`,
		`CREATE TABLE shop.lines (order_id int REFERENCES shop.orders, qty int)`,
		`INSERT INTO shop.orders (item) SELECT 'item-' || g FROM generate_series(1, 500) g`,
		`INSERT INTO shop.lines SELECT g, g FROM generate_series(1, 500) g`,
		`CREATE VIEW shop.big AS SELECT * FROM shop.orders WHERE id > 250`,
		fmt.Sprintf(`ALTER TABLE shop.orders OWNER TO %s`, owner),
		fmt.Sprintf(`ALTER TABLE shop.lines OWNER TO %s`, owner),
		fmt.Sprintf(`GRANT SELECT ON shop.orders TO %s`, reader),
	)
	sc.Close(ctx)

	// Back it up with the engine, as a run would.
	var buf bytes.Buffer
	if _, err := e.Run(ctx, devContext(du, devUser, devPW, map[string]any{"databases": []string{src}}), &buf); err != nil {
		t.Fatalf("backup: %v", err)
	}
	archive := buf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	var dumpSize int64
	for _, f := range zr.File {
		if f.Name == src+".dump" {
			dumpSize = int64(f.UncompressedSize64)
		}
	}

	if _, ok := restore.InspectorFor("postgresql"); !ok {
		t.Fatal("no inspector registered for postgresql")
	}
	if r, ok := backup.RestorerFor("postgresql"); !ok || r == nil {
		t.Fatal("no restorer registered for postgresql")
	}
	inspect := func(user, pw string) *restore.TargetReport {
		t.Helper()
		rep, err := e.InspectRestoreTarget(ctx, targetContext(tg, user, pw), []string{src})
		if err != nil {
			t.Fatalf("inspect: %v", err)
		}
		return rep
	}
	runOn := func(ec backup.EngineContext, superuser bool, opts map[string]any) (*backup.RestoreResult, *progressLog, error) {
		t.Helper()
		raw, _ := json.Marshal(opts)
		pl := &progressLog{}
		res, err := e.Restore(ctx, backup.RestoreContext{
			EngineContext: ec,
			Archive:       memObject{bytes.NewReader(archive)},
			Databases:     []string{src},
			Options:       raw,
			Superuser:     superuser,
			Progress:      pl.report,
		})
		return res, pl, err
	}
	run := func(user, pw string, superuser bool, opts map[string]any) (*backup.RestoreResult, *progressLog, error) {
		t.Helper()
		return runOn(targetContext(tg, user, pw), superuser, opts)
	}
	checkRows := func(user, pw string) *pgx.Conn {
		t.Helper()
		c := connectDB(t, tu, src, user, pw)
		if n := queryOne[int64](t, c, `SELECT count(*) FROM shop.orders`); n != 500 {
			t.Fatalf("orders: %d rows", n)
		}
		if n := queryOne[int64](t, c, `SELECT count(*) FROM shop.lines`); n != 500 {
			t.Fatalf("lines: %d rows", n)
		}
		return c
	}

	t.Run("superuser", func(t *testing.T) {
		// The reader exists on the target already, as a login of its own:
		// the restore must leave it alone.
		execAll(t, target, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'target-own-pw'`, reader))
		rep := inspect("postgres", superPW)
		if !rep.Superuser || len(rep.Existing) != 0 || !strings.HasPrefix(rep.ServerVersion, "17") {
			t.Fatalf("report %+v", rep)
		}
		res, pl, err := run("postgres", superPW, true, map[string]any{"globals": true, "superuser": true})
		if err != nil {
			t.Fatalf("restore: %v (%+v)", err, res)
		}
		g := item(t, res, "globals.sql")
		if g.Status != "succeeded" || !strings.Contains(strings.Join(g.Skipped, "\n"), "role "+reader+": exists on the target, not changed") {
			t.Fatalf("globals %+v", g)
		}
		it := item(t, res, src)
		if it.Status != "succeeded" || it.Tables != 2 || it.Bytes != dumpSize || it.Error != "" {
			t.Fatalf("item %+v", it)
		}
		if strings.Join(res.Created, ",") != src || strings.Join(pl.created, ",") != src {
			t.Fatalf("created %v, progress %v", res.Created, pl.created)
		}
		if strings.Join(pl.phases, ",") != "globals,restore" {
			t.Fatalf("phases %v", pl.phases)
		}
		if !queryOne[bool](t, target, `SELECT rolcanlogin FROM pg_roles WHERE rolname = $1`, reader) {
			t.Fatal("the existing reader role was changed")
		}
		if queryOne[bool](t, target, `SELECT pg_has_role($1, $2, 'MEMBER')`, owner, reader) {
			t.Fatal("membership in an existing role was granted")
		}
		c := checkRows("postgres", superPW)
		defer c.Close(ctx)
		// Owners, grants and the database's own entries.
		if o := queryOne[string](t, c, `SELECT tableowner FROM pg_tables WHERE schemaname = 'shop' AND tablename = 'orders'`); o != owner {
			t.Fatalf("table owner %s", o)
		}
		if o := queryOne[string](t, c, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()`); o != owner {
			t.Fatalf("database owner %s", o)
		}
		if !queryOne[bool](t, c, `SELECT has_table_privilege($1, 'shop.orders', 'SELECT')`, reader) {
			t.Fatal("grant to the reader not restored")
		}
		if s := queryOne[string](t, c, `SELECT array_to_string(setconfig, ',') FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase
			WHERE d.datname = current_database() AND s.setrole = 0`); s != "work_mem=8MB" {
			t.Fatalf("database setting %q", s)
		}
		if s := queryOne[string](t, c, `SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = current_database()`); s != "restore test" {
			t.Fatalf("comment %q", s)
		}
	})

	t.Run("existing with user objects", func(t *testing.T) {
		if rep := inspect("postgres", superPW); rep.Existing[src] != true {
			t.Fatalf("report %+v", rep)
		}
		res, _, err := run("postgres", superPW, true, map[string]any{"globals": false})
		if err != nil {
			t.Fatal(err)
		}
		it := item(t, res, src)
		if it.Status != "failed" || !strings.Contains(it.Error, "exists on the target with user objects") || len(res.Created) != 0 {
			t.Fatalf("result %+v", res)
		}
		if !strings.Contains(strings.Join(res.Notes, "\n"), "turned off for this request") {
			t.Fatalf("notes %v", res.Notes)
		}
	})

	t.Run("existing empty database is restored into", func(t *testing.T) {
		execAll(t, target, fmt.Sprintf(`DROP DATABASE %s WITH (FORCE)`, src), fmt.Sprintf(`CREATE DATABASE %s`, src))
		// An extension's objects are not user objects.
		ext := connectDB(t, tu, src, "postgres", superPW)
		execAll(t, ext, `CREATE EXTENSION pg_trgm`)
		ext.Close(ctx)
		if rep := inspect("postgres", superPW); len(rep.Existing) != 1 || rep.Existing[src] != false {
			t.Fatalf("report %+v", rep)
		}
		res, _, err := run("postgres", superPW, true, map[string]any{"globals": false})
		if err != nil {
			t.Fatal(err)
		}
		it := item(t, res, src)
		if it.Status != "succeeded" || len(res.Created) != 0 || !strings.Contains(strings.Join(it.Skipped, "\n"), "restored into it") {
			t.Fatalf("result %+v", res)
		}
		checkRows("postgres", superPW).Close(ctx)
	})

	t.Run("not a superuser", func(t *testing.T) {
		execAll(t, target, fmt.Sprintf(`DROP DATABASE %s WITH (FORCE)`, src),
			fmt.Sprintf(`CREATE ROLE %s LOGIN CREATEDB PASSWORD '%s'`, plain, plainPW))
		rep := inspect(plain, plainPW)
		if rep.Superuser || len(rep.Existing) != 0 {
			t.Fatalf("report %+v", rep)
		}
		res, pl, err := run(plain, plainPW, false, map[string]any{"globals": false, "superuser": false})
		if err != nil {
			t.Fatalf("restore: %v (%+v)", err, res)
		}
		for _, it := range res.Items {
			if it.Name == "globals.sql" {
				t.Fatalf("globals restored without a superuser: %+v", it)
			}
		}
		if !strings.Contains(strings.Join(res.Notes, "\n"), "not a superuser") {
			t.Fatalf("notes %v", res.Notes)
		}
		it := item(t, res, src)
		if it.Status != "succeeded" || it.Tables != 2 || strings.Join(res.Created, ",") != src || strings.Join(pl.created, ",") != src {
			t.Fatalf("result %+v", res)
		}
		c := checkRows(plain, plainPW)
		defer c.Close(ctx)
		// --no-owner --no-privileges: everything belongs to the login.
		if o := queryOne[string](t, c, `SELECT tableowner FROM pg_tables WHERE schemaname = 'shop' AND tablename = 'orders'`); o != plain {
			t.Fatalf("table owner %s", o)
		}
		if o := queryOne[string](t, c, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()`); o != plain {
			t.Fatalf("database owner %s", o)
		}
		if queryOne[bool](t, c, `SELECT has_table_privilege($1, 'shop.orders', 'SELECT')`, reader) {
			t.Fatal("grant restored with --no-privileges")
		}
		if s := queryOne[string](t, c, `SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = current_database()`); s != "restore test" {
			t.Fatalf("comment %q", s)
		}
	})

	t.Run("a password never shows in errors", func(t *testing.T) {
		res, err := e.Restore(ctx, backup.RestoreContext{
			EngineContext: targetContext(tg, plain, "wrong-"+plainPW),
			Archive:       memObject{bytes.NewReader(archive)},
			Databases:     []string{src},
			Progress:      func(backup.Progress) {},
		})
		if err == nil {
			t.Fatalf("restore with a wrong password: %+v", res)
		}
		if strings.Contains(err.Error(), plainPW) {
			t.Fatalf("password in %q", err)
		}
	})

	t.Run("pg_restore 17 into PostgreSQL 16 is refused before writing", func(t *testing.T) {
		execAll(t, admin, fmt.Sprintf(`ALTER DATABASE %s RENAME TO %s_orig`, src, src))
		res, _, err := runOn(devContext(du, devUser, devPW, nil), true, map[string]any{"globals": false})
		if err != nil {
			t.Fatal(err)
		}
		it := item(t, res, src)
		if it.Status != "failed" || !strings.Contains(it.Error, "cannot restore into PostgreSQL 16") || len(res.Created) != 0 {
			t.Fatalf("result %+v", res)
		}
		if queryOne[bool](t, admin, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, src) {
			t.Fatal("a database was created")
		}
	})
}

func TestFindRestoreTool(t *testing.T) {
	bin := findPgBin()
	if bin == "" {
		t.Skip("pg_dump not found")
	}
	pgBin = bin
	dir := dumpDir(t) // pg_dump and pg_dumpall only
	t.Setenv("PATH", "")
	if tool, err := postgres.FindTool(context.Background(), dir, 16); err != nil || tool.PgRestore != "" {
		t.Fatalf("backup tool: %+v %v", tool, err)
	}
	if _, err := postgres.FindRestoreTool(context.Background(), dir, 16); err == nil || !strings.Contains(err.Error(), "no pg_restore") {
		t.Fatalf("restore tool without pg_restore: %v", err)
	}
	dir = restoreToolDir(t)
	tool, err := postgres.FindRestoreTool(context.Background(), dir, 16)
	if err != nil || !strings.HasPrefix(tool.PgRestore, dir) {
		t.Fatalf("restore tool: %+v %v", tool, err)
	}
}
