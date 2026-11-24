// Package postgres is the PostgreSQL backup engine (SPEC §10.2): pg_dump -Fc
// per database plus pg_dumpall --globals-only, run on the server against a
// local listener bridged to the agent tunnel, streamed into one zip.
package postgres

import (
	"github.com/Warewave-Technology/olympos/internal/targettls"

	"archive/zip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/tunnelbridge"
)

// DefaultDumpDir holds <major>/bin/pg_dump (Debian layout).
const DefaultDumpDir = "/usr/lib/postgresql"

var dumpDir atomic.Value

// SetDumpDir sets the directory containing <major>/bin/pg_dump
// (config backup.pgDumpDir). Call before workers start.
func SetDumpDir(dir string) {
	if dir == "" {
		dir = DefaultDumpDir
	}
	dumpDir.Store(dir)
}

func currentDumpDir() string {
	if v, ok := dumpDir.Load().(string); ok && v != "" {
		return v
	}
	return DefaultDumpDir
}

func init() { backup.RegisterEngine(&Engine{}) }

// Engine implements backup.Engine for PostgreSQL.
type Engine struct {
	// DumpDir overrides SetDumpDir (tests).
	DumpDir string
}

func (e *Engine) dir() string {
	if e.DumpDir != "" {
		return e.DumpDir
	}
	return currentDumpDir()
}

func (e *Engine) Name() string        { return "postgresql" }
func (e *Engine) Ext() string         { return "zip" }
func (e *Engine) ContentType() string { return "application/zip" }

// Options are the job's engine_options for PostgreSQL.
type Options struct {
	// Databases to dump; empty = every non-template database.
	Databases []string `json:"databases"`
	// Globals: include pg_dumpall --globals-only (default true).
	Globals *bool `json:"globals"`
	// TLSCAPEM: CA bundle (PEM) to verify the target; default system roots.
	TLSCAPEM string `json:"tls_ca_pem"`
}

func parseOptions(raw json.RawMessage) (Options, error) {
	var o Options
	if len(raw) == 0 {
		return o, nil
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return o, fmt.Errorf("invalid engine_options: %w", err)
	}
	return o, nil
}

func (o Options) globals() bool { return o.Globals == nil || *o.Globals }

func (o Options) rootCAs(trustSystem bool) (*x509.CertPool, error) {
	if strings.TrimSpace(o.TLSCAPEM) == "" {
		// Configured target CA bundle (+ system pool when trusted).
		return targettls.Roots(trustSystem), targettls.Usable(trustSystem, false)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(o.TLSCAPEM)) {
		return nil, errors.New("engine_options.tls_ca_pem holds no PEM certificate")
	}
	return p, nil
}

// sslRequest is the PostgreSQL SSLRequest message.
var sslRequest = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

// ProbeTLS asks the server whether it accepts TLS (SSLRequest → 'S'/'N').
func ProbeTLS(ctx context.Context, dial func(ctx context.Context) (net.Conn, error)) (bool, error) {
	c, err := dial(ctx)
	if err != nil {
		return false, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(sslRequest); err != nil {
		return false, fmt.Errorf("tls probe: %w", err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		return false, fmt.Errorf("tls probe: %w", err)
	}
	switch b[0] {
	case 'S':
		return true, nil
	case 'N':
		return false, nil
	}
	return false, fmt.Errorf("tls probe: unexpected response %q (not a PostgreSQL server?)", b[0])
}

// session is the per-call TLS decision and connection settings.
type session struct {
	ec     backup.EngineContext
	opts   Options
	useTLS bool // speak (verified) TLS with the target
	tlsOK  bool // the target offers TLS
	// guard: e2e-tls mode but the target has no TLS. Every connection is
	// wrapped in authGuard so only SCRAM-SHA-256 gets the password (F1).
	guard   bool
	rootCAs *x509.CertPool
	cred    backup.Credential
	// toolDir is the engine's pg_dump layout (restores pick pg_restore).
	toolDir string
}

func (e *Engine) open(ctx context.Context, ec backup.EngineContext) (*session, error) {
	opts, err := parseOptions(ec.Options)
	if err != nil {
		return nil, err
	}
	roots, rootsErr := opts.rootCAs(ec.TrustSystemRoots)
	if rootsErr != nil && !errors.Is(rootsErr, targettls.ErrNoRoots) {
		return nil, rootsErr
	}
	s := &session{ec: ec, opts: opts, rootCAs: roots}
	s.tlsOK, err = ProbeTLS(ctx, ec.Dial)
	if err != nil {
		return nil, err
	}
	s.useTLS = ec.UseTLS && s.tlsOK
	s.guard = ec.UseTLS && !s.tlsOK
	if s.useTLS && rootsErr != nil {
		return nil, rootsErr
	}
	return s, nil
}

// dial opens a tunnel, guarded when the password must not travel in clear.
func (s *session) dial(ctx context.Context) (net.Conn, error) {
	c, err := s.ec.Dial(ctx)
	if err != nil || !s.guard {
		return c, err
	}
	return guardAuth(c), nil
}

func (s *session) trustSystem() bool { return s.ec.TrustSystemRoots || targettls.SystemRoots() }

func (s *session) serverName() string {
	if s.ec.TLSServerName != "" {
		return s.ec.TLSServerName
	}
	return s.ec.Target.TLSServerName
}

// connect opens a pgx connection through the tunnel. No address from the
// environment or DNS is used: every connection goes through ec.Dial.
func (s *session) connect(ctx context.Context, db string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, err
	}
	cfg.Host = s.serverName()
	cfg.Port = uint16(s.ec.Target.Port)
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	cfg.User = s.cred.Username
	cfg.Password = string(s.cred.Secret)
	cfg.Database = db
	cfg.Fallbacks = nil
	cfg.ValidateConnect = nil
	cfg.ConnectTimeout = 30 * time.Second
	cfg.RuntimeParams = map[string]string{"application_name": "olympos"}
	cfg.LookupFunc = func(ctx context.Context, host string) ([]string, error) { return []string{host}, nil }
	var g *authGuard
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := s.dial(ctx)
		g, _ = c.(*authGuard)
		return c, err
	}
	cfg.TLSConfig = nil
	if s.useTLS {
		cfg.TLSConfig = &tls.Config{ServerName: s.serverName(), RootCAs: s.rootCAs, MinVersion: tls.VersionTLS12}
	}
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil && g != nil && g.Err() != nil {
		return nil, g.Err()
	}
	return c, err
}

// connectAny connects to the first database that accepts the login.
func (s *session) connectAny(ctx context.Context) (*pgx.Conn, error) {
	cands := []string{"postgres", "template1"}
	if len(s.opts.Databases) > 0 {
		cands = append([]string{s.opts.Databases[0]}, cands...)
	}
	var firstErr error
	for _, db := range cands {
		c, err := s.connect(ctx, db)
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "3D000" { // invalid_catalog_name: try the next one
			return nil, err
		}
	}
	return nil, firstErr
}

type serverInfo struct {
	versionNum int
	version    string
	databases  []string
	superuser  bool
	readAll    bool
	authid     bool // can read pg_authid (role passwords)
	user       string
}

func (si serverInfo) major() int { return si.versionNum / 10000 }

func inspect(ctx context.Context, c *pgx.Conn) (serverInfo, error) {
	var si serverInfo
	err := c.QueryRow(ctx, `SELECT current_setting('server_version_num')::int, current_setting('server_version'), current_user,
		(SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
		CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pg_read_all_data')
		     THEN pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') ELSE false END,
		has_table_privilege('pg_catalog.pg_authid', 'SELECT')`).
		Scan(&si.versionNum, &si.version, &si.user, &si.superuser, &si.readAll, &si.authid)
	if err != nil {
		return si, fmt.Errorf("inspect server: %w", err)
	}
	rows, err := c.Query(ctx, `SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname`)
	if err != nil {
		return si, fmt.Errorf("list databases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return si, err
		}
		si.databases = append(si.databases, d)
	}
	return si, rows.Err()
}

// selected returns the databases to dump, verifying requested ones exist.
func (s *session) selected(si serverInfo) ([]string, error) {
	if len(s.opts.Databases) == 0 {
		if len(si.databases) == 0 {
			return nil, errors.New("no databases to back up")
		}
		return si.databases, nil
	}
	have := map[string]bool{}
	for _, d := range si.databases {
		have[d] = true
	}
	var missing []string
	for _, d := range s.opts.Databases {
		if !have[d] {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("databases not found or not connectable: %s", strings.Join(missing, ", "))
	}
	return s.opts.Databases, nil
}

// ---------------------------------------------------------------- run

// Run dumps globals and each database into a streaming zip on w.
func (e *Engine) Run(ctx context.Context, ec backup.EngineContext, w io.Writer) (*backup.RunResult, error) {
	cred, err := ec.Credential(ctx)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	s, err := e.open(ctx, ec)
	if err != nil {
		return nil, err
	}
	s.cred = cred
	tlsUsed := s.useTLS
	res := &backup.RunResult{TLS: &tlsUsed, Details: map[string]any{}}

	conn, err := s.connectAny(ctx)
	if err != nil {
		return res, fmt.Errorf("connect: %w", err)
	}
	si, err := inspect(ctx, conn)
	conn.Close(context.Background())
	if err != nil {
		return res, err
	}
	res.ServerVersion = si.version
	dbs, err := s.selected(si)
	if err != nil {
		return res, err
	}
	if ec.Test {
		dbs = dbs[:1]
	}
	tool, err := FindTool(ctx, e.dir(), si.major())
	if err != nil {
		return res, err
	}
	res.ToolVersion = tool.Version

	tmp, err := os.MkdirTemp("", "olympos-pg-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return res, err
	}
	env, err := s.childEnv(tmp)
	if err != nil {
		return res, err
	}
	sslArgs, err := s.sslParams(tmp, tool.Major)
	if err != nil {
		return res, err
	}

	zw := zip.NewWriter(w)
	files := map[string]string{}
	entry := func(name string) (io.Writer, error) {
		return zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Modified: time.Now().UTC()})
	}
	globalsMode := ""
	if s.opts.globals() {
		args := []string{"--globals-only", "--no-password", "-l", dbs[0]}
		globalsMode = "full"
		if !si.authid {
			args = append(args, "--no-role-passwords")
			globalsMode = "no-role-passwords"
		}
		zf, err := entry("globals.sql")
		if err != nil {
			return res, err
		}
		if err := s.runTool(ctx, tool.PgDumpAll, args, s.conninfo(dbs[0], sslArgs), env, zf); err != nil {
			return res, err
		}
		files["globals.sql"] = ""
	}
	for _, db := range dbs {
		name := entryName(db)
		zf, err := entry(name)
		if err != nil {
			return res, err
		}
		args := []string{"-Fc", "--no-password"}
		if ec.Test {
			args = append(args, "--schema-only")
		}
		if err := s.runTool(ctx, tool.PgDump, args, s.conninfo(db, sslArgs), env, zf); err != nil {
			return res, err
		}
		files[name] = db
	}
	if err := zw.Close(); err != nil {
		return res, fmt.Errorf("finish zip: %w", err)
	}
	res.Details["databases"] = dbs
	res.Details["files"] = files
	res.Details["format"] = "zip: globals.sql (pg_dumpall --globals-only) + <database>.dump (pg_dump -Fc)"
	res.Details["globals"] = globalsMode
	res.Details["schema_only"] = ec.Test
	res.Details["pg_dump_major"] = tool.Major
	res.Details["restore"] = "unzip; psql -f globals.sql postgres; for each <db>.dump: pg_restore --create -d postgres <db>.dump (the new server's pg_restore, major >= " +
		strconv.Itoa(tool.Major) + ")"
	return res, nil
}

// entryName maps a database name to a zip entry name.
func entryName(db string) string {
	n := strings.NewReplacer("/", "_", "\\", "_", "\x00", "_").Replace(db)
	if strings.HasPrefix(n, ".") || n == "globals.sql" {
		n = "_" + n
	}
	return n + ".dump"
}

// childEnv is the whole environment of pg_dump: nothing is inherited from
// the server (no PG* variables, no HOME with ~/.pgpass). The password goes
// in a 0600 passfile inside the private temp dir.
func (s *session) childEnv(tmp string) ([]string, error) {
	env := []string{"HOME=" + tmp, "PGSYSCONFDIR=" + tmp, "LC_ALL=C", "PGCONNECT_TIMEOUT=30"}
	pw := s.cred.Secret
	if len(pw) == 0 {
		return env, nil
	}
	if strings.ContainsAny(string(pw), "\n\r") {
		return nil, errors.New("password contains a newline, which libpq cannot use")
	}
	esc := strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(string(pw))
	f := filepath.Join(tmp, "pgpass")
	if err := os.WriteFile(f, []byte("*:*:*:*:"+esc+"\n"), 0o600); err != nil {
		return nil, err
	}
	return append(env, "PGPASSFILE="+f), nil
}

// sslParams returns libpq TLS keywords.
func (s *session) sslParams(tmp string, libpqMajor int) ([][2]string, error) {
	if !s.useTLS {
		return [][2]string{{"sslmode", "disable"}}, nil
	}
	root := "system"
	if strings.TrimSpace(s.opts.TLSCAPEM) != "" {
		root = filepath.Join(tmp, "root.crt")
		if err := os.WriteFile(root, []byte(s.opts.TLSCAPEM), 0o600); err != nil {
			return nil, err
		}
	} else if bundle := targettls.BundleFile(); bundle != "" {
		// libpq takes one file: the configured bundle (+ system roots when
		// trusted).
		extra, err := os.ReadFile(bundle)
		if err != nil {
			return nil, fmt.Errorf("read target CA bundle: %w", err)
		}
		var all []byte
		if sys := systemRootsFile(); sys != "" && s.trustSystem() {
			all, _ = os.ReadFile(sys)
			all = append(all, '\n')
		}
		root = filepath.Join(tmp, "root.crt")
		if err := os.WriteFile(root, append(all, extra...), 0o600); err != nil {
			return nil, err
		}
	} else if !s.trustSystem() {
		return nil, targettls.ErrNoRoots
	} else if libpqMajor < 16 {
		if root = systemRootsFile(); root == "" {
			return nil, errors.New("no system CA bundle found for pg_dump < 16; set engine_options.tls_ca_pem")
		}
	}
	return [][2]string{{"sslmode", "verify-full"}, {"sslrootcert", root}}, nil
}

func quote(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// conninfo is the libpq connection string; host is the TLS name (verified
// by libpq) while hostaddr is replaced per process by the local bridge.
func (s *session) conninfo(db string, ssl [][2]string) [][2]string {
	return s.conninfoFor(db, ssl, "olympos-backup")
}

// conninfoFor is conninfo with the application_name the target sees.
func (s *session) conninfoFor(db string, ssl [][2]string, app string) [][2]string {
	kv := [][2]string{{"host", s.serverName()}, {"user", s.cred.Username}, {"dbname", db},
		{"gssencmode", "disable"}, {"application_name", app}, {"connect_timeout", "30"}}
	return append(kv, ssl...)
}

func render(kv [][2]string) string {
	parts := make([]string, len(kv))
	for i, p := range kv {
		parts[i] = p[0] + "=" + quote(p[1])
	}
	return strings.Join(parts, " ")
}

// runTool runs one pg_dump/pg_dumpall process against a fresh local bridge
// and streams its stdout to out.
func (s *session) runTool(ctx context.Context, bin string, args []string, kv [][2]string, env []string, out io.Writer) error {
	return s.runToolStdin(ctx, bin, args, kv, env, nil, out, nil)
}

// runToolStdin is runTool with the process's stdin read from in (nil: no
// stdin). With kv nil the tool does not connect (pg_restore -l): no bridge
// and no --dbname. trim, when set, filters the tool's stderr before it goes
// into the error. It returns only after the copy into stdin has ended, so
// the caller may close in's source afterwards.
func (s *session) runToolStdin(ctx context.Context, bin string, args []string, kv [][2]string, env []string, in io.Reader, out io.Writer,
	trim func(string) string) error {
	var br *tunnelbridge.Bridge
	if kv != nil {
		var err error
		br, err = tunnelbridge.Start(ctx, s.dial, maxBridgeConns)
		if err != nil {
			return err
		}
		defer br.Close()
		kv = append(kv, [2]string{"hostaddr", "127.0.0.1"}, [2]string{"port", strconv.Itoa(br.Port())})
		args = append(args, "--dbname="+render(kv))
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = env
	cmd.Dir = filepath.Dir(bin)
	sw := &cancelOnErr{w: out, cancel: cancel}
	cmd.Stdout = sw
	stderr := &tailBuffer{max: 8 << 10}
	cmd.Stderr = stderr
	cmd.WaitDelay = 10 * time.Second
	var err error
	if in == nil {
		err = cmd.Run()
	} else {
		err = runWithStdin(cmd, in)
	}
	if sw.err != nil {
		return fmt.Errorf("%s: write output: %w", filepath.Base(bin), sw.err)
	}
	if err != nil {
		msg := stderr.String()
		if trim != nil {
			msg = trim(msg)
		}
		if br != nil {
			br.Close() // waits for the pipes, so a guard refusal is recorded
			if bErr := br.Err(); errors.Is(bErr, ErrPlaintextPassword) {
				return bErr
			} else if bErr != nil {
				msg += " (tunnel: " + bErr.Error() + ")"
			}
		}
		return fmt.Errorf("%s failed: %v: %s", filepath.Base(bin), err, msg)
	}
	return nil
}

// runWithStdin runs cmd with in copied to its stdin through an os.Pipe by
// a goroutine of ours, and waits for that goroutine: exec's own copy may be
// abandoned after WaitDelay while still reading in. A tool that exits
// before reading everything (pg_restore -l) is not an error.
func runWithStdin(cmd *exec.Cmd, in io.Reader) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdin = pr
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	pr.Close() // the child has its copy
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(pw, in) // EPIPE / closed when the child stops reading
		_ = pw.Close()
	}()
	err = cmd.Wait()
	_ = pw.Close() // unblocks a copy into a child that has exited
	<-copied
	return err
}

// cancelOnErr stops the child when the downstream writer fails (otherwise
// the child would block on a full stdout pipe).
type cancelOnErr struct {
	w      io.Writer
	cancel func()
	err    error
}

func (c *cancelOnErr) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.w.Write(p)
	if err != nil {
		c.err = err
		c.cancel()
	}
	return n, err
}

// maxBridgeConns is the connections one tool process may open through its
// bridge.
const maxBridgeConns = 2

// ---------------------------------------------------------------- test

// TestConnection checks reachability, TLS, version, privileges and lists
// databases (Configure wizard step 2).
func (e *Engine) TestConnection(ctx context.Context, ec backup.EngineContext) (*backup.ConnectionTest, error) {
	ct := &backup.ConnectionTest{Privileges: []backup.Privilege{}, Databases: []string{}}
	cred, err := ec.Credential(ctx)
	if err != nil {
		ct.Error = "credential: " + err.Error()
		return ct, nil
	}
	s, err := e.open(ctx, ec)
	if err != nil {
		ct.Error = err.Error()
		return ct, nil
	}
	s.cred = cred
	ct.TLS = s.tlsOK
	ct.Reached = true // the TLS probe got an answer
	tlsLine := backup.Privilege{Name: "tls", OK: s.tlsOK}
	switch {
	case !s.tlsOK && s.guard:
		tlsLine.Detail = "the target does not offer TLS: the password is only sent with SCRAM-SHA-256 (a tls.missing finding is opened)"
	case !s.tlsOK:
		tlsLine.Detail = "the target does not offer TLS (a tls.missing finding is opened)"
	case s.useTLS:
		tlsLine.Detail = "verified end-to-end for " + s.serverName()
	default:
		tlsLine.Detail = "offered by the target, not used in compressed transfer mode"
	}
	conn, err := s.connectAny(ctx)
	if err != nil {
		ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "connect", OK: false, Detail: err.Error()}, tlsLine)
		ct.Error = "connect: " + err.Error()
		return ct, nil
	}
	defer conn.Close(context.Background())
	si, err := inspect(ctx, conn)
	if err != nil {
		ct.Error = err.Error()
		return ct, nil
	}
	ct.ServerVersion = si.version
	ct.Databases = append(ct.Databases, si.databases...)
	ok := true
	add := func(p backup.Privilege, required bool) {
		ct.Privileges = append(ct.Privileges, p)
		if required && !p.OK {
			ok = false
		}
	}
	add(backup.Privilege{Name: "connect", OK: true, Detail: "logged in as " + si.user}, true)
	ct.Privileges = append(ct.Privileges, tlsLine)

	dbs, selErr := s.selected(si)
	if selErr != nil {
		add(backup.Privilege{Name: "databases", OK: false, Detail: selErr.Error()}, true)
	} else {
		add(backup.Privilege{Name: "databases", OK: true, Detail: fmt.Sprintf("%d to back up: %s", len(dbs), strings.Join(dbs, ", "))}, true)
	}
	switch {
	case si.superuser:
		add(backup.Privilege{Name: "read_all_data", OK: true, Detail: "superuser"}, true)
	case si.readAll:
		add(backup.Privilege{Name: "read_all_data", OK: true, Detail: "member of pg_read_all_data"}, true)
	default:
		const maxChecked = 10
		for i, db := range dbs {
			if i >= maxChecked {
				add(backup.Privilege{Name: "select", OK: true, Detail: fmt.Sprintf("%d more databases not checked", len(dbs)-maxChecked)}, false)
				break
			}
			add(s.checkDatabase(ctx, db), true)
		}
	}
	if si.authid {
		add(backup.Privilege{Name: "globals", OK: true, Detail: "roles incl. password hashes"}, false)
	} else {
		add(backup.Privilege{Name: "globals", OK: true, Detail: "roles without passwords (no access to pg_authid)"}, false)
	}
	if t, err := FindTool(ctx, e.dir(), si.major()); err != nil {
		add(backup.Privilege{Name: "pg_dump", OK: false, Detail: err.Error()}, true)
	} else {
		add(backup.Privilege{Name: "pg_dump", OK: true, Detail: t.Version}, true)
	}
	ct.OK = ok
	return ct, nil
}

// checkDatabase verifies CONNECT and SELECT on every user table of db.
func (s *session) checkDatabase(ctx context.Context, db string) backup.Privilege {
	p := backup.Privilege{Name: "select:" + db}
	c, err := s.connect(ctx, db)
	if err != nil {
		p.Detail = "cannot connect: " + err.Error()
		return p
	}
	defer c.Close(context.Background())
	var missing int
	var sample *string
	err = c.QueryRow(ctx, `SELECT count(*), min(n.nspname || '.' || cl.relname) FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
		WHERE cl.relkind IN ('r','p','m','S') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
		  AND NOT has_table_privilege(cl.oid, 'SELECT')`).Scan(&missing, &sample)
	if err != nil {
		p.Detail = err.Error()
		return p
	}
	if missing > 0 {
		p.Detail = fmt.Sprintf("no SELECT on %d relations (e.g. %s)", missing, *sample)
		return p
	}
	p.OK = true
	p.Detail = "CONNECT and SELECT on all tables"
	return p
}
