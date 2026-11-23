package postgres

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
)

var (
	_ backup.Restorer         = (*Engine)(nil)
	_ restore.TargetInspector = (*Engine)(nil)
	_ restore.BackupChecker   = (*Engine)(nil)
)

func init() {
	e := &Engine{}
	backup.RegisterRestorer("postgresql", e)
	restore.RegisterInspector("postgresql", e)
}

// userNamespace excludes the system schemas.
const userNamespace = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'`

// notExtension: the object (catalog cat, row alias a) is not an
// extension's member.
func notExtension(cat, a string) string {
	return `NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = '` + cat + `'::regclass AND d.objid = ` + a + `.oid AND d.deptype = 'e')`
}

// inUserSchema: catalog cat (alias a, schema column nsp) rows in a user
// schema that no extension owns.
func inUserSchema(cat, a, nsp, extra string) string {
	return `SELECT 1 FROM ` + cat + ` ` + a + ` JOIN pg_namespace n ON n.oid = ` + a + `.` + nsp +
		` WHERE ` + userNamespace + extra + ` AND ` + notExtension(cat, a)
}

// userObjectsSQL is true when the connected database holds user objects:
// relations, functions, types, operators, collations, conversions and text
// search objects in a user schema, non-public schemas, casts, foreign data
// wrappers and servers, user mappings, publications, subscriptions, event
// triggers and large objects; none of them owned by an extension.
var userObjectsSQL = `SELECT EXISTS (` + strings.Join([]string{
	inUserSchema("pg_class", "c", "relnamespace", ""),
	inUserSchema("pg_proc", "p", "pronamespace", ""),
	inUserSchema("pg_type", "t", "typnamespace", ` AND t.typrelid = 0 AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid)`),
	inUserSchema("pg_operator", "o", "oprnamespace", ""),
	inUserSchema("pg_collation", "co", "collnamespace", ""),
	inUserSchema("pg_conversion", "cv", "connamespace", ""),
	inUserSchema("pg_ts_config", "tc", "cfgnamespace", ""),
	inUserSchema("pg_ts_dict", "td", "dictnamespace", ""),
	`SELECT 1 FROM pg_namespace n WHERE ` + userNamespace + ` AND n.nspname <> 'public' AND ` + notExtension("pg_namespace", "n"),
	`SELECT 1 FROM pg_cast ca WHERE ca.oid >= 16384 AND ` + notExtension("pg_cast", "ca"),
	`SELECT 1 FROM pg_foreign_data_wrapper w WHERE ` + notExtension("pg_foreign_data_wrapper", "w"),
	`SELECT 1 FROM pg_foreign_server fs WHERE ` + notExtension("pg_foreign_server", "fs"),
	`SELECT 1 FROM pg_user_mappings`,
	`SELECT 1 FROM pg_publication pb WHERE ` + notExtension("pg_publication", "pb"),
	`SELECT 1 FROM pg_subscription su WHERE su.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())`,
	`SELECT 1 FROM pg_event_trigger et WHERE ` + notExtension("pg_event_trigger", "et"),
	`SELECT 1 FROM pg_largeobject_metadata`,
}, "\n\tUNION ALL\n\t") + `)`

// targetState is what a restore needs to know about its target.
type targetState struct {
	si serverInfo
	// existing: selected databases that exist, true when they hold user
	// objects (or cannot be connected to, so cannot be shown empty).
	existing map[string]bool
}

// inspectTarget reads the target over conn and one connection per existing
// selected database. It writes nothing.
func (s *session) inspectTarget(ctx context.Context, conn *pgx.Conn, databases []string) (*targetState, error) {
	si, err := inspect(ctx, conn)
	if err != nil {
		return nil, err
	}
	st := &targetState{si: si, existing: map[string]bool{}}
	rows, err := conn.Query(ctx, `SELECT datname, datallowconn FROM pg_database WHERE datname = ANY($1)`, databases)
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	type found struct {
		name  string
		allow bool
	}
	var fs []found
	for rows.Next() {
		var f found
		if err := rows.Scan(&f.name, &f.allow); err != nil {
			rows.Close()
			return nil, err
		}
		fs = append(fs, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, f := range fs {
		if !f.allow {
			st.existing[f.name] = true
			continue
		}
		has, err := s.hasUserObjects(ctx, f.name)
		if err != nil {
			return nil, fmt.Errorf("database %s: %w", f.name, err)
		}
		st.existing[f.name] = has
	}
	return st, nil
}

func (s *session) hasUserObjects(ctx context.Context, db string) (bool, error) {
	c, err := s.connect(ctx, db)
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer c.Close(context.Background())
	var has bool
	if err := c.QueryRow(ctx, userObjectsSQL).Scan(&has); err != nil {
		return false, fmt.Errorf("look for user objects: %w", err)
	}
	return has, nil
}

// InspectRestoreTarget implements restore.TargetInspector: whether the
// credential is a superuser, and for each selected database that exists
// whether it holds user objects. It writes nothing.
func (e *Engine) InspectRestoreTarget(ctx context.Context, ec backup.EngineContext, databases []string) (*restore.TargetReport, error) {
	cred, err := ec.Credential(ctx)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	s, err := e.open(ctx, ec)
	if err != nil {
		return nil, err
	}
	s.cred = cred
	conn, err := s.connectAny(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())
	st, err := s.inspectTarget(ctx, conn, databases)
	if err != nil {
		return nil, err
	}
	return &restore.TargetReport{Existing: st.existing, Superuser: st.si.superuser, ServerVersion: st.si.version}, nil
}

// restoreTool picks pg_restore by the target server's major: the lowest
// major >= the server's (its own major when that pg_restore is installed;
// the image ships 13–17), so a PostgreSQL 16 → 16 restore runs pg_restore
// 16. pg_restore reads archives of its own major or older, and a dump of a
// newer major than the server holds SQL the server may not know, so a dump
// newer than the target's major is refused. pg_restore 17 and newer also
// cannot restore into a server older than 17 at all (it sets
// transaction_timeout); that is refused too, when no pg_restore of the
// server's own major is installed.
func restoreTool(ctx context.Context, dir string, dumpMajor, serverMajor int) (*Tool, error) {
	if msg := dumpMajorProblem(dumpMajor, serverMajor); msg != "" {
		return nil, errors.New(msg)
	}
	tool, err := FindRestoreTool(ctx, dir, serverMajor)
	if err != nil {
		return nil, err
	}
	if tool.Major >= 17 && serverMajor < 17 {
		return nil, fmt.Errorf("no pg_restore %d is installed, and pg_restore %d cannot restore into PostgreSQL %d "+
			"(it sets transaction_timeout, unknown before PostgreSQL 17)", serverMajor, tool.Major, serverMajor)
	}
	return tool, nil
}

// dumpMajorProblem is why a dump of dumpMajor cannot be restored into a
// server of serverMajor ("": it can).
func dumpMajorProblem(dumpMajor, serverMajor int) string {
	if dumpMajor > serverMajor {
		return fmt.Sprintf("the backup was made by pg_dump %d; the target runs PostgreSQL %d: a dump is only restored into "+
			"PostgreSQL %d or newer", dumpMajor, serverMajor, dumpMajor)
	}
	return ""
}

// CheckBackup implements restore.BackupChecker: the backup's pg_dump major
// (manifest details.pg_dump_major) against the target's server major, so
// the maker sees a refused version pair before the approval. Restore checks
// the archive's own header again.
func (e *Engine) CheckBackup(details map[string]any, r *restore.TargetReport) string {
	var dump int
	switch v := details["pg_dump_major"].(type) {
	case float64:
		dump = int(v)
	case int:
		dump = v
	case json.Number:
		n, _ := v.Int64()
		dump = int(n)
	}
	m := leadingNumber.FindStringSubmatch(r.ServerVersion)
	if dump <= 0 || m == nil {
		return ""
	}
	server, _ := strconv.Atoi(m[1])
	return dumpMajorProblem(dump, server)
}

// restoreOptions are the request's options the engine reads
// (restore.Options).
type restoreOptions struct {
	Globals *bool `json:"globals"`
}

// maxGlobals bounds globals.sql, which is read into memory.
const maxGlobals = 64 << 20

// Restore implements backup.Restorer (docs/design/ui-restore.md
// "Engines"). Nothing is written before every selected database passed its
// preflight (in the archive, not on the target with data, archive header
// and table of contents readable, a usable pg_restore). Then globals.sql
// (superuser only), then per database CREATE DATABASE from template0
// (unless it exists without user objects) and pg_restore with the archive
// entry on its stdin. Nothing is dropped. The first failed database ends
// the restore; the rest are reported skipped.
func (e *Engine) Restore(ctx context.Context, rc backup.RestoreContext) (_ *backup.RestoreResult, err error) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
	// Errors and items are scrubbed of the credential (the executor scrubs
	// again).
	scrub := &backup.SecretScrubber{}
	defer func() {
		if err != nil {
			err = errors.New(scrub.Scrub(err.Error()))
		}
		for i := range res.Items {
			res.Items[i].Error = scrub.Scrub(res.Items[i].Error)
			for k := range res.Items[i].Skipped {
				res.Items[i].Skipped[k] = scrub.Scrub(res.Items[i].Skipped[k])
			}
		}
	}()
	var ro restoreOptions
	if len(rc.Options) > 0 {
		if err := json.Unmarshal(rc.Options, &ro); err != nil {
			return res, fmt.Errorf("restore options: %w", err)
		}
	}
	if len(rc.Databases) == 0 {
		return res, errors.New("no databases selected")
	}
	if rc.Archive == nil {
		return res, errors.New("no archive")
	}
	progress := rc.Progress
	if progress == nil {
		progress = func(backup.Progress) {}
	}
	cred, err := rc.Credential(ctx)
	if err != nil {
		return res, fmt.Errorf("credential: %w", err)
	}
	// The caller zeroes the secret; the scrubber only reads it.
	scrub.Track(cred)
	s, err := e.open(ctx, rc.EngineContext)
	if err != nil {
		return res, err
	}
	s.cred = cred
	s.toolDir = e.dir()

	zr, err := zip.NewReader(rc.Archive, rc.Archive.Size())
	if err != nil {
		return res, fmt.Errorf("open the backup archive: %w", err)
	}
	entries := map[string]*zip.File{}
	for _, f := range zr.File {
		entries[f.Name] = f
	}

	conn, err := s.connectAny(ctx)
	if err != nil {
		return res, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())
	st, err := s.inspectTarget(ctx, conn, rc.Databases)
	if err != nil {
		return res, err
	}

	tmp, err := os.MkdirTemp("", "olympos-pgr-")
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

	// Preflight: every database, before anything is written.
	plans := make([]*dbPlan, len(rc.Databases))
	var refused []string
	for i, db := range rc.Databases {
		plan, msg := s.prepareDatabase(ctx, st, entries[entryName(db)], db, tmp, env)
		if msg != "" {
			res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "failed", Bytes: plan.bytes(), Error: msg + "; nothing was written"})
			refused = append(refused, db)
			continue
		}
		plans[i] = plan
	}
	if len(refused) > 0 {
		for i, db := range rc.Databases {
			if plans[i] != nil {
				res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "skipped", Bytes: plans[i].bytes(),
					Error: "not restored: nothing was written because " + strings.Join(refused, ", ") + " cannot be restored"})
			}
		}
		return res, nil
	}

	// The roles the target had before the restore: they are never changed
	// (globals, per-role settings in a database).
	existingRoles, err := listRoles(ctx, conn)
	if err != nil {
		return res, err
	}
	// The statements run here are split by our own lexer, which reads
	// literals as standard_conforming_strings = on does.
	if err := execOne(ctx, conn, "SET standard_conforming_strings = on"); err != nil {
		return res, err
	}

	// Globals: roles, superuser only.
	switch {
	case !rc.Superuser:
		res.Notes = append(res.Notes, "The credential is not a superuser: roles (globals.sql) were not restored, and the databases were "+
			"restored with --no-owner --no-privileges, so their objects belong to "+cred.Username+" and carry no grants.")
	case ro.Globals != nil && !*ro.Globals:
		res.Notes = append(res.Notes, "Roles (globals.sql) were not restored: turned off for this request.")
	case entries["globals.sql"] == nil:
		res.Notes = append(res.Notes, "The backup holds no globals.sql (taken without globals): no roles were restored.")
	default:
		progress(backup.Progress{Phase: "globals"})
		item, err := s.restoreGlobals(ctx, conn, entries["globals.sql"], existingRoles)
		res.Items = append(res.Items, item)
		if err != nil {
			return res, err
		}
	}

	var done []string
	for i, plan := range plans {
		db := plan.db
		if err := ctx.Err(); err != nil {
			return res, err
		}
		progress(backup.Progress{Phase: "restore", Database: db, Done: done, Created: res.Created})
		item := s.restoreDatabase(ctx, conn, rc, plan, existingRoles, tmp, env, func(created string) {
			res.Created = append(res.Created, created)
			progress(backup.Progress{Phase: "restore", Database: db, Done: done, Created: res.Created})
		})
		res.Items = append(res.Items, item)
		if item.Status != "succeeded" {
			for _, rest := range plans[i+1:] {
				res.Items = append(res.Items, backup.RestoreItem{Name: rest.db, Status: "skipped", Bytes: rest.bytes(),
					Error: "not restored: the restore stopped after " + db + " failed"})
			}
			break
		}
		done = append(done, db)
		progress(backup.Progress{Phase: "restore", Done: done, Created: res.Created})
	}
	return res, nil
}

// restoreGlobals runs the filtered globals.sql in one transaction over the
// tunnel connection, so a failure creates no role. Each statement is sent
// alone with the extended protocol, which runs exactly one statement: text
// the splitter misread can never smuggle in a second one.
func (s *session) restoreGlobals(ctx context.Context, conn *pgx.Conn, f *zip.File, existing map[string]bool) (backup.RestoreItem, error) {
	start := time.Now()
	item := backup.RestoreItem{Name: "globals.sql", Status: "failed", Bytes: int64(f.UncompressedSize64)}
	finish := func(err error) (backup.RestoreItem, error) {
		item.Duration = time.Since(start).Seconds()
		if err != nil {
			item.Error = err.Error()
			return item, fmt.Errorf("globals.sql: %w", err)
		}
		item.Status = "succeeded"
		return item, nil
	}
	if f.UncompressedSize64 > maxGlobals {
		return finish(fmt.Errorf("%d bytes is more than the %d a restore reads", f.UncompressedSize64, maxGlobals))
	}
	r, err := f.Open()
	if err != nil {
		return finish(fmt.Errorf("open: %w", err))
	}
	b, err := io.ReadAll(io.LimitReader(r, maxGlobals+1))
	r.Close()
	if err != nil {
		return finish(fmt.Errorf("read: %w", err))
	}
	stmts, skipped := filterGlobals(string(b), existing)
	item.Skipped = skipped
	if turnsOffStandardStrings(stmts) {
		return finish(errors.New("it turns standard_conforming_strings off; no role was created"))
	}
	if err := execOne(ctx, conn, "BEGIN"); err != nil {
		return finish(err)
	}
	for i, st := range stmts {
		if err := execOne(ctx, conn, st); err != nil {
			_ = execOne(context.WithoutCancel(ctx), conn, "ROLLBACK")
			return finish(fmt.Errorf("statement %d (%s): %w; no role was created", i+1, describeStmt(st), err))
		}
	}
	if err := execOne(ctx, conn, "COMMIT"); err != nil {
		return finish(err)
	}
	return finish(nil)
}

// listRoles returns the names of the target's roles.
func listRoles(ctx context.Context, conn *pgx.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, `SELECT rolname FROM pg_roles`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		out[n] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}

// execOne runs one statement with the extended protocol (a single
// statement, no parameters).
func execOne(ctx context.Context, conn *pgx.Conn, st string) error {
	return conn.PgConn().ExecParams(ctx, st, nil, nil, nil, nil).Read().Err
}

// describeStmt names a statement without its text (which may carry a
// password hash): its first three words or identifiers.
func describeStmt(st string) string {
	var parts []string
	for _, t := range lexSQL(st) {
		if len(parts) == 3 || (t.kind != tokWord && t.kind != tokIdent) {
			break
		}
		if len(parts) == 0 {
			parts = append(parts, strings.ToUpper(t.text))
		} else {
			parts = append(parts, t.text)
		}
	}
	return strings.Join(parts, " ")
}

// dbPlan is a database that passed its preflight.
type dbPlan struct {
	db     string
	f      *zip.File
	exists bool // exists on the target without user objects
	hdr    archiveHeader
	tool   *Tool
	tables int
	def    dbDefinition
}

func (p *dbPlan) bytes() int64 {
	if p == nil || p.f == nil {
		return 0
	}
	return int64(p.f.UncompressedSize64)
}

// prepareDatabase checks one database without writing anything: it is in
// the archive and not on the target with data, the archive entry's header
// names it and picks a usable pg_restore (restoreTool), and its table of
// contents gives the tables and the database's own statements. msg is why
// it cannot be restored ("" when it can); plan is filled as far as it got.
func (s *session) prepareDatabase(ctx context.Context, st *targetState, f *zip.File, db, tmp string, env []string) (*dbPlan, string) {
	plan := &dbPlan{db: db, f: f}
	if f == nil {
		return plan, "the backup holds no archive for this database"
	}
	has, exists := st.existing[db]
	if exists && has {
		return plan, "the database exists on the target with user objects in it"
	}
	plan.exists = exists
	r, err := f.Open()
	if err != nil {
		return plan, fmt.Sprintf("open the archive entry: %v", err)
	}
	plan.hdr, err = readArchiveHeader(r)
	r.Close()
	if err != nil {
		return plan, err.Error()
	}
	if plan.hdr.DBName != db {
		return plan, fmt.Sprintf("the archive entry holds database %q, not %q", plan.hdr.DBName, db)
	}
	if plan.tool, err = restoreTool(ctx, s.toolDir, plan.hdr.DumpMajor, st.si.major()); err != nil {
		return plan, err.Error()
	}

	// The table of contents: one sanitized line per entry.
	toc := &tocScan{DB: db}
	if err := s.feedTool(ctx, plan.tool.PgRestore, []string{"--create", "--list"}, nil, env, f, toc, false); err != nil {
		return plan, fmt.Sprintf("read the archive's table of contents: %v", err)
	}
	if err := toc.Close(); err != nil {
		return plan, fmt.Sprintf("read the archive's table of contents: %v", err)
	}
	plan.tables = toc.Tables
	if len(toc.DBEntries) == 0 {
		return plan, "the archive has no entry for the database itself (not a pg_dump -Fc archive of one database)"
	}
	// Only the database's own entries are printed, so nothing of its
	// contents (function bodies, comments of other objects) is read as
	// SQL to run.
	list := filepath.Join(tmp, "entries.list")
	if err := os.WriteFile(list, listFile(toc.DBEntries), 0o600); err != nil {
		return plan, err.Error()
	}
	out := &limitBuffer{max: maxDBScript}
	if err := s.feedTool(ctx, plan.tool.PgRestore, []string{"--create", "--schema-only", "--use-list=" + list, "--file=-"}, nil, env, f, out, false); err != nil {
		return plan, fmt.Sprintf("read the database's entries in the archive: %v", err)
	}
	if out.over {
		return plan, "the database's own entries in the archive are too large"
	}
	if plan.def, err = databaseDefinition(out.String(), db); err != nil {
		return plan, err.Error()
	}
	return plan, ""
}

// maxDBScript bounds the script of the database's own entries.
const maxDBScript = 1 << 20

// limitBuffer keeps up to max bytes and records an overflow.
type limitBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.over = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// restoreDatabase restores one prepared database; onCreated is called
// right after CREATE DATABASE succeeded.
func (s *session) restoreDatabase(ctx context.Context, conn *pgx.Conn, rc backup.RestoreContext, plan *dbPlan,
	existingRoles map[string]bool, tmp string, env []string, onCreated func(string)) backup.RestoreItem {
	start := time.Now()
	db := plan.db
	item := backup.RestoreItem{Name: db, Status: "failed", Bytes: plan.bytes(), Tables: plan.tables}
	fail := func(format string, a ...any) backup.RestoreItem {
		item.Duration = time.Since(start).Seconds()
		item.Error = fmt.Sprintf(format, a...)
		return item
	}
	def := plan.def
	if len(def.Unused) > 0 {
		item.Skipped = append(item.Skipped, "statements about the database not applied: "+strings.Join(def.Unused, "; "))
	}
	if plan.exists {
		item.Skipped = append(item.Skipped, "the database existed on the target without user objects: restored into it; "+
			"its settings, comment and privileges from the backup were not applied")
	} else {
		if len(def.Ignored) > 0 {
			item.Skipped = append(item.Skipped, "CREATE DATABASE options not used: "+strings.Join(def.Ignored, ", "))
		}
		if err := execOne(ctx, conn, def.createSQL(db, rc.Superuser)); err != nil {
			return fail("create the database: %v", err)
		}
		onCreated(db)
	}

	sslArgs, err := s.sslParams(tmp, plan.tool.Major)
	if err != nil {
		return fail("%v", err)
	}
	args := []string{"--exit-on-error", "--no-tablespaces", "--no-password"}
	if !rc.Superuser {
		args = append(args, "--no-owner", "--no-privileges")
	}
	kv := s.conninfoFor(db, sslArgs, "olympos-restore")
	if err := s.feedTool(ctx, plan.tool.PgRestore, args, kv, env, plan.f, io.Discard, true); err != nil {
		return fail("%v", err)
	}

	if !plan.exists {
		skipped, err := applyDatabaseEntries(ctx, conn, def, rc.Superuser, existingRoles)
		item.Skipped = append(item.Skipped, skipped...)
		if err != nil {
			return fail("%v", err)
		}
	}
	item.Status = "succeeded"
	item.Duration = time.Since(start).Seconds()
	return item
}

// feedTool runs pg_restore with the zip entry on its stdin. With whole, the
// entry is read to its end (archive/zip checks its CRC-32 there) even when
// pg_restore stopped reading before. pg_restore's messages are trimmed of
// the SQL and rows they quote (pgRestoreMessage).
func (s *session) feedTool(ctx context.Context, bin string, args []string, kv [][2]string, env []string, f *zip.File, out io.Writer, whole bool) error {
	r, err := f.Open()
	if err != nil {
		return fmt.Errorf("open the archive entry: %w", err)
	}
	defer r.Close()
	in := &readErr{r: r}
	// runToolStdin returns only after its stdin copy ended, so in and r
	// are no longer used by it here.
	runErr := s.runToolStdin(ctx, bin, args, kv, env, in, out, pgRestoreMessage)
	if in.err != nil && !errors.Is(in.err, io.EOF) {
		return fmt.Errorf("read the backup: %w", in.err)
	}
	if runErr != nil {
		return runErr
	}
	if whole {
		if _, err := io.Copy(io.Discard, in); err != nil {
			return fmt.Errorf("read the backup: %w", err)
		}
	}
	return nil
}

// pgRestoreMessage keeps pg_restore's own message lines ("pg_restore: …")
// and drops the lines quoting SQL or data: "Command was:" with the
// statement after it, CONTEXT (COPY … line N: <row>), DETAIL, HINT.
func pgRestoreMessage(stderr string) string {
	var keep []string
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, "pg_restore: ") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// readErr remembers the first read error (the zip CRC check).
type readErr struct {
	r   io.Reader
	err error
}

func (r *readErr) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && r.err == nil {
		r.err = err
	}
	return n, err
}

// applyDatabaseEntries runs the archive's statements about the database
// itself (pg_restore applies them only with --create), each alone: its
// settings and comment, and with a superuser its privileges and the
// per-role settings in it, except those of roles the target had before the
// restore (existing roles are never changed).
func applyDatabaseEntries(ctx context.Context, conn *pgx.Conn, def dbDefinition, superuser bool, existingRoles map[string]bool) ([]string, error) {
	var skipped []string
	if err := execOne(ctx, conn, "SET standard_conforming_strings = on"); err != nil {
		return skipped, err
	}
	run := func(sts []string) error {
		for _, st := range sts {
			if err := execOne(ctx, conn, st); err != nil {
				return fmt.Errorf("apply the database's %s: %w", describeStmt(st), err)
			}
		}
		return nil
	}
	if err := run(def.Settings); err != nil {
		return skipped, err
	}
	if err := run(def.Comment); err != nil {
		return skipped, err
	}
	if !superuser {
		if len(def.RoleSettings) > 0 {
			skipped = append(skipped, "per-role settings in the database: not restored without a superuser")
		}
		if len(def.ACL) > 0 {
			skipped = append(skipped, "the database's privileges: not restored without a superuser")
		}
		return skipped, nil
	}
	var roleSettings []string
	for _, st := range def.RoleSettings {
		if r := lexSQL(st)[2].name(); existingRoles[r] {
			skipped = append(skipped, "role "+r+": exists on the target, its setting in the database was not applied")
			continue
		}
		roleSettings = append(roleSettings, st)
	}
	if err := run(roleSettings); err != nil {
		return skipped, err
	}
	return skipped, run(def.ACL)
}
