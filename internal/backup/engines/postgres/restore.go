package postgres

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
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

// userObjectsSQL is true when the connected database holds user objects:
// a relation, function, type or schema outside the system schemas that no
// extension owns. The public schema itself does not count.
const userObjectsSQL = `SELECT EXISTS (
	SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
	   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
	UNION ALL
	SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
	 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
	   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
	UNION ALL
	SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
	 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
	   AND t.typrelid = 0 AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid)
	   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e')
	UNION ALL
	SELECT 1 FROM pg_namespace n
	 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'public') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
	   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_namespace'::regclass AND d.objid = n.oid AND d.deptype = 'e'))`

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
	m := regexp.MustCompile(`^(\d+)`).FindStringSubmatch(r.ServerVersion)
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
// "Engines"): globals.sql first (superuser only), then per database CREATE
// DATABASE from template0 (unless it exists without user objects) and
// pg_restore with the archive entry on its stdin. Nothing is dropped. The
// first failed database ends the restore; the rest are reported skipped.
func (e *Engine) Restore(ctx context.Context, rc backup.RestoreContext) (_ *backup.RestoreResult, err error) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
	// Errors and items are scrubbed of the credential (the executor scrubs
	// again).
	scrub := &backup.SecretScrubber{}
	defer func() {
		if err != nil {
			err = errors.New(scrub.Scrub(err.Error()))
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
		item, err := s.restoreGlobals(ctx, conn, entries["globals.sql"])
		item.Error = scrub.Scrub(item.Error)
		res.Items = append(res.Items, item)
		if err != nil {
			return res, err
		}
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

	var done []string
	for i, db := range rc.Databases {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		progress(backup.Progress{Phase: "restore", Database: db, Done: done, Created: res.Created})
		item := s.restoreDatabase(ctx, conn, rc, st, entries[entryName(db)], db, tmp, env, func(created string) {
			res.Created = append(res.Created, created)
			progress(backup.Progress{Phase: "restore", Database: db, Done: done, Created: res.Created})
		})
		item.Error = scrub.Scrub(item.Error)
		for k := range item.Skipped {
			item.Skipped[k] = scrub.Scrub(item.Skipped[k])
		}
		res.Items = append(res.Items, item)
		if item.Status != "succeeded" {
			for _, rest := range rc.Databases[i+1:] {
				res.Items = append(res.Items, backup.RestoreItem{Name: rest, Status: "skipped",
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
// tunnel connection (simple protocol), so a failure creates no role.
func (s *session) restoreGlobals(ctx context.Context, conn *pgx.Conn, f *zip.File) (backup.RestoreItem, error) {
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
	existing := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT rolname FROM pg_roles`)
	if err != nil {
		return finish(fmt.Errorf("list roles: %w", err))
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return finish(err)
		}
		existing[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return finish(fmt.Errorf("list roles: %w", err))
	}
	stmts, skipped := filterGlobals(string(b), existing)
	item.Skipped = skipped
	pc := conn.PgConn()
	if _, err := pc.Exec(ctx, "BEGIN").ReadAll(); err != nil {
		return finish(err)
	}
	for i, st := range stmts {
		if _, err := pc.Exec(ctx, st).ReadAll(); err != nil {
			_, _ = pc.Exec(context.WithoutCancel(ctx), "ROLLBACK").ReadAll()
			return finish(fmt.Errorf("statement %d (%s): %w; no role was created", i+1, describeStmt(st), err))
		}
	}
	if _, err := pc.Exec(ctx, "COMMIT").ReadAll(); err != nil {
		return finish(err)
	}
	return finish(nil)
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

// restoreDatabase restores one database; onCreated is called right after
// CREATE DATABASE succeeded.
func (s *session) restoreDatabase(ctx context.Context, conn *pgx.Conn, rc backup.RestoreContext, st *targetState, f *zip.File,
	db, tmp string, env []string, onCreated func(string)) backup.RestoreItem {
	start := time.Now()
	item := backup.RestoreItem{Name: db, Status: "failed"}
	fail := func(format string, a ...any) backup.RestoreItem {
		item.Duration = time.Since(start).Seconds()
		item.Error = fmt.Sprintf(format, a...)
		return item
	}
	if f == nil {
		return fail("the backup holds no archive for this database")
	}
	item.Bytes = int64(f.UncompressedSize64)
	has, exists := st.existing[db]
	if exists && has {
		return fail("the database exists on the target with user objects in it; nothing was written")
	}

	// The archive's header tells the dump's major before any pg_restore
	// runs (see restoreTool).
	r, err := f.Open()
	if err != nil {
		return fail("open the archive entry: %v", err)
	}
	hdr, err := readArchiveHeader(r)
	r.Close()
	if err != nil {
		return fail("%v", err)
	}
	tool, err := restoreTool(ctx, s.toolDir, hdr.DumpMajor, st.si.major())
	if err != nil {
		return fail("%v; nothing was written", err)
	}

	// The schema pass: the TOC's tables and the database's own entries.
	scan := &schemaScan{}
	if err := s.feedTool(ctx, tool.PgRestore, []string{"--create", "--schema-only", "--file=-"}, nil, env, f, scan, false); err != nil {
		return fail("read the archive's table of contents: %v", err)
	}
	if err := scan.Close(); err != nil {
		return fail("read the archive's table of contents: %v", err)
	}
	item.Tables = scan.Tables
	def, err := databaseDefinition(scan.Blocks)
	if err != nil {
		return fail("%v", err)
	}

	if exists {
		item.Skipped = append(item.Skipped, "the database existed on the target without user objects: restored into it; "+
			"its settings, comment and privileges from the backup were not applied")
	} else {
		if len(def.Ignored) > 0 {
			item.Skipped = append(item.Skipped, "CREATE DATABASE options not used: "+strings.Join(def.Ignored, ", "))
		}
		if _, err := conn.PgConn().Exec(ctx, def.createSQL(db, rc.Superuser)).ReadAll(); err != nil {
			return fail("create the database: %v", err)
		}
		onCreated(db)
	}

	sslArgs, err := s.sslParams(tmp, tool.Major)
	if err != nil {
		return fail("%v", err)
	}
	args := []string{"--exit-on-error", "--no-tablespaces", "--no-password"}
	if !rc.Superuser {
		args = append(args, "--no-owner", "--no-privileges")
	}
	kv := s.conninfoFor(db, sslArgs, "olympos-restore")
	if err := s.feedTool(ctx, tool.PgRestore, args, kv, env, f, &tailBuffer{max: 8 << 10}, true); err != nil {
		return fail("%v", err)
	}

	if !exists {
		skipped, err := s.applyDatabaseEntries(ctx, conn, def, rc.Superuser)
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
// pg_restore stopped reading before.
func (s *session) feedTool(ctx context.Context, bin string, args []string, kv [][2]string, env []string, f *zip.File, out io.Writer, whole bool) error {
	r, err := f.Open()
	if err != nil {
		return fmt.Errorf("open the archive entry: %w", err)
	}
	defer r.Close()
	in := &readErr{r: r}
	runErr := s.runToolStdin(ctx, bin, args, kv, env, in, out)
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
// itself (pg_restore applies them only with --create): settings, comment
// and, with a superuser, privileges. Without a superuser only ALTER
// DATABASE … SET and the comment are run.
func (s *session) applyDatabaseEntries(ctx context.Context, conn *pgx.Conn, def dbDefinition, superuser bool) ([]string, error) {
	var skipped []string
	run := func(st string) error {
		if _, err := conn.PgConn().Exec(ctx, st).ReadAll(); err != nil {
			return fmt.Errorf("apply the database's %s: %w", describeStmt(st), err)
		}
		return nil
	}
	for _, st := range def.Settings {
		if !superuser && !isWords(lexSQL(st), "ALTER", "DATABASE") {
			skipped = append(skipped, "a per-role database setting ("+describeStmt(st)+"): needs a superuser")
			continue
		}
		if err := run(st); err != nil {
			return skipped, err
		}
	}
	for _, st := range def.Comment {
		if err := run(st); err != nil {
			return skipped, err
		}
	}
	if !superuser {
		if len(def.ACL) > 0 {
			skipped = append(skipped, "the database's privileges: not restored without a superuser")
		}
		return skipped, nil
	}
	for _, st := range def.ACL {
		if err := run(st); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}
