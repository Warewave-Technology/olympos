package clickhouse

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/ch-go"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
	"github.com/Warewave-Technology/olympos/internal/targettls"
	"github.com/Warewave-Technology/olympos/internal/tunnelbridge"
)

var (
	_ backup.Restorer         = Engine{}
	_ restore.TargetInspector = Engine{}
)

func init() {
	backup.RegisterRestorer(Name, Engine{})
	restore.RegisterInspector(Name, Engine{})
}

// restorableDatabaseEngines are the database engines a restore creates. A
// Replicated database is refused (its Keeper path could collide with the
// source's when Keeper is shared); the others proxy external systems.
var restorableDatabaseEngines = map[string]bool{"Atomic": true, "Ordinary": true, "Lazy": true, "Memory": true}

func databaseEngineProblem(engine string) string {
	switch {
	case engine == "Replicated":
		return "it has the Replicated database engine, which Olympos does not restore: its Keeper path could collide with the source's " +
			"when Keeper is shared (restore its tables into an Atomic database by hand)"
	case !restorableDatabaseEngines[engine]:
		return "it has the " + engine + " database engine, a proxy for another system, which Olympos does not restore"
	}
	return ""
}

// targetDB is a selected database found on the target.
type targetDB struct {
	engine  string
	objects int // tables, views, dictionaries (system.tables)
}

// targetState is what the restore knows about its target.
type targetState struct {
	version string
	dbs     map[string]targetDB
}

// inspectTarget reads the selected databases on the target. It writes
// nothing. A database the credential cannot see is reported absent; its
// CREATE DATABASE then fails, so nothing is overwritten.
func (s *session) inspectTarget(ctx context.Context, databases []string) (*targetState, error) {
	v, err := s.queryValue(ctx, "SELECT version()")
	if err != nil {
		return nil, fmt.Errorf("server version: %w", err)
	}
	st := &targetState{version: v, dbs: map[string]targetDB{}}
	if len(databases) == 0 {
		return st, nil
	}
	in := make([]string, len(databases))
	for i, d := range databases {
		in[i] = quoteString(d)
	}
	list := strings.Join(in, ", ")
	rows, err := s.queryStrings(ctx, "SELECT name, engine FROM system.databases WHERE name IN ("+list+")")
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	for _, r := range rows {
		st.dbs[r[0]] = targetDB{engine: r[1]}
	}
	rows, err = s.queryStrings(ctx, "SELECT database, toString(count()) FROM system.tables WHERE database IN ("+list+") GROUP BY database")
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	for _, r := range rows {
		n, _ := strconv.Atoi(r[1])
		d := st.dbs[r[0]]
		d.objects = n
		st.dbs[r[0]] = d
	}
	return st, nil
}

// InspectRestoreTarget implements restore.TargetInspector: for each
// selected database that exists on the target, whether it holds tables,
// views or dictionaries. It writes nothing.
func (Engine) InspectRestoreTarget(ctx context.Context, ec backup.EngineContext, databases []string) (*restore.TargetReport, error) {
	opts, err := ParseOptions(ec.Options)
	if err != nil {
		return nil, err
	}
	s, err := connect(ctx, ec, opts)
	if err != nil {
		return nil, err
	}
	defer s.close()
	st, err := s.inspectTarget(ctx, databases)
	if err != nil {
		return nil, err
	}
	rep := &restore.TargetReport{Existing: map[string]bool{}, ServerVersion: st.version}
	for name, d := range st.dbs {
		rep.Existing[name] = d.objects > 0
	}
	return rep, nil
}

// ---------------------------------------------------------------- plan

// Restore phases, in order (docs/design/ui-restore.md "ClickHouse objects").
const (
	phaseDatabase = iota
	phaseTable
	phaseData
)

var phaseNames = []string{"database", "table", "data"}

// objPlan is one table the restore creates: a table of the backup, or a
// materialized view's inner table under a new name.
type objPlan struct {
	db     string
	t      Table
	sql    string // the CREATE TABLE Olympos generated (table.go)
	target string // its name on the target
}

// dbPlan is a selected database that passed its preflight.
type dbPlan struct {
	db      Database
	exists  bool   // exists on the target without objects: restored into
	create  string // the generated CREATE DATABASE ("" when it exists)
	objs    []*objPlan
	skipped []string
	notes   []string
}

func (p *dbPlan) dataBytes() int64 {
	var n int64
	for _, o := range p.objs {
		for _, pt := range o.t.Partitions {
			n += pt.Bytes
		}
	}
	return n
}

// step is one thing the restore does, in order.
type step struct {
	phase int
	plan  *dbPlan
	obj   *objPlan // nil for CREATE DATABASE
}

func (s step) String() string {
	if s.obj == nil {
		return phaseNames[s.phase] + " " + s.plan.db.Name
	}
	return phaseNames[s.phase] + " " + s.plan.db.Name + "." + s.obj.target
}

// steps orders the work: every database, then the tables of every
// database, then their data.
func steps(plans []*dbPlan) []step {
	var out []step
	for _, p := range plans {
		if p.create != "" {
			out = append(out, step{phase: phaseDatabase, plan: p})
		}
	}
	for _, phase := range []int{phaseTable, phaseData} {
		for _, p := range plans {
			for _, o := range p.objs {
				if phase == phaseTable || (o.t.HasData && hasEntries(o.t)) {
					out = append(out, step{phase: phase, plan: p, obj: o})
				}
			}
		}
	}
	return out
}

func hasEntries(t Table) bool {
	for _, p := range t.Partitions {
		if p.Entry != "" {
			return true
		}
	}
	return false
}

// maxSchemaEntry bounds the bytes of a schema entry that are read into
// memory and lexed, and maxManifest those of the manifest. A schema entry is
// only read for its ENGINE clause, and the lexer's cost grows with the
// number of tokens (a 16 MiB run of commas takes about 3.6 GB of heap), so
// the cap is small: a longer entry is not read, and the table whose engine
// parameters it would have given is reported as not created.
const (
	maxSchemaEntry = 1 << 20
	maxManifest    = 256 << 20
)

func readSmall(f *zip.File, max int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(max) {
		return nil, fmt.Errorf("%s: %d bytes is more than the %d a restore reads", f.Name, f.UncompressedSize64, max)
	}
	r, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name, err)
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is too large", f.Name)
	}
	return b, nil
}

func readManifest(entries map[string]*zip.File) (*Manifest, error) {
	f := entries["manifest.json"]
	if f == nil {
		return nil, errors.New("the backup holds no manifest.json (not an Olympos ClickHouse backup)")
	}
	b, err := readSmall(f, maxManifest)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	if m.Format != ManifestFormat || m.Engine != Name {
		return nil, fmt.Errorf("manifest.json has format %q, engine %q; this restore reads %q", m.Format, m.Engine, ManifestFormat)
	}
	if m.DryRun {
		return nil, errors.New("the backup is a dry run (schema only, no data): it is not restored")
	}
	return &m, nil
}

// requestIDRe is what a request id may look like in a Keeper path.
var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// planDatabase checks one selected database without writing anything: it
// is in the backup, not on the target with objects, its database engine is
// restorable, and every table that is created has its data entries. It
// generates the CREATE DATABASE and each CREATE TABLE (buildTable); objects
// that are not created are listed in skipped. msg is why the database
// cannot be restored ("" when it can).
func planDatabase(md *Database, entries map[string]*zip.File, ts *targetState, requestID string) (*dbPlan, string) {
	p, msg := planDatabase1(md, entries, ts, requestID)
	for i := range p.skipped {
		p.skipped[i] = printable(p.skipped[i])
	}
	for i := range p.notes {
		p.notes[i] = printable(p.notes[i])
	}
	return p, printable(msg)
}

// printable escapes control characters (names in the backup may hold
// any) so a message is one plain line.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			fmt.Fprintf(&b, "\\x%02x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// maxFileName is the longest file name the target's filesystem takes; a
// table's metadata file is its escaped name with ".sql".
const maxFileName = 255

// escapeForFileName is ClickHouse's: [A-Za-z0-9_] stay, every other byte
// is %XX.
func escapeForFileName(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isWordByte(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func planDatabase1(md *Database, entries map[string]*zip.File, ts *targetState, requestID string) (*dbPlan, string) {
	p := &dbPlan{}
	if md == nil {
		return p, "the backup holds no such database"
	}
	p.db = *md
	if d, ok := ts.dbs[md.Name]; ok {
		if d.objects > 0 {
			return p, "the database exists on the target with tables, views or dictionaries in it"
		}
		if why := databaseEngineProblem(d.engine); why != "" {
			return p, "the database exists on the target, and " + why
		}
		p.exists = true
	}
	if why := databaseEngineProblem(md.Engine); why != "" {
		return p, why
	}
	if !p.exists {
		p.create = databaseSQL(md.Name)
		if md.Engine != "Atomic" {
			p.notes = append(p.notes, md.Name+": created with the Atomic database engine (the backup's was "+md.Engine+")")
		}
	}

	names := map[string]string{} // name -> kind
	for _, t := range md.Tables {
		names[t.Name] = t.Kind
	}
	targets := map[string]bool{}
	dataPrefix := func(t Table) string { return "data/" + pathSegment(md.Name) + "/" + pathSegment(t.Name) + "/" }
	checkData := func(t Table) string {
		if !t.HasData {
			return ""
		}
		var rows uint64
		for _, pt := range t.Partitions {
			rows += pt.Rows
			if pt.Entry == "" {
				if pt.Rows != 0 {
					return fmt.Sprintf("%s: partition %s has %d rows and no data entry", t.Name, pt.ID, pt.Rows)
				}
				continue
			}
			if !strings.HasPrefix(pt.Entry, dataPrefix(t)) || entries[pt.Entry] == nil {
				return fmt.Sprintf("%s: the data entry of partition %s is missing from the backup", t.Name, pt.ID)
			}
			if entries[pt.Entry].UncompressedSize64 != uint64(pt.Bytes) {
				return fmt.Sprintf("%s: the data entry of partition %s has %d bytes, the manifest recorded %d", t.Name, pt.ID,
					entries[pt.Entry].UncompressedSize64, pt.Bytes)
			}
		}
		if rows != t.Rows {
			return fmt.Sprintf("%s: the manifest's partitions hold %d rows, its table %d", t.Name, rows, t.Rows)
		}
		switch t.DataFormat {
		case FormatNative, FormatRowBinary:
		default:
			return fmt.Sprintf("%s: unknown data format %q", t.Name, t.DataFormat)
		}
		return ""
	}
	for _, t := range md.Tables {
		what := md.Name + "." + t.Name + " (" + kindWord(t.Kind) + ")"
		if t.Kind != KindTable && t.Kind != KindMVInner {
			p.skipped = append(p.skipped, what+": "+notRecreated)
			continue
		}
		target := t.Name
		if t.Kind == KindMVInner {
			// The view is not created; its rows are kept in a table of
			// their own.
			if t.InnerOf == "" || names[t.InnerOf] != KindMaterializedView {
				return p, fmt.Sprintf("%s: the backup names no materialized view %q for this inner table", t.Name, t.InnerOf)
			}
			target = t.InnerOf + "__restored_data"
			what = "the data of materialized view " + md.Name + "." + t.InnerOf
			switch {
			case names[target] != "" || targets[target]:
				return p, fmt.Sprintf("the data of materialized view %s would be restored into table %s, which the backup also holds", t.InnerOf, target)
			case len(escapeForFileName(target))+len(".sql.tmp") > maxFileName:
				return p, fmt.Sprintf("the data of materialized view %s would be restored into table %s, a name too long for the target", t.InnerOf, target)
			}
			targets[target] = true
		}
		if _, replicated, ok := splitEngine(t.Engine); ok && replicated && !requestIDRe.MatchString(requestID) {
			return p, t.Name + ": a Keeper path needs the restore request's id, and there is none"
		}
		// The schema entry is only read for engine parameters; a missing or
		// oversized (more than maxSchemaEntry) one leaves "" (the engines
		// that need it are then not created). readSmall reads no more than
		// the cap.
		ddl := ""
		if f := entries[t.SchemaEntry]; f != nil && strings.HasPrefix(t.SchemaEntry, "schema/") {
			if b, err := readSmall(f, maxSchemaEntry); err == nil {
				ddl = string(b)
			}
		}
		def, why := buildTable(md.Name, target, t, ddl, requestID)
		if why != "" {
			if t.Kind == KindMVInner {
				p.skipped = append(p.skipped, fmt.Sprintf("%s (%d rows) was not restored: %s; not created (create it by hand)", what, t.Rows, why))
			} else {
				p.skipped = append(p.skipped, what+": "+why+"; not created (create it by hand)")
			}
			continue
		}
		if why := checkData(t); why != "" {
			return p, why
		}
		if def.keeperPath != "" {
			p.notes = append(p.notes, md.Name+"."+target+": its Keeper path is "+def.keeperPath+" (replica {replica}), "+
				"so it shares no Keeper state with the source")
		}
		if t.Kind == KindMVInner {
			p.notes = append(p.notes, fmt.Sprintf("%s was restored into table %s.%s; recreate the view with TO %s.%s",
				what, md.Name, target, quoteIdent(md.Name), quoteIdent(target)))
		}
		p.notes = append(p.notes, md.Name+"."+target+": created from its columns, types, engine and keys; not restored: "+
			strings.Join(def.notRestored, "; ")+"; re-apply them from your schema")
		p.objs = append(p.objs, &objPlan{db: md.Name, t: t, sql: def.sql, target: target})
	}
	return p, ""
}

// ---------------------------------------------------------------- restore

// restorer is one Restore call.
type restorer struct {
	rc     backup.RestoreContext
	s      *session
	client *clientRunner
	res    *backup.RestoreResult
	items  map[string]*backup.RestoreItem
	files  map[string]*zip.File
	done   []string
	// stepFn performs a step (r.do; tests replace it).
	stepFn func(ctx context.Context, st step) error
	opts   Options
}

// session returns the native-protocol session, connected again when the
// server or the tunnel closed it while clickhouse client loaded data.
func (r *restorer) session(ctx context.Context) (*session, error) {
	if !r.s.client.IsClosed() && r.s.client.Ping(ctx) == nil {
		return r.s, nil
	}
	r.s.close()
	s, err := connect(ctx, r.rc.EngineContext, r.opts)
	if err != nil {
		return nil, err
	}
	r.s = s
	return s, nil
}

// Restore implements backup.Restorer (docs/design/ui-restore.md
// "Engines"). Nothing is written before every selected database passed its
// preflight (in the backup, not on the target with objects, a restorable
// database engine, the data entries of every created table) and the
// clickhouse client was found. Then, across the selected databases: CREATE
// DATABASE (unless it exists without objects), the tables of the MergeTree
// and Log families and Memory (materialized views' inner tables as
// <view>__restored_data), and their data through `clickhouse client`.
// Every statement is generated by Olympos from the manifest (table.go); no
// SQL text of the backup is run. Views, materialized views, dictionaries and other
// engines are not created and are reported by name. Nothing is dropped;
// the first failure ends the restore.
func (Engine) Restore(ctx context.Context, rc backup.RestoreContext) (_ *backup.RestoreResult, err error) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
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
		for i := range res.Notes {
			res.Notes[i] = scrub.Scrub(res.Notes[i])
		}
		scrub.Zero()
	}()
	if len(rc.Databases) == 0 {
		return res, errors.New("no databases selected")
	}
	if rc.Archive == nil {
		return res, errors.New("no archive")
	}
	if rc.Progress == nil {
		rc.Progress = func(backup.Progress) {}
	}
	opts, err := ParseOptions(rc.EngineContext.Options)
	if err != nil {
		return res, err
	}
	cred, err := rc.Credential(ctx)
	if err != nil {
		return res, fmt.Errorf("credential: %w", err)
	}
	// A copy: the caller zeroes its own, connect zeroes the one it gets.
	secret := append([]byte(nil), cred.Secret...)
	scrub.Track(backup.Credential{Secret: secret})
	user := cred.Username
	if user == "" {
		user = ch.DefaultUser
	}

	zr, err := zip.NewReader(rc.Archive, rc.Archive.Size())
	if err != nil {
		return res, fmt.Errorf("open the backup archive: %w", err)
	}
	entries := map[string]*zip.File{}
	for _, f := range zr.File {
		entries[f.Name] = f
	}
	m, err := readManifest(entries)
	if err != nil {
		return res, err
	}

	s, err := connect(ctx, rc.EngineContext, opts)
	if err != nil {
		return res, err
	}
	defer func() { s.close() }()
	ts, err := s.inspectTarget(ctx, rc.Databases)
	if err != nil {
		return res, err
	}

	tmp, err := os.MkdirTemp("", "olympos-chr-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return res, err
	}

	// Preflight: every database, and the client, before anything is
	// written.
	inBackup := map[string]*Database{}
	for i := range m.Databases {
		inBackup[m.Databases[i].Name] = &m.Databases[i]
	}
	plans := make([]*dbPlan, len(rc.Databases))
	var refused []string
	for i, db := range rc.Databases {
		plan, msg := planDatabase(inBackup[db], entries, ts, rc.RequestID)
		if msg != "" {
			res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "failed", Bytes: plan.dataBytes(), Error: msg + "; nothing was written"})
			refused = append(refused, db)
			continue
		}
		plans[i] = plan
	}
	var client *clientRunner
	if len(refused) == 0 {
		client, err = newClientRunner(ctx, rc.EngineContext, opts, tmp, user, string(secret))
		if err != nil {
			for _, db := range rc.Databases {
				res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "failed", Bytes: plans[indexOf(rc.Databases, db)].dataBytes(),
					Error: err.Error() + "; nothing was written"})
			}
			return res, nil
		}
	}
	if len(refused) > 0 {
		for i, db := range rc.Databases {
			if plans[i] != nil {
				res.Items = append(res.Items, backup.RestoreItem{Name: db, Status: "skipped", Bytes: plans[i].dataBytes(),
					Error: "not restored: nothing was written because " + strings.Join(refused, ", ") + " cannot be restored"})
			}
		}
		return res, nil
	}
	res.Notes = append(res.Notes, "Data was loaded with "+client.version+".")

	r := &restorer{rc: rc, s: s, client: client, res: res, items: map[string]*backup.RestoreItem{}, files: entries, opts: opts}
	r.stepFn = r.do
	defer func() { s = r.s }()
	for _, p := range plans {
		item := backup.RestoreItem{Name: p.db.Name, Status: "failed", Skipped: append([]string{}, p.skipped...)}
		if p.exists {
			item.Skipped = append(item.Skipped, "the database existed on the target without tables: restored into it, without CREATE DATABASE")
		}
		res.Items = append(res.Items, item)
		res.Notes = append(res.Notes, p.notes...)
	}
	for i := range res.Items {
		r.items[res.Items[i].Name] = &res.Items[i]
	}
	r.run(ctx, plans)
	return res, nil
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// ddlSettings let the target accept the column types and features the
// source accepted (not "important": a server that does not know one
// ignores it).
var ddlSettings = []ch.Setting{
	{Key: "allow_suspicious_low_cardinality_types", Value: "1"},
	{Key: "allow_suspicious_fixed_string_types", Value: "1"},
	// A Nested column is created as a Nested column, not flattened into
	// n.a, n.b arrays (the source reports it as Nested only when it was
	// created with flatten_nested = 0): the data is inserted by column name.
	{Key: "flatten_nested", Value: "0"},
	{Key: "allow_experimental_object_type", Value: "1"},
	{Key: "allow_experimental_variant_type", Value: "1"},
	{Key: "allow_experimental_dynamic_type", Value: "1"},
	{Key: "allow_experimental_json_type", Value: "1"},
}

// exec runs one statement Olympos generated over the native protocol.
func (s *session) exec(ctx context.Context, stmt string) error {
	return s.client.Do(ctx, ch.Query{Body: stmt, Settings: ddlSettings})
}

// createError is a failed CREATE without the server's message, which can
// quote anything the statement made the server read: the error code and
// name only. Other errors (the connection) are kept.
func createError(err error) error {
	e, ok := ch.AsException(err)
	if !ok {
		return err
	}
	name := "UNKNOWN"
	if e.Code.IsAError() {
		name = e.Code.String()
	}
	return fmt.Errorf("the target refused it: Code %d %s", int(e.Code), name)
}

// run performs the steps in order; the first failure ends the restore. A
// database whose steps all succeeded is reported succeeded, the failing
// one with the error, the others as not completed.
func (r *restorer) run(ctx context.Context, plans []*dbPlan) {
	all := steps(plans)
	left := map[string]int{} // database -> steps not done yet
	for _, st := range all {
		left[st.plan.db.Name]++
	}
	start := map[string]time.Time{}
	finish := func(db string) {
		it := r.items[db]
		it.Status = "succeeded"
		it.Duration = time.Since(start[db]).Seconds()
		r.done = append(r.done, db)
		r.progress("", "")
	}
	for _, p := range plans {
		start[p.db.Name] = time.Now()
		if left[p.db.Name] == 0 {
			finish(p.db.Name)
		}
	}
	failAt := func(failed step, err error) {
		db := failed.plan.db.Name
		what := db
		if failed.obj != nil {
			what += "." + failed.obj.t.Name
		}
		r.items[db].Error = fmt.Sprintf("%s (%s): %v", what, phaseNames[failed.phase], err)
		r.items[db].Duration = time.Since(start[db]).Seconds()
		for _, p := range plans {
			if n := p.db.Name; n != db && left[n] > 0 {
				r.items[n].Error = "not completed: the restore stopped after " + what + " failed"
				r.items[n].Duration = time.Since(start[n]).Seconds()
			}
		}
	}
	for _, st := range all {
		if err := ctx.Err(); err != nil {
			failAt(st, err)
			return
		}
		if err := r.stepFn(ctx, st); err != nil {
			failAt(st, err)
			return
		}
		db := st.plan.db.Name
		if left[db]--; left[db] == 0 {
			finish(db)
		}
	}
}

func (r *restorer) progress(db, table string) {
	r.rc.Progress(backup.Progress{Phase: "restore", Database: db, Table: table,
		Done: append([]string{}, r.done...), Created: append([]string{}, r.res.Created...)})
}

// do performs one step.
func (r *restorer) do(ctx context.Context, st step) error {
	db := st.plan.db.Name
	item := r.items[db]
	if st.phase != phaseData {
		if _, err := r.session(ctx); err != nil {
			return err
		}
	}
	if st.obj == nil {
		r.progress(db, "")
		if err := r.s.exec(ctx, st.plan.create); err != nil {
			return fmt.Errorf("create the database: %w", createError(err))
		}
		r.res.Created = append(r.res.Created, db)
		r.progress(db, "")
		return nil
	}
	o := st.obj
	r.progress(db, o.target)
	if st.phase == phaseData {
		rows, n, err := r.load(ctx, db, o.target, o.t)
		item.Rows += int64(rows)
		item.Bytes += n
		return err
	}
	if err := r.s.exec(ctx, o.sql); err != nil {
		err = createError(err)
		if _, replicated, _ := splitEngine(o.t.Engine); replicated {
			return fmt.Errorf("%w (a Replicated table needs Keeper and the {replica} macro on the target)", err)
		}
		return err
	}
	item.Tables++
	return nil
}

// load streams the data entries of table t into db.target through
// `clickhouse client`, one entry at a time: each entry's size, SHA-256 and
// row count are checked against the manifest, and so is the table's.
func (r *restorer) load(ctx context.Context, db, target string, t Table) (uint64, int64, error) {
	files := r.files
	var rows uint64
	var bytes int64
	query := "INSERT INTO " + qualified(db, target) + " FORMAT " + t.DataFormat
	for _, p := range t.Partitions {
		if p.Entry == "" {
			continue
		}
		f := files[p.Entry]
		if f == nil {
			return rows, bytes, fmt.Errorf("partition %s: the data entry is missing", p.ID)
		}
		n, read, err := r.loadEntry(ctx, query, f, p)
		rows += n
		bytes += read
		if err != nil {
			return rows, bytes, fmt.Errorf("partition %s: %w", p.ID, err)
		}
	}
	if rows != t.Rows {
		return rows, bytes, fmt.Errorf("%d rows written, the backup holds %d", rows, t.Rows)
	}
	return rows, bytes, nil
}

func (r *restorer) loadEntry(ctx context.Context, query string, f *zip.File, p Partition) (uint64, int64, error) {
	rd, err := f.Open()
	if err != nil {
		return 0, 0, fmt.Errorf("open the data entry: %w", err)
	}
	defer rd.Close()
	in := &hashReader{r: rd, h: sha256.New()}
	rows, runErr := r.client.insert(ctx, query, in)
	if in.err != nil && !errors.Is(in.err, io.EOF) {
		return rows, in.n, fmt.Errorf("read the backup: %w", in.err)
	}
	if runErr != nil {
		return rows, in.n, runErr
	}
	// The rest of the entry (archive/zip checks its CRC-32 at the end).
	if _, err := io.Copy(io.Discard, in); err != nil {
		return rows, in.n, fmt.Errorf("read the backup: %w", err)
	}
	if in.n != p.Bytes {
		return rows, in.n, fmt.Errorf("the data entry has %d bytes, the backup recorded %d", in.n, p.Bytes)
	}
	if p.SHA256 != "" && !strings.EqualFold(hex.EncodeToString(in.h.Sum(nil)), p.SHA256) {
		return rows, in.n, errors.New("the data entry's SHA-256 differs from the one the backup recorded")
	}
	if rows != p.Rows {
		return rows, in.n, fmt.Errorf("%d rows written, the backup holds %d", rows, p.Rows)
	}
	return rows, in.n, nil
}

// hashReader hashes and counts what is read and remembers the first error
// (the zip CRC check).
type hashReader struct {
	r   io.Reader
	h   hash.Hash
	n   int64
	err error
}

func (r *hashReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.h.Write(p[:n])
	r.n += int64(n)
	if err != nil && r.err == nil {
		r.err = err
	}
	return n, err
}

// ---------------------------------------------------------------- client

// clientRunner runs `<bin> client` processes, each through its own local
// bridge to the target's tunnel. The login is in the environment
// (CLICKHOUSE_USER, CLICKHOUSE_PASSWORD), never in argv; TLS settings are
// in a client config file in the restore's 0700 directory.
type clientRunner struct {
	bin     string
	version string
	config  string
	dir     string
	env     []string
	dial    func(ctx context.Context) (net.Conn, error)
}

// clientTimeout bounds the client's --version and --help.
const clientTimeout = 30 * time.Second

var clientVersionRe = regexp.MustCompile(`version (\d+\.\d+[0-9.]*)`)

// newClientRunner finds the clickhouse binary (ClientBin), checks that it
// runs and, with TLS, that it can verify the target's name through the
// local bridge (--tls-sni-override), and writes the client config: with
// TLS verificationMode strict, the target's CAs only, the target's TLS
// name for SNI and the host name check, TLS 1.2 or newer.
func newClientRunner(ctx context.Context, ec backup.EngineContext, opts Options, dir, user, password string) (*clientRunner, error) {
	if strings.ContainsRune(password, 0) || strings.ContainsRune(user, 0) {
		return nil, errors.New("the credential contains a NUL byte, which clickhouse client cannot take")
	}
	bin, err := exec.LookPath(ClientBin())
	if err != nil {
		return nil, fmt.Errorf("the clickhouse client (%s, setting backup.clickhouseClient) was not found: %v", ClientBin(), err)
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	base := []string{"HOME=" + dir, "LC_ALL=C", "TZ=UTC"}
	c := &clientRunner{bin: bin, dir: dir, dial: ec.Dial}
	out, err := c.quick(ctx, base, "--version")
	if err != nil {
		return nil, fmt.Errorf("the clickhouse client %s does not run: %v", bin, err)
	}
	m := clientVersionRe.FindStringSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("the clickhouse client %s printed no version", bin)
	}
	c.version = "clickhouse client " + m[1]

	var cfg strings.Builder
	cfg.WriteString("<clickhouse>\n  <print-num-processed-rows>true</print-num-processed-rows>\n")
	if ec.UseTLS {
		help, err := c.quick(ctx, base, "--help")
		if err != nil {
			return nil, fmt.Errorf("the clickhouse client %s does not run: %v", bin, err)
		}
		if !strings.Contains(help, "--tls-sni-override") {
			return nil, fmt.Errorf("%s cannot verify the target's TLS name through the local bridge (it has no --tls-sni-override); "+
				"use the clickhouse binary shipped with Olympos", c.version)
		}
		name := ec.TLSServerName
		if name == "" {
			name = ec.Target.TLSServerName
		}
		if name == "" {
			return nil, errors.New("clickhouse: TLS server name is required in e2e-tls mode")
		}
		cas, loadDefault, err := clientCAs(ec.TrustSystemRoots, opts.CAPEM)
		if err != nil {
			return nil, err
		}
		caFile := filepath.Join(dir, "target-ca.pem")
		if len(cas) > 0 {
			if err := os.WriteFile(caFile, cas, 0o600); err != nil {
				return nil, err
			}
		}
		cfg.WriteString("  <secure>true</secure>\n  <tls-sni-override>" + xmlText(name) + "</tls-sni-override>\n")
		cfg.WriteString("  <openSSL><client>\n")
		if len(cas) > 0 {
			cfg.WriteString("    <caConfig>" + xmlText(caFile) + "</caConfig>\n")
		}
		cfg.WriteString("    <loadDefaultCAFile>" + strconv.FormatBool(loadDefault) + "</loadDefaultCAFile>\n" +
			"    <verificationMode>strict</verificationMode>\n" +
			"    <extendedVerification>true</extendedVerification>\n" +
			"    <invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler>\n" +
			"    <disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols>\n" +
			"  </client></openSSL>\n")
	} else {
		cfg.WriteString("  <secure>false</secure>\n")
	}
	cfg.WriteString("</clickhouse>\n")
	c.config = filepath.Join(dir, "client.xml")
	if err := os.WriteFile(c.config, []byte(cfg.String()), 0o600); err != nil {
		return nil, err
	}
	c.env = append(base, "CLICKHOUSE_USER="+user, "CLICKHOUSE_PASSWORD="+password)
	return c, nil
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// clientCAs is the PEM file clickhouse client verifies the target with:
// the configured target bundle, the per-target ca_pem and, when system
// roots are trusted, the system bundle (the same roots as tlsConfig).
// loadDefault is set when system roots are trusted and no system bundle
// file was found.
func clientCAs(trustSystem bool, caPEM string) ([]byte, bool, error) {
	perTarget := strings.TrimSpace(caPEM) != ""
	if err := targettls.Usable(trustSystem, perTarget); err != nil {
		return nil, false, err
	}
	var out []byte
	if f := targettls.BundleFile(); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, false, fmt.Errorf("read target CA bundle: %w", err)
		}
		out = append(append(out, b...), '\n')
	}
	if perTarget {
		out = append(append(out, caPEM...), '\n')
	}
	loadDefault := false
	if trustSystem || targettls.SystemRoots() {
		if f := systemRootsFile(); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, false, fmt.Errorf("read the system CA bundle: %w", err)
			}
			out = append(append(out, b...), '\n')
		} else {
			loadDefault = true
		}
	}
	if len(out) == 0 && !loadDefault {
		return nil, false, targettls.ErrNoRoots
	}
	return out, loadDefault, nil
}

// systemRootsFile finds the system CA bundle.
func systemRootsFile() string {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		return f
	}
	for _, f := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ""
}

// quick runs `<bin> client <arg>` without connecting.
func (c *clientRunner) quick(ctx context.Context, env []string, arg string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.bin, "client", arg)
	cmd.Env = env
	cmd.Dir = c.dir
	out := &limitBuffer{max: 1 << 20}
	cmd.Stdout = out
	stderr := &tailBuffer{max: 4 << 10}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, truncate(stderr.String(), 300))
	}
	return out.String(), nil
}

var processedRowsRe = regexp.MustCompile(`(?m)^Processed rows: (\d+)\s*$`)

// insertSettings: the entry is inserted as it is (no deduplication of
// identical blocks, no merge-on-insert of Replacing/Summing tables, not
// asynchronously), so the rows written are the rows the backup streamed. A
// column the table lacks is an error, never skipped (the default skips it
// silently, and the row count would still match).
var insertSettings = []string{"--insert_deduplicate=0", "--optimize_on_insert=0", "--async_insert=0", "--input_format_skip_unknown_fields=0"}

// insert runs one INSERT … FORMAT with in on the client's stdin and returns
// the rows the client sent (print-num-processed-rows).
func (c *clientRunner) insert(ctx context.Context, query string, in io.Reader) (uint64, error) {
	br, err := tunnelbridge.Start(ctx, c.dial, maxBridgeConns)
	if err != nil {
		return 0, err
	}
	defer br.Close()
	args := append([]string{"client", "--config-file", c.config, "--host", "127.0.0.1", "--port", strconv.Itoa(br.Port()),
		"--query", query}, insertSettings...)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin, args...)
	cmd.Env = c.env
	cmd.Dir = c.dir
	out := &limitBuffer{max: 64 << 10}
	cmd.Stdout = out
	stderr := &tailBuffer{max: 16 << 10}
	cmd.Stderr = stderr
	cmd.WaitDelay = 10 * time.Second
	if err := runWithStdin(cmd, in); err != nil {
		msg := clientMessage(stderr.String())
		br.Close()
		if bErr := br.Err(); bErr != nil {
			msg += " (tunnel: " + bErr.Error() + ")"
		}
		return 0, fmt.Errorf("clickhouse client failed: %v: %s", err, msg)
	}
	m := processedRowsRe.FindStringSubmatch(out.String())
	if m == nil {
		return 0, fmt.Errorf("%s did not report the rows it sent (print-num-processed-rows)", c.version)
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// maxBridgeConns is the connections one client process may open through
// its bridge.
const maxBridgeConns = 2

var (
	clientCodeRe = regexp.MustCompile(`Code: (\d+)\. `)
	clientNameRe = regexp.MustCompile(`\(([A-Z][A-Z0-9_]{2,})\)`)
)

// quotableCodes are client errors whose message is about the connection,
// the login or the table, not the rows sent: their text is kept.
var quotableCodes = map[int]bool{
	60: true, 81: true, 115: true, 159: true, 164: true, 194: true, 202: true, 209: true, 210: true,
	241: true, 242: true, 252: true, 497: true, 516: true, 999: true,
}

// clientMessage trims clickhouse client's stderr: the error code and name,
// and the message only for errors that cannot quote the rows being
// inserted (connection, TLS, login, access, missing table).
func clientMessage(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	loc := clientCodeRe.FindStringSubmatchIndex(stderr)
	if loc == nil {
		// No ClickHouse error: its text is not shown at all.
		return "the client reported no error code; its output is not shown"
	}
	code, _ := strconv.Atoi(stderr[loc[2]:loc[3]])
	rest := stderr[loc[0]:]
	name := ""
	if ms := clientNameRe.FindAllStringSubmatch(rest, -1); len(ms) > 0 {
		name = ms[len(ms)-1][1]
	}
	if quotableCodes[code] {
		line, _, _ := strings.Cut(rest, "\n")
		return truncate(line, 500)
	}
	return fmt.Sprintf("Code: %d (%s); the client's message is not shown, as it may quote rows of the backup", code, name)
}

// runWithStdin runs cmd with in copied to its stdin through an os.Pipe by a
// goroutine of ours, and waits for that goroutine: exec's own copy may be
// abandoned after WaitDelay while still reading in.
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
	pr.Close()
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(pw, in)
		_ = pw.Close()
	}()
	err = cmd.Wait()
	_ = pw.Close()
	<-copied
	return err
}

// limitBuffer keeps up to max bytes.
type limitBuffer struct {
	b   []byte
	max int
}

func (l *limitBuffer) Write(p []byte) (int, error) {
	if room := l.max - len(l.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *limitBuffer) String() string { return string(l.b) }

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(t.b)) }
