package clickhouse

// The restore check of a native backup (design docs/design/clickhouse-native.md
// §6, task 16): the copy's chain verifies (VerifyChain), every incremental of
// it was taken through the endpoint the restore uses, and the allowlist
// decides for the selected databases, from the definitions read through the
// chain's checked reader. What the restore then runs is task 17's.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/ch-go"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

var _ backup.NativeRestoreEngine = Engine{}

// CheckNativeRestore implements backup.NativeRestoreEngine.
//
// When the chain does not verify, nothing of it is read: the copy's own
// manifest is verified alone (VerifySigned), and when it verifies, the
// objects of the selected databases it lists are returned, every one left
// out because the backup's manifest does not verify, with the error. A
// manifest that verifies alone vouches for what the backup holds, not for
// the DDL it takes from other runs (VerifySigned), so nothing is allowed on
// it.
func (Engine) CheckNativeRestore(ctx context.Context, in backup.NativeRestoreInput) (*backup.NativeRestoreCheck, error) {
	ms, err := VerifyChain(ctx, in.KV, in.KeyName, in.RunID, in.Signed)
	if err != nil {
		return unverifiedCheck(ctx, in), fmt.Errorf("%w: %v", backup.ErrNativeNotVerified, err)
	}
	last := ms[len(ms)-1]
	check := &backup.NativeRestoreCheck{Databases: []string{}, Objects: []backup.NativeDecision{}}
	for _, d := range last.Databases {
		check.Databases = append(check.Databases, d.Name)
	}
	// Each incremental's BACKUP named its base by URL (statementSettings),
	// and its .backup keeps that URL: the restore's ClickHouse reads the
	// base from there, so it must be the endpoint the restore is served on.
	for i := 1; i < len(ms); i++ {
		want := "S3(" + quoteString(backup.NativeRunURL(in.IngestURL, ms[i-1].RunID)) + ")"
		if got := ms[i].Settings["base_backup"]; got != want {
			return check, fmt.Errorf("%w: run %s was taken through another ingest endpoint (its base is %s), and ClickHouse would read its base "+
				"from there; restore a full backup, or a run whose chain was taken through ingest.url as it is now",
				backup.ErrNativeChain, ms[i].RunID, short(strings.TrimSuffix(strings.TrimPrefix(got, "S3('"), "')")))
		}
	}
	chain := make([]backup.NativeChainManifest, len(ms))
	for i, m := range ms {
		chain[i] = backup.NativeChainManifest{RunID: m.RunID, SHA256: m.SHA256(), Objects: slices.Clone(m.Objects)}
	}
	read, err := in.Bind(chain)
	if err != nil {
		return check, fmt.Errorf("%w: %v", backup.ErrNativeNotVerified, err)
	}
	selected := selectedDatabases(in.Databases)
	ddl, err := readDefinitions(ctx, read, last.Databases, selected)
	if err != nil {
		return check, err
	}
	if check.RefusedDatabases, err = refusedDatabases(ctx, read, chain, last.Databases, selected); err != nil {
		return check, err
	}
	check.DDL, check.Rows = map[string][]byte{}, map[string]uint64{}
	objects := map[string]NativeObject{}
	for _, d := range last.Databases {
		for _, o := range d.Objects {
			objects[restoreKey(d.Name, o.Name)] = o
		}
	}
	for _, dec := range classify(last.Databases, selected, ddl) {
		check.Objects = append(check.Objects, backup.NativeDecision(dec))
		if !dec.Allowed || dec.Kind != KindTable {
			continue
		}
		// What the restore needs of an allowed table: its row count, and the
		// definition of a Replicated one, which it creates itself.
		key := restoreKey(dec.Database, dec.Name)
		o := objects[key]
		check.Rows[key] = o.Rows
		if body := ddl[o.DDLKey]; readDefinition(dec.Database, dec.Name, body).replicated {
			check.DDL[key] = body
		}
	}
	check.Manifests = chain
	return check, nil
}

// refusedDatabases reads the own definition (metadata/<db>.sql) of each
// selected database, from the latest run of the chain that holds it (an
// incremental keeps an unchanged one in its base), and returns those a
// native restore cannot create, with the reason (R52): the restore creates
// each database as Atomic, and RESTORE refuses a database whose definition
// in the backup is another. Only CREATE DATABASE <db> [UUID '…'] ENGINE =
// Atomic, with nothing after it, is restored. A definition that cannot be
// read through the chain's checked reader is ErrNativeNotVerified.
func refusedDatabases(ctx context.Context, read backup.NativeObjectReader, chain []backup.NativeChainManifest, dbs []NativeDatabase,
	selected map[string]bool) (map[string]string, error) {
	// The database definitions the chain holds, by key.
	listed := map[string]bool{}
	for _, m := range chain {
		for _, o := range m.Objects {
			if rest, ok := strings.CutPrefix(o.Key, m.RunID+"/metadata/"); ok && !strings.Contains(rest, "/") && strings.HasSuffix(rest, ".sql") {
				listed[o.Key] = true
			}
		}
	}
	out := map[string]string{}
	for _, d := range dbs {
		if selected != nil && !selected[d.Name] {
			continue
		}
		key := ""
		for i := len(chain) - 1; i >= 0 && key == ""; i-- {
			if k := chain[i].RunID + "/metadata/" + escapeForFileName(d.Name) + ".sql"; listed[k] {
				key = k
			}
		}
		if key == "" {
			out[d.Name] = "its definition is not in the backup"
			continue
		}
		body, err := read(ctx, key, maxSchemaEntry)
		if err != nil {
			return nil, fmt.Errorf("%w: the definition of database %s: %v", backup.ErrNativeNotVerified, clip(d.Name), err)
		}
		if why := atomicDatabase(key, d.Name, body); why != "" {
			out[d.Name] = why
		}
	}
	return out, nil
}

// atomicDatabase says why body, the backup's definition of database db, is
// not one a native restore creates ("" when it is: CREATE DATABASE db
// [UUID '…'] ENGINE = Atomic and nothing after it).
func atomicDatabase(key, db string, body []byte) string {
	_, engine, err := readCreate(key, db, "", body)
	switch {
	case err != nil:
		return "its definition cannot be read with certainty"
	case engine != "Atomic":
		return "it has the " + shortName(engine) + " database engine; a native restore creates Atomic databases only, and RESTORE " +
			"refuses a database of another engine (restore it with the logical method)"
	}
	toks, err := lexSQL(string(body))
	if n := len(toks); err != nil || n < 3 || !toks[n-3].is("ENGINE") || !toks[n-2].punct("=") || toks[n-1].val != "Atomic" {
		return "its definition holds more than ENGINE = Atomic, which RESTORE would compare with the database a native restore creates"
	}
	return ""
}

// restoreKey is the key of an object in NativeRestoreCheck.DDL and Rows:
// its metadata file's path in the backup, as ClickHouse names it.
func restoreKey(db, name string) string {
	return "metadata/" + escapeForFileName(db) + "/" + escapeForFileName(name) + ".sql"
}

// ddlReaders is how many definitions the check reads at once: each is one
// GET from the destination, and a schema of thousands of objects would
// otherwise hold the check's slot for as many round trips.
const ddlReaders = 8

// readDefinitions reads the definitions of the selected databases' objects
// through read, ddlReaders at a time, by DDLKey. Any failure is
// ErrNativeNotVerified, naming the object.
func readDefinitions(ctx context.Context, read backup.NativeObjectReader, dbs []NativeDatabase, selected map[string]bool) (map[string][]byte, error) {
	type job struct{ db, name, key string }
	var jobs []job
	seen := map[string]bool{}
	for _, d := range dbs {
		if selected != nil && !selected[d.Name] {
			continue
		}
		for _, o := range d.Objects {
			if !seen[o.DDLKey] {
				seen[o.DDLKey] = true
				jobs = append(jobs, job{d.Name, o.Name, o.DDLKey})
			}
		}
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bodies := make([][]byte, len(jobs))
	done := make([]bool, len(jobs))
	errs := make([]error, len(jobs))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(ddlReaders, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				// The manifest was built only from definitions up to
				// maxSchemaEntry (ObjectsFromMetadata).
				b, err := read(ctx, jobs[i].key, maxSchemaEntry)
				if err != nil {
					// A read cut by another's failure is not one.
					if !(errors.Is(err, context.Canceled) && ctx.Err() != nil) {
						errs[i] = err
					}
					cancel() // a failure stops the others
					continue
				}
				bodies[i], done[i] = b, true
			}
		}()
	}
feed:
	for i := range jobs {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if err := parent.Err(); err != nil {
		return nil, err
	}
	// The first failure in the manifest's order.
	for i, j := range jobs {
		if errs[i] != nil {
			return nil, fmt.Errorf("%w: the definition of %s.%s: %v", backup.ErrNativeNotVerified, clip(j.db), clip(j.name), errs[i])
		}
	}
	out := make(map[string][]byte, len(jobs))
	for i, j := range jobs {
		if !done[i] {
			return nil, fmt.Errorf("%w: the definition of %s.%s was not read", backup.ErrNativeNotVerified, clip(j.db), clip(j.name))
		}
		out[j.key] = bodies[i]
	}
	return out, nil
}

// unverifiedCheck lists the objects of the selected databases that the
// copy's own manifest holds, when it verifies alone and is the one its copy
// row records (in.SHA256), every one left out; none otherwise.
func unverifiedCheck(ctx context.Context, in backup.NativeRestoreInput) *backup.NativeRestoreCheck {
	check := &backup.NativeRestoreCheck{Databases: []string{}, Objects: []backup.NativeDecision{}}
	if len(in.Signed) == 0 {
		return check
	}
	// It must also be the manifest the copy row records: a sidecar copied
	// from another copy of the run, or one written again, lists nothing.
	m, err := VerifySigned(ctx, in.KV, in.KeyName, in.RunID, in.Signed[len(in.Signed)-1])
	if err != nil || m.SHA256() != in.SHA256 {
		return check
	}
	selected := selectedDatabases(in.Databases)
	for _, d := range m.Databases {
		check.Databases = append(check.Databases, d.Name)
		if selected != nil && !selected[d.Name] {
			continue
		}
		for _, o := range d.Objects {
			check.Objects = append(check.Objects, backup.NativeDecision{Database: d.Name, Name: o.Name, Kind: o.Kind,
				Reason: backup.ErrNativeNotVerified.Error()})
		}
	}
	return check
}

// selectedDatabases is the set of names (trimmed, as the restore takes
// them); nil selects every database.
func selectedDatabases(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, n := range names {
		out[strings.TrimSpace(n)] = true
	}
	return out
}

// ---------------------------------------------------------------- the restore (task 17)

// The statuses of system.backups a restore goes through. KILL ends one as
// RESTORE_FAILED, or as RESTORE_CANCELLED on versions that have it.
const (
	statusRestoring        = "RESTORING"
	statusRestored         = "RESTORED"
	statusRestoreFailed    = "RESTORE_FAILED"
	statusRestoreCancelled = "RESTORE_CANCELLED"
)

// NativeRestore is one native restore: where the target reads the copy,
// with which ingest credential, and what the check decided.
type NativeRestore struct {
	// URL is the copy's run directory on the endpoint,
	// "<ingest.url>/olympos/<run-id>/", and RunID that run.
	URL, RunID string
	// AccessKey and Secret are the restore's read-only ingest credential.
	// The secret goes into the statement and nowhere else.
	AccessKey, Secret string
	// Decisions are the check's for the selected databases: what is not
	// allowed is left out (EXCEPT TABLES).
	Decisions []Decision
	// DDL holds the definitions of the allowed Replicated tables, by
	// restoreKey: the restore creates them itself, with their Keeper path
	// rewritten, before RESTORE fills them. Rows holds every allowed table's
	// row count in the backup, by restoreKey.
	DDL  map[string][]byte
	Rows map[string]uint64
	// Stop delivers why the restore's ingest session stopped: the restore
	// is then ended with KILL QUERY.
	Stop <-chan string
}

// String and LogValue keep the secret out of every print and log.
func (nr NativeRestore) String() string {
	return fmt.Sprintf("clickhouse.NativeRestore{run %s, key %s, secret redacted}", nr.RunID, nr.AccessKey)
}
func (nr NativeRestore) GoString() string { return nr.String() }

func (nr NativeRestore) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run", nr.RunID), slog.String("access_key", nr.AccessKey))
}

var _ backup.NativeRestorer = Engine{}

// RestoreNativeBackup implements backup.NativeRestorer with RestoreNative.
func (e Engine) RestoreNativeBackup(ctx context.Context, rc backup.RestoreContext, run backup.NativeRestoreRun) (*backup.RestoreResult, error) {
	nr := NativeRestore{URL: run.URL, RunID: run.RunID, AccessKey: run.AccessKey, Secret: run.Secret, DDL: run.DDL, Rows: run.Rows, Stop: run.Stop}
	for _, d := range run.Decisions {
		nr.Decisions = append(nr.Decisions, Decision(d))
	}
	return e.RestoreNative(ctx, rc, nr)
}

// nativeRestorePlan is what a native restore does, decided before anything
// is sent to the target.
type nativeRestorePlan struct {
	databases []string
	// tables are the allowed tables by database, in the decisions' order;
	// creates the CREATE TABLE of each Replicated one, by restoreKey.
	tables  map[string][]Decision
	creates map[string]string
	// allowed are every allowed object, by database and name.
	allowed map[objRef]Decision
	// except are the objects left out, by database.
	except map[string][]Decision
}

// planNativeRestore checks nr against the selection and builds the
// statements of the Replicated tables with requestID's Keeper paths. Every
// decision is of a selected database, and every definition in nr.DDL is of
// an allowed table; a definition the rewrite refuses fails the restore
// (the check ran the same rewrite).
func planNativeRestore(requestID string, databases []string, nr NativeRestore) (*nativeRestorePlan, error) {
	p := &nativeRestorePlan{tables: map[string][]Decision{}, creates: map[string]string{}, except: map[string][]Decision{},
		allowed: map[objRef]Decision{}}
	selected := map[string]bool{}
	for _, db := range databases {
		if db == "" || strings.ContainsRune(db, 0) || isSystemDatabase(db) {
			return nil, fmt.Errorf("clickhouse: database %q cannot be restored", clip(db))
		}
		if !selected[db] {
			selected[db] = true
			p.databases = append(p.databases, db)
		}
	}
	if len(p.databases) == 0 {
		return nil, errors.New("clickhouse: no databases selected")
	}
	seen := map[string]bool{}
	for _, d := range nr.Decisions {
		if !selected[d.Database] {
			return nil, fmt.Errorf("clickhouse: the decision for %s.%s is not of a selected database", clip(d.Database), clip(d.Name))
		}
		key := restoreKey(d.Database, d.Name)
		if seen[key] {
			return nil, fmt.Errorf("clickhouse: %s.%s is decided twice", clip(d.Database), clip(d.Name))
		}
		seen[key] = true
		if d.Allowed {
			p.allowed[objRef{d.Database, d.Name}] = d
		}
		switch {
		case !d.Allowed:
			p.except[d.Database] = append(p.except[d.Database], d)
		case d.Kind == KindTable:
			p.tables[d.Database] = append(p.tables[d.Database], d)
			if body, ok := nr.DDL[key]; ok {
				stmt, err := replicatedCreate(string(body), requestID, d.Database, d.Name)
				if err != nil {
					return nil, fmt.Errorf("clickhouse: %s.%s: %w", clip(d.Database), clip(d.Name), err)
				}
				p.creates[key] = stmt
			}
		}
	}
	for key := range nr.DDL {
		if _, ok := p.creates[key]; !ok {
			return nil, fmt.Errorf("clickhouse: a definition to create (%s) is not of an allowed table", clip(key))
		}
	}
	for _, ts := range p.tables {
		for _, d := range ts {
			if _, ok := nr.Rows[restoreKey(d.Database, d.Name)]; !ok {
				return nil, fmt.Errorf("clickhouse: the backup's row count of %s.%s is missing", clip(d.Database), clip(d.Name))
			}
		}
	}
	return p, nil
}

// restoreStatement is the RESTORE of a native restore (design §6, R26, R51). It
// holds the secret: never log it, log redactStatement of it.
func restoreStatement(p *nativeRestorePlan, nr NativeRestore, requestID string) string {
	var b strings.Builder
	b.WriteString("RESTORE ")
	for i, db := range p.databases {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("DATABASE " + quoteIdent(db))
		for j, d := range p.except[db] {
			if j == 0 {
				b.WriteString(" EXCEPT TABLES ")
			} else {
				b.WriteString(", ")
			}
			b.WriteString(quoteIdent(db) + "." + quoteIdent(d.Name))
		}
	}
	b.WriteString(" FROM S3(" + quoteString(nr.URL) + ", " + quoteString(nr.AccessKey) + ", " + quoteString(nr.Secret) + ")")
	// allow_s3_native_copy = 0 (R51): a target table on an S3 disk would
	// otherwise copy its files server-side (CopyObject through the disk's
	// own S3 client), past the endpoint's verified read.
	b.WriteString(" SETTINGS async = 1, allow_different_table_def = 1, allow_s3_native_copy = 0, " +
		"use_same_s3_credentials_for_base_backup = 1, id = " + quoteString(requestID))
	return b.String()
}

// RestoreNative restores a native copy into the target of rc (design §6,
// Execute): it creates the selected databases that do
// not exist (an existing one must be empty), then every allowed Replicated
// table from the backup's own CREATE TABLE with its Keeper path rewritten
// and its UUID dropped (replicatedCreate), then sends RESTORE … EXCEPT
// TABLES <every object left out> with async = 1, on a new connection in the
// first restored database, which fills the tables it finds and creates the
// others, and polls system.backups every 5 s. When
// nr.Stop delivers or ctx is cancelled, it KILLs the RESTORE on that
// connection, and on a new one when it lost track of it (an error wrapping
// backup.ErrNativeOrphan says that did not end it either). After RESTORED,
// every allowed table's row count must be the backup's; a table that
// differs fails the restore, named.
//
// The statement and its secret are never logged or returned.
func (Engine) RestoreNative(ctx context.Context, rc backup.RestoreContext, nr NativeRestore) (_ *backup.RestoreResult, err error) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
	defer func() {
		if err != nil {
			err = errors.New(maskSecret(err.Error(), nr.Secret))
		}
	}()
	if rc.Progress == nil {
		rc.Progress = func(backup.Progress) {}
	}
	if !isRunID(rc.RequestID) {
		return res, fmt.Errorf("clickhouse: request id %q is not a lower-case UUID", clip(rc.RequestID))
	}
	if !isRunID(nr.RunID) {
		return res, fmt.Errorf("clickhouse: native run id %q is not a lower-case UUID", clip(nr.RunID))
	}
	if nr.AccessKey == "" || nr.Secret == "" {
		return res, errors.New("clickhouse: a native restore needs its ingest credential")
	}
	if _, err := runURL(nr.URL, nr.RunID); err != nil {
		return res, err
	}
	plan, err := planNativeRestore(rc.RequestID, rc.Databases, nr)
	if err != nil {
		return res, err
	}
	opts, err := ParseOptions(rc.EngineContext.Options)
	if err != nil {
		return res, err
	}
	s, err := connect(ctx, rc.EngineContext, opts)
	if err != nil {
		return res, err
	}
	defer func() { s.close() }()
	ts, err := s.inspectTarget(ctx, plan.databases)
	if err != nil {
		return res, fmt.Errorf("clickhouse: %w", err)
	}
	major, minor, ok := parseVersion(ts.version)
	if !ok || major < 24 || major == 24 && minor < 8 {
		return res, fmt.Errorf("clickhouse: native backups are restored into ClickHouse 24.8 or later, and this target runs %s", clip(ts.version))
	}
	for _, db := range plan.databases {
		if d, ok := ts.dbs[db]; ok && d.objects > 0 {
			return res, fmt.Errorf("clickhouse: database %s exists on the target with tables, views or dictionaries in it; nothing was written", clip(db))
		} else if ok {
			if why := databaseEngineProblem(d.engine); why != "" {
				return res, fmt.Errorf("clickhouse: database %s exists on the target, and %s; nothing was written", clip(db), why)
			}
		}
	}

	log := slog.Default().With("restore_id", rc.RequestID, "run", nr.RunID)
	// 1. The databases, 2. the Replicated tables: RESTORE fills a table it
	// finds (allow_different_table_def) and creates the others.
	for _, db := range plan.databases {
		if _, ok := ts.dbs[db]; ok {
			continue
		}
		if err := s.exec(ctx, databaseSQL(db)); err != nil {
			return res, fmt.Errorf("clickhouse: create database %s: %w", clip(db), err)
		}
		res.Created = append(res.Created, db)
		rc.Progress(backup.Progress{Phase: "restore", Database: db, Created: slices.Clone(res.Created)})
	}
	for _, db := range plan.databases {
		for _, d := range plan.tables[db] {
			stmt, ok := plan.creates[restoreKey(db, d.Name)]
			if !ok {
				continue
			}
			if err := s.exec(ctx, stmt); err != nil {
				return res, fmt.Errorf("clickhouse: create the Replicated table %s.%s: %w", clip(db), clip(d.Name), createError(err))
			}
			log.Info("clickhouse: created a Replicated table before its RESTORE", "database", db, "table", d.Name,
				"keeper_path", keeperPath(rc.RequestID, db, d.Name))
			rc.Progress(backup.Progress{Phase: "restore", Database: db, Table: d.Name, Created: slices.Clone(res.Created)})
		}
	}

	// 3. RESTORE, polled as a backup is, on a connection whose default
	// database is the first restored one (security review v0.4, finding 4):
	// RESTORE qualifies a definition's unqualified names with the session's
	// database, and that one held nothing before this restore (it created it
	// or found it empty), so such a name can only reach what the restore
	// creates, never system's tables. The allowlist refuses such a name, and
	// the definitions are compared after the restore, besides.
	s.close()
	if s, err = connectIn(ctx, rc.EngineContext, opts, plan.databases[0]); err != nil {
		return res, err
	}
	again := func(ctx context.Context) (*session, error) { return connect(ctx, rc.EngineContext, opts) }
	if err := s.runRestore(ctx, log, plan, nr, rc.RequestID, again); err != nil {
		return res, err
	}

	// 4. What the target holds now: exactly what was allowed.
	if err := s.checkRestoredObjects(ctx, plan); err != nil {
		return res, err
	}

	// 5. The row counts.
	var mismatched []string
	for _, db := range plan.databases {
		item := backup.RestoreItem{Name: db, Status: "succeeded"}
		for _, d := range plan.tables[db] {
			n, err := s.queryValue(ctx, "SELECT toString(count()) FROM "+quoteIdent(db)+"."+quoteIdent(d.Name))
			if err != nil {
				return res, fmt.Errorf("clickhouse: count the rows of %s.%s: %w", clip(db), clip(d.Name), err)
			}
			got, err := strconv.ParseUint(n, 10, 64)
			if err != nil {
				return res, fmt.Errorf("clickhouse: the row count of %s.%s is %q", clip(db), clip(d.Name), clip(n))
			}
			want := nr.Rows[restoreKey(db, d.Name)]
			if got != want {
				mismatched = append(mismatched, fmt.Sprintf("%s.%s has %d rows, the backup %d", printable(db), printable(d.Name), got, want))
				item.Status = "failed"
			}
			item.Tables++
			item.Rows += int64(got)
		}
		for _, d := range plan.except[db] {
			item.Skipped = append(item.Skipped, printable(d.Name)+": "+d.Reason)
		}
		if item.Status == "failed" {
			item.Error = "row counts differ from the backup's"
		}
		res.Items = append(res.Items, item)
		rc.Progress(backup.Progress{Phase: "restore", Database: db, Done: doneNames(res.Items), Created: slices.Clone(res.Created)})
	}
	if len(mismatched) > 0 {
		return res, fmt.Errorf("clickhouse: the restored row counts differ from the backup's: %s", strings.Join(mismatched, "; "))
	}
	return res, nil
}

func doneNames(items []backup.RestoreItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Name
	}
	return out
}

// runRestore sends the RESTORE and follows it to its end, as runBackup does
// a backup: once the statement may have reached the server, every way out
// that did not see the restore end goes through a KILL, on the run's
// connection when it still works, else on a new one.
func (s *session) runRestore(ctx context.Context, log *slog.Logger, p *nativeRestorePlan, nr NativeRestore, requestID string, again redial) error {
	select {
	case reason, ok := <-nr.Stop:
		return fmt.Errorf("clickhouse: native restore not started: the ingest session stopped (%s)", stopReason(reason, ok))
	default:
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("clickhouse: native restore not started: %w", err)
	}
	op := restoreOp(requestID, nr.Secret)
	stmt := restoreStatement(p, nr, requestID)
	log.Info("clickhouse: starting a native restore", "query_id", op.queryID, "statement", redactStatement(stmt))
	if err := s.nativeExec(context.WithoutCancel(ctx), stmt, op.queryID, nativeRestoreSettings...); err != nil {
		if e, refused := ch.AsException(err); refused {
			// The server refused the statement: no restore runs. Its message
			// can quote the statement and the backup's DDL: only its summary.
			name := ""
			if e.Code.IsAError() {
				name = e.Code.String()
			}
			return fmt.Errorf("clickhouse: RESTORE refused: %s", serverErrorSummary(maskSecret(e.Message, nr.Secret), int(e.Code), name))
		}
		return op.orphanKill(log, again, "RESTORE: "+maskSecret(err.Error(), nr.Secret))
	}
	tick := time.NewTicker(nativePollInterval)
	defer tick.Stop()
	for {
		status, msg, err := s.backupStatus(context.WithoutCancel(ctx), requestID)
		if err != nil {
			return op.orphanKill(log, again, "read system.backups: "+maskSecret(err.Error(), nr.Secret))
		}
		switch status {
		case statusRestored:
			log.Info("clickhouse: native restore done")
			return nil
		case statusRestoreFailed, statusRestoreCancelled:
			// system.backups.error can quote the backup's DDL (R52): only its
			// summary, and where the whole message is.
			return fmt.Errorf("clickhouse: native restore %s: %s; the whole message: run SELECT error FROM system.backups WHERE id = %s on the target",
				status, serverErrorSummary(maskSecret(msg, nr.Secret), 0, ""), quoteString(requestID))
		case statusRestoring:
		case "":
			return op.orphanKill(log, again, "the native restore is no longer in system.backups (did the server restart?)")
		default:
			return op.orphanKill(log, again, fmt.Sprintf("the native restore has the unexpected status %q", clip(status)))
		}
		select {
		case <-tick.C:
		case reason, ok := <-nr.Stop:
			return op.kill(s, log, again, "the ingest session stopped: "+stopReason(reason, ok))
		case <-ctx.Done():
			return op.kill(s, log, again, ctx.Err().Error())
		}
	}
}

// nativeOp is a RESTORE that KILL ends: its id in system.backups, its query
// id, the secret to mask, and its statuses.
type nativeOp struct {
	id, queryID, secret, hint string
	running, done             string
	ended                     []string // the statuses KILL leaves
}

func restoreOp(requestID, secret string) nativeOp {
	return nativeOp{id: requestID, queryID: backup.NativeRestoreQueryID(requestID), secret: secret,
		hint: backup.NativeRestoreKillQuery(requestID), running: statusRestoring, done: statusRestored,
		ended: []string{statusRestoreFailed, statusRestoreCancelled}}
}

// kill ends a running restore with KILL QUERY … SYNC on s and waits up to
// nativeKillWait for system.backups to show it ended; when that fails, it
// tries once more on a new connection (orphanKill). It always returns an
// error that names why.
func (op nativeOp) kill(s *session, log *slog.Logger, again redial, why string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nativeKillWait)
	defer cancel()
	log.Warn("clickhouse: ending the native restore with KILL QUERY", "query_id", op.queryID, "reason", why)
	status, err := op.killOn(ctx, s)
	switch {
	case slices.Contains(op.ended, status):
		log.Warn("clickhouse: native restore ended by KILL QUERY", "status", status)
		return fmt.Errorf("clickhouse: native restore ended (%s): KILL QUERY made it %s", why, status)
	case status == op.done:
		return fmt.Errorf("clickhouse: native restore ended (%s), although it was done before KILL QUERY", why)
	case err != nil:
		return op.orphanKill(log, again, why+"; KILL QUERY: "+maskSecret(err.Error(), op.secret))
	default:
		return op.orphanKill(log, again, fmt.Sprintf("%s; still %s %s after KILL QUERY", why, statusText(status), nativeKillWait))
	}
}

// orphanKill is the last try to end a restore the run lost track of: one
// KILL QUERY … SYNC on a new connection, within nativeKillWait. When that
// does not end it either, the error wraps ErrNativeOrphan and names the
// statement that ends it.
func (op nativeOp) orphanKill(log *slog.Logger, again redial, why string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nativeKillWait)
	defer cancel()
	log.Warn("clickhouse: lost the native restore; KILL QUERY on a new connection", "query_id", op.queryID, "reason", why)
	var status string
	s, err := again(ctx)
	if err != nil {
		err = fmt.Errorf("a new connection: %s", maskSecret(err.Error(), op.secret))
	} else {
		defer s.close()
		status, err = op.killOn(ctx, s)
		if err != nil {
			err = errors.New(maskSecret(err.Error(), op.secret))
		}
	}
	switch {
	case slices.Contains(op.ended, status):
		return fmt.Errorf("clickhouse: native restore ended (%s): KILL QUERY on a new connection made it %s", why, status)
	case status == op.done:
		return fmt.Errorf("clickhouse: native restore ended (%s), although it was done", why)
	}
	end := "; run " + op.hint + " on the target"
	if err != nil {
		err = fmt.Errorf("%w (%s); KILL QUERY on a new connection failed: %v%s", ErrNativeOrphan, why, err, end)
	} else {
		err = fmt.Errorf("%w (%s); after KILL QUERY on a new connection it is %s%s", ErrNativeOrphan, why, statusText(status), end)
	}
	log.Error("clickhouse: the native restore may still run on the server", "query_id", op.queryID, "err", err)
	return err
}

// killOn sends KILL QUERY … SYNC for op on s and reads its status once a
// second until it is no longer running, ctx ends, or the row is missing.
func (op nativeOp) killOn(ctx context.Context, s *session) (string, error) {
	if err := s.nativeExec(ctx, "KILL QUERY WHERE query_id = "+quoteString(op.queryID)+" SYNC", ""); err != nil {
		return "", err
	}
	for {
		status, _, err := s.backupStatus(ctx, op.id)
		if err != nil {
			return "", err
		}
		if status != op.running {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, nil
		case <-time.After(time.Second):
		}
	}
}

// serverErrorSummary is what is kept of a ClickHouse error message (R52):
// the message can quote the statement and the backup's DDL, and a
// dictionary's or a database's source can carry a password there. What is
// kept is the error code and name (code and name, or read from msg's
// "Code: N." and its last "(NAME)") and the start of its first line, cut
// before the first quote character or CREATE, at most 120 characters.
func serverErrorSummary(msg string, code int, name string) string {
	if code == 0 {
		if m := errorCodeRe.FindStringSubmatch(msg); m != nil {
			code, _ = strconv.Atoi(m[1])
		}
	}
	if name == "" || name == "UNKNOWN" {
		if m := errorNameRe.FindAllStringSubmatch(msg, -1); m != nil {
			name = m[len(m)-1][1]
		}
	}
	line, _, _ := strings.Cut(msg, "\n")
	line = errorNameRe.ReplaceAllString(errorCodeRe.ReplaceAllString(line, ""), "")
	for {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "DB::Exception:"))
		if t == strings.TrimSpace(line) {
			break
		}
		line = t
	}
	if i := strings.IndexAny(line, "'\"`"); i >= 0 {
		line = line[:i]
	}
	if i := strings.Index(strings.ToUpper(line), "CREATE "); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimRight(strings.TrimSpace(line), ":,;( ")
	if r := []rune(line); len(r) > 120 {
		line = string(r[:120]) + "…"
	}
	line = printable(line)
	head := "Code " + strconv.Itoa(code)
	if code == 0 {
		head = "an error"
	}
	if name != "" && name != "UNKNOWN" {
		head += " " + name
	}
	if line == "" {
		return head
	}
	return head + ": " + line
}

var (
	errorCodeRe = regexp.MustCompile(`Code: (\d+)\.\s*`)
	errorNameRe = regexp.MustCompile(`\(([A-Z][A-Z0-9_]{2,})\)`)
)

// checkRestoredObjects checks, after RESTORED, that the restored databases
// hold what was allowed and nothing else: an object left out that is there
// (an EXCEPT TABLES name RESTORE did not match), or one the restore was not
// to create, fails the restore, named; so does an allowed one that is
// missing. A materialized view's inner table belongs to an allowed view of
// its database: .inner_id.<its UUID> or .inner.<its name>.
func (s *session) checkRestoredObjects(ctx context.Context, p *nativeRestorePlan) error {
	quoted := make([]string, len(p.databases))
	for i, db := range p.databases {
		quoted[i] = quoteString(db)
	}
	rows, err := s.queryStrings(ctx, "SELECT database, name, toString(uuid), engine FROM system.tables WHERE database IN ("+
		strings.Join(quoted, ", ")+") ORDER BY database, name")
	if err != nil {
		return fmt.Errorf("clickhouse: list the restored objects: %w", err)
	}
	found := make([]restoredObject, len(rows))
	for i, r := range rows {
		found[i] = restoredObject{db: r[0], name: r[1], uuid: r[2], engine: r[3]}
	}
	return p.restoredObjects(found)
}

// restoredObject is a row of system.tables.
type restoredObject struct{ db, name, uuid, engine string }

// restoredObjects is checkRestoredObjects on the rows found.
func (p *nativeRestorePlan) restoredObjects(found []restoredObject) error {
	views := map[string]string{} // "<db>\x00.inner_id.<uuid>" or ".inner.<name>" → the view
	for _, o := range found {
		if d, ok := p.allowed[objRef{o.db, o.name}]; ok && d.Kind == KindMaterializedView {
			views[o.db+"\x00.inner_id."+o.uuid] = o.name
			views[o.db+"\x00.inner."+o.name] = o.name
		}
	}
	excluded := map[objRef]bool{}
	for db, ds := range p.except {
		for _, d := range ds {
			excluded[objRef{db, d.Name}] = true
		}
	}
	var problems []string
	seen := map[objRef]bool{}
	for _, o := range found {
		r := objRef{o.db, o.name}
		seen[r] = true
		switch {
		case p.allowed[r].Name != "":
		case isInnerName(o.name) && views[o.db+"\x00"+o.name] != "":
		case excluded[r]:
			problems = append(problems, r.String()+" was to be left out, and the target holds it")
		default:
			problems = append(problems, r.String()+" is not an object the restore was to create")
		}
	}
	for r := range p.allowed {
		if !seen[r] {
			problems = append(problems, r.String()+" was to be restored, and the target does not hold it")
		}
	}
	if len(problems) == 0 {
		return nil
	}
	slices.Sort(problems)
	if len(problems) > 5 {
		problems = append(problems[:5], fmt.Sprintf("and %d more", len(problems)-5))
	}
	return fmt.Errorf("clickhouse: the restored databases do not hold what was decided: %s", strings.Join(problems, "; "))
}
