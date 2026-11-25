package clickhouse

// Native backups (#62, design docs/design/clickhouse-native.md §4): the
// target runs BACKUP DATABASE … TO S3(…) against the Olympos ingest endpoint
// (internal/ingest), with the run's own credential. Olympos sends the
// statement, polls system.backups and, when the run must end early, KILLs
// it, all over one connection: system.backups and the process list are per
// server, and a Service may route a second connection to another pod.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

const (
	// nativeBucket is the ingest endpoint's one bucket.
	nativeBucket = "olympos"
	// nativePollInterval is how often system.backups is read while the
	// backup runs.
	nativePollInterval = 5 * time.Second
	// nativeKillWait bounds the KILL and the wait for the backup to fail
	// after it.
	nativeKillWait = 30 * time.Second
	// nativeQueryTimeout bounds one query on the run's connection. A query
	// is never cut by the run's context: ch-go closes the connection on a
	// cancelled query, and the KILL still needs it.
	nativeQueryTimeout = time.Minute
	// hidden replaces a secret in what is logged, as ClickHouse masks it.
	hidden = "[HIDDEN]"
)

// The statuses of system.backups a backup goes through. KILL ends one as
// BACKUP_FAILED, or as BACKUP_CANCELLED on versions that have it.
const (
	statusCreating  = "CREATING_BACKUP"
	statusCreated   = "BACKUP_CREATED"
	statusFailed    = "BACKUP_FAILED"
	statusCancelled = "BACKUP_CANCELLED"
)

var (
	// ErrNativeVersion: the target is older than 24.8, the first version
	// native backups were tested with (spike).
	ErrNativeVersion = errors.New("clickhouse: native backups need ClickHouse 24.8 or later")
	// ErrNativeSharded: the target is sharded. A BACKUP without ON CLUSTER
	// saves the shard it runs on and reports success (design §4.1).
	ErrNativeSharded = errors.New("clickhouse: native backups of sharded targets are not supported")
)

// NativeRun is one native backup: where ClickHouse writes it, with which
// ingest credential, and what it backs up.
type NativeRun struct {
	// URL is the run's directory on the ingest endpoint,
	// "<ingest.url>/olympos/<run-id>/".
	URL string
	// AccessKey and Secret are the run's ingest credential. The secret goes
	// into the statement and nowhere else: it is never logged or returned.
	AccessKey, Secret string
	// RunID is the backup run, a lower-case UUID: the backup's id in
	// system.backups and the last segment of URL.
	RunID string
	// Base is the base of an incremental; nil for a full backup.
	Base *NativeBase
	// Databases are backed up whole. Empty means every database the
	// backup user sees, except the system databases.
	Databases []string
	// Stop delivers why the run's ingest session stopped (a quota, a rate
	// storm, expiry). ClickHouse retries refused uploads almost forever, so
	// the run is then ended with KILL QUERY (spike §3).
	Stop <-chan string
}

// NativeBase is the backup an incremental is taken on.
type NativeBase struct {
	// URL is the base run's directory, "<ingest.url>/olympos/<run-id>/". The
	// run's own credential reads it (use_same_s3_credentials_for_base_backup,
	// R26), so the base carries none.
	URL   string
	RunID string
}

// String and LogValue keep the secret out of every print and log of a run.
func (nr NativeRun) String() string {
	return fmt.Sprintf("clickhouse.NativeRun{run %s, key %s, secret redacted}", nr.RunID, nr.AccessKey)
}
func (nr NativeRun) GoString() string { return nr.String() }

func (nr NativeRun) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run", nr.RunID), slog.String("access_key", nr.AccessKey))
}

// validate checks what the statement is built from. Its errors never hold
// the secret.
func (nr NativeRun) validate() error {
	if !isRunID(nr.RunID) {
		return fmt.Errorf("clickhouse: native run id %q is not a lower-case UUID", clip(nr.RunID))
	}
	if nr.AccessKey == "" || nr.Secret == "" {
		return errors.New("clickhouse: a native run needs its ingest credential")
	}
	endpoint, err := runURL(nr.URL, nr.RunID)
	if err != nil {
		return err
	}
	if nr.Base != nil {
		if !isRunID(nr.Base.RunID) || nr.Base.RunID == nr.RunID {
			return fmt.Errorf("clickhouse: base run id %q is not another run's lower-case UUID", clip(nr.Base.RunID))
		}
		base, err := runURL(nr.Base.URL, nr.Base.RunID)
		if err != nil {
			return fmt.Errorf("%w (the base)", err)
		}
		// The run's credential reads the base, so it is on the same endpoint.
		if base != endpoint {
			return errors.New("clickhouse: the base of a native run is not on the run's ingest endpoint")
		}
	}
	for _, db := range nr.Databases {
		if db == "" || strings.ContainsRune(db, 0) {
			return errors.New("clickhouse: a native run names an empty or invalid database")
		}
		if isSystemDatabase(db) {
			return fmt.Errorf("clickhouse: database %q is a system database and cannot be backed up", db)
		}
	}
	return nil
}

// runURL checks a run's directory URL, http(s) without user info, query or
// fragment whose path ends in /olympos/<run-id>/, and returns the URL without
// "<run-id>/": the endpoint's bucket.
func runURL(raw, runID string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" ||
		!strings.HasSuffix(u.Path, "/"+nativeBucket+"/"+runID+"/") || !strings.HasSuffix(raw, runID+"/") {
		return "", fmt.Errorf("clickhouse: %q is not the ingest URL of run %s (<ingest.url>/%s/<run-id>/)", clip(raw), runID, nativeBucket)
	}
	return strings.TrimSuffix(raw, runID+"/"), nil
}

// backupStatement is the BACKUP statement of a run (design §4, R26). It
// holds the secret: never log it, log redactStatement of it.
func backupStatement(nr NativeRun) string {
	var b strings.Builder
	b.WriteString("BACKUP ")
	for i, db := range nr.Databases {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("DATABASE " + quoteIdent(db))
	}
	b.WriteString(" TO S3(" + quoteString(nr.URL) + ", " + quoteString(nr.AccessKey) + ", " + quoteString(nr.Secret) + ")")
	b.WriteString(" SETTINGS async = 1, allow_s3_native_copy = 0, id = " + quoteString(nr.RunID))
	if nr.Base != nil {
		b.WriteString(", base_backup = S3(" + quoteString(nr.Base.URL) + "), use_same_s3_credentials_for_base_backup = 1")
	}
	return b.String()
}

// nativeThrottle are query settings (ch-go Query.Settings, not the BACKUP
// SETTINGS clause) under which ClickHouse keeps its own S3 requests per
// second, bursts included, below the endpoint's 200 per run (R29): without
// them its backup threads stay over the rate, and a run of more than about
// 6,000 objects is stopped for a rate storm (task 9, gate R17). The PUT
// throttler counts PUT, POST, COPY and LIST, the GET throttler GET.
func nativeThrottle(put, get int) []ch.Setting {
	return []ch.Setting{
		{Key: "s3_max_put_rps", Value: strconv.Itoa(put), Important: true},
		{Key: "s3_max_put_burst", Value: strconv.Itoa(put), Important: true},
		{Key: "s3_max_get_rps", Value: strconv.Itoa(get), Important: true},
		{Key: "s3_max_get_burst", Value: strconv.Itoa(get), Important: true},
	}
}

var (
	// nativeBackupSettings go with every native BACKUP: it mostly writes.
	nativeBackupSettings = nativeThrottle(150, 40)
	// nativeRestoreSettings are the mirror for the native RESTORE (task 13):
	// it mostly reads.
	nativeRestoreSettings = nativeThrottle(40, 150)
)

// redactStatement returns s with the secret of every S3(url, key, secret,
// …) replaced by '[HIDDEN]': the arguments from the third on. The URL and
// the key stay. What it cannot read for certain, an unterminated quote or
// an S3 argument that is not a string literal, is hidden from there to the
// end.
func redactStatement(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'' || c == '`' || c == '"':
			_, end, err := lexQuoted(s, i)
			if err != nil {
				return b.String() + hidden
			}
			b.WriteString(s[i:end])
			i = end
		case (c == 'S' || c == 's') && i+1 < len(s) && s[i+1] == '3' && (i == 0 || !isWordByte(s[i-1])):
			open := skipSpace(s, i+2)
			if open >= len(s) || s[open] != '(' {
				b.WriteString(s[i : i+2])
				i += 2
				continue
			}
			call, end, ok := redactS3Args(s, open)
			if !ok {
				return b.String() + hidden
			}
			b.WriteString(s[i:open])
			b.WriteString(call)
			i = end
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// redactS3Args reads the argument list at s[open] == '(' of string literals
// and returns it with the arguments from the third on hidden, and the index
// after its ')'.
func redactS3Args(s string, open int) (string, int, bool) {
	var b strings.Builder
	b.WriteByte('(')
	i := skipSpace(s, open+1)
	if i < len(s) && s[i] == ')' {
		return "()", i + 1, true
	}
	for n := 0; ; n++ {
		if i >= len(s) || s[i] != '\'' {
			return "", 0, false
		}
		_, end, err := lexQuoted(s, i)
		if err != nil {
			return "", 0, false
		}
		if n >= 2 {
			b.WriteString("'" + hidden + "'")
		} else {
			b.WriteString(s[i:end])
		}
		i = skipSpace(s, end)
		if i >= len(s) {
			return "", 0, false
		}
		switch s[i] {
		case ')':
			b.WriteByte(')')
			return b.String(), i + 1, true
		case ',':
			b.WriteString(", ")
			i = skipSpace(s, i+1)
		default:
			return "", 0, false
		}
	}
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// querier runs the queries of checkNativeTarget: a *session.
type querier interface {
	queryStrings(ctx context.Context, body string, settings ...ch.Setting) ([][]string, error)
}

// checkNativeTarget refuses a target native backups do not cover (design
// §4.1): a version before 24.8, a Distributed table in one of the run's
// databases, or a cluster of this server with more than one shard.
func checkNativeTarget(ctx context.Context, c querier, databases []string) error {
	rows, err := c.queryStrings(ctx, "SELECT version()")
	if err != nil {
		return fmt.Errorf("clickhouse: server version: %w", err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return errors.New("clickhouse: server version: no result")
	}
	version := rows[0][0]
	major, minor, ok := parseVersion(version)
	if !ok {
		return fmt.Errorf("clickhouse: server version %q cannot be read", clip(version))
	}
	if major < 24 || major == 24 && minor < 8 {
		return fmt.Errorf("%w, and this target runs %s. Use the logical method for this job, or upgrade the target", ErrNativeVersion, version)
	}

	if len(databases) > 0 {
		quoted := make([]string, len(databases))
		for i, db := range databases {
			quoted[i] = quoteString(db)
		}
		rows, err := c.queryStrings(ctx, "SELECT database, name FROM system.tables WHERE engine = 'Distributed' AND database IN ("+
			strings.Join(quoted, ", ")+") ORDER BY database, name LIMIT 6")
		if err != nil {
			return fmt.Errorf("clickhouse: list Distributed tables: %w", err)
		}
		if len(rows) > 0 {
			names := make([]string, 0, len(rows))
			for i, r := range rows {
				if i == 5 {
					names = append(names, "…")
					break
				}
				names = append(names, r[0]+"."+r[1])
			}
			return fmt.Errorf("%w: it has Distributed tables (%s), and a native backup saves only the one shard it runs on. "+
				"Use the logical method for this job", ErrNativeSharded, strings.Join(names, ", "))
		}
	}

	rows, err = c.queryStrings(ctx, "SELECT cluster, toString(uniqExact(shard_num)) FROM system.clusters "+
		"WHERE cluster IN (SELECT cluster FROM system.clusters WHERE is_local) "+
		"GROUP BY cluster HAVING uniqExact(shard_num) > 1 ORDER BY cluster LIMIT 6")
	if err != nil {
		return fmt.Errorf("clickhouse: read system.clusters: %w", err)
	}
	var names []string
	for _, r := range rows {
		// The Altinity operator generates all-sharded for every install,
		// with each replica as its own shard, so an unsharded replicated
		// install has it too (R30). A really sharded one is still refused
		// by its own cluster and its Distributed tables.
		if r[0] == altinityAllSharded {
			continue
		}
		names = append(names, fmt.Sprintf("%s with %s shards", r[0], r[1]))
	}
	if len(names) > 0 {
		return fmt.Errorf("%w: this server is in a sharded cluster (%s), and a native backup saves only the one shard it runs on. "+
			"Use the logical method for this job", ErrNativeSharded, strings.Join(names, ", "))
	}
	return nil
}

// altinityAllSharded is the cluster the Altinity operator generates with
// every replica as a shard.
const altinityAllSharded = "all-sharded"

// parseVersion reads the major and minor of version() ("24.8.14.39").
func parseVersion(v string) (major, minor int, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	return major, minor, err1 == nil && err2 == nil && major >= 0 && minor >= 0
}

// RunNative runs one native backup on the target and returns its server
// version. It checks the target (checkNativeTarget), sends the BACKUP
// statement with async = 1 and polls system.backups every 5 s until the
// backup is created or failed, all on one connection from ec.Dial. When
// nr.Stop delivers or ctx is cancelled, it KILLs the backup on that
// connection, waits up to 30 s for system.backups to show it failed, and
// returns an error that names the reason. The caller revokes the run's
// credential in every case.
//
// The statement and its secret are never logged or returned; errors from
// the server have the secret masked as well.
func (Engine) RunNative(ctx context.Context, ec backup.EngineContext, nr NativeRun) (serverVersion string, err error) {
	if err := nr.validate(); err != nil {
		return "", err
	}
	opts, err := ParseOptions(ec.Options)
	if err != nil {
		return "", err
	}
	s, err := connect(ctx, ec, opts)
	if err != nil {
		return "", err
	}
	defer s.close()

	version, err := s.queryValue(ctx, "SELECT version()")
	if err != nil {
		return "", fmt.Errorf("clickhouse: server version: %w", err)
	}
	dbs, err := s.nativeDatabases(ctx, nr.Databases)
	if err != nil {
		return version, err
	}
	nr.Databases = dbs
	if err := checkNativeTarget(ctx, s, dbs); err != nil {
		return version, err
	}
	return version, s.runBackup(ctx, nr)
}

// nativeDatabases is the run's databases, sorted: the ones named, each of
// which must exist, or every non-system database the user sees.
func (s *session) nativeDatabases(ctx context.Context, named []string) ([]string, error) {
	all, err := s.listDatabases(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	present := map[string]bool{}
	for _, r := range all {
		present[r[0]] = true
	}
	var dbs []string
	if len(named) == 0 {
		for _, r := range all {
			dbs = append(dbs, r[0])
		}
	}
	for _, db := range named {
		if !present[db] {
			return nil, fmt.Errorf("clickhouse: database %q does not exist or is not visible to the backup user", db)
		}
		dbs = append(dbs, db)
	}
	if len(dbs) == 0 {
		return nil, errors.New("clickhouse: no database to back up")
	}
	sort.Strings(dbs)
	return compactStrings(dbs), nil
}

func compactStrings(sorted []string) []string {
	out := sorted[:0]
	for i, v := range sorted {
		if i == 0 || v != sorted[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// nativeQueryID is the query id of a run's BACKUP, which KILL names.
func nativeQueryID(runID string) string { return "olympos-backup-" + runID }

// runBackup sends the statement and follows the backup to its end.
func (s *session) runBackup(ctx context.Context, nr NativeRun) error {
	log := slog.Default().With("run", nr.RunID)
	select {
	case reason, ok := <-nr.Stop:
		return fmt.Errorf("clickhouse: native backup not started: the ingest session stopped (%s)", stopReason(reason, ok))
	default:
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("clickhouse: native backup not started: %w", err)
	}

	stmt := backupStatement(nr)
	queryID := nativeQueryID(nr.RunID)
	log.Info("clickhouse: starting a native backup", "query_id", queryID, "statement", redactStatement(stmt))
	if err := s.nativeExec(context.WithoutCancel(ctx), stmt, queryID, nativeBackupSettings...); err != nil {
		return fmt.Errorf("clickhouse: BACKUP: %s", maskSecret(err.Error(), nr.Secret))
	}

	tick := time.NewTicker(nativePollInterval)
	defer tick.Stop()
	for {
		status, msg, err := s.backupStatus(context.WithoutCancel(ctx), nr.RunID)
		if err != nil {
			return fmt.Errorf("clickhouse: read system.backups: %s", maskSecret(err.Error(), nr.Secret))
		}
		switch status {
		case statusCreated:
			log.Info("clickhouse: native backup created")
			return nil
		case statusFailed, statusCancelled:
			return fmt.Errorf("clickhouse: native backup %s: %s", status, maskSecret(msg, nr.Secret))
		case statusCreating:
		case "":
			return errors.New("clickhouse: the native backup is no longer in system.backups (did the server restart?)")
		default:
			return fmt.Errorf("clickhouse: native backup has the unexpected status %q", clip(status))
		}
		select {
		case <-tick.C:
		case reason, ok := <-nr.Stop:
			return s.killBackup(log, nr, queryID, "the ingest session stopped: "+stopReason(reason, ok))
		case <-ctx.Done():
			return s.killBackup(log, nr, queryID, ctx.Err().Error())
		}
	}
}

func stopReason(reason string, ok bool) string {
	if !ok || reason == "" {
		return "stopped"
	}
	return reason
}

// killBackup ends a running backup with KILL QUERY … SYNC and waits up to
// nativeKillWait for system.backups to show it failed. It always returns an
// error that names why.
func (s *session) killBackup(log *slog.Logger, nr NativeRun, queryID, why string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nativeKillWait)
	defer cancel()
	log.Warn("clickhouse: ending the native backup with KILL QUERY", "query_id", queryID, "reason", why)
	if err := s.nativeExec(ctx, "KILL QUERY WHERE query_id = "+quoteString(queryID)+" SYNC", ""); err != nil {
		return fmt.Errorf("clickhouse: native backup ended (%s), but KILL QUERY failed: %s", why, maskSecret(err.Error(), nr.Secret))
	}
	for {
		status, _, err := s.backupStatus(ctx, nr.RunID)
		if err != nil {
			return fmt.Errorf("clickhouse: native backup ended (%s); its status after KILL QUERY could not be read: %s",
				why, maskSecret(err.Error(), nr.Secret))
		}
		switch status {
		case statusFailed, statusCancelled:
			log.Warn("clickhouse: native backup ended by KILL QUERY", "status", status)
			return fmt.Errorf("clickhouse: native backup ended (%s): KILL QUERY made it %s", why, status)
		case statusCreated:
			return fmt.Errorf("clickhouse: native backup ended (%s), although it was created before KILL QUERY", why)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("clickhouse: native backup ended (%s), but it is still %s %s after KILL QUERY", why, clip(status), nativeKillWait)
		case <-time.After(time.Second):
		}
	}
}

// backupStatus reads the run's row of system.backups: its status and error,
// or "" when there is none.
func (s *session) backupStatus(ctx context.Context, runID string) (status, msg string, err error) {
	ctx, cancel := context.WithTimeout(ctx, nativeQueryTimeout)
	defer cancel()
	rows, err := s.queryStrings(ctx, "SELECT toString(status), error FROM system.backups WHERE id = "+quoteString(runID))
	if err != nil {
		return "", "", err
	}
	if len(rows) == 0 {
		return "", "", nil
	}
	return rows[0][0], rows[0][1], nil
}

// nativeExec runs a statement and drops its result, within nativeQueryTimeout.
func (s *session) nativeExec(ctx context.Context, body, queryID string, settings ...ch.Setting) error {
	ctx, cancel := context.WithTimeout(ctx, nativeQueryTimeout)
	defer cancel()
	var res nativeResult
	return s.client.Do(ctx, ch.Query{
		Body:     body,
		QueryID:  queryID,
		Settings: settings,
		Result:   &res,
		OnResult: func(context.Context, proto.Block) error { return nil },
	})
}

// maskSecret replaces the secret in a server message, in case one holds it
// (24.8 and 25.8 mask it themselves, spike §6).
func maskSecret(msg, secret string) string {
	if secret == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, hidden)
}
