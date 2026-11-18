// Package clickhouse is the ClickHouse backup engine (SPEC §10.2).
//
// The server connects to the target over the native protocol (9440 TLS /
// 9000) through the agent tunnel with zstd network compression and writes
// one zip container to Blob:
//
//	schema/<db>.sql                       CREATE DATABASE
//	schema/<db>/<table>.sql               CREATE TABLE/VIEW/MATERIALIZED VIEW/DICTIONARY
//	data/<db>/<table>/<partition_id>.native     data, FORMAT Native
//	data/<db>/<table>/<partition_id>.rowbinary  fallback, RowBinaryWithNamesAndTypes
//	manifest.json                         written last
//
// Partitioned MergeTree tables are split per active partition
// (WHERE _partition_id = ...); other tables are one "all" entry. Names in
// paths are escaped (see pathSegment); the manifest maps entries to names.
// ClickHouse never receives a Blob credential.
package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// Name is the engine name.
const Name = "clickhouse"

// ManifestFormat identifies the archive layout version.
const ManifestFormat = "olympos.clickhouse.v1"

func init() { backup.RegisterEngine(Engine{}) }

// Engine implements backup.Engine for ClickHouse.
type Engine struct{}

var _ backup.Engine = Engine{}

func (Engine) Name() string        { return Name }
func (Engine) Ext() string         { return "zip" }
func (Engine) ContentType() string { return "application/zip" }

// TestConnection connects through the tunnel and reports version, TLS,
// privileges (SHOW GRANTS plus real SHOW/SELECT checks on the selected
// databases) and the visible databases. Target-side failures are reported
// in the result (OK=false, Error); only invalid options return an error.
func (Engine) TestConnection(ctx context.Context, ec backup.EngineContext) (*backup.ConnectionTest, error) {
	opts, err := ParseOptions(ec.Options)
	if err != nil {
		return nil, err
	}
	ct := &backup.ConnectionTest{TLS: ec.UseTLS, Privileges: []backup.Privilege{}, Databases: []string{}}
	s, err := connect(ctx, ec, opts)
	if err != nil {
		ct.Error = err.Error()
		ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "connect", OK: false, Detail: err.Error()})
		return ct, nil
	}
	defer s.close()
	ct.TLS = s.tls

	detail := "native protocol, zstd compression, plaintext (transfer mode compressed)"
	if ec.UseTLS && !s.tls {
		detail = "native protocol, zstd compression, plaintext: target has no TLS on this port"
	}
	if s.tls {
		detail = "native protocol, zstd compression, TLS verified"
	}
	ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "connect", OK: true, Detail: detail})

	if v, err := s.queryValue(ctx, "SELECT version()"); err != nil {
		ct.Error = "version: " + err.Error()
		return ct, nil
	} else {
		ct.ServerVersion = v
	}

	grants, err := s.userGrants(ctx)
	if err != nil {
		ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "SHOW GRANTS", OK: false, Detail: err.Error()})
	} else {
		ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "SHOW GRANTS", OK: true, Detail: truncate(strings.Join(grants, "; "), 2000)})
	}

	all, err := s.listDatabases(ctx)
	if err != nil {
		ct.Error = err.Error()
		return ct, nil
	}
	for _, r := range all {
		ct.Databases = append(ct.Databases, r[0])
	}

	dbs, err := s.discover(ctx, opts)
	if err != nil {
		ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "SHOW TABLES", OK: false, Detail: err.Error()})
	} else {
		if len(dbs) == 0 {
			ct.Privileges = append(ct.Privileges, backup.Privilege{Name: "databases", OK: false, Detail: "no database selected or visible"})
		}
		parts := backup.Privilege{Name: "SELECT on system.parts", OK: true, Detail: "granted: partitions and row counts from part metadata"}
		if s.noSystemParts {
			parts.Detail = "not granted (optional): partitions are listed with SELECT _partition_id, count() on each table"
		}
		ct.Privileges = append(ct.Privileges, parts)
		for _, db := range dbs {
			ct.Privileges = append(ct.Privileges, s.checkShow(ctx, db), s.checkSelect(ctx, db))
			if grants != nil {
				ct.Privileges = append(ct.Privileges, grantCheck(grants, db.name, opts))
			}
		}
	}

	ct.OK = ct.Error == ""
	for _, p := range ct.Privileges {
		ct.OK = ct.OK && p.OK
	}
	return ct, nil
}

// grantCheck verifies the grants cover the whole selection (see grants.go).
func grantCheck(grants []string, db string, opts Options) backup.Privilege {
	p := backup.Privilege{Name: "SELECT grant on " + db + ".*"}
	if opts.tables != nil {
		p.Name = "SELECT grant on selected tables of " + db
		for _, t := range opts.Tables {
			d, name, _ := strings.Cut(t, ".")
			if d != db {
				continue
			}
			if ok, why := selectCovered(grants, db, name); !ok {
				p.Detail = why
				return p
			}
		}
		p.OK = true
		return p
	}
	p.OK, p.Detail = selectCovered(grants, db, "")
	return p
}

func (s *session) checkShow(ctx context.Context, db *dbInfo) backup.Privilege {
	p := backup.Privilege{Name: "SHOW on " + db.name}
	if _, err := s.showCreateDatabase(ctx, db.name); err != nil {
		p.Detail = err.Error()
		return p
	}
	for _, t := range db.tables {
		if _, err := s.showCreate(ctx, db.name, t); err != nil {
			p.Detail = t.Name + ": " + err.Error()
			return p
		}
	}
	p.OK = true
	p.Detail = fmt.Sprintf("%d objects", len(db.tables))
	return p
}

func (s *session) checkSelect(ctx context.Context, db *dbInfo) backup.Privilege {
	p := backup.Privilege{Name: "SELECT on " + db.name + ".*"}
	n := 0
	for _, t := range db.tables {
		if !t.HasData {
			continue
		}
		if _, _, err := s.selectHeader(ctx, qualified(db.name, t.Name)); err != nil {
			p.Detail = t.Name + ": " + err.Error()
			return p
		}
		n++
	}
	p.OK = true
	p.Detail = fmt.Sprintf("%d tables readable", n)
	return p
}

// Run streams the backup (or, for ec.Test, schema + manifest only) into w.
func (Engine) Run(ctx context.Context, ec backup.EngineContext, w io.Writer) (*backup.RunResult, error) {
	opts, err := ParseOptions(ec.Options)
	if err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	s, err := connect(ctx, ec, opts)
	if err != nil {
		return nil, err
	}
	defer s.close()

	info, err := s.queryStrings(ctx, "SELECT version(), timezone()")
	if err != nil || len(info) != 1 {
		return nil, fmt.Errorf("clickhouse: server version: %w", errOr(err, "no result"))
	}
	dbs, err := s.discover(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}

	manifestOpts := opts
	manifestOpts.CAPEM = ""
	m := &Manifest{
		Format:        ManifestFormat,
		Engine:        Name,
		ServerVersion: info[0][0],
		Timezone:      info[0][1],
		ToolVersion:   toolVersion(),
		DryRun:        ec.Test,
		StartedAt:     started,
		Transfer:      Transfer{Protocol: "native", TLS: s.tls, Compression: "zstd", Container: "zip"},
		Consistency: "per data entry: each entry is one SELECT (one partition of a partitioned MergeTree table, or the whole table); " +
			"no point-in-time snapshot across entries; partitions created after backup start are not included",
		Options:      manifestOpts,
		Databases:    []Database{},
		RestoreOrder: restoreOrder(dbs),
		RowsSource:   "system.parts",
	}
	if s.noSystemParts {
		m.RowsSource = "count()"
	}

	a := newArchive(w, started)
	// Schema first, so a restore can create everything before loading data.
	for _, db := range dbs {
		stmt, err := s.showCreateDatabase(ctx, db.name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: SHOW CREATE DATABASE %s: %w", db.name, err)
		}
		entry := "schema/" + pathSegment(db.name) + ".sql"
		if _, err := a.writeFile(entry, sqlFile(stmt)); err != nil {
			return nil, err
		}
		md := Database{Name: db.name, Engine: db.engine, UUID: db.uuid, SchemaEntry: entry, Tables: []Table{}}
		for _, t := range db.tables {
			stmt, err := s.showCreate(ctx, db.name, t)
			if err != nil {
				return nil, fmt.Errorf("clickhouse: SHOW CREATE %s.%s: %w", db.name, t.Name, err)
			}
			t.SchemaEntry = "schema/" + pathSegment(db.name) + "/" + pathSegment(t.Name) + ".sql"
			if _, err := a.writeFile(t.SchemaEntry, sqlFile(stmt)); err != nil {
				return nil, err
			}
		}
		m.Databases = append(m.Databases, md)
	}

	var warnings []string
	for i, db := range dbs {
		for _, t := range db.tables {
			if t.HasData {
				m.Totals.Tables++
				if ec.Test {
					t.HasData = false
					t.DataNote = "dry run: schema only"
					t.Partitions = t.parts
				} else if err := s.backupTable(ctx, a, db.name, t, &warnings); err != nil {
					return nil, fmt.Errorf("clickhouse: data %s.%s: %w", db.name, t.Name, err)
				}
				for _, p := range t.Partitions {
					if p.Entry != "" {
						m.Totals.DataEntries++
						m.Totals.Bytes += p.Bytes
					}
				}
				m.Totals.Rows += t.Rows
			}
			m.Databases[i].Tables = append(m.Databases[i].Tables, t.Table)
		}
	}
	m.Totals.Databases = len(dbs)
	m.FinishedAt = time.Now().UTC()

	m.Warnings = warnings
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := a.writeFile("manifest.json", append(mj, '\n')); err != nil {
		return nil, err
	}
	if err := a.close(); err != nil {
		return nil, err
	}

	var fallback []string
	for _, db := range m.Databases {
		for _, t := range db.Tables {
			if t.DataFormat == FormatRowBinary {
				fallback = append(fallback, db.Name+"."+t.Name)
			}
		}
	}
	details := map[string]any{
		"databases":    m.Totals.Databases,
		"tables":       m.Totals.Tables,
		"data_entries": m.Totals.DataEntries,
		"rows":         m.Totals.Rows,
		"data_bytes":   m.Totals.Bytes,
		"dry_run":      ec.Test,
		"tls":          s.tls,
		"compression":  "zstd",
		"container":    "zip",
	}
	if len(fallback) > 0 {
		details["rowbinary_tables"] = fallback
	}
	if len(warnings) > 0 {
		details["warnings"] = warnings
	}
	tlsUsed := s.tls
	return &backup.RunResult{ServerVersion: m.ServerVersion, ToolVersion: m.ToolVersion, Details: details, TLS: &tlsUsed}, nil
}

// backupTable streams the data entries of one table.
func (s *session) backupTable(ctx context.Context, a *archive, db string, t *tableInfo, warnings *[]string) error {
	from := qualified(db, t.Name)
	names, types, err := s.selectHeader(ctx, from)
	if err != nil {
		return err
	}
	ext := "native"
	t.DataFormat = FormatNative
	for i, typ := range types {
		if !nativeSupported(typ) {
			t.DataFormat, ext = FormatRowBinary, "rowbinary"
			t.FallbackReason = fmt.Sprintf("column %s has type %s", names[i], typ)
			break
		}
	}

	parts := t.parts
	if !t.partitioned {
		p := Partition{ID: "all"}
		for _, x := range t.parts {
			p.RowsExpected += x.RowsExpected
			p.Parts += x.Parts
		}
		parts = []Partition{p}
	}
	t.Partitions = make([]Partition, 0, len(parts))
	for _, p := range parts {
		where := ""
		if t.partitioned {
			where = " WHERE _partition_id = " + quoteString(p.ID)
		}
		name := "data/" + pathSegment(db) + "/" + pathSegment(t.Name) + "/" + pathSegment(p.ID) + "." + ext
		var cur *entry
		open := func() (io.Writer, error) {
			e, err := a.create(name)
			cur = e
			return e, err
		}
		var rows uint64
		if t.DataFormat == FormatNative {
			rows, err = s.streamNative(ctx, "SELECT * FROM "+from+where, open)
		} else {
			rows, err = s.streamRowBinary(ctx, from, where, names, types, open)
		}
		if err != nil {
			return fmt.Errorf("partition %s: %w", p.ID, err)
		}
		p.Rows = rows
		if cur != nil {
			p.Entry, p.Bytes, p.SHA256 = name, cur.size, cur.sum()
		}
		if t.mergeTree && p.Rows != p.RowsExpected {
			*warnings = append(*warnings, fmt.Sprintf("%s.%s partition %s: streamed %d rows, system.parts reported %d (concurrent writes or lightweight deletes)",
				db, t.Name, p.ID, p.Rows, p.RowsExpected))
		}
		t.Rows += rows
		t.Partitions = append(t.Partitions, p)
	}
	return nil
}

func (s *session) showCreateDatabase(ctx context.Context, db string) (string, error) {
	return s.queryValue(ctx, "SHOW CREATE DATABASE "+quoteIdent(db), schemaSettings...)
}

func (s *session) showCreate(ctx context.Context, db string, t *tableInfo) (string, error) {
	kw := "TABLE"
	if t.Kind == KindDictionary {
		kw = "DICTIONARY"
	}
	return s.queryValue(ctx, "SHOW CREATE "+kw+" "+qualified(db, t.Name), schemaSettings...)
}

func sqlFile(stmt string) []byte {
	stmt = strings.TrimRight(strings.TrimSpace(stmt), ";")
	return []byte(stmt + ";\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func errOr(err error, msg string) error {
	if err != nil {
		return err
	}
	return errors.New(msg)
}

func toolVersion() string {
	v := "olympos/ch-go"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/ClickHouse/ch-go" {
				return v + " " + d.Version
			}
		}
	}
	return v
}
