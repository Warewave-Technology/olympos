package clickhouse

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ClickHouse/ch-go"
	"github.com/ClickHouse/ch-go/proto"
)

// dbInfo / tableInfo are the discovered catalog of one run.
type dbInfo struct {
	name, engine, uuid string
	tables             []*tableInfo
}

type tableInfo struct {
	Table
	partitioned bool
	parts       []Partition // from system.parts (active), MergeTree only
	mergeTree   bool
}

// dataEngines store data locally and can be read with SELECT *. Everything
// else (Distributed, Merge, Buffer, Null, Kafka, S3, URL, MySQL, ...) is
// schema only.
var dataEngines = map[string]bool{
	"Log": true, "TinyLog": true, "StripeLog": true, "Memory": true,
	"EmbeddedRocksDB": true, "KeeperMap": true,
}

func isMergeTree(engine string) bool { return strings.HasSuffix(engine, "MergeTree") }

// listDatabases returns visible non-system databases.
func (s *session) listDatabases(ctx context.Context) ([][]string, error) {
	rows, err := s.queryStrings(ctx, "SELECT name, engine, toString(uuid) FROM system.databases ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	out := rows[:0]
	for _, r := range rows {
		if !isSystemDatabase(r[0]) {
			out = append(out, r)
		}
	}
	return out, nil
}

// discover builds the catalog for the selected databases/tables.
func (s *session) discover(ctx context.Context, opts Options) ([]*dbInfo, error) {
	all, err := s.listDatabases(ctx)
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	var dbs []*dbInfo
	for _, r := range all {
		present[r[0]] = true
		if opts.wantDatabase(r[0]) {
			dbs = append(dbs, &dbInfo{name: r[0], engine: r[1], uuid: nilUUID(r[2])})
		}
	}
	for _, d := range opts.requestedDatabases() {
		if !present[d] {
			return nil, fmt.Errorf("database %q does not exist or is not visible to the backup user", d)
		}
	}
	for _, db := range dbs {
		if err := s.discoverTables(ctx, db, opts); err != nil {
			return nil, fmt.Errorf("database %q: %w", db.name, err)
		}
	}
	// Every explicitly requested table must exist.
	for _, t := range opts.Tables {
		dbName, name, _ := strings.Cut(t, ".")
		found := false
		for _, db := range dbs {
			if db.name != dbName {
				continue
			}
			for _, ti := range db.tables {
				if ti.Name == name {
					found = true
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("table %q does not exist or is not visible to the backup user", t)
		}
	}
	return dbs, nil
}

func (s *session) discoverTables(ctx context.Context, db *dbInfo, opts Options) error {
	q := quoteString(db.name)
	// DDL dictionaries are listed in system.tables with engine "Dictionary"
	// (as are tables with ENGINE = Dictionary(...)); the create query tells
	// them apart. system.dictionaries is not used: it needs an extra grant.
	rows, err := s.queryStrings(ctx, "SELECT name, engine, toString(uuid), partition_key, sorting_key, primary_key, "+
		"toString(engine = 'Dictionary' AND startsWith(create_table_query, 'CREATE DICTIONARY')) "+
		"FROM system.tables WHERE database = "+q+" AND NOT is_temporary ORDER BY name")
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	dicts := map[string]bool{}
	for _, r := range rows {
		if r[6] == "1" || r[6] == "true" {
			dicts[r[0]] = true
		}
	}

	byName := map[string]*tableInfo{}
	mvByUUID := map[string]string{}
	var all []*tableInfo
	for _, r := range rows {
		t := &tableInfo{Table: Table{
			Name: r[0], Engine: r[1], UUID: nilUUID(r[2]),
			PartitionKey: r[3], SortingKey: r[4], PrimaryKey: r[5],
		}}
		switch {
		case r[1] == "View":
			t.Kind = KindView
		case r[1] == "MaterializedView":
			t.Kind = KindMaterializedView
			if t.UUID != "" {
				mvByUUID[t.UUID] = t.Name
			}
		case dicts[r[0]]:
			t.Kind = KindDictionary
		case r[1] == "LiveView" || r[1] == "WindowView":
			t.Kind = KindOther
		default:
			t.Kind = KindTable
		}
		byName[t.Name] = t
		all = append(all, t)
	}
	// Inner tables of materialized views without TO: ".inner_id.<mv uuid>"
	// (Atomic) or ".inner.<mv name>" (Ordinary).
	for _, t := range all {
		if t.Kind != KindTable {
			continue
		}
		if u, ok := strings.CutPrefix(t.Name, ".inner_id."); ok {
			if mv, ok := mvByUUID[u]; ok {
				t.Kind, t.InnerOf = KindMVInner, mv
			}
		} else if mv, ok := strings.CutPrefix(t.Name, ".inner."); ok {
			if m := byName[mv]; m != nil && m.Kind == KindMaterializedView {
				t.Kind, t.InnerOf = KindMVInner, mv
			}
		}
	}
	for _, t := range all {
		want := opts.wantTable(db.name, t.Name)
		if t.Kind == KindMVInner {
			want = opts.wantTable(db.name, t.InnerOf)
		}
		if !want {
			continue
		}
		t.mergeTree = isMergeTree(t.Engine)
		t.partitioned = t.mergeTree && t.PartitionKey != ""
		switch {
		case t.Kind != KindTable && t.Kind != KindMVInner:
			t.DataNote = "no data: " + t.Kind
		case t.mergeTree || dataEngines[t.Engine]:
			t.HasData = true
		default:
			t.DataNote = "no local data: engine " + t.Engine
		}
		db.tables = append(db.tables, t)
	}
	if len(db.tables) == 0 {
		return nil
	}
	byName = map[string]*tableInfo{}
	for _, t := range db.tables {
		byName[t.Name] = t
	}

	cols, err := s.queryStrings(ctx, "SELECT table, name, type, default_kind, default_expression "+
		"FROM system.columns WHERE database = "+q+" ORDER BY table, position")
	if err != nil {
		return fmt.Errorf("list columns: %w", err)
	}
	for _, r := range cols {
		if t := byName[r[0]]; t != nil {
			t.Columns = append(t.Columns, Column{Name: r[1], Type: r[2], DefaultKind: r[3], DefaultExpression: r[4]})
		}
	}

	parts, err := s.queryStrings(ctx, "SELECT table, partition_id, any(partition), toString(sum(rows)), toString(count()) "+
		"FROM system.parts WHERE active AND database = "+q+" GROUP BY table, partition_id ORDER BY table, partition_id")
	if ch.IsErr(err, proto.ErrAccessDenied) {
		// No grant on system.parts: list partitions through the tables
		// themselves (_partition_id needs only SELECT on the table).
		s.noSystemParts = true
		parts = nil
		for _, t := range db.tables {
			if !t.mergeTree || !t.HasData {
				continue
			}
			value := "''" // _partition_value only exists with a partition key
			if t.partitioned {
				value = "any(toString(_partition_value))"
			}
			rows, err := s.queryStrings(ctx, "SELECT "+quoteString(t.Name)+", toString(_partition_id) AS pid, "+value+", toString(count()), '0' "+
				"FROM "+qualified(db.name, t.Name)+" GROUP BY pid ORDER BY pid")
			if err != nil {
				return fmt.Errorf("list partitions of %s: %w", t.Name, err)
			}
			parts = append(parts, rows...)
		}
	} else if err != nil {
		return fmt.Errorf("list parts: %w", err)
	}
	for _, r := range parts {
		t := byName[r[0]]
		if t == nil || !t.mergeTree {
			continue
		}
		rowsN, _ := strconv.ParseUint(r[3], 10, 64)
		partsN, _ := strconv.ParseUint(r[4], 10, 64)
		t.parts = append(t.parts, Partition{ID: r[1], Partition: r[2], RowsExpected: rowsN, Parts: partsN})
		t.RowsExpected += rowsN
	}
	return nil
}

// restoreOrder: plain tables, then dictionaries, then views and
// materialized views (created after data load so MVs do not re-ingest
// restored rows), then anything else. MV inner tables are created by their MV.
func restoreOrder(dbs []*dbInfo) []string {
	rank := map[string]int{KindTable: 0, KindDictionary: 1, KindView: 2, KindMaterializedView: 2, KindOther: 3}
	var out []string
	for phase := 0; phase <= 3; phase++ {
		for _, db := range dbs {
			var names []string
			for _, t := range db.tables {
				if r, ok := rank[t.Kind]; ok && r == phase {
					names = append(names, db.name+"."+t.Name)
				}
			}
			sort.Strings(names)
			out = append(out, names...)
		}
	}
	return out
}

func nilUUID(u string) string {
	if u == "" || u == "00000000-0000-0000-0000-000000000000" {
		return ""
	}
	return u
}
