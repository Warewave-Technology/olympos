package clickhouse

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Warewave-Technology/olympos/internal/backup"
)

// Options are the ClickHouse engine_options of a backup job.
//
//	{
//	  "databases": ["analytics"],          // empty = all except system databases
//	  "tables":    ["analytics.events"],   // optional "db.table" allow-list
//	  "ca_pem":    "-----BEGIN CERTIFICATE-----...", // optional extra roots (e2e-tls)
//	  "method":    "native",                         // "native" | "logical" (default: logical)
//	  "incremental": "weekly_full_daily"             // native only
//	}
type Options struct {
	Databases []string `json:"databases,omitempty"`
	Tables    []string `json:"tables,omitempty"`
	// CAPEM is an optional PEM bundle appended to the system roots when
	// verifying the target certificate (in-cluster CAs are common). It is
	// public material, never a secret.
	CAPEM string `json:"ca_pem,omitempty"`
	// Method is how the backup is taken: MethodNative (BACKUP to the ingest
	// endpoint) or MethodLogical, the zip of DDL and Native-format data.
	// Empty means logical: jobs created before the field existed have none.
	Method string `json:"method,omitempty"`
	// Incremental is "" (every run is full) or IncrementalWeeklyFullDaily: a
	// full backup weekly and incrementals on the other days. Native only.
	Incremental string `json:"incremental,omitempty"`

	tables map[string]map[string]bool // db -> table set, from Tables
}

// Backup methods (Options.Method).
const (
	MethodNative  = "native"
	MethodLogical = "logical"
)

// IncrementalWeeklyFullDaily is the only incremental schedule (Options.Incremental).
const IncrementalWeeklyFullDaily = "weekly_full_daily"

// Native reports whether the job takes native backups.
func (o Options) Native() bool { return o.Method == MethodNative }

// optionError is an invalid value of one option; CheckOptions reports it on
// that field.
type optionError struct{ field, msg string }

func (e *optionError) Error() string { return "clickhouse engine_options: " + e.field + " " + e.msg }

// systemDatabases are never backed up.
var systemDatabases = map[string]bool{
	"system":             true,
	"INFORMATION_SCHEMA": true,
	"information_schema": true,
}

func isSystemDatabase(name string) bool { return systemDatabases[name] }

// ParseOptions decodes and validates engine_options. Unknown fields are
// rejected so typos do not silently widen or narrow a backup.
func ParseOptions(raw json.RawMessage) (Options, error) {
	var o Options
	if t := bytes.TrimSpace(raw); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
		dec := json.NewDecoder(bytes.NewReader(t))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return Options{}, fmt.Errorf("clickhouse engine_options: %w", err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return Options{}, errors.New("clickhouse engine_options: trailing data")
		}
	}

	dbs, err := normalizeNames("databases", o.Databases)
	if err != nil {
		return Options{}, err
	}
	for _, d := range dbs {
		if isSystemDatabase(d) {
			return Options{}, fmt.Errorf("clickhouse engine_options: database %q is a system database and cannot be backed up", d)
		}
	}
	o.Databases = dbs

	tbls, err := normalizeNames("tables", o.Tables)
	if err != nil {
		return Options{}, err
	}
	o.Tables = tbls
	if len(tbls) > 0 {
		o.tables = map[string]map[string]bool{}
		inDBs := map[string]bool{}
		for _, d := range dbs {
			inDBs[d] = true
		}
		for _, t := range tbls {
			db, name, ok := strings.Cut(t, ".")
			if !ok || db == "" || name == "" {
				return Options{}, fmt.Errorf("clickhouse engine_options: table %q must be \"database.table\"", t)
			}
			if isSystemDatabase(db) {
				return Options{}, fmt.Errorf("clickhouse engine_options: table %q is in a system database", t)
			}
			if len(dbs) > 0 && !inDBs[db] {
				return Options{}, fmt.Errorf("clickhouse engine_options: table %q is not in the selected databases", t)
			}
			if o.tables[db] == nil {
				o.tables[db] = map[string]bool{}
			}
			o.tables[db][name] = true
		}
	}

	switch o.Method {
	case "", MethodNative, MethodLogical:
	default:
		return Options{}, &optionError{"method", `must be "native" or "logical"`}
	}
	switch o.Incremental {
	case "":
	case IncrementalWeeklyFullDaily:
		if !o.Native() {
			return Options{}, &optionError{"incremental", `needs method "native"`}
		}
	default:
		return Options{}, &optionError{"incremental", `must be "weekly_full_daily" or empty`}
	}
	// A native run backs up whole databases; a table filter would be
	// silently ignored (R31).
	if o.Native() && len(o.Tables) > 0 {
		return Options{}, &optionError{"tables", `cannot be used with method "native", which backs up whole databases`}
	}

	if strings.TrimSpace(o.CAPEM) != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(o.CAPEM)) {
			return Options{}, errors.New("clickhouse engine_options: ca_pem contains no valid certificate")
		}
	}
	return o, nil
}

// CheckOptions implements backup.OptionsChecker: the field errors of a job's
// engine_options at create and update. Native needs the ingest endpoint; the
// version and sharding of the target are checked when the run starts.
func (Engine) CheckOptions(raw json.RawMessage, env backup.OptionsEnv) map[string]string {
	o, err := ParseOptions(raw)
	if err != nil {
		var oe *optionError
		if errors.As(err, &oe) {
			return map[string]string{oe.field: oe.msg}
		}
		return map[string]string{"engine_options": strings.TrimPrefix(err.Error(), "clickhouse engine_options: ")}
	}
	if o.Native() && !env.IngestEnabled {
		return map[string]string{"method": "native backups need the ingest endpoint, which is off (set ingest.url)"}
	}
	return nil
}

func normalizeNames(field string, in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("clickhouse engine_options: %s contains an empty name", field)
		}
		if strings.ContainsRune(s, 0) {
			return nil, fmt.Errorf("clickhouse engine_options: %s contains an invalid name", field)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// wantDatabase reports whether db is selected (existing is the server list).
func (o Options) wantDatabase(db string) bool {
	if isSystemDatabase(db) {
		return false
	}
	if len(o.Databases) > 0 {
		i := sort.SearchStrings(o.Databases, db)
		if i >= len(o.Databases) || o.Databases[i] != db {
			return false
		}
	}
	if o.tables != nil && o.tables[db] == nil {
		return false
	}
	return true
}

// wantTable reports whether db.table is selected by the tables allow-list.
func (o Options) wantTable(db, table string) bool {
	if o.tables == nil {
		return true
	}
	return o.tables[db][table]
}

// requestedDatabases is the explicit list of databases that must exist.
func (o Options) requestedDatabases() []string {
	if len(o.Databases) > 0 {
		return o.Databases
	}
	if o.tables != nil {
		out := make([]string, 0, len(o.tables))
		for db := range o.tables {
			out = append(out, db)
		}
		sort.Strings(out)
		return out
	}
	return nil
}
