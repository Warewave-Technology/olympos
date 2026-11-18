package clickhouse

import "time"

// Manifest is written as the last zip entry ("manifest.json"). It contains
// everything needed to restore without the Olympos UI (SPEC §10.4): object
// kinds and restore phases, create statements (by entry), columns, and per
// data entry the format, row counts and sha256.
type Manifest struct {
	Format        string    `json:"format"`         // "olympos.clickhouse.v1"
	Engine        string    `json:"engine"`         // "clickhouse"
	ServerVersion string    `json:"server_version"` // SELECT version()
	ServerName    string    `json:"server_name,omitempty"`
	Timezone      string    `json:"server_timezone,omitempty"`
	ToolVersion   string    `json:"tool_version"`
	DryRun        bool      `json:"dry_run"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Transfer      Transfer  `json:"transfer"`
	// Consistency documents the guarantee: each data entry is one SELECT
	// (per partition for partitioned tables); there is no cross-table
	// point-in-time snapshot.
	Consistency string     `json:"consistency"`
	Options     Options    `json:"options"`
	Databases   []Database `json:"databases"`
	// RestoreOrder lists "db.table" objects in the order they should be
	// created; see docs/restore.md for the phases.
	RestoreOrder []string `json:"restore_order"`
	// RowsSource tells where partitions and rows_expected came from:
	// "system.parts" (active parts) or "count()" when system.parts is not
	// readable by the backup user.
	RowsSource string   `json:"rows_source"`
	Totals     Totals   `json:"totals"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Transfer describes how data travelled.
type Transfer struct {
	Protocol    string `json:"protocol"`    // "native"
	TLS         bool   `json:"tls"`         // end-to-end TLS with the server
	Compression string `json:"compression"` // network compression method
	Container   string `json:"container"`   // "zip"
}

// Totals summarize the run.
type Totals struct {
	Databases   int    `json:"databases"`
	Tables      int    `json:"tables"`
	DataEntries int    `json:"data_entries"`
	Rows        uint64 `json:"rows"`
	Bytes       int64  `json:"bytes"` // uncompressed data entry bytes
}

// Database is one backed-up database.
type Database struct {
	Name        string  `json:"name"`
	Engine      string  `json:"engine"`
	UUID        string  `json:"uuid,omitempty"`
	SchemaEntry string  `json:"schema_entry"`
	Tables      []Table `json:"tables"`
}

// Table kinds.
const (
	KindTable            = "table"
	KindView             = "view"
	KindMaterializedView = "materialized_view"
	KindMVInner          = "materialized_view_inner" // created by its MV
	KindDictionary       = "dictionary"
	KindOther            = "other" // schema only (LiveView, WindowView, ...)
)

// Data formats.
const (
	FormatNative    = "Native"
	FormatRowBinary = "RowBinaryWithNamesAndTypes"
)

// Table is one object (table, view, dictionary, ...) of a database.
type Table struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Engine       string   `json:"engine"`
	UUID         string   `json:"uuid,omitempty"`
	SchemaEntry  string   `json:"schema_entry"`
	InnerOf      string   `json:"inner_of,omitempty"` // MV owning this inner table
	PartitionKey string   `json:"partition_key,omitempty"`
	SortingKey   string   `json:"sorting_key,omitempty"`
	PrimaryKey   string   `json:"primary_key,omitempty"`
	Columns      []Column `json:"columns,omitempty"`
	// HasData is true when data entries are produced for this object.
	HasData bool `json:"has_data"`
	// DataNote explains why there is no data (view, remote engine, dry run).
	DataNote string `json:"data_note,omitempty"`
	// DataFormat is Native, or RowBinaryWithNamesAndTypes when a column
	// type cannot be streamed as Native blocks (see FallbackReason).
	DataFormat     string      `json:"data_format,omitempty"`
	FallbackReason string      `json:"fallback_reason,omitempty"`
	Partitions     []Partition `json:"partitions,omitempty"`
	// RowsExpected sums system.parts rows of active parts (MergeTree) at
	// backup start; Rows is what was actually streamed.
	RowsExpected uint64 `json:"rows_expected"`
	Rows         uint64 `json:"rows"`
}

// Column describes one table column (system.columns).
type Column struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	DefaultKind       string `json:"default_kind,omitempty"`
	DefaultExpression string `json:"default_expression,omitempty"`
}

// Partition is one data entry of a table. ID "all" is the whole table.
type Partition struct {
	ID           string `json:"id"`
	Partition    string `json:"partition,omitempty"` // partition expression value
	Entry        string `json:"entry,omitempty"`     // empty when no rows
	RowsExpected uint64 `json:"rows_expected"`
	Rows         uint64 `json:"rows"`
	Parts        uint64 `json:"parts,omitempty"`
	Bytes        int64  `json:"bytes"` // uncompressed entry size
	SHA256       string `json:"sha256,omitempty"`
}
