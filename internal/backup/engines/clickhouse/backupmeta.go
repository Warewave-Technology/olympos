package clickhouse

// Reading what a native backup run wrote (design docs/design/clickhouse-native.md
// §4, §5): the ingest endpoint keeps the bodies of the run's .backup, of each
// metadata/*.sql and of each count.txt while they stream, and the manifest is
// built from them with the parsers below. Nothing here evaluates SQL:
// ObjectsFromMetadata reads the CREATE prefix and, for a table, the engine
// name, by position, with the strict lexer of ddl.go. Whatever these parsers
// cannot read with certainty is an ErrNativeMeta, never a guess.
//
// What ClickHouse 24.8 and 25.8 write (testdata/native, captured by
// TestCaptureNativeTestdata):
//
//   - .backup is XML: <config> with <version>1</version>, <deduplicate_files>,
//     <timestamp>, <uuid>, for an incremental <base_backup> and
//     <base_backup_uuid> (25.8 adds <base_backup_copy_s3_credentials_from_backup>),
//     and <contents>, one <file> per file of the backup.
//   - A file is in the base by content, not by name: <use_base>true</use_base>
//     marks a file whose bytes the base already holds (a new part's
//     metadata_version.txt can be one). An appended file (a Log table's) is in
//     the base up to <base_size>, and the run stores only the rest.
//   - Identical files of one run are stored once: <data_file> names the file
//     whose object holds the bytes (two count.txt with the same count are one
//     object).
//   - An incremental does not write the metadata/*.sql of an object whose DDL
//     did not change: it is use_base, and its DDL is the base's object (R23).
//   - 24.8 writes the base's S3 credentials, secret included, into an
//     incremental's <base_backup>; 25.8 writes only the URL. BaseBackup is the
//     URL alone, and no error quotes the element.
//   - A materialized view's inner table has no metadata/*.sql of its own,
//     Atomic and Ordinary databases alike: its definition is in the view's
//     statement (TO INNER UUID '…' or ENGINE = …), its data under
//     data/<db>/<view>/.
//   - count.txt is the part's row count in decimal, without a newline.

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrNativeMeta is returned when a .backup, a metadata/*.sql or a count.txt
// is not what ClickHouse writes, or holds something these parsers do not
// read with certainty.
var ErrNativeMeta = errors.New("clickhouse: native backup metadata not read")

// MaxBackupMetaBytes caps the .backup ParseBackupMeta reads, the ingest
// endpoint's capture limit. A metadata/*.sql is capped at maxSchemaEntry
// (1 MiB) and a count.txt at maxCountBytes, the endpoint's limits too.
const MaxBackupMetaBytes = 64 << 20

const maxCountBytes = 64

func metaErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNativeMeta, fmt.Sprintf(format, a...))
}

// BackupMeta is a parsed .backup.
type BackupMeta struct {
	Version int // 1, the only version ClickHouse writes
	// BaseBackup is the URL of an incremental's base, from its
	// <base_backup>S3('<url>'[, '<key>', '<secret>'])</base_backup>, without
	// the credentials; "" for a full backup.
	BaseBackup string
	Files      []MetaFile // in the order of the .backup
}

// MetaFile is one <file> of a .backup.
type MetaFile struct {
	Name     string // the file's path in the backup, relative to the run
	Size     uint64
	Checksum string // 32 lower-case hex digits (ClickHouse's 128-bit checksum); "" for an empty file
	// UseBase: the base holds the file's first BaseSize bytes. BaseSize is
	// Size when the base holds all of it, less for an appended file; 0
	// without UseBase.
	UseBase  bool
	BaseSize uint64
	// DataFile is the file of this run whose object holds this file's bytes,
	// when ClickHouse stored identical files once; "" otherwise.
	DataFile string
}

// Written reports whether the run stored an object for the file: one named
// Name, of Size-BaseSize bytes. It did not for a file the base holds all of,
// for one whose bytes are DataFile's, nor for an empty file.
func (f MetaFile) Written() bool {
	return f.Size > f.BaseSize && f.DataFile == ""
}

// ---------------------------------------------------------------- .backup

// ParseBackupMeta parses a .backup strictly: the elements ClickHouse 24.8
// and 25.8 write and no others, each at most once (a <file> once per name),
// no attributes, comments or directives, and the values checked: sizes and
// versions as decimal, checksums as 32 lower-case hex digits, names as
// relative paths, UUIDs canonical. It also checks the file list itself:
// use_base only in an incremental, a base_size below the size, a data_file
// that names a file of the run with the same size and checksum.
func ParseBackupMeta(b []byte) (*BackupMeta, error) {
	if len(b) > MaxBackupMetaBytes {
		return nil, metaErr(".backup is larger than %d bytes", MaxBackupMetaBytes)
	}
	root, err := readXMLTree(b)
	if err != nil {
		return nil, err
	}
	if root.name != "config" {
		return nil, metaErr(".backup: root element %s, not config", clip(root.name))
	}
	if err := root.container(); err != nil {
		return nil, err
	}
	m := &BackupMeta{}
	seen := map[string]bool{}
	var contents *xmlNode
	var baseUUID, copyCreds bool
	for _, n := range root.kids {
		if seen[n.name] {
			return nil, metaErr(".backup: element %s twice", clip(n.name))
		}
		seen[n.name] = true
		if n.name == "contents" {
			if err := n.container(); err != nil {
				return nil, err
			}
			contents = n
			continue
		}
		v, err := n.leaf()
		if err != nil {
			return nil, err
		}
		switch n.name {
		case "version":
			if v != "1" {
				return nil, metaErr(".backup: version %s (Olympos reads version 1)", clip(v))
			}
			m.Version = 1
		case "deduplicate_files":
			if v != "0" && v != "1" {
				return nil, metaErr(".backup: deduplicate_files %s", clip(v))
			}
		case "timestamp":
		case "uuid":
			if !isRunID(v) {
				return nil, metaErr(".backup: uuid %s", clip(v))
			}
		case "base_backup":
			// The text can hold the base's secret (24.8): it is never quoted.
			url, ok := s3URL(v)
			if !ok {
				return nil, metaErr(".backup: base_backup is not S3('<url>') or S3('<url>', '<key>', '<secret>')")
			}
			m.BaseBackup = url
		case "base_backup_uuid":
			if !isRunID(v) {
				return nil, metaErr(".backup: base_backup_uuid %s", clip(v))
			}
			baseUUID = true
		case "base_backup_copy_s3_credentials_from_backup":
			if v != "true" && v != "false" {
				return nil, metaErr(".backup: base_backup_copy_s3_credentials_from_backup %s", clip(v))
			}
			copyCreds = true
		default:
			return nil, metaErr(".backup: element %s", clip(n.name))
		}
	}
	switch {
	case m.Version == 0:
		return nil, metaErr(".backup: no version")
	case contents == nil:
		return nil, metaErr(".backup: no contents")
	case (m.BaseBackup != "") != baseUUID:
		return nil, metaErr(".backup: base_backup and base_backup_uuid go together")
	case copyCreds && m.BaseBackup == "":
		return nil, metaErr(".backup: base_backup_copy_s3_credentials_from_backup without base_backup")
	}
	byName := map[string]int{}
	for _, n := range contents.kids {
		if n.name != "file" {
			return nil, metaErr(".backup: element %s in contents", clip(n.name))
		}
		f, err := parseMetaFile(n, m.BaseBackup != "")
		if err != nil {
			return nil, err
		}
		if _, dup := byName[f.Name]; dup {
			return nil, metaErr(".backup: file %s twice", clip(f.Name))
		}
		byName[f.Name] = len(m.Files)
		m.Files = append(m.Files, f)
	}
	for _, f := range m.Files {
		if f.DataFile == "" {
			continue
		}
		i, ok := byName[f.DataFile]
		if !ok || f.DataFile == f.Name {
			return nil, metaErr(".backup: file %s: data_file %s is not another file of the backup", clip(f.Name), clip(f.DataFile))
		}
		// The object that holds the bytes is one this run wrote: the file it
		// names is itself stored, whole, under its own name.
		if t := m.Files[i]; t.DataFile != "" || t.UseBase || t.Size != f.Size || t.Checksum != f.Checksum {
			return nil, metaErr(".backup: file %s: data_file %s is not a stored file with the same size and checksum", clip(f.Name), clip(f.DataFile))
		}
	}
	return m, nil
}

func parseMetaFile(n *xmlNode, incremental bool) (MetaFile, error) {
	if err := n.container(); err != nil {
		return MetaFile{}, err
	}
	var f MetaFile
	vals := map[string]string{}
	for _, k := range n.kids {
		v, err := k.leaf()
		if err != nil {
			return f, err
		}
		switch k.name {
		case "name", "size", "checksum", "use_base", "base_size", "base_checksum", "data_file":
		default:
			return f, metaErr(".backup: element %s in a file", clip(k.name))
		}
		if _, dup := vals[k.name]; dup {
			return f, metaErr(".backup: element %s twice in a file", clip(k.name))
		}
		vals[k.name] = v
	}
	name, ok := vals["name"]
	if !ok || !validBackupPath(name) {
		return f, metaErr(".backup: a file without a valid name (%s)", clip(name))
	}
	f.Name = name
	bad := func(format string, a ...any) error {
		return metaErr(".backup: file %s: %s", clip(name), fmt.Sprintf(format, a...))
	}
	size, ok := vals["size"]
	if !ok {
		return f, bad("no size")
	}
	var err error
	if f.Size, err = parseDecimal(size); err != nil {
		return f, bad("size %s", clip(size))
	}
	// An empty file is listed with its size alone.
	sum, hasSum := vals["checksum"]
	switch {
	case f.Size == 0:
		if len(vals) != 2 {
			return f, bad("an empty file with more than its size")
		}
		return f, nil
	case !hasSum || !isChecksum(sum):
		return f, bad("checksum %s", clip(sum))
	}
	f.Checksum = sum
	if v, ok := vals["use_base"]; ok {
		if v != "true" {
			return f, bad("use_base %s", clip(v))
		}
		if !incremental {
			return f, bad("use_base in a backup without a base")
		}
		f.UseBase, f.BaseSize = true, f.Size
	}
	bs, hasBS := vals["base_size"]
	bc, hasBC := vals["base_checksum"]
	switch {
	case hasBS != hasBC:
		return f, bad("base_size and base_checksum go together")
	case hasBS && !f.UseBase:
		return f, bad("base_size without use_base")
	case hasBS:
		if f.BaseSize, err = parseDecimal(bs); err != nil || f.BaseSize == 0 || f.BaseSize >= f.Size {
			return f, bad("base_size %s of a file of %d bytes", clip(bs), f.Size)
		}
		if !isChecksum(bc) {
			return f, bad("base_checksum %s", clip(bc))
		}
	}
	if d, ok := vals["data_file"]; ok {
		if f.UseBase || !validBackupPath(d) {
			return f, bad("data_file %s", clip(d))
		}
		f.DataFile = d
	}
	return f, nil
}

// s3URL reads S3('<url>') or S3('<url>', '<key>', '<secret>') and returns
// the URL.
func s3URL(s string) (string, bool) {
	toks, err := lexSQL(s)
	if err != nil {
		return "", false
	}
	at := func(i int) token { return tokenAt(toks, i) }
	if len(toks) != 4 && len(toks) != 8 || at(0).kind != tokWord || at(0).val != "S3" || !at(1).punct("(") ||
		at(2).kind != tokString || !at(len(toks)-1).punct(")") {
		return "", false
	}
	if len(toks) == 8 && (!at(3).punct(",") || at(4).kind != tokString || !at(5).punct(",") || at(6).kind != tokString) {
		return "", false
	}
	url := at(2).val
	return url, url != "" && validText(url)
}

// parseDecimal reads an unsigned decimal as ClickHouse writes one: digits
// only, no sign, no leading zero, at most 2^64-1.
func parseDecimal(s string) (uint64, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, strconv.ErrSyntax
	}
	for i := range len(s) {
		if !isDigit(s[i]) {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func isChecksum(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !isDigit(c) && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validText: UTF-8 without control characters.
func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validBackupPath: a relative path of non-empty segments, none "." or "..".
func validBackupPath(s string) bool {
	return s != "" && validText(s) && validPath(s)
}

// ---------------------------------------------------------------- XML

// xmlNode is an element of a .backup: its children, or its text.
type xmlNode struct {
	name string
	text strings.Builder
	kids []*xmlNode
}

// leaf returns the text of an element that holds text only.
func (n *xmlNode) leaf() (string, error) {
	if len(n.kids) > 0 {
		return "", metaErr(".backup: element %s holds elements, not a value", clip(n.name))
	}
	return n.text.String(), nil
}

// container checks that an element holds elements and whitespace only.
func (n *xmlNode) container() error {
	if strings.TrimLeft(n.text.String(), " \t\r\n") != "" {
		return metaErr(".backup: element %s holds text", clip(n.name))
	}
	return nil
}

// maxXMLDepth: config, contents, file, and a file's values.
const maxXMLDepth = 4

// readXMLTree reads one element tree: an optional XML declaration, the
// root element and whitespace. Attributes, namespaces, comments, processing
// instructions and directives are refused, and so is anything deeper than
// maxXMLDepth.
func readXMLTree(b []byte) (*xmlNode, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var root *xmlNode
	var stack []*xmlNode
	first := true
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// The decoder's message can quote the input, and a 24.8 .backup
			// holds a secret: only the line is reported.
			var se *xml.SyntaxError
			if errors.As(err, &se) {
				return nil, metaErr(".backup is not XML Olympos reads (line %d)", se.Line)
			}
			return nil, metaErr(".backup is not XML Olympos reads")
		}
		decl := first
		first = false
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case len(t.Attr) > 0 || t.Name.Space != "":
				return nil, metaErr(".backup: element %s has attributes or a namespace", clip(t.Name.Local))
			case root != nil && len(stack) == 0:
				return nil, metaErr(".backup: an element after the root")
			case len(stack) == maxXMLDepth:
				return nil, metaErr(".backup: elements nested deeper than %d", maxXMLDepth)
			}
			n := &xmlNode{name: t.Name.Local}
			if len(stack) == 0 {
				root = n
			} else {
				p := stack[len(stack)-1]
				p.kids = append(p.kids, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimLeft(t, " \t\r\n")) != 0 {
					return nil, metaErr(".backup: text outside the root")
				}
				continue
			}
			stack[len(stack)-1].text.Write(t)
		case xml.ProcInst:
			if !decl || t.Target != "xml" {
				return nil, metaErr(".backup: a processing instruction")
			}
		default:
			return nil, metaErr(".backup: a comment or directive")
		}
	}
	if root == nil {
		return nil, metaErr(".backup: no root element")
	}
	return root, nil
}

// ---------------------------------------------------------------- count.txt

// ParseCount reads a part's count.txt: its row count in decimal, nothing
// else (no sign, leading zero, whitespace or newline).
func ParseCount(b []byte) (uint64, error) {
	if len(b) > maxCountBytes {
		return 0, metaErr("count.txt is larger than %d bytes", maxCountBytes)
	}
	n, err := parseDecimal(string(b))
	if err != nil {
		return 0, metaErr("count.txt %s is not a row count", clip(string(b)))
	}
	return n, nil
}

// ---------------------------------------------------------------- metadata/*.sql

// ObjectsFromMetadata reads the databases and objects of a backup from its
// metadata/*.sql bodies, keyed as the ingest endpoint keeps them:
// "<run-id>/metadata/<db>.sql" for a database and
// "<run-id>/metadata/<db>/<name>.sql" for an object, with the names escaped
// as ClickHouse escapes file names. Each object's DDLKey is its key. The
// keys may be of several runs (an incremental's unchanged metadata is its
// base's); an object or database twice is refused.
//
// The kind and the engine come from the statement's prefix, which must name
// the same database and object as the key:
//
//	CREATE DATABASE db [UUID '…'] ENGINE = …                -- the database
//	CREATE TABLE db.name [UUID '…'] (…) ENGINE = Name …     -- KindTable, Name
//	CREATE VIEW db.name …                                   -- KindView, View
//	CREATE MATERIALIZED VIEW db.name …                      -- KindMaterializedView, MaterializedView
//	CREATE DICTIONARY db.name …                             -- KindDictionary, Dictionary
//
// A table of any engine is a table; the restore's allowlist decides what is
// restored. A materialized view's inner table has no metadata of its own
// (see the top of this file), so it is part of its view; a metadata file
// named like one (.inner.<name>, .inner_id.<uuid>) is refused.
//
// Everything else is refused rather than left out: a LIVE VIEW or WINDOW
// VIEW, a table over a table function (CREATE TABLE … AS url(…)), any other
// CREATE, and a statement the lexer does not read (comments, query
// parameters, text outside ASCII outside quotes, more than one statement).
// An object left out of the manifest would still be restored by RESTORE
// DATABASE, unseen by the allowlist, so a backup the manifest cannot
// describe fully must not be one.
func ObjectsFromMetadata(files map[string][]byte) ([]NativeDatabase, error) {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys) // the first error does not depend on map order
	dbs := map[string]*NativeDatabase{}
	dbFiles := map[string]bool{}
	objects := map[[2]string]bool{}
	for _, key := range keys {
		db, name, err := metadataPath(key)
		if err != nil {
			return nil, err
		}
		kind, engine, err := readCreate(key, db, name, files[key])
		if err != nil {
			return nil, err
		}
		d := dbs[db]
		if d == nil {
			d = &NativeDatabase{Name: db}
			dbs[db] = d
		}
		if name == "" {
			if dbFiles[db] {
				return nil, metaErr("%s: database %s twice", clip(key), clip(db))
			}
			dbFiles[db] = true
			continue
		}
		if objects[[2]string{db, name}] {
			return nil, metaErr("%s: object %s.%s twice", clip(key), clip(db), clip(name))
		}
		objects[[2]string{db, name}] = true
		d.Objects = append(d.Objects, NativeObject{Name: name, Kind: kind, Engine: engine, DDLKey: key})
	}
	var out []NativeDatabase
	for _, d := range dbs {
		slices.SortFunc(d.Objects, func(x, y NativeObject) int { return strings.Compare(x.Name, y.Name) })
		out = append(out, *d)
	}
	slices.SortFunc(out, func(x, y NativeDatabase) int { return strings.Compare(x.Name, y.Name) })
	return out, nil
}

// metadataPath reads "<run>/metadata/<db>.sql" (name "") or
// "<run>/metadata/<db>/<name>.sql" and returns the unescaped names.
func metadataPath(key string) (db, name string, err error) {
	bad := func(why string) (string, string, error) {
		return "", "", metaErr("%s is not <run-id>/metadata/<db>[/<name>].sql: %s", clip(key), why)
	}
	parts := strings.Split(key, "/")
	if len(parts) != 3 && len(parts) != 4 || !validPath(parts[0]) || parts[1] != "metadata" {
		return bad("its segments")
	}
	last, ok := strings.CutSuffix(parts[len(parts)-1], ".sql")
	if !ok {
		return bad("not .sql")
	}
	parts[len(parts)-1] = last
	names := make([]string, 0, 2)
	for _, seg := range parts[2:] {
		n, ok := unescapeFileName(seg)
		if !ok {
			return bad("a name not escaped as ClickHouse escapes it")
		}
		names = append(names, n)
	}
	if len(names) == 1 {
		return names[0], "", nil
	}
	if strings.HasPrefix(names[1], ".inner.") || strings.HasPrefix(names[1], ".inner_id.") {
		return bad("a materialized view's inner table, which ClickHouse does not write on its own")
	}
	return names[0], names[1], nil
}

// unescapeFileName undoes escapeForFileName, and reports whether seg is
// exactly what escapeForFileName writes for a non-empty UTF-8 name.
func unescapeFileName(seg string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(seg) || !isHex(seg[i+1]) || !isHex(seg[i+2]) {
			return "", false
		}
		v, _ := strconv.ParseUint(seg[i+1:i+3], 16, 8)
		b.WriteByte(byte(v))
		i += 2
	}
	s := b.String()
	return s, s != "" && utf8.ValidString(s) && escapeForFileName(s) == seg
}

// readCreate reads the kind and engine of key's statement, which must be a
// CREATE of db.name (of database db when name is "").
func readCreate(key, db, name string, body []byte) (kind, engine string, err error) {
	bad := func(format string, a ...any) (string, string, error) {
		return "", "", metaErr("%s: %s", clip(key), fmt.Sprintf(format, a...))
	}
	if len(body) > maxSchemaEntry {
		return bad("larger than %d bytes", maxSchemaEntry)
	}
	if !utf8.Valid(body) {
		return bad("not UTF-8")
	}
	toks, err := lexSQL(string(body))
	if err != nil {
		return bad("%v", err)
	}
	for _, t := range toks {
		if t.punct(";") {
			return bad("more than one statement")
		}
	}
	at := func(i int) token { return tokenAt(toks, i) }
	if !at(0).is("CREATE") {
		return bad("not a CREATE statement")
	}
	i := 2
	switch {
	case at(1).is("DATABASE"):
		kind = "database"
	case at(1).is("TABLE"):
		kind = KindTable
	case at(1).is("VIEW"):
		kind, engine = KindView, "View"
	case at(1).is("MATERIALIZED") && at(2).is("VIEW"):
		kind, engine, i = KindMaterializedView, "MaterializedView", 3
	case at(1).is("DICTIONARY"):
		kind, engine = KindDictionary, "Dictionary"
	case at(1).is("LIVE") && at(2).is("VIEW"), at(1).is("WINDOW") && at(2).is("VIEW"):
		return bad("a %s VIEW, which a native backup does not record", strings.ToUpper(at(1).val))
	default:
		return bad("CREATE %s is not a database, table, view, materialized view or dictionary", clip(at(1).val))
	}
	switch {
	case name == "" && kind != "database":
		return bad("a database's metadata that is not CREATE DATABASE")
	case name != "" && kind == "database":
		return bad("CREATE DATABASE in an object's metadata")
	}
	// The name, qualified for an object: the same as the key's.
	if !at(i).ident() {
		return bad("no name after CREATE")
	}
	sdb, sname := at(i).val, ""
	i++
	if name != "" {
		if !at(i).punct(".") || !at(i+1).ident() {
			return bad("the name is not <database>.<name>")
		}
		sname = at(i + 1).val
		i += 2
	}
	if sdb != db || sname != name {
		return bad("it creates %s, not what its key names", clip(strings.TrimSuffix(sdb+"."+sname, ".")))
	}
	if at(i).is("UUID") {
		if at(i+1).kind != tokString || !isRunID(at(i+1).val) {
			return bad("a UUID that is not one")
		}
		i += 2
	}
	switch kind {
	case "database":
		if !at(i).is("ENGINE") || !at(i+1).punct("=") || at(i+2).kind != tokWord {
			return bad("no ENGINE = <name> after the database name")
		}
	case KindTable:
		if !at(i).punct("(") {
			return bad("no column list after the table name")
		}
		c := matching(toks, i)
		if c < 0 || !at(c).punct(")") {
			return bad("the column list does not end")
		}
		i = c + 1
		switch {
		case at(i).is("AS"):
			return bad("a table over a table function, which a native backup does not record")
		case !at(i).is("ENGINE") || !at(i+1).punct("=") || at(i+2).kind != tokWord:
			return bad("no ENGINE = <name> after the column list")
		}
		engine = at(i + 2).val
	}
	return kind, engine, nil
}
