package postgres

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

var leadingNumber = regexp.MustCompile(`^(\d+)`)

// archiveHeader is the start of a pg_dump custom-format archive.
type archiveHeader struct {
	DBName        string
	ServerVersion string // "Dumped from database version"
	DumpVersion   string // "Dumped by pg_dump version"
	DumpMajor     int
}

// readArchiveHeader reads the header of a custom-format archive (pg_dump
// -Fc), enough to choose a pg_restore before running one: pg_restore
// refuses archives of a newer format than its own.
func readArchiveHeader(r io.Reader) (archiveHeader, error) {
	var h archiveHeader
	br := bufio.NewReader(io.LimitReader(r, 64<<10))
	fixed := make([]byte, 11)
	if _, err := io.ReadFull(br, fixed); err != nil {
		return h, fmt.Errorf("read the archive header: %w", err)
	}
	if string(fixed[:5]) != "PGDMP" {
		return h, errors.New("not a pg_dump custom-format archive")
	}
	vmaj, vmin := int(fixed[5]), int(fixed[6])
	intSize, format := int(fixed[8]), fixed[10]
	version := vmaj*100 + vmin
	if version < 110 { // 1.10 (PostgreSQL 9.0) added the version strings
		return h, fmt.Errorf("archive format %d.%d is too old to restore here", vmaj, vmin)
	}
	if format != 1 {
		return h, fmt.Errorf("archive format %d is not the custom format", format)
	}
	if intSize < 1 || intSize > 8 {
		return h, fmt.Errorf("archive integer size %d is invalid", intSize)
	}
	readInt := func() (int, error) {
		b := make([]byte, 1+intSize)
		if _, err := io.ReadFull(br, b); err != nil {
			return 0, err
		}
		v := 0
		for i := intSize; i >= 1; i-- {
			v = v<<8 | int(b[i])
		}
		if b[0] != 0 {
			v = -v
		}
		return v, nil
	}
	readStr := func() (string, error) {
		n, err := readInt()
		if err != nil || n < 0 {
			return "", err
		}
		if n > 4096 {
			return "", fmt.Errorf("archive header string of %d bytes", n)
		}
		b := make([]byte, n)
		_, err = io.ReadFull(br, b)
		return string(b), err
	}
	// Compression: one byte from 1.15, an int before.
	if version >= 115 {
		if _, err := br.ReadByte(); err != nil {
			return h, err
		}
	} else if _, err := readInt(); err != nil {
		return h, err
	}
	for i := 0; i < 7; i++ { // creation time
		if _, err := readInt(); err != nil {
			return h, fmt.Errorf("read the archive header: %w", err)
		}
	}
	var err error
	if h.DBName, err = readStr(); err == nil {
		if h.ServerVersion, err = readStr(); err == nil {
			h.DumpVersion, err = readStr()
		}
	}
	if err != nil {
		return h, fmt.Errorf("read the archive header: %w", err)
	}
	m := leadingNumber.FindStringSubmatch(h.DumpVersion)
	if m == nil {
		return h, fmt.Errorf("archive made by an unrecognized pg_dump version %q", h.DumpVersion)
	}
	h.DumpMajor, _ = strconv.Atoi(m[1])
	if h.DumpMajor < 10 && strings.HasPrefix(h.DumpVersion, "9.") {
		// 9.x majors are two numbers; any pg_restore >= 10 reads them.
		h.DumpMajor = 9
	}
	return h, nil
}

// ---------------------------------------------------------------- TOC

// tocScan reads the TOC listing pg_restore --create -l writes (an
// io.Writer, line by line, without keeping it). pg_restore writes one line
// per entry with names sanitized (no newlines), so nothing from the
// database's contents can start a line: it counts the TABLE entries and
// keeps the dump IDs of the entries about the database itself (DATABASE,
// DATABASE PROPERTIES, and its COMMENT, ACL and SECURITY LABEL).
type tocScan struct {
	DB     string // the database the entries must name
	Tables int
	// DBEntries are the dump IDs of the database's own entries.
	DBEntries []string

	partial []byte
	err     error
}

// maxTOCLine bounds one line of the listing.
const maxTOCLine = 1 << 20

// maxDBEntries bounds the database's own entries (pg_dump writes at most 5).
const maxDBEntries = 16

// tocLine is "<dump id>; <catalog oid> <oid> <desc> <schema> <tag> <owner>".
var tocLine = regexp.MustCompile(`^(\d+); (\d+) (\d+) (.*)$`)

func (s *tocScan) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.partial = append(s.partial, p...)
			if len(s.partial) > maxTOCLine {
				s.err = errors.New("a line of the archive's table of contents is too long")
			}
			break
		}
		line := p[:i]
		if len(s.partial) > 0 {
			line = append(s.partial, line...)
			s.partial = s.partial[:0]
		}
		s.line(string(line))
		p = p[i+1:]
	}
	return n, s.err
}

// Close handles a last line without a newline.
func (s *tocScan) Close() error {
	if len(s.partial) > 0 {
		s.line(string(s.partial))
		s.partial = nil
	}
	return s.err
}

func (s *tocScan) line(l string) {
	m := tocLine.FindStringSubmatch(l)
	if m == nil || s.err != nil {
		return
	}
	id, catalog, rest := m[1], m[2], m[4]
	switch {
	case catalog == "1259" && strings.HasPrefix(rest, "TABLE "): // pg_class: not TABLE DATA / ATTACH (catalog 0)
		s.Tables++
		return
	case catalog == "1262" && strings.HasPrefix(rest, "DATABASE - "+s.DB+" "): // pg_database
	case catalog == "0" && (strings.HasPrefix(rest, "DATABASE PROPERTIES - "+s.DB+" ") ||
		strings.HasPrefix(rest, "COMMENT - DATABASE "+s.DB+" ") ||
		strings.HasPrefix(rest, "ACL - DATABASE "+s.DB+" ") ||
		strings.HasPrefix(rest, "SECURITY LABEL - DATABASE "+s.DB+" ")):
	default:
		return
	}
	if len(s.DBEntries) == maxDBEntries {
		s.err = errors.New("the archive has too many entries about the database itself")
		return
	}
	s.DBEntries = append(s.DBEntries, id)
}

// listFile is the pg_restore -L list selecting the given dump IDs.
func listFile(ids []string) []byte {
	var b strings.Builder
	for _, id := range ids {
		b.WriteString(id + ";\n")
	}
	return []byte(b.String())
}

// ---------------------------------------------------------------- CREATE DATABASE

// createOptions are the CREATE DATABASE options taken from the archive.
// Others (TABLESPACE, OID, ...) are not: tablespaces are not restored.
var createOptions = map[string]bool{
	"ENCODING": true, "LOCALE_PROVIDER": true, "LOCALE": true, "LC_COLLATE": true, "LC_CTYPE": true,
	"ICU_LOCALE": true, "ICU_RULES": true, "BUILTIN_LOCALE": true,
}

var optionWord = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// dbDefinition is what the archive says about the database itself.
type dbDefinition struct {
	// Options: KEY = value pairs of the archive's CREATE DATABASE, values as
	// SQL text (literals as pg_dump quoted them).
	Options [][2]string
	// Owner from ALTER DATABASE … OWNER TO.
	Owner string
	// Ignored lists CREATE DATABASE options not used.
	Ignored []string
	// Settings: ALTER DATABASE <db> SET / RESET / CONNECTION LIMIT.
	Settings []string
	// RoleSettings: ALTER ROLE r IN DATABASE <db> SET / RESET.
	RoleSettings []string
	// Comment: COMMENT ON DATABASE <db> IS '…'.
	Comment []string
	// ACL: GRANT / REVOKE … ON DATABASE <db>, SECURITY LABEL … ON DATABASE.
	ACL []string
	// Unused names the statements of those entries that are none of the
	// forms above (not run).
	Unused []string
}

// databaseDefinition reads the script pg_restore --create --schema-only -L
// writes for the database's own entries. Only these statement forms, each
// naming db, are kept (they run with the restore's credential):
// CREATE DATABASE db …; ALTER DATABASE db OWNER TO r | SET … | RESET … |
// CONNECTION LIMIT …; ALTER ROLE r IN DATABASE db SET|RESET …; COMMENT ON
// DATABASE db IS '…'; GRANT|REVOKE … ON DATABASE db TO|FROM …; SECURITY
// LABEL [FOR p] ON DATABASE db IS '…'. Session settings and \connect are
// dropped; anything else is listed in Unused. A script that turns
// standard_conforming_strings off is refused (its literals would be read
// differently).
func databaseDefinition(script, db string) (dbDefinition, error) {
	var d dbDefinition
	for _, st := range splitSQL(script) {
		toks := lexSQL(st)
		if n := len(toks); n > 0 && toks[n-1].kind == tokPunct && toks[n-1].text == ";" {
			toks = toks[:n-1]
		}
		kw := func(i int) string {
			if i < len(toks) && toks[i].kind == tokWord {
				return strings.ToUpper(toks[i].text)
			}
			return ""
		}
		named := func(i int) bool {
			return i < len(toks) && (toks[i].kind == tokWord || toks[i].kind == tokIdent) && toks[i].name() == db
		}
		isName := func(i int) bool { return i < len(toks) && (toks[i].kind == tokWord || toks[i].kind == tokIdent) }
		literalEnd := func(i int) bool { // IS '…' | IS NULL, ending the statement
			return kw(i) == "IS" && i+2 == len(toks) && (toks[i+1].kind == tokString || kw(i+1) == "NULL")
		}
		switch {
		case len(toks) == 0:
		case kw(0) == "SET":
			if turnsOffStandardStrings([]string{st}) {
				return d, errors.New("the archive turns standard_conforming_strings off; it is not restored")
			}
		case kw(0) == "SELECT" || kw(0) == "RESET":
		case isWords(toks, "CREATE", "DATABASE"):
			if !named(2) {
				return d, fmt.Errorf("the archive creates database %s, not %s", toks[2].name(), db)
			}
			if err := d.parseCreate(toks); err != nil {
				return d, err
			}
		case isWords(toks, "ALTER", "DATABASE") && named(2) && kw(3) == "OWNER" && kw(4) == "TO" && isName(5) && len(toks) == 6:
			d.Owner = toks[5].name()
		case isWords(toks, "ALTER", "DATABASE") && named(2) && (kw(3) == "SET" && kw(4) != "TABLESPACE" || kw(3) == "RESET" ||
			kw(3) == "CONNECTION" && kw(4) == "LIMIT"):
			d.Settings = append(d.Settings, st)
		case isWords(toks, "ALTER", "ROLE") && isName(2) && kw(3) == "IN" && kw(4) == "DATABASE" && named(5) && (kw(6) == "SET" || kw(6) == "RESET"):
			d.RoleSettings = append(d.RoleSettings, st)
		case isWords(toks, "COMMENT", "ON", "DATABASE") && named(3) && literalEnd(4):
			d.Comment = append(d.Comment, st)
		case (kw(0) == "GRANT" || kw(0) == "REVOKE") && onDatabase(toks, db):
			d.ACL = append(d.ACL, st)
		case isWords(toks, "SECURITY", "LABEL"):
			i := 2
			if kw(i) == "FOR" && isName(i+1) {
				i += 2
			}
			if kw(i) == "ON" && kw(i+1) == "DATABASE" && named(i+2) && literalEnd(i+3) {
				d.ACL = append(d.ACL, st)
			} else {
				d.Unused = append(d.Unused, describeStmt(st))
			}
		default:
			d.Unused = append(d.Unused, describeStmt(st))
		}
	}
	return d, nil
}

// onDatabase: a GRANT/REVOKE whose object is exactly ON DATABASE db,
// followed by TO/FROM and role names.
func onDatabase(toks []token, db string) bool {
	for i, t := range toks {
		if t.kind == tokWord && strings.EqualFold(t.text, "ON") {
			return i+4 < len(toks) && isWords(toks[i+1:], "DATABASE") &&
				(toks[i+2].kind == tokWord || toks[i+2].kind == tokIdent) && toks[i+2].name() == db &&
				toks[i+3].kind == tokWord && (strings.EqualFold(toks[i+3].text, "TO") || strings.EqualFold(toks[i+3].text, "FROM"))
		}
	}
	return false
}

func isWords(toks []token, words ...string) bool {
	if len(toks) < len(words) {
		return false
	}
	for i, w := range words {
		if toks[i].kind != tokWord || !strings.EqualFold(toks[i].text, w) {
			return false
		}
	}
	return true
}

// parseCreate reads CREATE DATABASE <name> [WITH] KEY = value ... ;
func (d *dbDefinition) parseCreate(toks []token) error {
	i := 3
	if i < len(toks) && toks[i].kind == tokWord && strings.EqualFold(toks[i].text, "WITH") {
		i++
	}
	for i < len(toks) {
		if toks[i].kind == tokPunct && toks[i].text == ";" {
			break
		}
		if toks[i].kind != tokWord {
			return fmt.Errorf("unexpected %q in the archive's CREATE DATABASE", toks[i].text)
		}
		// KEY [WORD ...] = value (CONNECTION LIMIT = -1).
		var words []string
		for i < len(toks) && toks[i].kind == tokWord {
			words = append(words, strings.ToUpper(toks[i].text))
			i++
		}
		key := strings.Join(words, " ")
		if i >= len(toks) || toks[i].kind != tokPunct || toks[i].text != "=" {
			return fmt.Errorf("CREATE DATABASE option %s has no value in the archive", key)
		}
		i++
		if i >= len(toks) {
			return fmt.Errorf("CREATE DATABASE option %s has no value in the archive", key)
		}
		v := toks[i]
		i++
		if v.kind == tokPunct && v.text == "-" && i < len(toks) { // a negative number
			v = token{kind: tokWord, text: "-" + toks[i].text}
			i++
		}
		if v.kind != tokWord && v.kind != tokString && v.kind != tokIdent {
			return fmt.Errorf("CREATE DATABASE option %s has an unexpected value in the archive", key)
		}
		if key == "TEMPLATE" { // always template0
			continue
		}
		if !createOptions[key] {
			d.Ignored = append(d.Ignored, key)
			continue
		}
		val := v.text
		if v.kind == tokWord && !optionWord.MatchString(val) {
			return fmt.Errorf("CREATE DATABASE option %s has an unexpected value in the archive", key)
		}
		d.Options = append(d.Options, [2]string{key, val})
	}
	return nil
}

// createSQL is the CREATE DATABASE for db: from template0, with the
// archive's encoding and locale, and its owner when owner is true.
func (d dbDefinition) createSQL(db string, owner bool) string {
	var b strings.Builder
	b.WriteString("CREATE DATABASE " + pgx.Identifier{db}.Sanitize() + " WITH TEMPLATE = template0")
	for _, o := range d.Options {
		b.WriteString(" " + o[0] + " = " + o[1])
	}
	if owner && d.Owner != "" {
		b.WriteString(" OWNER = " + pgx.Identifier{d.Owner}.Sanitize())
	}
	return b.String()
}
