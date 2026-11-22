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
	m := regexp.MustCompile(`^(\d+)`).FindStringSubmatch(h.DumpVersion)
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

// ---------------------------------------------------------------- schema pass

// dbBlock is one TOC entry about the database itself in the output of
// pg_restore --create --schema-only.
type dbBlock struct {
	Type string // DATABASE, DATABASE PROPERTIES, COMMENT, ACL, SECURITY LABEL
	SQL  string
}

// schemaScan reads the SQL script pg_restore --create --schema-only -f -
// writes (an io.Writer, line by line, without keeping it): it counts the
// TABLE entries and keeps the entries about the database itself (its
// CREATE DATABASE and owner, settings, comment and privileges).
type schemaScan struct {
	Tables int
	Blocks []dbBlock

	partial []byte
	cur     *dbBlock
	size    int
	err     error
}

// maxDBBlocks bounds what is kept of the database's own entries.
const maxDBBlocks = 1 << 20

var tocHeader = regexp.MustCompile(`^-- (?:Data for )?Name: (.*); Type: ([A-Z ]+); Schema: `)

func (s *schemaScan) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.partial = append(s.partial, p...)
			if len(s.partial) > maxDBBlocks {
				// A single line this long is inside an entry we do not keep
				// (a function body); only its start matters.
				s.partial = s.partial[:256]
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
func (s *schemaScan) Close() error {
	if len(s.partial) > 0 {
		s.line(string(s.partial))
		s.partial = nil
	}
	s.end()
	return s.err
}

func (s *schemaScan) end() {
	if s.cur != nil {
		s.cur.SQL = strings.TrimSpace(s.cur.SQL)
		if s.cur.SQL != "" {
			s.Blocks = append(s.Blocks, *s.cur)
		}
		s.cur = nil
	}
}

func (s *schemaScan) line(l string) {
	if m := tocHeader.FindStringSubmatch(l); m != nil {
		s.end()
		name, typ := m[1], strings.TrimSpace(m[2])
		switch {
		case typ == "TABLE" && !strings.HasPrefix(l, "-- Data for"):
			s.Tables++
		case typ == "DATABASE" || typ == "DATABASE PROPERTIES":
			s.cur = &dbBlock{Type: typ}
		case (typ == "COMMENT" || typ == "ACL" || typ == "SECURITY LABEL") && strings.HasPrefix(name, "DATABASE "):
			s.cur = &dbBlock{Type: typ}
		}
		return
	}
	if s.cur == nil {
		return
	}
	if strings.HasPrefix(l, `\`) {
		// \connect: the entry ends; what follows are session settings.
		s.end()
		return
	}
	if strings.HasPrefix(l, "--") && strings.TrimSpace(s.cur.SQL) == "" {
		return
	}
	s.size += len(l) + 1
	if s.size > maxDBBlocks {
		s.err = errors.New("the database's own entries in the archive are too large")
		return
	}
	s.cur.SQL += l + "\n"
}

// ---------------------------------------------------------------- CREATE DATABASE

// createOptions are the CREATE DATABASE options taken from the archive.
// Others (TABLESPACE, OID, ...) are not: tablespaces are not restored.
var createOptions = map[string]bool{
	"ENCODING": true, "LOCALE_PROVIDER": true, "LOCALE": true, "LC_COLLATE": true, "LC_CTYPE": true,
	"ICU_LOCALE": true, "ICU_RULES": true, "BUILTIN_LOCALE": true,
}

// dbDefinition is what the archive says about the database itself.
type dbDefinition struct {
	// Options: KEY = value pairs of the archive's CREATE DATABASE, values as
	// SQL text (literals as pg_dump quoted them).
	Options [][2]string
	// Owner from ALTER DATABASE … OWNER TO.
	Owner string
	// Ignored lists CREATE DATABASE options not used.
	Ignored []string
	// Settings, Comment and ACL are the statements of the DATABASE
	// PROPERTIES, COMMENT and ACL / SECURITY LABEL entries.
	Settings, Comment, ACL []string
}

// databaseDefinition interprets the database entries of a schema scan.
func databaseDefinition(blocks []dbBlock) (dbDefinition, error) {
	var d dbDefinition
	for _, b := range blocks {
		// pg_restore writes the session settings of the next entry (SET
		// default_tablespace, set_config('search_path', ...)) before its
		// header: they are not the database's.
		var stmts []string
		for _, st := range splitSQL(b.SQL) {
			if t := lexSQL(st); len(t) > 0 && !isWords(t, "SET") && !isWords(t, "RESET") && !isWords(t, "SELECT") {
				stmts = append(stmts, st)
			}
		}
		switch b.Type {
		case "DATABASE":
			for _, st := range stmts {
				toks := lexSQL(st)
				switch {
				case isWords(toks, "CREATE", "DATABASE"):
					if err := d.parseCreate(toks); err != nil {
						return d, err
					}
				case isWords(toks, "ALTER", "DATABASE") && len(toks) > 5 && isWords(toks[3:], "OWNER", "TO"):
					d.Owner = toks[5].name()
				}
			}
		case "DATABASE PROPERTIES":
			d.Settings = append(d.Settings, stmts...)
		case "COMMENT":
			d.Comment = append(d.Comment, stmts...)
		default: // ACL, SECURITY LABEL
			d.ACL = append(d.ACL, stmts...)
		}
	}
	return d, nil
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
		if v.kind == tokWord && !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(val) {
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
