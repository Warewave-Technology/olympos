package postgres

import (
	"fmt"
	"strings"
)

// filterGlobals picks the statements of a pg_dumpall --globals-only script
// that a restore may run on a target (docs/design/ui-restore.md "Engines").
// Only the statement forms pg_dumpall writes for roles are run (an
// allowlist); anything else is skipped and reported:
//
//   - session lines: SET default_transaction_read_only, client_encoding,
//     standard_conforming_strings, and SELECT pg_catalog.set_config(
//     'search_path', ”, false);
//   - CREATE ROLE r; ALTER ROLE r WITH …; ALTER ROLE r SET/RESET …;
//     GRANT role, … TO role, … [WITH …] [GRANTED BY r]; COMMENT ON ROLE r
//     IS '…'; SECURITY LABEL [FOR p] ON ROLE r IS '…'.
//
// Of those:
//
//   - roles that do not exist on the target are created with all their
//     statements;
//   - every statement about a role in existingRoles is skipped: CREATE ROLE,
//     ALTER ROLE, COMMENT / SECURITY LABEL ON ROLE, and memberships where it
//     is the member or the granted role. A predefined role (pg_*) granted
//     to a new role is kept: such roles cannot be created or changed by a
//     restore, and the membership only concerns the new role;
//   - GRANTED BY is dropped unless the grantor is a role this restore
//     creates (a grantor missing on the target would fail the step);
//   - tablespaces are not restored (their paths do not exist on a new
//     server): CREATE / ALTER / COMMENT ON TABLESPACE and grants on them;
//   - ALTER ROLE … IN DATABASE (the database does not exist yet), ALTER ROLE
//     ALL / CURRENT_USER / SESSION_USER / CURRENT_ROLE and DROP are not run;
//   - psql meta-commands (\restrict, \unrestrict, any line starting with
//     a backslash) and comments are dropped.
//
// skipped describes what was left out, one line per role or tablespace,
// never with statement text (ALTER ROLE carries password hashes).
func filterGlobals(sql string, existingRoles map[string]bool) (stmts []string, skipped []string) {
	type count struct {
		msg func(n int) string
		n   int
	}
	var order []string
	counts := map[string]*count{}
	bump := func(key string, msg func(n int) string) {
		c, ok := counts[key]
		if !ok {
			c = &count{msg: msg}
			counts[key] = c
			order = append(order, key)
		}
		c.n++
	}
	note := func(key, msg string) {
		bump(key, func(int) string { return msg })
	}
	role := func(name string) {
		bump("role:"+name, func(n int) string {
			return fmt.Sprintf("role %s: exists on the target, not changed (%s skipped)", name, plural(n, "statement"))
		})
	}
	tablespace := func(name string) {
		bump("tablespace:"+name, func(n int) string {
			return fmt.Sprintf("tablespace %s: not created, tablespaces are not restored (%s skipped)", name, plural(n, "statement"))
		})
	}

	all := splitSQL(sql)
	classes := make([]globalsStmt, len(all))
	created := map[string]bool{}
	for i, st := range all {
		classes[i] = classify(st)
		if c := classes[i]; c.create && !existingRoles[c.roles[0]] {
			created[c.roles[0]] = true
		}
	}
	for i, st := range all {
		c := classes[i]
		switch {
		case c.session:
		case c.drop != "":
			note("drop:"+st, c.drop+": not executed, a restore drops nothing")
			continue
		case c.tablespace != "":
			tablespace(c.tablespace)
			continue
		case c.allRoles != "":
			note("all:"+st, "ALTER ROLE "+c.allRoles+": not applied, it would change the target's existing roles")
			continue
		case c.inDatabase != "":
			note("indb:"+st, fmt.Sprintf("role %s: per-database setting not applied (ALTER ROLE … IN DATABASE %s)", c.roles[0], c.inDatabase))
			continue
		case !c.allowed:
			note("other:"+describeStmt(st), "statement not run ("+describeStmt(st)+"): not a role statement pg_dumpall writes")
			continue
		}
		var hit []string
		for _, r := range c.roles {
			if existingRoles[r] && !contains(hit, r) {
				hit = append(hit, r)
			}
		}
		for _, r := range c.granted {
			if existingRoles[r] && !strings.HasPrefix(r, "pg_") && !contains(hit, r) {
				hit = append(hit, r)
			}
		}
		if len(hit) > 0 {
			for _, r := range hit {
				role(r)
			}
			continue
		}
		if c.grantedBy != "" && !created[c.grantedBy] {
			st = strings.TrimRight(st[:c.grantedByStart], " \t\n") + st[c.grantedByEnd:]
		}
		stmts = append(stmts, st)
	}
	for _, k := range order {
		c := counts[k]
		skipped = append(skipped, c.msg(c.n))
	}
	return stmts, skipped
}

// turnsOffStandardStrings: a kept statement sets standard_conforming_strings
// off, under which the splitter would read literals differently from the
// server.
func turnsOffStandardStrings(stmts []string) bool {
	for _, st := range stmts {
		t := lexSQL(st)
		if len(t) >= 4 && isWords(t, "SET") && strings.EqualFold(t[1].text, "standard_conforming_strings") {
			v := strings.ToLower(strings.Trim(t[3].text, "'"))
			if v != "on" && v != "true" && v != "1" && v != "yes" {
				return true
			}
		}
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// globalsStmt is what a globals statement is about.
type globalsStmt struct {
	// allowed: one of the forms pg_dumpall writes for roles.
	allowed bool
	// session: an allowed session line (SET, set_config).
	session bool
	// create: CREATE ROLE roles[0].
	create bool
	// roles the statement changes or grants to (CREATE/ALTER/COMMENT ON
	// ROLE, membership members).
	roles []string
	// granted: roles granted (memberships).
	granted []string
	// grantedBy: the GRANTED BY role of a membership, and the byte range of
	// the clause in the statement.
	grantedBy                    string
	grantedByStart, grantedByEnd int
	tablespace                   string
	inDatabase                   string
	allRoles                     string // ALL, CURRENT_USER, ...
	drop                         string // "DROP ROLE", ... when the statement drops something
}

// specialRole: CURRENT_USER, SESSION_USER or CURRENT_ROLE written as a
// role name (the restore's own login); pg_dumpall never writes them.
func specialRole(t token) bool {
	if t.kind != tokWord {
		return false
	}
	switch strings.ToUpper(t.text) {
	case "CURRENT_USER", "SESSION_USER", "CURRENT_ROLE":
		return true
	}
	return false
}

// sessionParams are the settings pg_dumpall writes at the top of the script.
var sessionParams = map[string]bool{"default_transaction_read_only": true, "client_encoding": true, "standard_conforming_strings": true}

const setConfigLine = "SELECT pg_catalog.set_config('search_path', '', false);"

func classify(st string) globalsStmt {
	var c globalsStmt
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
	isName := func(i int) bool {
		return i < len(toks) && (toks[i].kind == tokWord || toks[i].kind == tokIdent) && !specialRole(toks[i])
	}
	name := func(i int) string {
		if i < len(toks) {
			return toks[i].name()
		}
		return ""
	}
	// IS '…' | IS NULL ending the statement at i.
	isLiteral := func(i int) bool {
		return kw(i) == "IS" && i+2 == len(toks) && (toks[i+1].kind == tokString || kw(i+1) == "NULL")
	}
	switch kw(0) {
	case "SET":
		c.session = len(toks) == 4 && sessionParams[strings.ToLower(toks[1].text)] && (kw(2) == "TO" || toks[2].text == "=")
		c.allowed = c.session
	case "SELECT":
		c.session = strings.Join(strings.Fields(st), " ") == setConfigLine
		c.allowed = c.session
	case "DROP":
		c.drop = strings.TrimSpace("DROP " + kw(1))
	case "CREATE":
		switch {
		case kw(1) == "ROLE" && isName(2) && len(toks) == 3:
			c.allowed, c.create, c.roles = true, true, []string{name(2)}
		case kw(1) == "TABLESPACE":
			c.tablespace = name(2)
		}
	case "ALTER":
		switch {
		case kw(1) == "ROLE" && (kw(2) == "ALL" || len(toks) > 2 && specialRole(toks[2])):
			c.allRoles = kw(2)
		case kw(1) == "ROLE" && isName(2) && kw(3) == "IN" && kw(4) == "DATABASE":
			c.roles, c.inDatabase = []string{name(2)}, name(5)
		case kw(1) == "ROLE" && isName(2) && (kw(3) == "WITH" || kw(3) == "SET" || kw(3) == "RESET"):
			c.allowed, c.roles = true, []string{name(2)}
		case kw(1) == "TABLESPACE":
			c.tablespace = name(2)
		}
	case "COMMENT":
		switch {
		case kw(1) == "ON" && kw(2) == "ROLE" && isName(3) && isLiteral(4):
			c.allowed, c.roles = true, []string{name(3)}
		case kw(1) == "ON" && kw(2) == "TABLESPACE":
			c.tablespace = name(3)
		}
	case "SECURITY":
		i := 2 // SECURITY LABEL [FOR provider] ON …
		if kw(i) == "FOR" {
			i += 2
		}
		switch {
		case kw(1) == "LABEL" && kw(i) == "ON" && kw(i+1) == "ROLE" && isName(i+2) && isLiteral(i+3):
			c.allowed, c.roles = true, []string{name(i + 2)}
		case kw(1) == "LABEL" && kw(i) == "ON" && kw(i+1) == "TABLESPACE":
			c.tablespace = name(i + 2)
		}
	case "GRANT":
		classifyGrant(toks, &c)
	}
	return c
}

// classifyGrant handles GRANT: memberships (GRANT role, … TO role, …
// [WITH …] [GRANTED BY role]) are allowed; a grant ON TABLESPACE is a
// tablespace statement; other grants (ON PARAMETER, …) are not allowed.
func classifyGrant(toks []token, c *globalsStmt) {
	to := -1
	for i, t := range toks {
		if t.kind != tokWord {
			continue
		}
		switch strings.ToUpper(t.text) {
		case "ON":
			if to < 0 {
				if i+2 < len(toks) && toks[i+1].kind == tokWord && strings.EqualFold(toks[i+1].text, "TABLESPACE") {
					c.tablespace = toks[i+2].name()
				}
				return
			}
		case "TO":
			if to < 0 {
				to = i
			}
		}
	}
	if to < 0 {
		return
	}
	// role, role, … : names separated by commas.
	names := func(from, to int) ([]string, bool) {
		var out []string
		for i := from; i < to; i++ {
			t := toks[i]
			if (i-from)%2 == 1 {
				if t.kind != tokPunct || t.text != "," {
					return nil, false
				}
				continue
			}
			if t.kind != tokWord && t.kind != tokIdent || specialRole(t) {
				return nil, false
			}
			out = append(out, t.name())
		}
		return out, len(out) > 0 && (to-from)%2 == 1
	}
	granted, ok := names(1, to)
	if !ok {
		return
	}
	end := len(toks)
	for i := to + 1; i < len(toks); i++ {
		if toks[i].kind == tokWord && (strings.EqualFold(toks[i].text, "WITH") || strings.EqualFold(toks[i].text, "GRANTED")) {
			end = i
			break
		}
	}
	members, ok := names(to+1, end)
	if !ok {
		return
	}
	for _, m := range members {
		if m == "public" {
			return
		}
	}
	// The tail: [WITH option [TRUE|FALSE], …] [GRANTED BY role].
	for i := end; i < len(toks); i++ {
		t := toks[i]
		if t.kind == tokWord && strings.EqualFold(t.text, "GRANTED") {
			if i+3 != len(toks) || !strings.EqualFold(toks[i+1].text, "BY") || (toks[i+2].kind != tokWord && toks[i+2].kind != tokIdent) ||
				specialRole(toks[i+2]) {
				return
			}
			c.grantedBy, c.grantedByStart, c.grantedByEnd = toks[i+2].name(), t.pos, toks[i+2].end
			break
		}
		if t.kind != tokWord && !(t.kind == tokPunct && t.text == ",") {
			return
		}
	}
	c.allowed, c.roles, c.granted = true, members, granted
}

// ---------------------------------------------------------------- SQL text

// splitSQL splits a SQL script into statements (each with its ';'),
// dropping comments and psql meta-commands (a line starting with '\' where
// a statement would start). It understands '…' (E'…' with backslash
// escapes), "…" and $tag$…$tag$ quoting.
func splitSQL(sql string) []string {
	var out []string
	var b strings.Builder
	blank := true // b holds only whitespace
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			out = append(out, s)
		}
		b.Reset()
		blank = true
	}
	n := len(sql)
	for i := 0; i < n; {
		ch := sql[i]
		switch {
		case blank && ch == '\\':
			for i < n && sql[i] != '\n' {
				i++
			}
		case ch == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' {
				i++
			}
		case ch == '/' && i+1 < n && sql[i+1] == '*':
			depth := 0
			for i < n {
				if sql[i] == '/' && i+1 < n && sql[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if sql[i] == '*' && i+1 < n && sql[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
			b.WriteByte(' ')
		case ch == '\'':
			esc := i > 0 && (sql[i-1] == 'E' || sql[i-1] == 'e') && (i < 2 || !isIdentByte(sql[i-2]))
			j := quotedEnd(sql, i, '\'', esc)
			b.WriteString(sql[i:j])
			blank = false
			i = j
		case ch == '"':
			j := quotedEnd(sql, i, '"', false)
			b.WriteString(sql[i:j])
			blank = false
			i = j
		case ch == '$' && (i == 0 || !isIdentByte(sql[i-1])):
			if tag, ok := dollarTag(sql, i); ok {
				j := strings.Index(sql[i+len(tag):], tag)
				end := n
				if j >= 0 {
					end = i + len(tag) + j + len(tag)
				}
				b.WriteString(sql[i:end])
				blank = false
				i = end
				continue
			}
			b.WriteByte(ch)
			blank = false
			i++
		case ch == ';':
			b.WriteByte(ch)
			i++
			flush()
		default:
			b.WriteByte(ch)
			if ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
				blank = false
			}
			i++
		}
	}
	flush()
	return out
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// quotedEnd returns the index after the quoted run starting at s[i] (the
// quote character q, doubled to escape; with esc also backslash escapes).
func quotedEnd(s string, i int, q byte, esc bool) int {
	for j := i + 1; j < len(s); j++ {
		switch {
		case esc && s[j] == '\\':
			j++
		case s[j] == q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(s)
}

// dollarTag reads a $tag$ opener at s[i].
func dollarTag(s string, i int) (string, bool) {
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		if c == '$' {
			tag := s[i : j+1]
			if len(tag) > 2 && tag[1] >= '0' && tag[1] <= '9' {
				return "", false // $1: a parameter, not a tag
			}
			return tag, true
		}
		if !(c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80) {
			return "", false
		}
	}
	return "", false
}

type tokKind int

const (
	tokWord   tokKind = iota // bare word (keyword or identifier)
	tokIdent                 // "quoted identifier"
	tokString                // '…', E'…', $$…$$
	tokPunct
)

type token struct {
	kind     tokKind
	text     string
	pos, end int // byte range in the statement
}

// name is the identifier a token names: a bare word folds to lower case,
// a quoted identifier is exact.
func (t token) name() string {
	switch t.kind {
	case tokWord:
		return strings.ToLower(t.text)
	case tokIdent:
		s := t.text
		if len(s) >= 2 {
			s = s[1 : len(s)-1]
		}
		return strings.ReplaceAll(s, `""`, `"`)
	}
	return t.text
}

// lexSQL tokenizes one statement (no comments; splitSQL removed them).
func lexSQL(s string) []token {
	var toks []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case (c == 'E' || c == 'e') && i+1 < len(s) && s[i+1] == '\'':
			j := quotedEnd(s, i+1, '\'', true)
			toks = append(toks, token{tokString, s[i:j], i, j})
			i = j
		case c == '\'':
			j := quotedEnd(s, i, '\'', false)
			toks = append(toks, token{tokString, s[i:j], i, j})
			i = j
		case c == '"':
			j := quotedEnd(s, i, '"', false)
			toks = append(toks, token{tokIdent, s[i:j], i, j})
			i = j
		case c == '$':
			if tag, ok := dollarTag(s, i); ok {
				end := len(s)
				if j := strings.Index(s[i+len(tag):], tag); j >= 0 {
					end = i + len(tag) + j + len(tag)
				}
				toks = append(toks, token{tokString, s[i:end], i, end})
				i = end
				continue
			}
			toks = append(toks, token{tokPunct, "$", i, i + 1})
			i++
		case isIdentByte(c):
			j := i
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			toks = append(toks, token{tokWord, s[i:j], i, j})
			i = j
		default:
			toks = append(toks, token{tokPunct, string(c), i, i + 1})
			i++
		}
	}
	return toks
}
