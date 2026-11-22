package postgres

import (
	"fmt"
	"strings"
)

// filterGlobals picks the statements of a pg_dumpall --globals-only script
// that a restore may run on a target (docs/design/ui-restore.md "Engines"):
//
//   - roles that do not exist on the target are created with all their
//     statements (CREATE ROLE, ALTER ROLE … WITH / SET, comments,
//     memberships);
//   - every statement about a role in existingRoles is skipped: CREATE ROLE,
//     ALTER ROLE, COMMENT / SECURITY LABEL ON ROLE, and memberships or
//     grants where it is the member or grantee, or the granted role. A
//     predefined role (pg_*) granted to a new role is kept: such roles
//     cannot be created or changed by a restore, and the membership only
//     concerns the new role;
//   - tablespaces are not restored (their paths do not exist on a new
//     server): CREATE / ALTER / COMMENT ON TABLESPACE and grants on them;
//   - ALTER ROLE … IN DATABASE (the database does not exist yet; its own
//     settings come with it), ALTER ROLE ALL and DROP are not run;
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

	for _, st := range splitSQL(sql) {
		c := classify(st)
		switch {
		case c.drop != "":
			note("drop:"+st, c.drop+": not executed, a restore drops nothing")
			continue
		case c.tablespace != "":
			tablespace(c.tablespace)
			continue
		case c.allRoles:
			note("all:"+st, "ALTER ROLE ALL: not applied, it would change the target's existing roles")
			continue
		case c.inDatabase != "":
			note("indb:"+st, fmt.Sprintf("role %s: per-database setting not applied (ALTER ROLE … IN DATABASE %s)", c.roles[0], c.inDatabase))
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
		stmts = append(stmts, st)
	}
	for _, k := range order {
		c := counts[k]
		skipped = append(skipped, c.msg(c.n))
	}
	return stmts, skipped
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
	// roles the statement changes or grants to (CREATE/ALTER/COMMENT ON
	// ROLE, membership members, grantees).
	roles []string
	// granted: roles granted (memberships).
	granted    []string
	tablespace string
	inDatabase string
	allRoles   bool
	drop       string // "DROP ROLE", ... when the statement drops something
}

func classify(st string) globalsStmt {
	var c globalsStmt
	toks := lexSQL(st)
	kw := func(i int) string {
		if i < len(toks) && toks[i].kind == tokWord {
			return strings.ToUpper(toks[i].text)
		}
		return ""
	}
	name := func(i int) string {
		if i < len(toks) {
			return toks[i].name()
		}
		return ""
	}
	isRoleKw := func(k string) bool { return k == "ROLE" || k == "USER" || k == "GROUP" }
	switch kw(0) {
	case "DROP":
		c.drop = strings.TrimSpace("DROP " + kw(1))
	case "CREATE":
		switch {
		case isRoleKw(kw(1)):
			c.roles = []string{name(2)}
		case kw(1) == "TABLESPACE":
			c.tablespace = name(2)
		}
	case "ALTER":
		switch {
		case isRoleKw(kw(1)) && kw(2) == "ALL" && toks[2].kind == tokWord:
			c.allRoles = true
		case isRoleKw(kw(1)):
			c.roles = []string{name(2)}
			if kw(3) == "IN" && kw(4) == "DATABASE" {
				c.inDatabase = name(5)
			}
		case kw(1) == "TABLESPACE":
			c.tablespace = name(2)
		}
	case "COMMENT", "SECURITY":
		// COMMENT ON <type> <name> / SECURITY LABEL [FOR p] ON <type> <name>
		for i := 1; i < len(toks); i++ {
			if kw(i) == "ON" {
				switch {
				case isRoleKw(kw(i + 1)):
					c.roles = []string{name(i + 2)}
				case kw(i+1) == "TABLESPACE":
					c.tablespace = name(i + 2)
				}
				break
			}
		}
	case "GRANT", "REVOKE":
		classifyGrant(toks, &c)
	}
	return c
}

// classifyGrant handles GRANT/REVOKE: memberships (no ON) and privileges
// on objects (ON TABLESPACE, ON PARAMETER, ...).
func classifyGrant(toks []token, c *globalsStmt) {
	on, to := -1, -1
	for i, t := range toks {
		if t.kind != tokWord {
			continue
		}
		switch strings.ToUpper(t.text) {
		case "ON":
			if on < 0 && to < 0 {
				on = i
			}
		case "TO", "FROM":
			if to < 0 {
				to = i
			}
		}
	}
	if to < 0 {
		return
	}
	// Grantees / members: after TO/FROM until WITH, GRANTED, CASCADE,
	// RESTRICT or the end.
	for i := to + 1; i < len(toks); i++ {
		t := toks[i]
		if t.kind == tokWord {
			switch strings.ToUpper(t.text) {
			case "WITH", "GRANTED", "CASCADE", "RESTRICT":
				i = len(toks)
				continue
			case "PUBLIC", "CURRENT_USER", "SESSION_USER", "CURRENT_ROLE", "GROUP":
				continue
			}
		}
		if t.kind == tokWord || t.kind == tokIdent {
			c.roles = append(c.roles, t.name())
		}
	}
	if on >= 0 {
		if on+1 < len(toks) && toks[on+1].kind == tokWord && strings.EqualFold(toks[on+1].text, "TABLESPACE") && on+2 < len(toks) {
			c.tablespace = toks[on+2].name()
		}
		return
	}
	// Membership: the granted roles between GRANT/REVOKE [… OPTION FOR]
	// and TO/FROM.
	start := 1
	for i := 1; i < to; i++ {
		if toks[i].kind == tokWord && strings.EqualFold(toks[i].text, "FOR") {
			start = i + 1
		}
	}
	for i := start; i < to; i++ {
		if t := toks[i]; t.kind == tokWord || t.kind == tokIdent {
			c.granted = append(c.granted, t.name())
		}
	}
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
	kind tokKind
	text string
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
			toks = append(toks, token{tokString, s[i:j]})
			i = j
		case c == '\'':
			j := quotedEnd(s, i, '\'', false)
			toks = append(toks, token{tokString, s[i:j]})
			i = j
		case c == '"':
			j := quotedEnd(s, i, '"', false)
			toks = append(toks, token{tokIdent, s[i:j]})
			i = j
		case c == '$':
			if tag, ok := dollarTag(s, i); ok {
				end := len(s)
				if j := strings.Index(s[i+len(tag):], tag); j >= 0 {
					end = i + len(tag) + j + len(tag)
				}
				toks = append(toks, token{tokString, s[i:end]})
				i = end
				continue
			}
			toks = append(toks, token{tokPunct, "$"})
			i++
		case isIdentByte(c):
			j := i
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			toks = append(toks, token{tokWord, s[i:j]})
			i = j
		default:
			toks = append(toks, token{tokPunct, string(c)})
			i++
		}
	}
	return toks
}
