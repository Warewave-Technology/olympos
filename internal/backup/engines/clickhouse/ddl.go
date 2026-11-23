package clickhouse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The restore never runs SQL text from the backup. It generates every
// CREATE DATABASE and CREATE TABLE itself (table.go) from structured data:
// the manifest's names, column types (read by the strict type grammar in
// types.go and written again), engine and keys. The lexer below is used to
// read those fields and, for the engines whose parameters are columns
// (ReplacingMergeTree, SummingMergeTree, CollapsingMergeTree,
// VersionedCollapsingMergeTree), the ENGINE clause of the archive's schema
// entry; only bare column names that exist in the restored table are taken
// from it.

// ---------------------------------------------------------------- lexer

type tokKind int

const (
	tokWord   tokKind = iota // [A-Za-z_][A-Za-z0-9_]*: keyword or identifier
	tokQIdent                // `quoted` or "quoted" identifier
	tokString                // 'literal'
	tokNumber
	tokPunct
)

type token struct {
	kind       tokKind
	val        string // decoded value (identifiers, strings), else the text
	start, end int    // byte offsets in the statement
	depth      int    // parenthesis depth at the token (an opening one is outside)
}

func (t token) is(word string) bool { return t.kind == tokWord && strings.EqualFold(t.val, word) }
func (t token) punct(p string) bool { return t.kind == tokPunct && t.val == p }
func (t token) ident() bool         { return t.kind == tokWord || t.kind == tokQIdent }

// errLex: the statement holds text the strict lexer does not read; the
// table is not created.
var errLex = errors.New("its definition holds text Olympos does not read")

func lexErr(format string, a ...any) error {
	return fmt.Errorf("%w (%s)", errLex, fmt.Sprintf(format, a...))
}

// operators are the punctuation a restored table's DDL may hold, longest
// first. Not among them: @ (global variables), ? and { } (query
// parameters), | & ^ ~ ! alone, $ (heredocs), # (comments).
var operators = []string{"<=", ">=", "!=", "<>", "||", "->", "::", "(", ")", ",", ".", ";", "=", "<", ">", "+", "-", "*", "/", "%", "[", "]", ":"}

// lexSQL splits a table's (or database's) DDL into tokens, strictly: ASCII
// whitespace, unquoted identifiers, quoted identifiers, single-quoted
// strings with ClickHouse's escapes, numbers exactly as ClickHouse reads
// them, and the operators above. Anything else (comments, other bytes, a
// digit-led word, an unknown escape) is an errLex, so text ClickHouse could
// read differently is never run.
func lexSQL(s string) ([]token, error) {
	var out []token
	depth := 0
	add := func(k tokKind, val string, start, end int) {
		d := depth
		if k == tokPunct {
			switch val {
			case "(", "[":
				depth++
			case ")", "]":
				depth--
				d = depth
			}
		}
		out = append(out, token{kind: k, val: val, start: start, end: end, depth: d})
	}
next:
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
			continue
		case c == '\'' || c == '`' || c == '"':
			val, j, err := lexQuoted(s, i)
			if err != nil {
				return nil, err
			}
			k := tokQIdent
			if c == '\'' {
				k = tokString
			}
			add(k, val, i, j)
			i = j
			continue
		case c >= '0' && c <= '9':
			j, err := lexNumber(s, i)
			if err != nil {
				return nil, err
			}
			// After ".", a tuple element: digits only (t.1), never 0x2 or 1e5.
			if n := len(out); n > 0 && out[n-1].punct(".") {
				for k := i; k < j; k++ {
					if !isDigit(s[k]) {
						return nil, lexErr("a tuple element Olympos does not read at byte %d", i)
					}
				}
			}
			add(tokNumber, s[i:j], i, j)
			i = j
			continue
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i + 1
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			add(tokWord, s[i:j], i, j)
			i = j
			continue
		}
		// Comments (which ClickHouse skips, quotes and all) and == are not
		// read.
		for _, no := range []string{"--", "/*", "==", "<=>"} {
			if strings.HasPrefix(s[i:], no) {
				return nil, lexErr("%q at byte %d", no, i)
			}
		}
		for _, op := range operators {
			if strings.HasPrefix(s[i:], op) {
				add(tokPunct, op, i, i+len(op))
				i += len(op)
				if depth < 0 {
					return nil, lexErr("unbalanced parentheses")
				}
				continue next
			}
		}
		if c >= 0x80 {
			return nil, lexErr("characters outside ASCII outside quotes")
		}
		return nil, lexErr("unexpected %q at byte %d", c, i)
	}
	if depth != 0 {
		return nil, lexErr("unbalanced parentheses")
	}
	return out, nil
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// lexNumber reads a number at s[i] (a digit) and returns its end:
// 0x hex [. hex*] [p [+-] digits], 0b binary, or digits [. digits*]
// [e [+-] digits]. A word byte or "." right after it (1p, 0x1e-f(…) read
// as one word, 1.2.3) is an errLex.
func lexNumber(s string, i int) (int, error) {
	j := i
	digits := func(ok func(byte) bool) int {
		n := 0
		for j < len(s) && ok(s[j]) {
			j++
			n++
		}
		return n
	}
	exponent := func(marks string) bool {
		if j >= len(s) || !strings.ContainsRune(marks, rune(s[j])) {
			return true
		}
		k := j + 1
		if k < len(s) && (s[k] == '+' || s[k] == '-') {
			k++
		}
		if k >= len(s) || !isDigit(s[k]) {
			return false
		}
		j = k
		digits(isDigit)
		return true
	}
	switch {
	case s[i] == '0' && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X'):
		j = i + 2
		if digits(isHex) == 0 {
			return 0, lexErr("a number Olympos does not read at byte %d", i)
		}
		if j < len(s) && s[j] == '.' {
			j++
			digits(isHex)
		}
		if !exponent("pP") {
			return 0, lexErr("a number Olympos does not read at byte %d", i)
		}
	case s[i] == '0' && i+1 < len(s) && (s[i+1] == 'b' || s[i+1] == 'B') && i+2 < len(s) && (s[i+2] == '0' || s[i+2] == '1'):
		j = i + 2
		digits(func(c byte) bool { return c == '0' || c == '1' })
	default:
		digits(isDigit)
		if j < len(s) && s[j] == '.' {
			j++
			digits(isDigit)
		}
		if !exponent("eE") {
			return 0, lexErr("a number Olympos does not read at byte %d", i)
		}
	}
	if j < len(s) && (isWordByte(s[j]) || s[j] == '.') {
		return 0, lexErr("a number or name Olympos does not read at byte %d", i)
	}
	return j, nil
}

// lexQuoted reads a quoted literal or identifier starting at s[i]: the quote
// doubled, or one of ClickHouse's backslash escapes; any other escape is an
// errLex.
func lexQuoted(s string, i int) (string, int, error) {
	q := s[i]
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '\\':
			if j+1 >= len(s) {
				return "", 0, lexErr("unterminated literal")
			}
			j++
			switch e := s[j]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'a':
				b.WriteByte('\a')
			case 'v':
				b.WriteByte('\v')
			case '\\', '\'', '"', '`':
				b.WriteByte(e)
			case 'x':
				if j+2 < len(s) && isHex(s[j+1]) && isHex(s[j+2]) {
					v, _ := strconv.ParseUint(s[j+1:j+3], 16, 8)
					b.WriteByte(byte(v))
					j += 2
					continue
				}
				return "", 0, lexErr("an escape Olympos does not read")
			default:
				return "", 0, lexErr("an escape Olympos does not read")
			}
		case c == q:
			if j+1 < len(s) && s[j+1] == q {
				b.WriteByte(q)
				j++
				continue
			}
			return b.String(), j + 1, nil
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, lexErr("unterminated literal")
}

// ---------------------------------------------------------------- engine clause

var errEngineClause = errors.New("its ENGINE clause could not be read")

// tokenAt is toks[i], or an end marker outside the slice.
func tokenAt(toks []token, i int) token {
	if i >= 0 && i < len(toks) {
		return toks[i]
	}
	return token{kind: tokPunct, val: "<end>"}
}

// matching returns the index of the ")" or "]" closing the bracket at
// toks[i] (-1 when there is none).
func matching(toks []token, i int) int {
	if i < 0 || i >= len(toks) {
		return -1
	}
	d := toks[i].depth
	for j := i + 1; j < len(toks); j++ {
		if (toks[j].punct(")") || toks[j].punct("]")) && toks[j].depth == d {
			return j
		}
	}
	return -1
}

// splitArgs splits the tokens between the bracket at open and its match
// at the commas of that level. "()" gives no arguments; an empty argument
// ("f(a,)") is an empty slice, which no caller accepts.
func splitArgs(toks []token, open, end int) [][]token {
	if end == open+1 {
		return nil
	}
	var out [][]token
	d := toks[open].depth + 1
	from := open + 1
	for j := open + 1; j <= end; j++ {
		if j == end || (toks[j].punct(",") && toks[j].depth == d) {
			out = append(out, toks[from:j])
			from = j + 1
		}
	}
	return out
}

// sourceEngine reads the engine name and arguments of a table's schema
// entry (SHOW CREATE TABLE text) by position only:
//
//	CREATE TABLE [db.]name [UUID '…'] (columns) ENGINE = Name[(args)] …
//
// Nothing else of the statement is used.
func sourceEngine(ddl string) (string, [][]token, error) {
	if len(ddl) > maxSchemaEntry {
		return "", nil, errEngineClause
	}
	toks, err := lexSQL(ddl)
	if err != nil {
		return "", nil, errEngineClause
	}
	at := func(i int) token { return tokenAt(toks, i) }
	if !at(0).is("CREATE") || !at(1).is("TABLE") || !at(2).ident() {
		return "", nil, errEngineClause
	}
	i := 3
	if at(i).punct(".") {
		if !at(i + 1).ident() {
			return "", nil, errEngineClause
		}
		i += 2
	}
	if at(i).is("UUID") && at(i+1).kind == tokString {
		i += 2
	}
	if !at(i).punct("(") {
		return "", nil, errEngineClause
	}
	c := matching(toks, i)
	if c < 0 || !at(c).punct(")") {
		return "", nil, errEngineClause
	}
	i = c + 1
	if !at(i).is("ENGINE") || !at(i+1).punct("=") || !at(i+2).ident() {
		return "", nil, errEngineClause
	}
	name := at(i + 2).val
	i += 3
	if !at(i).punct("(") {
		return name, nil, nil
	}
	c = matching(toks, i)
	if c < 0 || !at(c).punct(")") {
		return "", nil, errEngineClause
	}
	return name, splitArgs(toks, i, c), nil
}
