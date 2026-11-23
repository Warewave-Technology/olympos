package clickhouse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The restore creates databases and tables only, from the archive's
// schema entries (never from table data), one statement at a time, and
// only after the statement was checked (table.go): exactly one CREATE
// TABLE for the database and name the manifest records, of an engine that
// keeps its data on the target (MergeTree family, Log family, Memory),
// whose settings and expressions are an allowlist that cannot read
// anything. Views, materialized views, dictionaries and every other
// engine are not created and are reported by name, never with their DDL
// (it can carry another system's credentials): parsing ClickHouse queries
// to prove them confined to the restored databases is not something a
// restore can do safely.

// ---------------------------------------------------------------- lexer

type tokKind int

const (
	tokWord   tokKind = iota // bare word: keyword or identifier
	tokQIdent                // `quoted` or "quoted" identifier
	tokString                // 'literal' or $heredoc$
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

// lexSQL splits ClickHouse SQL into tokens, dropping whitespace and
// comments (--, # and #! to the end of the line, nested /* */). It fails on
// unterminated literals and on bytes ClickHouse would not accept, so text it
// misreads is refused rather than run.
func lexSQL(s string) ([]token, error) {
	var out []token
	depth := 0
	add := func(k tokKind, val string, start, end int) {
		d := depth
		if k == tokPunct {
			switch val {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
				d = depth
			}
		}
		out = append(out, token{kind: k, val: val, start: start, end: end, depth: d})
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-', c == '#' && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '!'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			n, j := 1, i+2
			for n > 0 {
				switch {
				case j+1 >= len(s):
					return nil, errors.New("unterminated comment")
				case s[j] == '/' && s[j+1] == '*':
					n, j = n+1, j+2
				case s[j] == '*' && s[j+1] == '/':
					n, j = n-1, j+2
				default:
					j++
				}
			}
			i = j
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
		case c == '$':
			j := i + 1
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			if j >= len(s) || s[j] != '$' {
				return nil, fmt.Errorf("unexpected $ at byte %d", i)
			}
			tag := s[i : j+1]
			end := strings.Index(s[j+1:], tag)
			if end < 0 {
				return nil, errors.New("unterminated heredoc literal")
			}
			add(tokString, s[j+1:j+1+end], i, j+1+end+len(tag))
			i = j + 1 + end + len(tag)
		case c >= '0' && c <= '9':
			j := i + 1
			for j < len(s) && (isWordByte(s[j]) || s[j] == '.' ||
				((s[j] == '+' || s[j] == '-') && strings.ContainsRune("eEpP", rune(s[j-1])))) {
				j++
			}
			add(tokNumber, s[i:j], i, j)
			i = j
		case isWordByte(c):
			j := i + 1
			for j < len(s) && (isWordByte(s[j]) || s[j] == '$') {
				j++
			}
			add(tokWord, s[i:j], i, j)
			i = j
		case strings.IndexByte("()[]{},.;:=<>!+-*/%|?@^~&", c) >= 0:
			add(tokPunct, s[i:i+1], i, i+1)
			i++
		case c >= 0x80:
			// ClickHouse reads some of these as quotes (‘’ “”) or spaces
			// (U+00A0), so text with them is not read here at all.
			return nil, errNonASCII
		default:
			return nil, fmt.Errorf("unexpected character %q at byte %d", c, i)
		}
		if depth < 0 {
			return nil, errors.New("unbalanced parentheses")
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced parentheses")
	}
	return out, nil
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// errNonASCII: the statement has a byte outside ASCII outside quotes.
var errNonASCII = errors.New("it holds characters outside ASCII outside quotes, which Olympos does not read")

// lexQuoted reads a quoted literal or identifier starting at s[i]: the quote
// doubled or backslash-escaped stands for itself.
func lexQuoted(s string, i int) (string, int, error) {
	q := s[i]
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '\\':
			if j+1 >= len(s) {
				return "", 0, errors.New("unterminated literal")
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
			case 'x':
				if j+2 < len(s) {
					if v, err := strconv.ParseUint(s[j+1:j+3], 16, 8); err == nil {
						b.WriteByte(byte(v))
						j += 2
						continue
					}
				}
				b.WriteByte(e)
			default:
				b.WriteByte(e)
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
	return "", 0, errors.New("unterminated literal")
}
