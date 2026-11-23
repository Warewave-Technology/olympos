package spec

import (
	"errors"
	"strconv"
	"strings"
)

// maxJSONPath is the longest JSON path.
const maxJSONPath = 256

// PathElem is one element of a JSON path: an object key, or an array index
// when IsIndex is set.
type PathElem struct {
	Key     string
	Index   int
	IsIndex bool
}

var errJSONPath = errors.New("not a valid JSON path")

// ParseJSONPath parses the JSON path subset used by json:<path> subjects
// and json_path extracts: an optional leading "$", then keys and indexes,
// as in "data.items[0].id", "$.data.items[0]['id']" or `["a.b"]`.
//
//   - A key after "." is letters, digits, "_" and "-". The first key may
//     omit the ".".
//   - [n] is an array index, n ≥ 0, without leading zeros.
//   - ["key"] or ['key'] is any key that does not contain its quote; there
//     are no escapes.
//
// "$" alone is the whole document. An empty path is refused.
func ParseJSONPath(p string) ([]PathElem, error) {
	if p == "" || len(p) > maxJSONPath {
		return nil, errJSONPath
	}
	s := p
	root := strings.HasPrefix(s, "$")
	if root {
		s = s[1:]
	}
	elems := []PathElem{}
	first := true
	for s != "" {
		switch {
		case s[0] == '[' && len(s) >= 2 && (s[1] == '"' || s[1] == '\''):
			// The key ends at the first quote followed by "]"; it may
			// contain "]" but not its own quote.
			q := s[1]
			end := strings.Index(s[2:], string(q)+"]")
			if end < 0 {
				return nil, errJSONPath
			}
			key := s[2 : 2+end]
			if strings.IndexByte(key, q) >= 0 {
				return nil, errJSONPath
			}
			elems = append(elems, PathElem{Key: key})
			s = s[2+end+2:]
		case s[0] == '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, errJSONPath
			}
			n, ok := parseIndex(s[1:end])
			if !ok {
				return nil, errJSONPath
			}
			elems = append(elems, PathElem{Index: n, IsIndex: true})
			s = s[end+1:]
		case s[0] == '.' && (root || !first), s[0] != '.' && first && !root:
			if s[0] == '.' {
				s = s[1:]
			}
			n := 0
			for n < len(s) && isKeyChar(s[n]) {
				n++
			}
			if n == 0 {
				return nil, errJSONPath
			}
			elems = append(elems, PathElem{Key: s[:n]})
			s = s[n:]
		default:
			return nil, errJSONPath
		}
		first = false
	}
	return elems, nil
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func parseIndex(s string) (int, bool) {
	if s == "" || len(s) > 9 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// LookupJSON follows path in doc, a value decoded by encoding/json into
// any (map[string]any, []any and scalars). It reports false when a key or
// index is missing or the value is not an object or array where the path
// needs one.
func LookupJSON(doc any, path []PathElem) (any, bool) {
	v := doc
	for _, e := range path {
		if e.IsIndex {
			a, ok := v.([]any)
			if !ok || e.Index < 0 || e.Index >= len(a) {
				return nil, false
			}
			v = a[e.Index]
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[e.Key]; !ok {
			return nil, false
		}
	}
	return v, true
}
