package spec

import "strings"

// maxVarName is the longest variable name.
const maxVarName = 64

// validVarName reports whether name is a variable name: a letter or "_",
// then letters, digits or "_", at most 64 characters.
func validVarName(name string) bool {
	if name == "" || len(name) > maxVarName {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// varRefs returns the variable names that s refers to with ${name}, in
// order and with repeats. ok is false when s has a "${" that does not start
// a valid reference (no closing brace, or not a valid name): there is no
// escape for a literal "${", so such text is refused rather than guessed.
func varRefs(s string) (names []string, ok bool) {
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			return names, true
		}
		s = s[i+2:]
		j := strings.IndexByte(s, '}')
		if j < 0 || !validVarName(s[:j]) {
			return names, false
		}
		names = append(names, s[:j])
		s = s[j+1:]
	}
}

// Substitute replaces each ${name} in in with vars[name]. A reference to a
// name that vars does not have is left as it is. It makes one pass:
// substituted values are not scanned again, so a value that contains
// "${...}" is inserted literally.
func Substitute(in string, vars map[string]string) string {
	if !strings.Contains(in, "${") {
		return in
	}
	var b strings.Builder
	b.Grow(len(in))
	rest := in
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:i])
		after := rest[i+2:]
		j := strings.IndexByte(after, '}')
		if j < 0 {
			b.WriteString(rest[i:])
			return b.String()
		}
		name := after[:j]
		if v, ok := vars[name]; ok && validVarName(name) {
			b.WriteString(v)
			rest = after[j+1:]
			continue
		}
		// Not a known reference: keep "${" and go on after it, so that
		// "${${a}" still substitutes ${a}.
		b.WriteString("${")
		rest = after
	}
}

// placeholderVars replaces each ${name} in s with ph, so that a URL or a
// JSON body with variables can be checked for its structure. s must have
// passed varRefs.
func placeholderVars(s, ph string) string {
	names, _ := varRefs(s)
	vars := make(map[string]string, len(names))
	for _, n := range names {
		vars[n] = ph
	}
	return Substitute(s, vars)
}
