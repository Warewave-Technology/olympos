package sensitive

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"regexp"
	"sort"
)

// Redacted replaces every value the Redactor removes.
const Redacted = "[redacted]"

// Headers whose values are always removed (docs/design/synthetic-monitoring.md
// §6.2), whatever their content.
var alwaysRedacted = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"X-Api-Key":           true,
}

// pairRE finds "name=value" and "name: value" pairs in text: query strings,
// form bodies, YAML, header-like lines, and JSON that is not valid as a
// whole (cut at the read limit). Groups: 1 name, 2 optional auth scheme
// ("Bearer "), 3 value.
var pairRE = regexp.MustCompile(`(?i)["']?([a-z0-9_.\-]{1,128})["']?\s*[:=]\s*["']?((?:bearer|basic|digest|token)\s+)?([^"'&\s,;<>(){}\[\]]+)`)

// Redactor removes credentials from HTTP responses: header and JSON field
// values whose names are sensitive, name/value pairs in text, and whatever
// the gitleaks rules match. D may be nil: then the gitleaks rules are not
// run. The zero Redactor and a nil *Redactor still redact by name.
type Redactor struct{ D *Detector }

// RedactHeaders returns a copy of h in which the values of the headers in
// §6.2 (Authorization, Proxy-Authorization, Cookie, Set-Cookie, X-Api-Key),
// the headers named in extra (a credential's own header), and any header
// whose name is sensitive (SensitiveName) are replaced by "[redacted]".
// Other values go through RedactValue.
func (r *Redactor) RedactHeaders(h http.Header, extra []string) http.Header {
	drop := map[string]bool{}
	for _, e := range extra {
		if e != "" {
			drop[textproto.CanonicalMIMEHeaderKey(e)] = true
		}
	}
	out := make(http.Header, len(h))
	for name, vals := range h {
		canon := textproto.CanonicalMIMEHeaderKey(name)
		nv := make([]string, len(vals))
		for i, v := range vals {
			if alwaysRedacted[canon] || drop[canon] || SensitiveName(canon) {
				nv[i] = Redacted
				continue
			}
			nv[i] = r.RedactValue(canon, v)
		}
		out[name] = nv
	}
	return out
}

// RedactValue redacts one named value, such as a header value or a JSON
// field shown as an assertion's actual value: all of it when the name is
// sensitive or the gitleaks rules match it with the name as context, and
// otherwise the pairs and secrets inside it (as RedactBody).
func (r *Redactor) RedactValue(name, value string) string {
	if SensitiveName(name) {
		return Redacted
	}
	if r != nil && r.D != nil {
		if _, _, ok := r.D.Find(name, value); ok {
			return Redacted
		}
	}
	return string(r.redactText([]byte(value)))
}

// RedactBody returns a redacted copy of a response body. When b is valid
// JSON, the value of every field whose name is sensitive becomes
// "[redacted]" (objects and arrays included) and the document is written
// again, compact, in its original key order. Then, in any body, the value
// of every name/value pair with a sensitive name and every secret the
// gitleaks rules find (in the first MaxValue bytes) are replaced.
func (r *Redactor) RedactBody(b []byte) []byte {
	out := b
	if json.Valid(b) {
		if j, err := redactJSON(b); err == nil {
			out = j
		}
	}
	return r.redactText(out)
}

// prefixMargin is how far past the requested prefix RedactPrefix scans,
// and prefixGuard how much of the end of that window it never returns: a
// pair or secret cut by the window's end is redacted as far as it is
// inside the window, and lies in the guard.
const (
	prefixMargin = 64 << 10
	prefixGuard  = 16 << 10
)

// RedactPrefix returns at most the first n bytes of RedactBody(b) without
// scanning all of b with the text rules: the JSON field rule runs on the
// whole body (it needs the whole document), the pair and gitleaks rules on
// the first n + 64 KiB of the result only, and the last 16 KiB of that
// window are never returned. cut reports that less than the whole
// redacted body is returned. Everything returned was redacted before it
// was cut.
func (r *Redactor) RedactPrefix(b []byte, n int) (out []byte, cut bool) {
	j := b
	if json.Valid(b) {
		if x, err := redactJSON(b); err == nil {
			j = x
		}
	}
	if len(j) <= n+prefixMargin {
		out = r.redactText(j)
		if len(out) <= n {
			return out, false
		}
		return out[:n], true
	}
	out = r.redactText(j[:n+prefixMargin])
	return out[:max(0, min(n, len(out)-prefixGuard))], true
}

// redactText redacts pairs and gitleaks secrets. It always returns a new
// slice.
func (r *Redactor) redactText(b []byte) []byte {
	out := redactPairs(b)
	if r != nil && r.D != nil {
		for _, s := range r.D.secrets(string(out)) {
			out = bytes.ReplaceAll(out, []byte(s), []byte(Redacted))
		}
	}
	return out
}

// redactPairs replaces the value of each name/value pair whose name is
// sensitive. A pair with another name is skipped from the end of its name
// only, so that a pair inside its value ("url=https://x/?token=...") is
// still found. It always returns a new slice.
func redactPairs(b []byte) []byte {
	out := make([]byte, 0, len(b))
	last, pos := 0, 0
	for pos < len(b) {
		m := pairRE.FindSubmatchIndex(b[pos:])
		if m == nil {
			break
		}
		if !SensitiveName(string(b[pos+m[2] : pos+m[3]])) {
			pos += m[3]
			continue
		}
		vs, ve := pos+m[6], pos+m[7]
		out = append(out, b[last:vs]...)
		out = append(out, Redacted...)
		last, pos = ve, ve
	}
	return append(out, b[last:]...)
}

// Scrub returns a copy of b in which every occurrence of each literal is
// replaced by "[redacted]". Longer literals are replaced first, so that a
// literal that contains another is replaced whole. Empty literals are
// ignored. The probe passes the credential values and the extracted values
// of a run, in each of their encodings.
func Scrub(b []byte, literals [][]byte) []byte {
	ls := make([][]byte, 0, len(literals))
	for _, l := range literals {
		if len(l) > 0 {
			ls = append(ls, l)
		}
	}
	sort.SliceStable(ls, func(i, j int) bool { return len(ls[i]) > len(ls[j]) })
	out := bytes.Clone(b)
	if out == nil {
		out = []byte{}
	}
	for _, l := range ls {
		if bytes.Contains(out, l) {
			out = bytes.ReplaceAll(out, l, []byte(Redacted))
		}
	}
	return out
}

// redactJSON rewrites one JSON document with the values of sensitive
// fields replaced, keeping key order. The input must be valid JSON.
func redactJSON(b []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var buf bytes.Buffer
	buf.Grow(len(b))
	if err := copyJSON(dec, &buf, false); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return buf.Bytes(), nil
}

var errJSON = errors.New("unexpected JSON token")

// copyJSON copies the next value from dec to w, or writes "[redacted]" in
// its place when redact is set.
func copyJSON(dec *json.Decoder, w *bytes.Buffer, redact bool) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok && redact {
		if d != '{' && d != '[' {
			return errJSON
		}
		if err := skipJSON(dec); err != nil {
			return err
		}
		writeJSONString(w, Redacted)
		return nil
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			w.WriteByte('{')
			for i := 0; dec.More(); i++ {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok {
					return errJSON
				}
				if i > 0 {
					w.WriteByte(',')
				}
				writeJSONString(w, key)
				w.WriteByte(':')
				if err := copyJSON(dec, w, SensitiveName(key)); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			w.WriteByte('}')
		case '[':
			w.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					w.WriteByte(',')
				}
				if err := copyJSON(dec, w, false); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			w.WriteByte(']')
		default:
			return errJSON
		}
	case string:
		if redact {
			t = Redacted
		}
		writeJSONString(w, t)
	case json.Number:
		if redact {
			writeJSONString(w, Redacted)
		} else {
			w.WriteString(t.String())
		}
	case bool:
		switch {
		case redact:
			writeJSONString(w, Redacted)
		case t:
			w.WriteString("true")
		default:
			w.WriteString("false")
		}
	case nil:
		if redact {
			writeJSONString(w, Redacted)
		} else {
			w.WriteString("null")
		}
	default:
		return errJSON
	}
	return nil
}

// skipJSON consumes the rest of an object or array whose opening delimiter
// was just read.
func skipJSON(dec *json.Decoder) error {
	for depth := 1; depth > 0; {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// writeJSONString writes s as a JSON string, without HTML escaping, so that
// the text stays as the server sent it and literals still match.
func writeJSONString(w *bytes.Buffer, s string) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	w.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}
