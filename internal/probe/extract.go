package probe

import (
	"net/textproto"
	"regexp"
	"strings"

	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// maxExtractValue is the longest value an extract may take.
const maxExtractValue = 8 << 10

// extract runs the step's extracts on f. It returns the names in step
// order and the values by name. An extract that finds nothing, or a value
// that cannot be used in a later request, fails the step: the later steps
// would otherwise send "${name}" literally. The values are never reported;
// the runner scrubs them from everything it reports.
func extract(es []spec.Extract, f *facts) ([]string, map[string]string, error) {
	names := make([]string, 0, len(es))
	vals := map[string]string{}
	var firstErr error
	for _, e := range es {
		names = append(names, e.Name)
		v, ok := extractOne(e, f)
		switch {
		case !ok:
			if firstErr == nil {
				firstErr = errorf(CodeAssertionFailed, "extract %s found no value", e.Name)
			}
			continue
		case len(v) > maxExtractValue:
			if firstErr == nil {
				firstErr = errorf(CodeAssertionFailed, "extract %s: the value is longer than %d bytes", e.Name, maxExtractValue)
			}
		}
		vals[e.Name] = v
	}
	return names, vals, firstErr
}

func extractOne(e spec.Extract, f *facts) (string, bool) {
	switch e.Source {
	case spec.SourceJSONPath:
		doc, ok := f.doc()
		if !ok {
			return "", false
		}
		p, err := spec.ParseJSONPath(e.Expr)
		if err != nil {
			return "", false
		}
		v, ok := spec.LookupJSON(doc, p)
		if !ok || v == nil {
			return "", false
		}
		return jsonRepr(v), true
	case spec.SourceHeader:
		vals, ok := f.header[textproto.CanonicalMIMEHeaderKey(e.Expr)]
		if !ok || len(vals) == 0 {
			return "", false
		}
		return strings.Join(vals, ", "), true
	case spec.SourceRegex:
		re, err := regexp.Compile(e.Expr)
		if err != nil {
			return "", false
		}
		m := re.FindSubmatch(f.body)
		switch {
		case m == nil:
			return "", false
		case len(m) > 1:
			return string(m[1]), true
		default:
			return string(m[0]), true
		}
	}
	return "", false
}
