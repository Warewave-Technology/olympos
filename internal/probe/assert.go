package probe

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// absent is the actual value of a header or JSON path that is not there.
const absent = "(absent)"

// notStored is the actual value of a header, body or JSON subject when the
// scenario does not store responses.
const notStored = "(not stored)"

// encodedBody stands for a body that is still content-encoded: redaction
// cannot see into it, so it is not shown.
const encodedBody = "[body not shown: content-encoded]"

// binaryBody stands for a body that is not UTF-8 text (it may be
// compressed without saying so): redaction cannot see into it either.
func binaryBody(n int) string { return fmt.Sprintf("[binary body, %d bytes]", n) }

// isText reports whether b is UTF-8, allowing an incomplete last
// character where the read limit cut it.
func isText(b []byte) bool {
	if utf8.Valid(b) {
		return true
	}
	for i := 1; i < utf8.UTFMax && i <= len(b); i++ {
		if utf8.RuneStart(b[len(b)-i]) {
			return !utf8.FullRune(b[len(b)-i:]) && utf8.Valid(b[:len(b)-i])
		}
	}
	return false
}

// facts are what one step attempt observed, for its assertions and
// extracts.
type facts struct {
	kind      string
	latencyMS int64

	// HTTP
	statusCode  int
	header      http.Header
	body        []byte
	hasTLS      bool
	tlsDaysLeft int64
	redact      *sensitive.Redactor
	credHeader  []string
	stored      bool // the scenario stores responses
	encoded     bool // the body is still content-encoded

	jsonOnce sync.Once
	jsonDoc  any
	jsonOK   bool
	redOnce  sync.Once
	redBody  []byte
	redCut   bool

	// DNS
	records []string

	// TCP
	connects bool

	// TLS
	chainValid      bool
	hostnameMatches bool
	tlsVersion      uint16
}

// doc returns the body parsed as JSON.
func (f *facts) doc() (any, bool) {
	f.jsonOnce.Do(func() {
		d := json.NewDecoder(bytes.NewReader(f.body))
		d.UseNumber()
		if err := d.Decode(&f.jsonDoc); err == nil && !d.More() {
			f.jsonOK = true
		}
	})
	return f.jsonDoc, f.jsonOK
}

// redactedPrefix is how much of a redacted body the excerpt and body
// assertions keep: more than an excerpt holds, so that scrubbing literals
// (which shortens the text) still leaves a full excerpt.
const redactedPrefix = 32 << 10

// redactedBody returns the start of the body, redacted once (for the
// excerpt and body assertions), and whether it is cut.
func (f *facts) redactedBody() ([]byte, bool) {
	f.redOnce.Do(func() {
		switch {
		case f.encoded:
			f.redBody = []byte(encodedBody)
			return
		case !isText(f.body):
			f.redBody = []byte(binaryBody(len(f.body)))
			return
		}
		f.redBody, f.redCut = f.redact.RedactPrefix(f.body, redactedPrefix)
	})
	return f.redBody, f.redCut
}

// defaultAssertions apply to a step without assertions: an HTTP status
// below 400, at least one DNS record, a TCP connection, a TLS certificate
// that verifies for the name.
func defaultAssertions(kind string) []spec.Assertion {
	switch kind {
	case spec.KindHTTP:
		return []spec.Assertion{{Subject: spec.SubjectStatusCode, Operator: spec.OpLessThan, Value: "400"}}
	case spec.KindDNS:
		return []spec.Assertion{{Subject: spec.SubjectRecordCount, Operator: spec.OpGreaterThan, Value: "0"}}
	case spec.KindTCP:
		return []spec.Assertion{{Subject: spec.SubjectConnects, Operator: spec.OpEquals, Value: "true"}}
	case spec.KindTLS:
		return []spec.Assertion{
			{Subject: spec.SubjectChainValid, Operator: spec.OpEquals, Value: "true"},
			{Subject: spec.SubjectHostnameMatches, Operator: spec.OpEquals, Value: "true"},
		}
	}
	return nil
}

// evaluate checks the step's assertions (or the defaults) against f. The
// actual values are redacted here; the runner scrubs and cuts them. cut
// reports, per assertion, an actual value that is already cut.
func (r *Runner) evaluate(st *spec.Step, f *facts) (out []*pb.AssertionResult, cut []bool) {
	as := st.Assertions
	if len(as) == 0 {
		as = defaultAssertions(st.Kind)
	}
	out = make([]*pb.AssertionResult, 0, len(as))
	for _, a := range as {
		actual, passed := r.check(f, a)
		out = append(out, &pb.AssertionResult{
			Subject: a.Subject, Operator: a.Operator, Expected: a.Value, Actual: actual, Passed: passed,
		})
		cut = append(cut, a.Subject == spec.SubjectBody && f.redCut)
	}
	return out, cut
}

func (r *Runner) check(f *facts, a spec.Assertion) (string, bool) {
	actual, passed := r.checkSubject(f, a)
	if f.kind == spec.KindHTTP && !f.stored && responseSubject(a.Subject) {
		actual = notStored
	}
	return actual, passed
}

// responseSubject reports subjects whose actual value shows the response's
// headers or body.
func responseSubject(s string) bool {
	return s == spec.SubjectBody || strings.HasPrefix(s, spec.SubjectHeaderPrefix) || strings.HasPrefix(s, spec.SubjectJSONPrefix)
}

func (r *Runner) checkSubject(f *facts, a spec.Assertion) (string, bool) {
	switch a.Subject {
	case spec.SubjectLatencyMS:
		return strconv.FormatInt(f.latencyMS, 10), compareInt(f.latencyMS, a)
	case spec.SubjectStatusCode:
		return strconv.Itoa(f.statusCode), compareInt(int64(f.statusCode), a)
	case spec.SubjectTLSDaysLeft:
		if f.kind == spec.KindHTTP && !f.hasTLS {
			return absent, false
		}
		return strconv.FormatInt(f.tlsDaysLeft, 10), compareInt(f.tlsDaysLeft, a)
	case spec.SubjectBody:
		red, _ := f.redactedBody()
		return string(red), compareText(f.body, true, a)
	case spec.SubjectRecordCount:
		return strconv.Itoa(len(f.records)), compareInt(int64(len(f.records)), a)
	case spec.SubjectRecord:
		return f.redact.RedactValue("record", strings.Join(f.records, ", ")), checkRecords(f.records, a)
	case spec.SubjectConnects:
		return strconv.FormatBool(f.connects), compareBool(f.connects, a)
	case spec.SubjectChainValid:
		return strconv.FormatBool(f.chainValid), compareBool(f.chainValid, a)
	case spec.SubjectHostnameMatches:
		return strconv.FormatBool(f.hostnameMatches), compareBool(f.hostnameMatches, a)
	case spec.SubjectTLSVersion:
		return tlsVersionName(f.tlsVersion), compareTLSVersion(f.tlsVersion, a)
	}
	if name, ok := strings.CutPrefix(a.Subject, spec.SubjectHeaderPrefix); ok {
		return r.checkHeader(f, name, a)
	}
	if path, ok := strings.CutPrefix(a.Subject, spec.SubjectJSONPrefix); ok {
		return r.checkJSON(f, path, a)
	}
	return "", false
}

func (r *Runner) checkHeader(f *facts, name string, a spec.Assertion) (string, bool) {
	canon := textproto.CanonicalMIMEHeaderKey(name)
	vals, ok := f.header[canon]
	if !ok {
		return absent, a.Operator == spec.OpNotEquals
	}
	v := strings.Join(vals, ", ")
	if a.Operator == spec.OpExists {
		return r.headerActual(f, canon, v), true
	}
	return r.headerActual(f, canon, v), compareText([]byte(v), false, a)
}

// headerActual is a header value as an assertion reports it: redacted as
// the excerpt's headers are.
func (r *Runner) headerActual(f *facts, canon, v string) string {
	h := r.Redactor.RedactHeaders(http.Header{canon: {v}}, f.credHeader)
	return h.Get(canon)
}

func (r *Runner) checkJSON(f *facts, path string, a spec.Assertion) (string, bool) {
	doc, ok := f.doc()
	if !ok {
		return absent, false
	}
	p, err := spec.ParseJSONPath(path)
	if err != nil {
		return absent, false
	}
	v, found := spec.LookupJSON(doc, p)
	if !found {
		return absent, a.Operator == spec.OpNotEquals
	}
	repr := jsonRepr(v)
	actual := repr
	key := "value"
	for _, e := range p {
		if !e.IsIndex {
			key = e.Key
			if sensitive.SensitiveName(e.Key) {
				actual = sensitive.Redacted
			}
		}
	}
	if actual != sensitive.Redacted {
		actual = r.Redactor.RedactValue(key, repr)
	}
	switch a.Operator {
	case spec.OpExists:
		return actual, true
	case spec.OpLengthGreaterThan:
		n, err := strconv.Atoi(a.Value)
		return actual, err == nil && jsonLen(v) > n
	case spec.OpLessThan, spec.OpGreaterThan:
		num, ok := v.(json.Number)
		if !ok {
			return actual, false
		}
		x, err1 := num.Float64()
		y, err2 := strconv.ParseFloat(a.Value, 64)
		if err1 != nil || err2 != nil {
			return actual, false
		}
		if a.Operator == spec.OpLessThan {
			return actual, x < y
		}
		return actual, x > y
	case spec.OpEquals, spec.OpNotEquals:
		eq := repr == a.Value
		if num, ok := v.(json.Number); ok {
			x, err1 := num.Float64()
			y, err2 := strconv.ParseFloat(a.Value, 64)
			if err1 == nil && err2 == nil {
				eq = x == y
			}
		}
		return actual, eq == (a.Operator == spec.OpEquals)
	}
	return actual, compareText([]byte(repr), false, a)
}

// jsonRepr is a JSON value as text: strings as they are, other values as
// compact JSON.
func jsonRepr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}

// jsonLen is the length of an array or object, the characters of a
// string, or the length of another value's text.
func jsonLen(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case map[string]any:
		return len(t)
	case string:
		return utf8.RuneCountInString(t)
	}
	return len(jsonRepr(v))
}

func compareInt(actual int64, a spec.Assertion) bool {
	want, err := strconv.ParseInt(a.Value, 10, 64)
	if err != nil {
		return false
	}
	switch a.Operator {
	case spec.OpEquals:
		return actual == want
	case spec.OpNotEquals:
		return actual != want
	case spec.OpLessThan:
		return actual < want
	case spec.OpGreaterThan:
		return actual > want
	}
	return false
}

func compareBool(actual bool, a spec.Assertion) bool {
	want, err := strconv.ParseBool(a.Value)
	if err != nil || (a.Value != "true" && a.Value != "false") {
		return false
	}
	switch a.Operator {
	case spec.OpEquals:
		return actual == want
	case spec.OpNotEquals:
		return actual != want
	}
	return false
}

// compareText applies a text operator. length_greater_than counts bytes
// for a body and characters otherwise.
func compareText(actual []byte, isBody bool, a spec.Assertion) bool {
	switch a.Operator {
	case spec.OpEquals:
		return string(actual) == a.Value
	case spec.OpNotEquals:
		return string(actual) != a.Value
	case spec.OpContains:
		return bytes.Contains(actual, []byte(a.Value))
	case spec.OpMatches:
		re, err := regexp.Compile(a.Value)
		return err == nil && re.Match(actual)
	case spec.OpLengthGreaterThan:
		n, err := strconv.Atoi(a.Value)
		if err != nil {
			return false
		}
		if isBody {
			return len(actual) > n
		}
		return utf8.RuneCount(actual) > n
	case spec.OpExists:
		return true
	}
	return false
}

// checkRecords passes when any record satisfies the operator.
func checkRecords(records []string, a spec.Assertion) bool {
	for _, rec := range records {
		if compareText([]byte(rec), false, a) {
			return true
		}
	}
	return false
}

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13,
}

func tlsVersionName(v uint16) string {
	for n, x := range tlsVersions {
		if x == v {
			return n
		}
	}
	if v == 0 {
		return absent
	}
	return "0x" + strconv.FormatUint(uint64(v), 16)
}

func compareTLSVersion(actual uint16, a spec.Assertion) bool {
	want, ok := tlsVersions[a.Value]
	if !ok || actual == 0 {
		return false
	}
	switch a.Operator {
	case spec.OpEquals:
		return actual == want
	case spec.OpNotEquals:
		return actual != want
	case spec.OpLessThan:
		return actual < want
	case spec.OpGreaterThan:
		return actual > want
	}
	return false
}
