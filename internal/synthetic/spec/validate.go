package spec

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
)

// Limits on sizes the design does not fix. They keep a scenario small
// enough to store, show and send; none of them is close to what a real
// check needs.
const (
	maxName        = 200
	maxURL         = 2048
	maxHeaders     = 32
	maxHeaderValue = 4096
	maxAssertions  = 20
	maxExtracts    = 10
	maxValue       = 1024
)

var methods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true,
}

var recordTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "TXT": true}

var tlsVersions = map[string]bool{"1.0": true, "1.1": true, "1.2": true, "1.3": true}

// Headers a step may not set. Host would pick another virtual host behind
// an allowed address; the others belong to the transport.
var reservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "Keep-Alive": true, "Proxy-Connection": true,
}

// subject classes: which operators apply and what Value holds.
type subjectClass int

const (
	classNumber subjectClass = iota
	classBool
	classTLSVersion
	classHeader
	classBody
	classJSON
	classRecord
)

var classOps = map[subjectClass][]string{
	classNumber:     {OpEquals, OpNotEquals, OpLessThan, OpGreaterThan},
	classBool:       {OpEquals, OpNotEquals},
	classTLSVersion: {OpEquals, OpNotEquals, OpLessThan, OpGreaterThan},
	classHeader:     {OpEquals, OpNotEquals, OpContains, OpMatches, OpExists},
	classBody:       {OpEquals, OpNotEquals, OpContains, OpMatches, OpLengthGreaterThan},
	classJSON:       {OpEquals, OpNotEquals, OpContains, OpMatches, OpExists, OpLengthGreaterThan, OpLessThan, OpGreaterThan},
	classRecord:     {OpEquals, OpContains, OpMatches},
}

var knownOps = map[string]bool{
	OpEquals: true, OpNotEquals: true, OpContains: true, OpMatches: true,
	OpLessThan: true, OpGreaterThan: true, OpExists: true, OpLengthGreaterThan: true,
}

// kindSubjects lists the fixed subjects of each step kind; HTTP steps also
// take header:<Name> and json:<path>.
var kindSubjects = map[string]map[string]subjectClass{
	KindHTTP: {
		SubjectStatusCode: classNumber, SubjectLatencyMS: classNumber,
		SubjectBody: classBody, SubjectTLSDaysLeft: classNumber,
	},
	KindDNS: {
		SubjectRecordCount: classNumber, SubjectRecord: classRecord, SubjectLatencyMS: classNumber,
	},
	KindTCP: {
		SubjectConnects: classBool, SubjectLatencyMS: classNumber,
	},
	KindTLS: {
		SubjectTLSDaysLeft: classNumber, SubjectChainValid: classBool, SubjectHostnameMatches: classBool,
		SubjectTLSVersion: classTLSVersion, SubjectLatencyMS: classNumber,
	},
}

// typeKind is the one step kind of each single-step scenario type.
var typeKind = map[string]string{TypeHTTP: KindHTTP, TypeDNS: KindDNS, TypeTCP: KindTCP, TypeTLS: KindTLS}

// Validate checks a scenario against the model and its limits. It returns
// one message per invalid field, keyed by the field's JSON path
// ("interval_seconds", "steps.2.http.url", "steps.0.assertions.1.value"),
// and an empty map when the scenario is valid.
//
// Hosts are checked with hostallow.Normalize only: IP literals, localhost
// and the Kubernetes API names are refused here, while matching against the
// allowlist is left to the caller.
func Validate(s *Scenario) map[string]string {
	f := map[string]string{}
	if s == nil {
		f["scenario"] = "required"
		return f
	}

	name := strings.TrimSpace(s.Name)
	switch {
	case name == "":
		f["name"] = "required"
	case utf8.RuneCountInString(s.Name) > maxName || !utf8.ValidString(s.Name):
		f["name"] = fmt.Sprintf("at most %d characters of valid UTF-8", maxName)
	}

	single, singleOK := typeKind[s.Type]
	if s.Type != TypeHTTPFlow && !singleOK {
		f["type"] = "must be http_flow, http, dns, tcp or tls"
	}

	minInterval := int(MinInterval / time.Second)
	maxTimeout := int(MaxRunTimeout / time.Second)
	if s.IntervalSeconds < minInterval {
		f["interval_seconds"] = fmt.Sprintf("at least %d", minInterval)
	}
	switch {
	case s.TimeoutSeconds < 1 || s.TimeoutSeconds > maxTimeout:
		f["timeout_seconds"] = fmt.Sprintf("between 1 and %d", maxTimeout)
	case s.TimeoutSeconds > s.IntervalSeconds && s.IntervalSeconds >= minInterval:
		f["timeout_seconds"] = "at most the interval: the timeout is the deadline of the whole run"
	}
	if s.StepRetries < 0 || s.StepRetries > MaxStepRetries {
		f["step_retries"] = fmt.Sprintf("between 0 and %d", MaxStepRetries)
	}

	switch {
	case len(s.Steps) == 0:
		f["steps"] = "at least one step"
	case len(s.Steps) > MaxSteps:
		f["steps"] = fmt.Sprintf("at most %d steps", MaxSteps)
	case singleOK && len(s.Steps) != 1:
		f["steps"] = fmt.Sprintf("a %s scenario has exactly one step", s.Type)
	}

	// Variables become usable after the step that extracts them.
	defined := map[string]bool{}
	for i := range s.Steps {
		if i >= MaxSteps {
			break
		}
		st := &s.Steps[i]
		p := fmt.Sprintf("steps.%d", i)
		if st.Position != i {
			f[p+".position"] = fmt.Sprintf("must be %d: positions follow the order of the steps, from 0", i)
		}
		if singleOK && st.Kind != single {
			f[p+".kind"] = fmt.Sprintf("must be %s in a %s scenario", single, s.Type)
		}
		validateStep(f, p, st, defined)
		for _, e := range st.Extracts {
			if validVarName(e.Name) {
				defined[e.Name] = true
			}
		}
	}
	return f
}

func validateStep(f map[string]string, p string, st *Step, defined map[string]bool) {
	set := 0
	for _, b := range []bool{st.DNS != nil, st.HTTP != nil, st.TCP != nil, st.TLS != nil} {
		if b {
			set++
		}
	}
	var present bool
	switch st.Kind {
	case KindHTTP:
		present = st.HTTP != nil
		if present {
			validateHTTP(f, p+".http", st.HTTP, defined)
		}
	case KindDNS:
		present = st.DNS != nil
		if present {
			validateHost(f, p+".dns.name", st.DNS.Name)
			if !recordTypes[st.DNS.RecordType] {
				f[p+".dns.record_type"] = "must be A, AAAA, CNAME or TXT"
			}
		}
	case KindTCP:
		present = st.TCP != nil
		if present {
			validateHost(f, p+".tcp.host", st.TCP.Host)
			validatePort(f, p+".tcp.port", st.TCP.Port)
		}
	case KindTLS:
		present = st.TLS != nil
		if present {
			validateHost(f, p+".tls.host", st.TLS.Host)
			validatePort(f, p+".tls.port", st.TLS.Port)
			if st.TLS.SNI != "" {
				validateHost(f, p+".tls.sni", st.TLS.SNI)
			}
		}
	default:
		f[p+".kind"] = "must be dns, http, tcp or tls"
		return
	}
	switch {
	case !present:
		f[p+"."+st.Kind] = "required for a " + st.Kind + " step"
	case set > 1:
		f[p] = "only the " + st.Kind + " settings may be set on a " + st.Kind + " step"
	}

	if st.CredentialID != nil && st.Kind != KindHTTP {
		f[p+".credential_id"] = "only HTTP steps use a credential"
	}

	if len(st.Assertions) > maxAssertions {
		f[p+".assertions"] = fmt.Sprintf("at most %d assertions", maxAssertions)
	}
	for j, a := range st.Assertions {
		if j >= maxAssertions {
			break
		}
		validateAssertion(f, fmt.Sprintf("%s.assertions.%d", p, j), st, a)
	}

	if len(st.Extracts) > 0 && st.Kind != KindHTTP {
		f[p+".extracts"] = "only HTTP steps extract values"
		return
	}
	if len(st.Extracts) > maxExtracts {
		f[p+".extracts"] = fmt.Sprintf("at most %d extracts", maxExtracts)
	}
	here := map[string]bool{}
	for j, e := range st.Extracts {
		if j >= maxExtracts {
			break
		}
		validateExtract(f, fmt.Sprintf("%s.extracts.%d", p, j), e, defined, here)
		here[e.Name] = true
	}
}

// validateHost checks a host field: no variables, and a name that
// hostallow.Normalize accepts.
func validateHost(f map[string]string, key, h string) {
	if h == "" {
		f[key] = "required"
		return
	}
	if strings.Contains(h, "${") {
		f[key] = "variables are not allowed in a host"
		return
	}
	if _, err := hostallow.Normalize(h); err != nil {
		f[key] = hostMessage(err)
	}
}

func hostMessage(err error) string {
	switch {
	case errors.Is(err, hostallow.ErrIPLiteral):
		return "IP addresses are not allowed; use a host name"
	case errors.Is(err, hostallow.ErrDeniedName):
		return "localhost and the Kubernetes API are always denied"
	default:
		return "not a valid host name"
	}
}

func validatePort(f map[string]string, key string, port int) {
	if port < 1 || port > 65535 {
		f[key] = "between 1 and 65535"
	}
}

func validateHTTP(f map[string]string, p string, h *HTTPSpec, defined map[string]bool) {
	if !methods[h.Method] {
		f[p+".method"] = "must be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS"
	}
	if msg := validateURL(h.URL, defined); msg != "" {
		f[p+".url"] = msg
	}

	if len(h.Headers) > maxHeaders {
		f[p+".headers"] = fmt.Sprintf("at most %d headers", maxHeaders)
	}
	// In name order, so that the same input always reports the same field.
	seen := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(h.Headers)) {
		value := h.Headers[name]
		key := p + ".headers." + name
		canon := textproto.CanonicalMIMEHeaderKey(name)
		switch {
		case !httpguts.ValidHeaderFieldName(name):
			f[key] = "not a valid header name"
		case reservedHeaders[canon]:
			f[key] = canon + " is set by the probe"
		case seen[canon] != "":
			f[key] = "the same header as " + seen[canon]
		case len(value) > maxHeaderValue:
			f[key] = fmt.Sprintf("at most %d bytes", maxHeaderValue)
		case !httpguts.ValidHeaderFieldValue(value):
			f[key] = "not a valid header value"
		default:
			if msg := checkVars(value, defined); msg != "" {
				f[key] = msg
			}
		}
		if seen[canon] == "" {
			seen[canon] = name
		}
	}

	switch h.BodyType {
	case "", BodyText, BodyJSON:
	default:
		f[p+".body_type"] = "must be text or json"
	}
	switch {
	case h.Body == "":
	case len(h.Body) > MaxBody:
		f[p+".body"] = fmt.Sprintf("at most %d bytes", MaxBody)
	case h.Method == "GET" || h.Method == "HEAD":
		f[p+".body"] = "a " + h.Method + " request has no body"
	default:
		if msg := checkVars(h.Body, defined); msg != "" {
			f[p+".body"] = msg
		} else if h.BodyType == BodyJSON && !strings.Contains(h.Body, "${") && !json.Valid([]byte(h.Body)) {
			f[p+".body"] = "not valid JSON"
		}
	}
}

// validateURL checks an HTTP step's URL and returns a message, or "".
func validateURL(raw string, defined map[string]bool) string {
	if raw == "" {
		return "required"
	}
	if len(raw) > maxURL {
		return fmt.Sprintf("at most %d characters", maxURL)
	}
	if !utf8.ValidString(raw) {
		return "not valid UTF-8"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return "must not contain spaces or control characters; percent-encode them"
		}
	}
	if !strings.Contains(raw, "://") {
		return "must be an absolute http:// or https:// URL"
	}
	if authorityHasVar(raw) {
		return "variables are not allowed in the scheme, host or port"
	}
	if msg := checkVars(raw, defined); msg != "" {
		return msg
	}
	u, ok := parseURL(raw)
	if !ok {
		return "not a valid URL"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "must be an absolute http:// or https:// URL"
	}
	if u.User != nil {
		return "must not contain a user name or password; use a credential"
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "port must be between 1 and 65535"
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "port must be between 1 and 65535"
	}
	if u.Hostname() == "" {
		return "must name a host"
	}
	if _, err := hostallow.Normalize(u.Hostname()); err != nil {
		return hostMessage(err)
	}
	return ""
}

// authorityHasVar reports whether "${" occurs in the scheme or authority
// of raw: anywhere before the first "/", "?" or "#" after "://", or
// anywhere at all when raw has no "://".
func authorityHasVar(raw string) bool {
	sep := strings.Index(raw, "://")
	if sep < 0 {
		return strings.Contains(raw, "${")
	}
	end := len(raw)
	if i := strings.IndexAny(raw[sep+3:], "/?#"); i >= 0 {
		end = sep + 3 + i
	}
	return strings.Contains(raw[:end], "${")
}

// parseURL parses an HTTP step's URL, with its variables replaced by a
// placeholder. It fails for an opaque or relative URL, for one with an
// invalid "${", and for one whose scheme or authority contains a variable,
// so the host it returns is always the literal one.
func parseURL(raw string) (*url.URL, bool) {
	if _, ok := varRefs(raw); !ok || authorityHasVar(raw) {
		return nil, false
	}
	u, err := url.Parse(placeholderVars(raw))
	if err != nil || u.Opaque != "" || u.Host == "" {
		return nil, false
	}
	return u, true
}

// checkVars returns a message when s refers to a variable that no earlier
// step extracts, or has a "${" that is not a reference, and "" otherwise.
func checkVars(s string, defined map[string]bool) string {
	names, ok := varRefs(s)
	if !ok {
		return `"${" must start a variable such as ${token}`
	}
	for _, n := range names {
		if !defined[n] {
			return fmt.Sprintf("${%s} is not extracted by an earlier step", n)
		}
	}
	return ""
}

func validateAssertion(f map[string]string, p string, st *Step, a Assertion) {
	class, ok := subjectClassOf(st, a.Subject)
	if !ok {
		if msg := subjectError(st, a.Subject); msg != "" {
			f[p+".subject"] = msg
		}
		return
	}
	if !knownOps[a.Operator] {
		f[p+".operator"] = "unknown operator"
		return
	}
	allowed := false
	for _, op := range classOps[class] {
		if op == a.Operator {
			allowed = true
			break
		}
	}
	if !allowed {
		f[p+".operator"] = fmt.Sprintf("%s does not apply to %s; use one of %s",
			a.Operator, a.Subject, strings.Join(classOps[class], ", "))
		return
	}
	if msg := checkValue(class, a.Operator, a.Value); msg != "" {
		f[p+".value"] = msg
	}
}

// subjectClassOf returns the class of subject on step st's kind.
func subjectClassOf(st *Step, subject string) (subjectClass, bool) {
	if c, ok := kindSubjects[st.Kind][subject]; ok {
		if subject == SubjectTLSDaysLeft && st.Kind == KindHTTP &&
			(st.HTTP == nil || !strings.HasPrefix(strings.ToLower(st.HTTP.URL), "https://")) {
			return 0, false
		}
		return c, true
	}
	if st.Kind != KindHTTP {
		return 0, false
	}
	if name, ok := strings.CutPrefix(subject, SubjectHeaderPrefix); ok && httpguts.ValidHeaderFieldName(name) {
		return classHeader, true
	}
	if path, ok := strings.CutPrefix(subject, SubjectJSONPrefix); ok {
		if _, err := ParseJSONPath(path); err == nil {
			return classJSON, true
		}
	}
	return 0, false
}

// subjectError explains why subject is not valid on st, or returns "" when
// the step kind itself is invalid (already reported).
func subjectError(st *Step, subject string) string {
	if _, ok := kindSubjects[st.Kind]; !ok {
		return ""
	}
	switch {
	case subject == SubjectTLSDaysLeft && st.Kind == KindHTTP:
		return "tls_days_left needs an https:// URL"
	case strings.HasPrefix(subject, SubjectHeaderPrefix) && st.Kind == KindHTTP:
		return "not a valid header name"
	case strings.HasPrefix(subject, SubjectJSONPrefix) && st.Kind == KindHTTP:
		return "not a valid JSON path"
	}
	return "unknown subject for a " + st.Kind + " step"
}

func checkValue(class subjectClass, op, v string) string {
	if len(v) > maxValue {
		return fmt.Sprintf("at most %d bytes", maxValue)
	}
	switch op {
	case OpExists:
		if v != "" {
			return "must be empty for exists"
		}
		return ""
	case OpLengthGreaterThan:
		if n, err := strconv.Atoi(v); err != nil || n < 0 {
			return "must be a whole number, 0 or more"
		}
		return ""
	case OpMatches:
		if v == "" {
			return "required"
		}
		if _, err := regexp.Compile(v); err != nil {
			return "not a valid regular expression (RE2)"
		}
		return ""
	case OpContains:
		if v == "" {
			return "required"
		}
	}
	switch class {
	case classNumber:
		if !isNumber(v) {
			return "must be a number"
		}
	case classBool:
		if v != "true" && v != "false" {
			return "must be true or false"
		}
	case classTLSVersion:
		if !tlsVersions[v] {
			return "must be 1.0, 1.1, 1.2 or 1.3"
		}
	case classJSON:
		if (op == OpLessThan || op == OpGreaterThan) && !isNumber(v) {
			return "must be a number"
		}
	}
	return ""
}

func isNumber(v string) bool {
	n, err := strconv.ParseFloat(v, 64)
	return err == nil && !math.IsInf(n, 0) && !math.IsNaN(n)
}

func validateExtract(f map[string]string, p string, e Extract, defined, here map[string]bool) {
	switch {
	case !validVarName(e.Name):
		f[p+".name"] = "a letter or _, then letters, digits or _, at most 64 characters"
	case defined[e.Name]:
		f[p+".name"] = "already extracted by an earlier step"
	case here[e.Name]:
		f[p+".name"] = "already extracted by this step"
	}
	switch e.Source {
	case SourceJSONPath:
		if _, err := ParseJSONPath(e.Expr); err != nil {
			f[p+".expr"] = "not a valid JSON path"
		}
	case SourceHeader:
		if !httpguts.ValidHeaderFieldName(e.Expr) {
			f[p+".expr"] = "not a valid header name"
		}
	case SourceRegex:
		if e.Expr == "" || len(e.Expr) > maxValue {
			f[p+".expr"] = fmt.Sprintf("required, at most %d bytes", maxValue)
		} else if _, err := regexp.Compile(e.Expr); err != nil {
			f[p+".expr"] = "not a valid regular expression (RE2)"
		}
	default:
		f[p+".source"] = "must be json_path, header or regex"
	}
}
