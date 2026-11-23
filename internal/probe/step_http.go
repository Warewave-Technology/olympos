package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Headers a step may not set (as spec.Validate refuses them). Host would
// pick another virtual host behind an allowed address. Accept-Encoding
// would make the transport hand back the body still compressed, where
// redaction cannot see a credential. Range and If-Range would let steps
// take a response apart slice by slice.
var reservedStepHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "Keep-Alive": true, "Proxy-Connection": true,
	"Accept-Encoding": true, "Range": true, "If-Range": true,
}

// Size limits once the variables are substituted: a template within the
// limits of spec.Validate can still grow with each ${var}.
const (
	maxURLLen       = 8 << 10
	maxHeaderLen    = 8 << 10
	maxHeadersTotal = 32 << 10
)

// varRef matches a ${name} reference, as spec.Substitute reads it.
var varRef = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]{0,63}\}`)

// buildURL substitutes the step's variables into its URL and checks that
// the scheme, host and port are still those of the template. spec.Validate
// already refuses variables in them; this holds even if it did not.
func buildURL(tmpl string, vars map[string]string) (*url.URL, error) {
	t, err := url.Parse(varRef.ReplaceAllString(tmpl, "x"))
	if err != nil || t.Host == "" || t.Opaque != "" {
		return nil, errorf(CodeInvalidRequest, "the URL is not valid")
	}
	raw := spec.Substitute(tmpl, vars)
	if len(raw) > maxURLLen {
		return nil, errorf(CodeInvalidRequest, "the URL is longer than %d bytes once its variables are substituted", maxURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errorf(CodeInvalidRequest, "the URL is not valid once its variables are substituted")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errorf(CodeInvalidRequest, "the URL must be http:// or https://")
	}
	if scheme != strings.ToLower(t.Scheme) || !strings.EqualFold(u.Host, t.Host) || u.Opaque != "" {
		return nil, errorf(CodeInvalidRequest, "a variable changed the URL's scheme, host or port")
	}
	if u.User != nil {
		return nil, errorf(CodeInvalidRequest, "the URL must not carry a user name or password")
	}
	return u, nil
}

// stepHeaders substitutes the variables into the step's headers and
// refuses values that would split the request.
func stepHeaders(h map[string]string, vars map[string]string) (http.Header, error) {
	out := http.Header{}
	total := 0
	for name, v := range h {
		canon := textproto.CanonicalMIMEHeaderKey(name)
		if !httpguts.ValidHeaderFieldName(name) || reservedStepHeaders[canon] {
			return nil, errorf(CodeInvalidRequest, "header %q cannot be set", name)
		}
		val := spec.Substitute(v, vars)
		if strings.ContainsAny(val, "\r\n\x00") {
			return nil, errorf(CodeInvalidRequest, "header %s: the value contains CR, LF or NUL once its variables are substituted", canon)
		}
		if !httpguts.ValidHeaderFieldValue(val) {
			return nil, errorf(CodeInvalidRequest, "header %s: the value is not valid once its variables are substituted", canon)
		}
		if len(val) > maxHeaderLen {
			return nil, errorf(CodeInvalidRequest, "header %s: the value is longer than %d bytes once its variables are substituted", canon, maxHeaderLen)
		}
		if total += len(canon) + len(val); total > maxHeadersTotal {
			return nil, errorf(CodeInvalidRequest, "the headers are longer than %d bytes once their variables are substituted", maxHeadersTotal)
		}
		out.Set(canon, val)
	}
	return out, nil
}

func (r *Runner) httpStep(ctx context.Context, rs *runState, st *spec.Step) *outcome {
	h := st.HTTP
	u, err := buildURL(h.URL, rs.vars)
	if err != nil {
		return failOutcome(classify(ctx, err))
	}
	hdr, err := stepHeaders(h.Headers, rs.vars)
	if err != nil {
		return failOutcome(classify(ctx, err))
	}
	cred, err := rs.creds.get(st.CredentialID)
	if err != nil {
		return failOutcome(classify(ctx, err))
	}
	var credHeaders []string
	if cred != nil {
		credHeaders = []string{cred.header}
	}
	// Ruling P11: the variables this request uses carry the taint of the
	// steps they come from; the request may only go where every credential
	// of that taint is bound. The step's own extracts inherit it, plus the
	// step's credential.
	used := spec.Taint{}
	for _, n := range spec.StepVars(st) {
		used.Add(rs.taint[n])
	}
	o := &outcome{timings: &pb.StepTimings{}, taint: spec.Taint{}}
	o.taint.Add(used)
	if st.CredentialID != nil {
		o.taint[*st.CredentialID] = true
	}
	origHost, err := hostallow.Normalize(u.Hostname())
	if err != nil {
		// The dialer refuses it with the right code.
		origHost = ""
	}

	method := h.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if h.Body != "" {
		b := spec.Substitute(h.Body, rs.vars)
		if len(b) > spec.MaxBody {
			return failOutcome(errorf(CodeInvalidRequest, "the body is longer than %d bytes once its variables are substituted", spec.MaxBody))
		}
		body = strings.NewReader(b)
	}

	sess := newSession(r.Dialer)
	// The trace hooks run on the transport's goroutines.
	var (
		traceMu   sync.Mutex
		tlsDur    time.Duration
		tlsStart  time.Time
		firstByte time.Time
	)
	start := time.Now()
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			traceMu.Lock()
			tlsStart = time.Now()
			traceMu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			traceMu.Lock()
			if !tlsStart.IsZero() {
				tlsDur += time.Since(tlsStart)
			}
			traceMu.Unlock()
		},
		GotFirstResponseByte: func() {
			traceMu.Lock()
			firstByte = time.Now()
			traceMu.Unlock()
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, u.String(), body)
	if err != nil {
		return failOutcome(errorf(CodeInvalidRequest, "the request could not be built"))
	}
	req.Header = hdr
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if h.Body != "" && h.BodyType == spec.BodyJSON && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	tr := r.transport(sess)
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: &credTransport{
			base: tr, r: r, cred: cred, cs: rs.creds, ctx: ctx, taint: used,
			origHost: origHost, origScheme: strings.ToLower(u.Scheme),
		},
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			return checkRedirect(sess, rs.creds, used, h.FollowRedirects, next, via)
		},
	}

	resp, err := client.Do(req)
	defer func() {
		traceMu.Lock()
		o.timings.TlsUs = tlsDur.Microseconds()
		traceMu.Unlock()
		rs.noteSession(sess, o, start)
	}()
	if err != nil {
		e := classify(ctx, err)
		o.status, o.err = StatusError, e
		return o
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, spec.MaxResponseRead))
	_ = resp.Body.Close()
	end := time.Now()
	if readErr != nil {
		o.status, o.err = StatusError, classify(ctx, readErr)
		return o
	}
	traceMu.Lock()
	if !firstByte.IsZero() {
		o.timings.TtfbUs = firstByte.Sub(start).Microseconds()
		o.timings.DownloadUs = end.Sub(firstByte).Microseconds()
	}
	traceMu.Unlock()
	o.statusCode = resp.StatusCode

	f := &facts{
		kind:       spec.KindHTTP,
		latencyMS:  end.Sub(start).Milliseconds(),
		statusCode: resp.StatusCode,
		header:     resp.Header,
		body:       data,
		redact:     r.Redactor,
		credHeader: credHeaders,
		stored:     rs.s.StoreResponses,
		encoded:    contentEncoded(resp.Header),
	}
	if len(rs.creds.byID) > 0 {
		f.leaky = func(b []byte) bool {
			return rs.creds.holdsCredential(sensitive.Scrub(b, rs.creds.lits.all()))
		}
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		f.hasTLS = true
		f.tlsDaysLeft = daysLeft(resp.TLS.PeerCertificates[0].NotAfter, r.now())
	}
	// §6.2: a credential never goes into an extracted variable. Ruling
	// P10: a response that echoes a credential gives no extracts at all,
	// since several extracts could each take a piece of it.
	bodyExtracts := false
	for _, e := range st.Extracts {
		bodyExtracts = bodyExtracts || e.Source != spec.SourceHeader
	}
	switch {
	case bodyExtracts && (f.encoded || !isText(data)):
		// P11: a body the checks cannot read as text (encoded, binary,
		// UTF-16) gives no body extracts: it may hide an echo.
		for _, e := range st.Extracts {
			o.names = append(o.names, e.Name)
		}
		err = errorf(CodeCredentialError, "the response body is not plain text, so no body extract is kept (%s)", strings.Join(o.names, ", "))
	case len(st.Extracts) > 0 && rs.creds.echoes(resp.Header, data):
		o.names = make([]string, 0, len(st.Extracts))
		for _, e := range st.Extracts {
			o.names = append(o.names, e.Name)
		}
		err = errorf(CodeCredentialError, "the response echoes a credential, so no extract is kept (%s)", strings.Join(o.names, ", "))
	default:
		o.names, o.extracted, err = extract(st.Extracts, f)
		for _, n := range o.names {
			// A value that carries a credential the response did not
			// show as it is (decoded from JSON, for instance).
			if v, ok := o.extracted[n]; ok && rs.creds.holdsCredential([]byte(v)) {
				o.extracted = nil
				err = errorf(CodeCredentialError, "extract %s holds a credential, so no extract of the step is kept", n)
				break
			}
		}
	}
	if rs.s.StoreResponses {
		var red []byte
		red, o.excerptCut = f.redactedBody()
		o.excerpt = r.httpExcerpt(resp, red, credHeaders, f)
	}
	o.assertions, o.actualCut = r.evaluate(st, f)
	o.finish()
	switch {
	case codeOf(err) == CodeCredentialError:
		o.status, o.err = StatusError, classify(ctx, err)
	case err != nil && o.status == StatusPassed:
		o.status, o.err = StatusFailed, classify(ctx, err)
	}
	return o
}

// checkRedirect runs every redirect hop through the same checks as the
// first request: tainted variables (P11) and credentials must stay within
// their bound hosts, the host must normalize and match the allowlist, and
// it is resolved once (the session pins the answer for the dial) with
// every answer checked. At most spec.MaxRedirects redirects are followed.
func checkRedirect(sess *session, cs *credSet, taint spec.Taint, follow bool, next *http.Request, via []*http.Request) error {
	if !follow {
		return http.ErrUseLastResponse
	}
	if len(via) > spec.MaxRedirects {
		return errorf(CodeRedirectBlocked, "more than %d redirects", spec.MaxRedirects)
	}
	if s := next.URL.Scheme; s != "http" && s != "https" {
		return errorf(CodeRedirectBlocked, "redirect to a %q URL", s)
	}
	if next.URL.User != nil {
		return errorf(CodeRedirectBlocked, "redirect to a URL with a user name or password")
	}
	// Before the hop's host is resolved: the host name itself may carry a
	// credential to the resolver.
	hop, err := hostallow.Normalize(next.URL.Hostname())
	if err != nil {
		hop = ""
	}
	if err := cs.checkTaint(hop, taint); err != nil {
		return err
	}
	if err := cs.checkRequest(next); err != nil {
		return err
	}
	if _, _, err := sess.resolve(next.Context(), next.URL.Hostname()); err != nil {
		if e, ok := err.(*Error); ok && e.Code == CodeHostNotAllowed {
			return errorf(CodeRedirectBlocked, "redirect to a host that is not allowed: %s", e.Msg)
		}
		return err
	}
	return nil
}

// contentEncoded reports a response body the transport did not decode
// (Content-Encoding other than identity): redaction cannot see into it, so
// it is never shown.
func contentEncoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" && !strings.EqualFold(e, "identity") {
				return true
			}
		}
	}
	return false
}

// daysLeft is the number of whole days from now until notAfter, negative
// once it has passed.
func daysLeft(notAfter, now time.Time) int64 {
	d := notAfter.Sub(now)
	days := int64(d / (24 * time.Hour))
	if d < 0 && d%(24*time.Hour) != 0 {
		days--
	}
	return days
}
