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
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Headers a step may not set (as spec.Validate refuses them). Host would
// pick another virtual host behind an allowed address.
var reservedStepHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "Keep-Alive": true, "Proxy-Connection": true,
}

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
	u, err := url.Parse(spec.Substitute(tmpl, vars))
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
		body = strings.NewReader(spec.Substitute(h.Body, rs.vars))
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
			base: tr, r: r, cred: cred, lits: rs.creds.lits, ctx: ctx,
			origHost: origHost, origScheme: strings.ToLower(u.Scheme),
		},
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			return checkRedirect(sess, h.FollowRedirects, next, via)
		},
	}

	o := &outcome{timings: &pb.StepTimings{}}
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
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		f.hasTLS = true
		f.tlsDaysLeft = daysLeft(resp.TLS.PeerCertificates[0].NotAfter, r.now())
	}
	o.names, o.extracted, err = extract(st.Extracts, f)
	if rs.s.StoreResponses {
		var red []byte
		red, o.excerptCut = f.redactedBody()
		o.excerpt = r.httpExcerpt(resp, red, credHeaders)
	}
	o.assertions, o.actualCut = r.evaluate(st, f)
	o.finish()
	if err != nil && o.status == StatusPassed {
		o.status, o.err = StatusFailed, classify(ctx, err)
	}
	return o
}

// checkRedirect runs every redirect hop through the same checks as the
// first request: the host must normalize and match the allowlist, and it
// is resolved once (the session pins the answer for the dial) with every
// answer checked. At most spec.MaxRedirects redirects are followed.
func checkRedirect(sess *session, follow bool, next *http.Request, via []*http.Request) error {
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
	if _, _, err := sess.resolve(next.Context(), next.URL.Hostname()); err != nil {
		if e, ok := err.(*Error); ok && e.Code == CodeHostNotAllowed {
			return errorf(CodeRedirectBlocked, "redirect to a host that is not allowed: %s", e.Msg)
		}
		return err
	}
	return nil
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
