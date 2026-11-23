package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Headers that carry credentials. A request to a host outside the
// credential's bound hosts never carries them.
var credentialHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie"}

// Header names a credential of kind "header" may not use.
var reservedCredHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "Keep-Alive": true, "Proxy-Connection": true,
	"Content-Type": true,
}

// maxTokenResponse is how much of an OAuth2 token response is read.
const maxTokenResponse = 64 << 10

// minExtractLiteral is the shortest extracted value that is scrubbed from
// excerpts: shorter ones (an id such as "42") are not secrets, and
// scrubbing them would garble every excerpt.
const minExtractLiteral = 4

// minLeakLiteral is the shortest credential form the leak checks look for
// in requests, responses and extracted values. Shorter forms would refuse
// ordinary traffic; they are still scrubbed from reports.
const minLeakLiteral = 6

// minFoldLiteral is the shortest credential form that is also looked for
// in lower-cased text. Shorter secrets are matched in their own case only,
// so that a short password such as "monitor" does not match "Monitoring".
const minFoldLiteral = 8

// credential is one RunCredential prepared for the run.
type credential struct {
	c        *spec.RunCredential
	bound    hostallow.List
	boundErr error  // a bound host did not parse: the credential is refused
	header   string // canonical name of the header it sets
	// lits are this credential's secret values in all their forms: the
	// secret, the basic or OAuth2 client pair, and the OAuth2 token once
	// fetched. They must not reach a host outside the bound hosts, and a
	// response that echoes one gives no extracts. The basic user name and
	// the OAuth2 client id are not among them (they are not secret and
	// appear in ordinary URLs and responses); they are only scrubbed from
	// reports.
	lits *literals

	mu       sync.Mutex
	token    *spec.Secret // OAuth2 access token, for this run only
	tokenErr error
}

// credSet holds the run's credentials and the literals to scrub.
type credSet struct {
	byID map[uuid.UUID]*credential
	lits *literals
}

func newCredSet(creds []spec.RunCredential) *credSet {
	cs := &credSet{byID: map[uuid.UUID]*credential{}, lits: &literals{}}
	for i := range creds {
		c := &creds[i]
		cr := &credential{c: c, header: "Authorization", lits: &literals{}}
		cr.bound, cr.boundErr = boundList(c.BoundHosts)
		if c.Kind == spec.CredHeader {
			cr.header = textproto.CanonicalMIMEHeaderKey(c.HeaderName)
		}
		cs.byID[c.ID] = cr
		cs.lits.addSecret(c.Username.Bytes())
		cs.addCredLiteral(cr, c.Secret.Bytes())
		switch c.Kind {
		case spec.CredBasic:
			pair := joinPair(c.Username.Bytes(), c.Secret.Bytes())
			cs.addCredLiteral(cr, pair)
			clear(pair)
		case spec.CredOAuth2:
			id, sec := formEscape(c.Username.Bytes()), formEscape(c.Secret.Bytes())
			pair := joinPair(id, sec)
			cs.addCredLiteral(cr, pair)
			clear(pair)
			clear(id)
			clear(sec)
		}
	}
	return cs
}

// addCredLiteral adds a value of credential cr, in all its forms, to the
// credential's own literals and to the run's scrub literals.
func (cs *credSet) addCredLiteral(cr *credential, b []byte) {
	cr.lits.addSecret(b)
	cs.lits.addSecret(b)
}

// holdsCredential reports whether b carries a secret form of a
// credential of the run (see foundIn).
func (cs *credSet) holdsCredential(b []byte) bool {
	texts := matchTexts(b)
	for _, c := range cs.byID {
		if c.foundIn(texts) {
			return true
		}
	}
	return false
}

// foundIn reports whether one of texts carries a secret form of c: as it
// is, and, for forms of minFoldLiteral bytes or more, lower-cased.
func (c *credential) foundIn(texts [][]byte) bool {
	lits := c.lits.all()
	for _, t := range texts {
		var lt []byte
		for _, l := range lits {
			if len(l) < minLeakLiteral {
				continue
			}
			if bytes.Contains(t, l) {
				return true
			}
			if len(l) >= minFoldLiteral {
				if lt == nil {
					lt = bytes.ToLower(t)
				}
				if bytes.Contains(lt, l) {
					return true
				}
			}
		}
	}
	return false
}

// matchTexts returns b and b with its escapes decoded (once and twice):
// JSON \uXXXX (either case), \/, \\ and \", and percent-encoding. A server
// that writes the credential through an encoder still echoes it.
func matchTexts(b []byte) [][]byte {
	out := [][]byte{b}
	d := b
	for range 2 {
		n := decodeEscapes(d)
		if bytes.Equal(n, d) {
			break
		}
		out = append(out, n)
		d = n
	}
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeEscapes decodes the escapes matchTexts names; anything else is
// copied as it is.
func decodeEscapes(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '%' && i+2 < len(b):
			h, ok1 := unhex(b[i+1])
			l, ok2 := unhex(b[i+2])
			if ok1 && ok2 {
				out = append(out, h<<4|l)
				i += 2
				continue
			}
		case c == '\\' && i+1 < len(b):
			switch b[i+1] {
			case '/', '\\', '"':
				out = append(out, b[i+1])
				i++
				continue
			case 'u', 'U':
				if i+5 < len(b) {
					var r rune
					ok := true
					for _, x := range b[i+2 : i+6] {
						v, k := unhex(x)
						ok = ok && k
						r = r<<4 | rune(v)
					}
					if ok && !utf16.IsSurrogate(r) {
						out = utf8.AppendRune(out, r)
						i += 5
						continue
					}
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// checkTaint refuses sending tainted variables (ruling P11) to host unless
// it is within the bound hosts of every credential of the taint.
func (cs *credSet) checkTaint(host string, t spec.Taint) error {
	for _, id := range t.IDs() {
		c := cs.byID[id]
		if c == nil || c.boundErr != nil || host == "" || !c.allows(host) {
			return errorf(CodeCredentialError, "the request uses a variable from a step with credential %s, and its host is not one of that credential's bound hosts", id)
		}
	}
	return nil
}

// boundTaint is the taint of a response from hosts (ruling P12): every
// credential of the run whose bound hosts cover one of them. A credential
// whose bound hosts did not parse is never attached, so it taints nothing.
func (cs *credSet) boundTaint(hosts []string) spec.Taint {
	t := spec.Taint{}
	for id, c := range cs.byID {
		if c.boundErr != nil {
			continue
		}
		for _, h := range hosts {
			if h != "" && c.allows(h) {
				t[id] = true
				break
			}
		}
	}
	return t
}

// echoes reports whether a response's headers or body carry a secret form
// of a credential of the run. Ruling P10: no extract is taken from such a
// response, since an extract (or several, piece by piece) could carry the
// credential to another host (§6.2: credentials never go into extracted
// variables).
func (cs *credSet) echoes(h http.Header, body []byte) bool {
	if len(cs.byID) == 0 {
		return false
	}
	if cs.holdsCredential(body) {
		return true
	}
	for name, vals := range h {
		for _, v := range vals {
			if cs.holdsCredential([]byte(name + ": " + v)) {
				return true
			}
		}
	}
	return false
}

// checkRequest refuses a request that would carry a credential of the run
// (in its URL, its headers or its body) to a host outside that
// credential's bound hosts. It runs before every request and redirect hop,
// before the hop's host is resolved, and for the OAuth2 token request.
func (cs *credSet) checkRequest(req *http.Request) error {
	host, err := hostallow.Normalize(req.URL.Hostname())
	if err != nil {
		host = ""
	}
	var hay [][]byte
	built := false
	build := func() error {
		u := req.URL.String()
		hay = append(hay, []byte(u), []byte(req.URL.Path), []byte(req.Host))
		if q, err := url.QueryUnescape(req.URL.RawQuery); err == nil {
			hay = append(hay, []byte(q))
		}
		for name, vals := range req.Header {
			for _, v := range vals {
				hay = append(hay, []byte(name+": "+v))
			}
		}
		if req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return errorf(CodeCredentialError, "the request body cannot be checked for credentials")
			}
			rc, err := req.GetBody()
			if err != nil {
				return errorf(CodeCredentialError, "the request body cannot be checked for credentials")
			}
			b, err := io.ReadAll(io.LimitReader(rc, spec.MaxBody+1))
			_ = rc.Close()
			if err != nil {
				return errorf(CodeCredentialError, "the request body cannot be checked for credentials")
			}
			hay = append(hay, b)
		}
		return nil
	}
	for _, c := range cs.byID {
		if host != "" && c.boundErr == nil && c.allows(host) {
			continue
		}
		lits := c.lits.all()
		if len(lits) == 0 {
			continue
		}
		if !built {
			if err := build(); err != nil {
				return err
			}
			built = true
		}
		for _, h := range hay {
			if c.foundIn(matchTexts(h)) {
				return errorf(CodeCredentialError, "a request to a host outside the bound hosts of credential %s would carry it", c.c.ID)
			}
		}
	}
	return nil
}

// checkTransport runs checkRequest before every request it sends.
type checkTransport struct {
	base http.RoundTripper
	cs   *credSet
}

func (t *checkTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.cs.checkRequest(req); err != nil {
		closeBody(req)
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// close zeroes the OAuth2 tokens and every literal. The RunCredentials
// themselves belong to the caller (spec.ZeroCredentials).
func (cs *credSet) close() {
	for _, c := range cs.byID {
		c.mu.Lock()
		c.token.Zero()
		c.token = nil
		c.mu.Unlock()
		c.lits.zero()
	}
	cs.lits.zero()
}

func (cs *credSet) get(id *uuid.UUID) (*credential, error) {
	if id == nil {
		return nil, nil
	}
	c, ok := cs.byID[*id]
	if !ok {
		return nil, errorf(CodeCredentialError, "credential %s was not sent with the run", *id)
	}
	if c.boundErr != nil {
		return nil, c.boundErr
	}
	return c, nil
}

// boundList parses a credential's bound hosts (hostallow.FormatRule
// form) into a list matched with the allowlist rules: a suffix bound
// includes its apex, a wildcard bound does not. A bound that does not
// parse, or no bound at all, refuses the credential: it fails closed.
func boundList(hosts []string) (hostallow.List, error) {
	l := hostallow.List{}
	if len(hosts) == 0 {
		return l, errorf(CodeCredentialError, "the credential has no bound hosts")
	}
	for i, h := range hosts {
		r, err := hostallow.ParseRule(h)
		if err != nil {
			return hostallow.List{}, errorf(CodeCredentialError, "bound host %d of the credential is not a valid rule", i)
		}
		l.Rules = append(l.Rules, r)
	}
	return l, nil
}

// allows reports whether the credential may be sent to host.
func (c *credential) allows(host string) bool {
	_, ok := c.bound.Match(host)
	return ok
}

// headerValue returns the header the credential sets. The value is a
// string because http.Header holds strings; it lives as long as the
// request. OAuth2 tokens are fetched on first use, through d.
func (c *credential) headerValue(ctx context.Context, r *Runner, cs *credSet) (string, string, error) {
	switch c.c.Kind {
	case spec.CredBearer:
		s := c.c.Secret.Bytes()
		if len(s) == 0 || !validHeaderBytes(s) {
			return "", "", errorf(CodeCredentialError, "the bearer token is empty or not a valid header value")
		}
		return "Authorization", "Bearer " + string(s), nil
	case spec.CredBasic:
		v, err := basicValue(c.c.Username.Bytes(), c.c.Secret.Bytes())
		if err != nil {
			return "", "", err
		}
		return "Authorization", v, nil
	case spec.CredHeader:
		s := c.c.Secret.Bytes()
		if !validHeaderName(c.header) || reservedCredHeaders[c.header] {
			return "", "", errorf(CodeCredentialError, "header name %q cannot carry a credential", c.c.HeaderName)
		}
		if len(s) == 0 || !validHeaderBytes(s) {
			return "", "", errorf(CodeCredentialError, "the header value is empty or not valid")
		}
		return c.header, string(s), nil
	case spec.CredOAuth2:
		tok, err := c.oauthToken(ctx, r, cs)
		if err != nil {
			return "", "", err
		}
		return "Authorization", "Bearer " + string(tok.Bytes()), nil
	}
	return "", "", errorf(CodeCredentialError, "unknown credential kind %q", c.c.Kind)
}

// oauthToken fetches the run's OAuth2 token once (client credentials grant,
// RFC 6749 §4.4, with client_secret_basic) from TokenURL, which must be
// within the bound hosts, must be https, and is dialed through the run's
// Dialer. The token is zeroed when the run ends.
func (c *credential) oauthToken(ctx context.Context, r *Runner, cs *credSet) (*spec.Secret, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil || c.tokenErr != nil {
		return c.token, c.tokenErr
	}
	c.token, c.tokenErr = c.fetchToken(ctx, r, cs)
	if c.token != nil {
		cs.addCredLiteral(c, c.token.Bytes())
	}
	return c.token, c.tokenErr
}

func (c *credential) fetchToken(ctx context.Context, r *Runner, cs *credSet) (*spec.Secret, error) {
	u, err := url.Parse(c.c.TokenURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		// The client secret is sent to it: plain http is refused.
		return nil, errorf(CodeCredentialError, "the token URL is not a valid https URL")
	}
	if !c.allows(u.Hostname()) {
		return nil, errorf(CodeCredentialError, "the token URL's host is not one of the credential's bound hosts")
	}
	form := "grant_type=client_credentials"
	if c.c.Scopes != "" {
		form += "&scope=" + url.QueryEscape(c.c.Scopes)
	}
	id, sec := formEscape(c.c.Username.Bytes()), formEscape(c.c.Secret.Bytes())
	auth, err := basicValue(id, sec)
	clear(id)
	clear(sec)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form))
	if err != nil {
		return nil, errorf(CodeCredentialError, "the token request could not be built")
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	sess := newSession(r.Dialer)
	tr := r.transport(sess)
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: &checkTransport{base: tr, cs: cs},
		// A token endpoint that redirects is refused: the client
		// credentials would follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		e := classify(ctx, err)
		return nil, errorf(CodeCredentialError, "fetching the OAuth2 token: %s", e.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	defer clear(body)
	if err != nil {
		return nil, errorf(CodeCredentialError, "reading the OAuth2 token response")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errorf(CodeCredentialError, "the token endpoint answered %d", resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "" && mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return nil, errorf(CodeCredentialError, "the token response is not JSON")
	}
	var tr2 struct {
		AccessToken json.RawMessage `json:"access_token"`
		TokenType   string          `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tr2); err != nil {
		return nil, errorf(CodeCredentialError, "the token response is not valid JSON")
	}
	if tt := strings.ToLower(tr2.TokenType); tt != "" && tt != "bearer" {
		return nil, errorf(CodeCredentialError, "token type %q is not supported", tr2.TokenType)
	}
	tok := rawJSONString(tr2.AccessToken)
	if len(tok) == 0 || !validHeaderBytes(tok) {
		clear(tok)
		return nil, errorf(CodeCredentialError, "the token response has no valid access_token")
	}
	return spec.NewSecret(tok), nil
}

// rawJSONString returns a copy of the content of a JSON string without
// escapes, so that the token is held only in buffers that can be zeroed. A
// string with escapes is decoded (an access token rarely has any).
func rawJSONString(raw json.RawMessage) []byte {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil
	}
	inner := raw[1 : len(raw)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		return bytes.Clone(inner)
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	return []byte(s)
}

// basicValue returns "Basic base64(user:pass)". The intermediate buffers
// are zeroed.
func basicValue(user, pass []byte) (string, error) {
	if bytes.IndexByte(user, ':') >= 0 {
		return "", errorf(CodeCredentialError, "a basic user name cannot contain \":\"")
	}
	pair := joinPair(user, pass)
	defer clear(pair)
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(pair)))
	defer clear(enc)
	base64.StdEncoding.Encode(enc, pair)
	return "Basic " + string(enc), nil
}

func joinPair(user, pass []byte) []byte {
	pair := make([]byte, 0, len(user)+1+len(pass))
	pair = append(pair, user...)
	pair = append(pair, ':')
	return append(pair, pass...)
}

// validHeaderBytes reports whether b is a valid header value: no control
// characters other than tab (so no CR, LF or NUL).
func validHeaderBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

func validHeaderName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

// credTransport attaches a step's credential to the requests whose host is
// in its bound hosts, and removes credential headers from every other
// request (a redirect to another host included).
type credTransport struct {
	base http.RoundTripper
	r    *Runner
	cred *credential // nil when the step has none
	cs   *credSet
	// taint is that of the variables the step's request uses (P11).
	taint spec.Taint
	// ctx is the run's context, without the step's trace, for the OAuth2
	// token request.
	ctx context.Context
	// origHost and origScheme are those of the step's first request.
	origHost   string
	origScheme string

	mu    sync.Mutex
	hosts []string // the hosts of the requests sent, every hop included
}

// sentHosts returns the hosts of the requests the transport sent.
func (t *credTransport) sentHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.hosts...)
}

func (t *credTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A RoundTripper must not change the request it is given.
	req = req.Clone(req.Context())
	host, _ := hostallow.Normalize(req.URL.Hostname())
	strip := func() {
		for _, h := range credentialHeaders {
			req.Header.Del(h)
		}
		if t.cred != nil {
			req.Header.Del(t.cred.header)
		}
	}
	if host != t.origHost {
		// The previous URL may carry an extracted value in its query.
		req.Header.Del("Referer")
	}
	if err := t.cs.checkTaint(host, t.taint); err != nil {
		closeBody(req)
		return nil, err
	}
	if err := t.cs.checkRequest(req); err != nil {
		closeBody(req)
		return nil, err
	}
	switch {
	case t.cred != nil:
		downgrade := t.origScheme == "https" && req.URL.Scheme != "https"
		if host == "" || !t.cred.allows(host) || downgrade {
			strip()
			break
		}
		name, value, err := t.cred.headerValue(t.ctx, t.r, t.cs)
		if err != nil {
			closeBody(req)
			return nil, err
		}
		req.Header.Set(name, value)
	case host != t.origHost:
		// No credential, but the step's own headers may carry one (an
		// extracted token): it stays with the step's host.
		strip()
	}
	t.mu.Lock()
	t.hosts = append(t.hosts, host)
	t.mu.Unlock()
	return t.base.RoundTrip(req)
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// transport is the HTTP transport of one step attempt: no proxy (the
// environment is ignored), one connection per request, every connection
// through the session's checks, and TLS verified against the system roots.
func (r *Runner) transport(sess *session) *http.Transport {
	cfg := &tls.Config{RootCAs: r.rootCAs}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            sess.dial,
		DisableKeepAlives:      true,
		TLSClientConfig:        cfg,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      false,
	}
}

// literals are the byte strings scrubbed from everything a run reports:
// each credential value and extracted value in its raw, base64, URL- and
// JSON-escaped forms. Every buffer is owned here and zeroed by zero.
type literals struct {
	mu   sync.Mutex
	bufs [][]byte
}

// addSecret adds b in all its forms. b is copied.
func (l *literals) addSecret(b []byte) {
	if len(b) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range forms(b) {
		dup := false
		for _, have := range l.bufs {
			if bytes.Equal(have, f) {
				dup = true
				break
			}
		}
		if dup {
			clear(f)
			continue
		}
		l.bufs = append(l.bufs, f)
	}
}

// addExtracted adds an extracted value unless it is too short to be a
// secret.
func (l *literals) addExtracted(v string) {
	if len(v) >= minExtractLiteral {
		l.addSecret([]byte(v))
	}
}

// all returns the current literals. The slices are shared: do not change
// them.
func (l *literals) all() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]byte(nil), l.bufs...)
}

func (l *literals) zero() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range l.bufs {
		clear(b)
	}
	l.bufs = nil
}

// minShiftedBase64 is the fewest bytes of a value whose base64 inner
// forms are scrubbed: shorter ones give strings of under 8 characters.
const minShiftedBase64 = 6

// forms returns fresh copies of b: raw and lower case (a host name is
// lowered before it is shown), base64 (standard and URL, with and without
// padding), the stable inner part of its base64 at each of the three
// offsets it can have inside a longer encoded text (such as
// base64("Bearer " + token)), percent-encoded (query and path style, upper
// and lower case hex) and
// JSON-escaped (with and without "\/" and HTML escapes).
func forms(b []byte) [][]byte {
	out := [][]byte{bytes.Clone(b), bytes.ToLower(b)}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		e := make([]byte, enc.EncodedLen(len(b)))
		enc.Encode(e, b)
		out = append(out, e)
	}
	// At offset k (mod 3) in the encoded text, b's bytes from the next
	// 3-byte boundary on are encoded on their own, in whole groups; the
	// first and last groups mix in the neighbouring bytes.
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for off := 0; off < 3; off++ {
			start := (3 - off) % 3
			n := (len(b) - start) / 3 * 3
			if n < minShiftedBase64 {
				continue
			}
			e := make([]byte, enc.EncodedLen(n))
			enc.Encode(e, b[start:start+n])
			out = append(out, e)
		}
	}
	for _, hex := range []string{upperHex, lowerHex} {
		out = append(out, percentEscape(b, true, hex), percentEscape(b, false, hex))
	}
	for _, slash := range []bool{false, true} {
		for _, html := range []bool{false, true} {
			out = append(out, jsonEscape(b, slash, html))
		}
	}
	return out
}

const (
	upperHex = "0123456789ABCDEF"
	lowerHex = "0123456789abcdef" // encoding/json writes \u escapes in lower case
)

func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~'
}

// formEscape is url.QueryEscape into a fresh []byte (space as "+").
func formEscape(b []byte) []byte { return percentEscape(b, true, upperHex) }

// percentEscape percent-encodes every byte that is not unreserved, with
// the hex digits given (servers echo either case); form style writes a
// space as "+".
func percentEscape(b []byte, form bool, hex string) []byte {
	out := make([]byte, 0, len(b)*3)
	for _, c := range b {
		switch {
		case unreserved(c):
			out = append(out, c)
		case c == ' ' && form:
			out = append(out, '+')
		default:
			out = append(out, '%', hex[c>>4], hex[c&15])
		}
	}
	return out
}

// jsonEscape writes b as the inside of a JSON string.
func jsonEscape(b []byte, slash, html bool) []byte {
	out := make([]byte, 0, len(b)+8)
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			out = append(out, '\\', c)
		case c == '/' && slash:
			out = append(out, '\\', '/')
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c == '\t':
			out = append(out, '\\', 't')
		case c < 0x20 || html && (c == '<' || c == '>' || c == '&'):
			out = append(out, '\\', 'u', '0', '0', lowerHex[c>>4], lowerHex[c&15])
		default:
			out = append(out, c)
		}
	}
	return out
}
