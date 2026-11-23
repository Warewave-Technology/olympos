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

// credential is one RunCredential prepared for the run.
type credential struct {
	c      *spec.RunCredential
	bound  hostallow.List
	header string // canonical name of the header it sets

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
		cr := &credential{c: c, bound: boundList(c.BoundHosts), header: "Authorization"}
		if c.Kind == spec.CredHeader {
			cr.header = textproto.CanonicalMIMEHeaderKey(c.HeaderName)
		}
		cs.byID[c.ID] = cr
		cs.lits.addSecret(c.Username.Bytes())
		cs.lits.addSecret(c.Secret.Bytes())
		switch c.Kind {
		case spec.CredBasic:
			pair := joinPair(c.Username.Bytes(), c.Secret.Bytes())
			cs.lits.addSecret(pair)
			clear(pair)
		case spec.CredOAuth2:
			id, sec := formEscape(c.Username.Bytes()), formEscape(c.Secret.Bytes())
			pair := joinPair(id, sec)
			cs.lits.addSecret(pair)
			clear(pair)
			clear(id)
			clear(sec)
		}
	}
	return cs
}

// close zeroes the OAuth2 tokens and every literal. The RunCredentials
// themselves belong to the caller (spec.ZeroCredentials).
func (cs *credSet) close() {
	for _, c := range cs.byID {
		c.mu.Lock()
		c.token.Zero()
		c.token = nil
		c.mu.Unlock()
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
	return c, nil
}

// boundList turns bound host patterns into a list: "*.example.com" is a
// wildcard rule, anything else an exact rule. Patterns that do not
// validate match nothing.
func boundList(hosts []string) hostallow.List {
	l := hostallow.List{}
	for _, h := range hosts {
		k := hostallow.Exact
		if strings.HasPrefix(h, "*.") {
			k = hostallow.Wildcard
		}
		l.Rules = append(l.Rules, hostallow.Rule{Pattern: h, Kind: k})
	}
	return l
}

// allows reports whether the credential may be sent to host.
func (c *credential) allows(host string) bool {
	_, ok := c.bound.Match(host)
	return ok
}

// headerValue returns the header the credential sets. The value is a
// string because http.Header holds strings; it lives as long as the
// request. OAuth2 tokens are fetched on first use, through d.
func (c *credential) headerValue(ctx context.Context, r *Runner, lits *literals) (string, string, error) {
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
		tok, err := c.oauthToken(ctx, r, lits)
		if err != nil {
			return "", "", err
		}
		return "Authorization", "Bearer " + string(tok.Bytes()), nil
	}
	return "", "", errorf(CodeCredentialError, "unknown credential kind %q", c.c.Kind)
}

// oauthToken fetches the run's OAuth2 token once (client credentials grant,
// RFC 6749 §4.4, with client_secret_basic) from TokenURL, which must be
// within the bound hosts and is dialed through the run's Dialer. The token
// is zeroed when the run ends.
func (c *credential) oauthToken(ctx context.Context, r *Runner, lits *literals) (*spec.Secret, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil || c.tokenErr != nil {
		return c.token, c.tokenErr
	}
	c.token, c.tokenErr = c.fetchToken(ctx, r)
	if c.token != nil {
		lits.addSecret(c.token.Bytes())
	}
	return c.token, c.tokenErr
}

func (c *credential) fetchToken(ctx context.Context, r *Runner) (*spec.Secret, error) {
	u, err := url.Parse(c.c.TokenURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, errorf(CodeCredentialError, "the token URL is not a valid http(s) URL")
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
		Transport: tr,
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
	lits *literals
	// ctx is the run's context, without the step's trace, for the OAuth2
	// token request.
	ctx context.Context
	// origHost and origScheme are those of the step's first request.
	origHost   string
	origScheme string
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
	switch {
	case t.cred != nil:
		downgrade := t.origScheme == "https" && req.URL.Scheme != "https"
		if host == "" || !t.cred.allows(host) || downgrade {
			strip()
			break
		}
		name, value, err := t.cred.headerValue(t.ctx, t.r, t.lits)
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

// forms returns fresh copies of b: raw, base64 (standard and URL, with and
// without padding), percent-encoded (query and path style) and
// JSON-escaped (with and without "\/" and HTML escapes).
func forms(b []byte) [][]byte {
	out := [][]byte{bytes.Clone(b)}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		e := make([]byte, enc.EncodedLen(len(b)))
		enc.Encode(e, b)
		out = append(out, e)
	}
	out = append(out, formEscape(b), pathEscape(b))
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
func formEscape(b []byte) []byte {
	out := make([]byte, 0, len(b)*3)
	for _, c := range b {
		switch {
		case unreserved(c):
			out = append(out, c)
		case c == ' ':
			out = append(out, '+')
		default:
			out = append(out, '%', upperHex[c>>4], upperHex[c&15])
		}
	}
	return out
}

// pathEscape percent-encodes every byte that is not unreserved.
func pathEscape(b []byte) []byte {
	out := make([]byte, 0, len(b)*3)
	for _, c := range b {
		if unreserved(c) {
			out = append(out, c)
		} else {
			out = append(out, '%', upperHex[c>>4], upperHex[c&15])
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
