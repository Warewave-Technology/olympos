// Package ingest serves the S3-compatible endpoint ClickHouse writes native
// backups to.
package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// Credential is one access key and its secret.
type Credential struct {
	AccessKey, Secret string
}

// Errors returned by Verify. The handler maps each to an S3 error code.
var (
	// ErrNoSigV4 means the request has no header-based SigV4 signature
	// (no Authorization header, another scheme, or a presigned URL).
	ErrNoSigV4 = errors.New("ingest: request is not signed with AWS4-HMAC-SHA256")
	// ErrUnknownKey means the access key is not known.
	ErrUnknownKey = errors.New("ingest: unknown access key")
	// ErrSignature means the signature does not match, or the Authorization
	// header or a signed header is malformed.
	ErrSignature = errors.New("ingest: signature does not match")
	// ErrClockSkew means the request date is too far from the server's clock.
	ErrClockSkew = errors.New("ingest: request time is outside the allowed clock skew")
	// ErrUnsignedPayload means x-amz-content-sha256 is missing or is not the
	// hex SHA-256 of the body (UNSIGNED-PAYLOAD, aws-chunked).
	ErrUnsignedPayload = errors.New("ingest: payload hash is not a signed SHA-256")
)

const (
	algorithm   = "AWS4-HMAC-SHA256"
	maxSkew     = 15 * time.Minute
	amzDateForm = "20060102T150405Z"
	dateForm    = "20060102"
	service     = "s3"
	scopeEnd    = "aws4_request"
	hexUpper    = "0123456789ABCDEF"
)

// Verify checks the header-based SigV4 signature of r against the secret that
// lookup returns for the request's access key. It returns the access key and
// the payload hash the client declared in x-amz-content-sha256 (lower-case
// hex). It does not read the body: the caller compares the body with the
// returned hash while it streams.
//
// Any region in the credential scope is accepted, but the service must be s3.
// host, x-amz-date and x-amz-content-sha256 must be signed. The payload must
// carry a real SHA-256, so UNSIGNED-PAYLOAD and the STREAMING-* values are
// refused.
func Verify(r *http.Request, lookup func(accessKey string) (secret string, ok bool), now time.Time) (accessKey, payloadHash string, err error) {
	auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), algorithm+" ")
	if !ok {
		return "", "", ErrNoSigV4
	}
	cred, signedHeaders, signature, err := parseAuthorization(auth)
	if err != nil {
		return "", "", err
	}
	// Credential=<key>/<date>/<region>/s3/aws4_request
	scope := strings.Split(cred, "/")
	if len(scope) != 5 || scope[0] == "" || scope[3] != service || scope[4] != scopeEnd {
		return "", "", ErrSignature
	}
	accessKey, date, region := scope[0], scope[1], scope[2]

	secret, ok := lookup(accessKey)
	if !ok {
		return "", "", ErrUnknownKey
	}

	reqTime, err := time.Parse(amzDateForm, r.Header.Get("X-Amz-Date"))
	if err != nil || reqTime.Format(dateForm) != date {
		return "", "", ErrSignature
	}
	if d := now.Sub(reqTime); d > maxSkew || d < -maxSkew {
		return "", "", ErrClockSkew
	}

	payloadHash = r.Header.Get("X-Amz-Content-Sha256")
	if !isLowerHexSHA256(payloadHash) {
		return "", "", ErrUnsignedPayload
	}
	for _, h := range []string{"host", "x-amz-date", "x-amz-content-sha256"} {
		if !slices.Contains(signedHeaders, h) {
			return "", "", ErrSignature
		}
	}

	canonical, err := canonicalRequest(r, signedHeaders, payloadHash)
	if err != nil {
		return "", "", err
	}
	canonicalSum := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		algorithm,
		r.Header.Get("X-Amz-Date"),
		strings.Join([]string{date, region, service, scopeEnd}, "/"),
		hex.EncodeToString(canonicalSum[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+secret), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, scopeEnd)
	want := hmacSHA256(key, stringToSign)

	got, err := hex.DecodeString(signature)
	if err != nil || !hmac.Equal(got, want) {
		return "", "", ErrSignature
	}
	return accessKey, payloadHash, nil
}

// parseAuthorization splits the part of the Authorization header after the
// algorithm: "Credential=..., SignedHeaders=a;b, Signature=...".
func parseAuthorization(s string) (cred string, signedHeaders []string, signature string, err error) {
	var signed string
	for _, part := range strings.Split(s, ",") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "", nil, "", ErrSignature
		}
		switch name {
		case "Credential":
			cred = val
		case "SignedHeaders":
			signed = val
		case "Signature":
			signature = val
		}
	}
	if cred == "" || signed == "" || signature == "" {
		return "", nil, "", ErrSignature
	}
	return cred, strings.Split(signed, ";"), signature, nil
}

// canonicalRequest builds the SigV4 canonical request for r from the headers
// the client signed.
func canonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) (string, error) {
	query, err := canonicalQuery(r.URL.RawQuery)
	if err != nil {
		return "", err
	}
	var headers strings.Builder
	for _, name := range signedHeaders {
		var val string
		if name == "host" {
			// net/http moves Host out of the header map.
			val = r.Host
		} else {
			vals, ok := r.Header[http.CanonicalHeaderKey(name)]
			if !ok {
				return "", ErrSignature
			}
			trimmed := make([]string, len(vals))
			for i, v := range vals {
				trimmed[i] = strings.Join(strings.Fields(v), " ")
			}
			val = strings.Join(trimmed, ",")
		}
		headers.WriteString(name + ":" + val + "\n")
	}
	return strings.Join([]string{
		r.Method,
		canonicalPath(r.URL.Path),
		query,
		headers.String(),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n"), nil
}

// canonicalPath encodes each segment of the decoded path once. S3 does not
// encode twice, unlike the other AWS services.
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery encodes the query parameters and sorts them by name, then by
// value. A parameter without a value (?uploads) becomes "uploads=".
func canonicalQuery(raw string) (string, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", ErrSignature
	}
	var pairs []string
	for name, vals := range values {
		for _, v := range vals {
			pairs = append(pairs, uriEncode(name)+"="+uriEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&"), nil
}

// uriEncode percent-encodes everything but the RFC 3986 unreserved set
// (A-Z a-z 0-9 - _ . ~), with upper-case hex.
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&15])
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func isLowerHexSHA256(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
