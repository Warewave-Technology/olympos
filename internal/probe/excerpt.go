package probe

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"unicode/utf8"

	"github.com/Warewave-Technology/olympos/internal/sensitive"
)

// httpExcerpt is the excerpt of a response before it is scrubbed and cut:
// the status line, the redacted headers in name order, an empty line and
// the redacted body. Everything is redacted here, before any truncation,
// so that a secret cannot be cut where its pattern no longer matches.
func (r *Runner) httpExcerpt(resp *http.Response, redactedBody []byte, credHeaders []string) []byte {
	var b bytes.Buffer
	b.WriteString(resp.Proto)
	b.WriteByte(' ')
	b.WriteString(resp.Status)
	b.WriteString("\r\n")
	h := r.Redactor.RedactHeaders(resp.Header, credHeaders)
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, v := range h[n] {
			b.WriteString(n)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(redactedBody)
	return b.Bytes()
}

// finalize scrubs b of every literal and cuts it to max bytes (at a UTF-8
// boundary). It reports whether it cut. Everything known is scrubbed
// before the cut, so the cut cannot leave part of a known literal; a tail
// that starts one is removed all the same.
func finalize(b []byte, lits [][]byte, max int) ([]byte, bool) {
	out := sensitive.Scrub(b, lits)
	if len(out) <= max {
		return out, false
	}
	return trimLiteralTail(cutUTF8(out, max), lits), true
}

// finalizeCut is finalize for a value that may already have been cut
// before it was scrubbed (wasCut): then a tail that is the start of a
// literal is removed even when finalize does not cut again. It reports
// whether the value is cut now or was before.
func finalizeCut(b []byte, wasCut bool, lits [][]byte, max int) ([]byte, bool) {
	out, cut := finalize(b, lits, max)
	if wasCut && !cut {
		out = trimLiteralTail(out, lits)
	}
	return out, cut || wasCut
}

// refinalize scrubs an already finalized value again, with literals that
// may have become known after it was cut: the first half of a literal cut
// before it was known must not stay.
func refinalize(b []byte, wasCut bool, lits [][]byte, max int) []byte {
	out, _ := finalizeCut(b, wasCut, lits, max)
	return out
}

// cutUTF8 returns at most max bytes of b, without splitting a UTF-8
// sequence.
func cutUTF8(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	cut := max
	for cut > 0 && cut > max-utf8.UTFMax && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}

// trimLiteralTail removes the longest tail of b that is a proper prefix of
// one of lits.
func trimLiteralTail(b []byte, lits [][]byte) []byte {
	cut := len(b)
	for _, l := range lits {
		if len(l) < 2 {
			continue
		}
		// Tails of b shorter than l, longest first.
		from := max(len(b)-(len(l)-1), 0)
		for i := from; i < len(b); i++ {
			if b[i] == l[0] && bytes.HasPrefix(l, b[i:]) {
				cut = min(cut, i)
				break
			}
		}
	}
	return b[:cut]
}

// isTLSError reports whether err comes from the TLS handshake or the
// certificate check.
func isTLSError(err error) bool {
	var (
		rh  tls.RecordHeaderError
		ae  tls.AlertError
		cve *tls.CertificateVerificationError
		ua  x509.UnknownAuthorityError
		he  x509.HostnameError
		ci  x509.CertificateInvalidError
	)
	return errors.As(err, &rh) || errors.As(err, &ae) || errors.As(err, &cve) ||
		errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci)
}

// innerMessage is err's message without the URL that url.Error adds (it
// may hold an extracted value in its path or query).
func innerMessage(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}
