package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// tlsStep connects to host:port through the Dialer and makes a TLS
// handshake for the SNI name (Host when SNI is empty), which must also be
// on the allowlist. The handshake always verifies the certificate; when
// the verification fails, the certificates it reports are checked again
// apart (chain without the name, name without the chain), so that the
// step can tell an expired or unknown chain from a wrong name. Nothing is
// ever accepted without verification.
func (r *Runner) tlsStep(ctx context.Context, rs *runState, st *spec.Step) *outcome {
	sniHost := st.TLS.SNI
	if sniHost == "" {
		sniHost = st.TLS.Host
	}
	sni, err := r.Dialer.checkHost(sniHost)
	if err != nil {
		return failOutcome(classify(ctx, err))
	}
	sess := newSession(r.Dialer)
	start := time.Now()
	o := &outcome{}
	conn, err := sess.dial(ctx, "tcp", net.JoinHostPort(st.TLS.Host, strconv.Itoa(st.TLS.Port)))
	if err != nil {
		rs.noteSession(sess, o, start)
		o.status, o.err = StatusError, classify(ctx, err)
		return o
	}
	defer func() { _ = conn.Close() }()

	cfg := &tls.Config{
		ServerName: sni,
		RootCAs:    r.rootCAs,
		// The step measures the server: it may speak TLS 1.0. No data
		// is sent over the connection.
		MinVersion: tls.VersionTLS10,
	}
	tc := tls.Client(conn, cfg)
	hsStart := time.Now()
	hsErr := tc.HandshakeContext(ctx)
	tlsDur := time.Since(hsStart)
	rs.noteSession(sess, o, start)
	o.timings.TlsUs = tlsDur.Microseconds()

	now := r.now()
	f := &facts{kind: spec.KindTLS, redact: r.Redactor}
	var certs []*x509.Certificate
	var cve *tls.CertificateVerificationError
	switch {
	case hsErr == nil:
		state := tc.ConnectionState()
		certs = state.PeerCertificates
		f.tlsVersion = state.Version
		f.chainValid, f.hostnameMatches = true, true
	case errors.As(hsErr, &cve) && len(cve.UnverifiedCertificates) > 0:
		certs = cve.UnverifiedCertificates
		f.tlsVersion = tc.ConnectionState().Version
		f.chainValid = r.chainVerifies(certs, now)
		f.hostnameMatches = certs[0].VerifyHostname(sni) == nil
	default:
		o.status, o.err = StatusError, classify(ctx, hsErr)
		if o.err.Code == CodeConnectError {
			o.err.Code = CodeTLSError
		}
		return o
	}
	leaf := certs[0]
	f.tlsDaysLeft = daysLeft(leaf.NotAfter, now)
	f.latencyMS = time.Since(start).Milliseconds()
	if rs.s.StoreResponses {
		o.excerpt = tlsExcerpt(f, leaf)
	}
	o.assertions, o.actualCut = r.evaluate(st, f)
	o.finish()
	return o
}

// chainVerifies checks the chain against the roots at now, without the
// host name.
func (r *Runner) chainVerifies(certs []*x509.Certificate, now time.Time) bool {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         r.rootCAs,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// tlsExcerpt describes the handshake and the leaf certificate: public
// data the server sends to anyone.
func tlsExcerpt(f *facts, leaf *x509.Certificate) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "TLS %s\r\n", tlsVersionName(f.tlsVersion))
	fmt.Fprintf(&b, "subject: %s\r\n", leaf.Subject.String())
	fmt.Fprintf(&b, "issuer: %s\r\n", leaf.Issuer.String())
	if len(leaf.DNSNames) > 0 {
		fmt.Fprintf(&b, "dns names: %s\r\n", strings.Join(leaf.DNSNames, ", "))
	}
	fmt.Fprintf(&b, "not before: %s\r\n", leaf.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "not after: %s\r\n", leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "chain valid: %t\r\nhostname matches: %t\r\n", f.chainValid, f.hostnameMatches)
	return []byte(b.String())
}
