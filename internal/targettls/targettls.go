// Package targettls builds the TLS configuration the server uses when it
// speaks TLS end-to-end with a target through the tunnel (SPEC §7). It never
// disables verification.
//
// Targets are in-cluster Services whose TLS name comes from an annotation,
// so public CAs are not trusted for them by default (security review #1:
// anyone with a public certificate for a name they own could otherwise pose
// as a target). Only the configured bundle is, unless systemRoots is set.
package targettls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
)

var (
	mu          sync.RWMutex
	bundle      string
	systemRoots bool
	pools       = map[bool]*x509.CertPool{}
)

// ErrNoRoots means no CA is trusted for targets.
var ErrNoRoots = errors.New("no CA is trusted for targets: set targetTLS.caBundleFile (PEM with the CAs that issue your targets' certificates), " +
	"a per-target CA, or targetTLS.systemRoots: true")

// Configure sets the extra trusted CAs and whether the system pool is
// trusted for targets (call once at startup).
func Configure(bundleFile string, trustSystem bool) error {
	mu.Lock()
	defer mu.Unlock()
	bundle, systemRoots, pools = bundleFile, trustSystem, map[bool]*x509.CertPool{}
	if bundleFile == "" {
		return nil
	}
	_, err := poolLocked(true)
	return err
}

func poolLocked(system bool) (*x509.CertPool, error) {
	if p := pools[system]; p != nil {
		return p, nil
	}
	p := x509.NewCertPool()
	if system {
		if sp, err := x509.SystemCertPool(); err == nil && sp != nil {
			p = sp
		}
	}
	if bundle != "" {
		b, err := os.ReadFile(bundle)
		if err != nil {
			return nil, fmt.Errorf("read target CA bundle: %w", err)
		}
		if !p.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("target CA bundle %s has no certificates", bundle)
		}
	}
	pools[system] = p
	return p, nil
}

// Roots returns the CAs trusted for a target: the configured bundle, plus
// the system pool when targetTLS.systemRoots is set or trustSystem is true
// (targets an admin configured by hand, such as Olympos' own database).
func Roots(trustSystem bool) *x509.CertPool {
	mu.Lock()
	defer mu.Unlock()
	p, err := poolLocked(trustSystem || systemRoots)
	if err != nil {
		return x509.NewCertPool()
	}
	return p
}

// RootCAs returns the CAs trusted for cluster targets.
func RootCAs() *x509.CertPool { return Roots(false) }

// Usable reports ErrNoRoots when nothing would verify a target and no
// per-target CA is given.
func Usable(trustSystem, perTargetCA bool) error {
	mu.RLock()
	defer mu.RUnlock()
	if perTargetCA || trustSystem || systemRoots || bundle != "" {
		return nil
	}
	return ErrNoRoots
}

// SystemRoots reports whether the system pool is trusted for cluster targets.
func SystemRoots() bool {
	mu.RLock()
	defer mu.RUnlock()
	return systemRoots
}

// Config returns a client TLS config verifying serverName.
func Config(serverName string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: RootCAs()}
}

// BundleFile returns the configured bundle path ("" if none), for external
// tools such as pg_dump (sslrootcert).
func BundleFile() string {
	mu.RLock()
	defer mu.RUnlock()
	return bundle
}
