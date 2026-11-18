// Package targettls builds the TLS configuration the server uses when it
// speaks TLS end-to-end with a target through the tunnel (SPEC §7). It never
// disables verification.
package targettls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
)

var (
	mu     sync.RWMutex
	bundle string
	pool   *x509.CertPool
)

// SetCABundleFile configures extra trusted CAs (call once at startup).
func SetCABundleFile(path string) error {
	mu.Lock()
	defer mu.Unlock()
	bundle, pool = path, nil
	if path == "" {
		return nil
	}
	_, err := rootsLocked()
	return err
}

func rootsLocked() (*x509.CertPool, error) {
	if pool != nil {
		return pool, nil
	}
	p, err := x509.SystemCertPool()
	if err != nil || p == nil {
		p = x509.NewCertPool()
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
	pool = p
	return p, nil
}

// RootCAs returns the system pool plus the configured bundle.
func RootCAs() *x509.CertPool {
	mu.Lock()
	defer mu.Unlock()
	p, err := rootsLocked()
	if err != nil {
		sp, _ := x509.SystemCertPool()
		return sp
	}
	return p
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
