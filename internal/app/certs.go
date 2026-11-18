package app

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// certFile is a key pair loaded from files and reloaded on SIGHUP (F16:
// certificates are renewed without a restart).
type certFile struct {
	certPath, keyPath string

	mu   sync.RWMutex
	cert *tls.Certificate
}

func loadCertFile(certPath, keyPath string) (*certFile, error) {
	c := &certFile{certPath: certPath, keyPath: keyPath}
	return c, c.reload()
}

func (c *certFile) reload() error {
	kp, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", c.certPath, err)
	}
	c.mu.Lock()
	c.cert = &kp
	c.mu.Unlock()
	return nil
}

func (c *certFile) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}
