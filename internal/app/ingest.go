package app

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/metrics"
)

// ingestServer is the S3 endpoint of native ClickHouse backups. The handler
// ends a failed or revoked stream by panicking with http.ErrAbortHandler so
// the client sees a broken transfer, never a truncated success: nothing may
// wrap it in a recover. The server sets no read or write timeout (a part
// takes as long as ClickHouse needs); the sessions bound a run.
//
// With an http ingest.url it serves plain HTTP (lab use, inside a trusted
// network). The returned certFile (nil for the internal-CA certificate) is
// reloaded on SIGHUP, and unregister takes the endpoint's metrics off /metrics.
func (d *Deps) ingestServer() (srv *http.Server, cf *certFile, unregister func(), err error) {
	var tlsCfg *tls.Config // nil: an http ingest.url serves plain HTTP
	if d.Cfg.IngestTLS() {
		if tlsCfg, cf, err = d.ingestTLS(); err != nil {
			return nil, nil, nil, err
		}
	}
	m := ingest.NewMetrics()
	if err := metrics.Registry.Register(m); err != nil {
		return nil, nil, nil, err
	}
	h := ingest.NewHandler(d.Ingest, d.Log.With("component", "ingest"), m, ingest.WithSpillDir(d.Cfg.Ingest.SpillDir))
	srv = &http.Server{Addr: d.Cfg.Listen.Ingest, Handler: h, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
	return srv, cf, func() { metrics.Registry.Unregister(m) }, nil
}

// ingestTLS is the ingest endpoint's TLS config: the certificate files when
// set (reloaded on SIGHUP), else a certificate of the internal CA for the
// host of ingest.url. Clients (ClickHouse) authenticate with SigV4, not a
// client certificate.
func (d *Deps) ingestTLS() (*tls.Config, *certFile, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.Cfg.Ingest.TLSCertFile != "" {
		cf, err := loadCertFile(d.Cfg.Ingest.TLSCertFile, d.Cfg.Ingest.TLSKeyFile)
		if err != nil {
			return nil, nil, err
		}
		c.GetCertificate = cf.get
		return c, cf, nil
	}
	get, err := d.internalServerCert("ingest", []string{d.Cfg.IngestHost()}, certValidity)
	if err != nil {
		return nil, nil, err
	}
	c.GetCertificate = get
	return c, nil, nil
}

// certValidity is the validity of the server certificates the internal CA
// issues for the gateway and the ingest endpoint.
const certValidity = 90 * 24 * time.Hour

// renewBefore is how long before expiry such a certificate is re-issued.
const renewBefore = 30 * 24 * time.Hour

// internalServerCert issues a certificate of the internal CA for hosts, valid
// for validity, and re-issues it when it has less than renewBefore left (a
// systemd service can run longer than that). what names the listener in the
// log.
func (d *Deps) internalServerCert(what string, hosts []string, validity time.Duration) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	var mu sync.Mutex
	var cur *tls.Certificate
	issue := func() error {
		der, key, err := d.CA.IssueServerCert(hosts, validity)
		if err != nil {
			return err
		}
		leaf, _ := x509.ParseCertificate(der)
		cur = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
		d.Log.Info("issued "+what+" certificate from internal CA", "hosts", hosts, "not_after", leaf.NotAfter)
		return nil
	}
	if err := issue(); err != nil {
		return nil, err
	}
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Until(cur.Leaf.NotAfter) < renewBefore {
			if err := issue(); err != nil {
				d.Log.Error("renew "+what+" certificate", "err", err)
			}
		}
		return cur, nil
	}, nil
}
