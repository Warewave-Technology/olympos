package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Warewave-Technology/olympos/internal/config"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func ingestDeps(t *testing.T) *Deps {
	t.Helper()
	db := testutil.DB(t)
	kv := &fakeKV{secrets: map[string][]byte{}}
	env := &secrets.Envelope{KV: kv}
	ca, err := pki.LoadOrCreate(context.Background(), db, env)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := secrets.NewFingerprinter([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Server{}
	cfg.Listen.Ingest = "127.0.0.1:0"
	cfg.Ingest.URL = "https://olympos-ingest.test:9444"
	cfg.Ingest.MaxRuns = 2
	d := &Deps{Cfg: cfg, Log: NewLogger(0), DB: db, Envelope: env, HMAC: fp, CA: ca}
	d.Ingest = ingest.NewRegistry(db, fp, cfg.Ingest.MaxRuns, nil)
	return d
}

// serve starts the endpoint on a free port and returns an HTTPS client that
// trusts roots and dials that port whatever the host of the URL.
func serve(t *testing.T, d *Deps, roots *x509.CertPool) (*http.Client, *certFile) {
	t.Helper()
	srv, cf, unregister, err := d.ingestServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unregister)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: d.Cfg.IngestHost()},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
		},
	}}, cf
}

// The endpoint serves the S3 handler over a certificate of the internal CA
// for the host of ingest.url, and its metrics join /metrics.
func TestIngestServerInternalCA(t *testing.T) {
	d := ingestDeps(t)
	c, cf := serve(t, d, d.CA.Pool())
	if cf != nil {
		t.Fatal("the internal-CA certificate is not reloaded from a file")
	}
	// An unsigned request reaches the handler and is refused there.
	resp, err := c.Get("https://olympos-ingest.test:9444/olympos/run/obj")
	if err != nil {
		t.Fatalf("TLS to the internal-CA certificate for the ingest host: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unsigned request: %d", resp.StatusCode)
	}
	mfs, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		found = found || mf.GetName() == "olympos_ingest_requests_total"
	}
	if !found {
		t.Error("olympos_ingest_requests_total is not on the metrics registry")
	}
}

func selfSigned(t *testing.T, dir, host string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

// Certificate files win over the internal CA and are reloaded (SIGHUP).
func TestIngestServerCertFiles(t *testing.T) {
	d := ingestDeps(t)
	dir := t.TempDir()
	first := selfSigned(t, dir, "olympos-ingest.test")
	d.Cfg.Ingest.TLSCertFile, d.Cfg.Ingest.TLSKeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")

	c, cf := serve(t, d, first)
	if cf == nil {
		t.Fatal("certificate files are reloaded on SIGHUP")
	}
	get := func(c *http.Client) error {
		resp, err := c.Get("https://olympos-ingest.test:9444/olympos/run/obj")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(c); err != nil {
		t.Fatalf("certificate from the files: %v", err)
	}
	if err := get(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: d.CA.Pool(), ServerName: "olympos-ingest.test"},
		DialContext: c.Transport.(*http.Transport).DialContext}}); err == nil {
		t.Fatal("the internal CA must not vouch for a certificate from the files")
	}
	// A new certificate in the files is served after the reload, not before.
	second := selfSigned(t, dir, "olympos-ingest.test")
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig.RootCAs = second
	tr.CloseIdleConnections()
	if err := get(c); err == nil {
		t.Fatal("before the reload the old certificate is still served")
	}
	if err := cf.reload(); err != nil {
		t.Fatal(err)
	}
	tr.CloseIdleConnections()
	if err := get(c); err != nil {
		t.Fatalf("after the reload: %v", err)
	}
}

// An http ingest.url serves plain HTTP (lab use).
func TestIngestServerPlainHTTP(t *testing.T) {
	d := ingestDeps(t)
	d.Cfg.Ingest.URL = "http://olympos-ingest.test:9444"
	srv, cf, unregister, err := d.ingestServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unregister)
	if cf != nil || srv.TLSConfig != nil {
		t.Fatal("an http ingest.url has no TLS")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	resp, err := http.Get("http://" + l.Addr().String() + "/olympos/run/obj")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unsigned request: %d", resp.StatusCode)
	}
}

// The gateway's internal-CA certificate (shared issuing code with the ingest
// endpoint) covers the host of agentGatewayURL and gateway.extraSANs, is
// signed by the CA, is kept while valid and re-issued when close to expiry.
func TestGatewayTLSInternalCA(t *testing.T) {
	d := ingestDeps(t)
	d.Cfg.AgentGatewayURL = "gw.test:8443"
	d.Cfg.Gateway.ExtraSANs = []string{"gw-alt.test", "10.1.2.3"}
	d.Gateway = gateway.New(d.DB, d.CA, d.Log)
	c, cf, err := d.gatewayTLS()
	if err != nil {
		t.Fatal(err)
	}
	if cf != nil || c.GetCertificate == nil || len(c.Certificates) != 0 {
		t.Fatalf("internal CA: a certificate callback, no file, no static certificate (%v, %d)", cf, len(c.Certificates))
	}
	first, err := c.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gw.test", "gw-alt.test", "10.1.2.3"} {
		if err := first.Leaf.VerifyHostname(name); err != nil {
			t.Errorf("certificate does not cover %s: %v", name, err)
		}
	}
	if _, err := first.Leaf.Verify(x509.VerifyOptions{Roots: d.CA.Pool(), DNSName: "gw.test"}); err != nil {
		t.Errorf("not signed by the internal CA: %v", err)
	}
	if again, _ := c.GetCertificate(nil); again != first {
		t.Error("a certificate with more than 30 days left is kept")
	}

	// Close to expiry (29 days of validity < 30 days renewBefore): every
	// handshake re-issues.
	get, err := d.internalServerCert("gateway", []string{"gw.test"}, 29*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := get(nil)
	b, err := get(nil)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) == 0 {
		t.Error("a certificate with less than 30 days left is re-issued")
	}
	if err := b.Leaf.VerifyHostname("gw.test"); err != nil {
		t.Errorf("re-issued certificate: %v", err)
	}
}
