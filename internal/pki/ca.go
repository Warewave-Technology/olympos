// Package pki is Olympos's internal CA. It issues agent client certificates
// (CN = cluster UUID) and, when no external certificate is configured, the
// agent gateway's server certificate. The CA key is stored envelope-encrypted.
package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// AgentCertValidity is the lifetime of agent client certificates (SPEC §4.4).
const AgentCertValidity = 30 * 24 * time.Hour

// CA holds the parsed CA certificate and its signer in memory.
type CA struct {
	Cert   *x509.Certificate
	signer crypto.Signer
}

var caAAD = []byte("olympos-pki-ca")

// LoadOrCreate loads the CA from the database, generating it on first start.
// Concurrent replicas race on the singleton row; the loser reloads.
func LoadOrCreate(ctx context.Context, db *store.DB, env *secrets.Envelope) (*CA, error) {
	ca, err := load(ctx, db, env)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "Olympos Internal CA", Organization: []string{"Olympos"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	sealed, err := env.Seal(ctx, keyDER, caAAD)
	secrets.Zero(keyDER)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(ctx, `INSERT INTO pki_ca (id, cert_der, key_ciphertext, wrapped_dek, kek_version)
		VALUES (1, $1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`,
		der, sealed.Ciphertext, sealed.WrappedDEK, sealed.KEKVersion)
	if err != nil {
		return nil, err
	}
	return load(ctx, db, env)
}

func load(ctx context.Context, db *store.DB, env *secrets.Envelope) (*CA, error) {
	var der []byte
	var s secrets.Sealed
	err := db.QueryRow(ctx, `SELECT cert_der, key_ciphertext, wrapped_dek, kek_version FROM pki_ca WHERE id = 1`).
		Scan(&der, &s.Ciphertext, &s.WrappedDEK, &s.KEKVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := env.Open(ctx, s, caAAD)
	if err != nil {
		return nil, fmt.Errorf("open ca key: %w", err)
	}
	defer secrets.Zero(keyDER)
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca key is not a signer")
	}
	return &CA{Cert: cert, signer: signer}, nil
}

// NewForTest returns an in-memory CA (tests only).
func NewForTest() *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(), Subject: pkix.Name{CommonName: "Olympos Test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return &CA{Cert: cert, signer: key}
}

// Pool returns a cert pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Cert)
	return p
}

// SignAgentCSR signs a client certificate for clusterID. The CSR subject is
// ignored: identity comes from the server, never from the agent.
func (c *CA) SignAgentCSR(csrDER []byte, clusterID string, validity time.Duration) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("csr key must be ECDSA P-256")
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: clusterID, Organization: []string{"olympos-agent"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// IssueServerCert issues a TLS server certificate for the agent gateway.
func (c *CA) IssueServerCert(hosts []string, validity time.Duration) (certDER []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "olympos-gateway"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.signer)
	return certDER, key, err
}

// SerialHex formats a certificate serial the way it is stored in the DB.
func SerialHex(n *big.Int) string { return fmt.Sprintf("%x", n) }

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
