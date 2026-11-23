package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseIdentityCN(t *testing.T) {
	id := uuid.New()
	for _, tc := range []struct {
		cn   string
		role IdentityRole
	}{{id.String(), RoleAgent}, {ProbeCN(id.String()), RoleProbe}} {
		got, role, err := ParseIdentityCN(tc.cn)
		if err != nil || got != id || role != tc.role {
			t.Fatalf("%q: %v %v %v", tc.cn, got, role, err)
		}
	}
	// One cluster has exactly one agent CN and one probe CN: only the
	// canonical UUID form this CA writes is accepted.
	for _, cn := range []string{"", "/probe", "probe", id.String() + "/agent", id.String() + "/probe/probe",
		"urn:uuid:" + id.String(), "{" + id.String() + "}", strings.ToUpper(id.String()),
		strings.ReplaceAll(id.String(), "-", ""), "urn:uuid:" + id.String() + "/probe", id.String() + "/PROBE"} {
		if _, _, err := ParseIdentityCN(cn); err == nil {
			t.Errorf("%q accepted", cn)
		}
	}
}

func TestSignProbeCSR(t *testing.T) {
	ca := NewForTest()
	id := uuid.NewString()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: uuid.NewString()}}, key)
	cert, err := ca.SignProbeCSR(csr, id, ProbeCertValidity)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id+"/probe" || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "olympos-probe" {
		t.Fatalf("subject %v", cert.Subject)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ext key usage %v", cert.ExtKeyUsage)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if d := cert.NotAfter.Sub(time.Now()); d < 29*24*time.Hour {
		t.Fatalf("validity %v", d)
	}
	// Same checks as for the agent: a P-384 key is refused.
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	csr384, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k384)
	if _, err := ca.SignProbeCSR(csr384, id, ProbeCertValidity); err == nil {
		t.Fatal("P-384 CSR accepted")
	}
}
