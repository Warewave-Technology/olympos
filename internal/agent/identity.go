package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// Identity secret keys.
const (
	keyBootstrap = "bootstrap-token"
	keyCert      = "tls.crt"
	keyKey       = "tls.key"
	keyClusterID = "cluster-id"
)

// identity is the agent's client certificate. The private key is generated
// in memory and persisted only in the agent's own namespaced Secret.
type identity struct {
	mu        sync.RWMutex
	cert      tls.Certificate
	leaf      *x509.Certificate
	clusterID string
}

func (i *identity) get() (*tls.Certificate, *x509.Certificate) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	c := i.cert
	return &c, i.leaf
}

func (i *identity) set(certDER []byte, key *ecdsa.PrivateKey) error {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cert = tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: leaf}
	i.leaf = leaf
	i.clusterID = leaf.Subject.CommonName
	return nil
}

// identityStore reads/writes the agent identity Secret (the only Secret the
// agent may touch; RBAC is resourceNames-restricted).
type identityStore struct {
	kube      kubernetes.Interface
	namespace string
	name      string
}

func (s *identityStore) load(ctx context.Context) (map[string][]byte, error) {
	sec, err := s.kube.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read identity secret %s/%s: %w", s.namespace, s.name, err)
	}
	return sec.Data, nil
}

func (s *identityStore) save(ctx context.Context, clusterID string, certDER []byte, key *ecdsa.PrivateKey) error {
	sec, err := s.kube.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	sec.Data = map[string][]byte{
		keyCert:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		keyKey:       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		keyClusterID: []byte(clusterID),
		// bootstrap-token is dropped: it is single-use.
	}
	_, err = s.kube.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{})
	return err
}

// dropToken removes the bootstrap token and leaves the rest of the Secret.
func (s *identityStore) dropToken(ctx context.Context) error {
	sec, err := s.kube.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if _, ok := sec.Data[keyBootstrap]; !ok {
		return nil
	}
	delete(sec.Data, keyBootstrap)
	_, err = s.kube.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{})
	return err
}

func parseStored(data map[string][]byte) ([]byte, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(data[keyCert])
	kb, _ := pem.Decode(data[keyKey])
	if cb == nil || kb == nil {
		return nil, nil, errors.New("no stored identity")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("stored key is not ECDSA")
	}
	return cb.Bytes, ek, nil
}

func newKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	return newKeyAndCSRFor("olympos-agent")
}

// newKeyAndCSRFor makes a key and a CSR for cn. The server ignores the
// subject and signs the identity it chose, so cn is only a label.
func newKeyAndCSRFor(cn string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	return key, csr, err
}

// ensureIdentity loads the stored cert, or enrolls with the bootstrap token.
func (a *Agent) ensureIdentity(ctx context.Context) error {
	data, err := a.ids.load(ctx)
	if err != nil {
		return err
	}
	if certDER, key, err := parseStored(data); err == nil {
		if err := a.id.set(certDER, key); err != nil {
			return err
		}
		_, leaf := a.id.get()
		if time.Now().Before(leaf.NotAfter) {
			a.log.Info("loaded stored identity", "cluster_id", leaf.Subject.CommonName, "expires", leaf.NotAfter)
			return nil
		}
		a.log.Warn("stored certificate expired; re-enrollment needed")
	}
	token := string(data[keyBootstrap])
	if token == "" {
		return errors.New("no valid identity and no bootstrap token; generate a new install command in Olympos")
	}
	key, csr, err := newKeyAndCSR()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(a.cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(a.tlsConfig(false))))
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := pb.NewAgentGatewayClient(conn).Enroll(ctx, &pb.EnrollRequest{
		BootstrapToken: token, CsrDer: csr, AgentVersion: Version,
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := a.id.set(resp.CertDer, key); err != nil {
		return err
	}
	if err := a.ids.save(ctx, resp.ClusterId, resp.CertDer, key); err != nil {
		return fmt.Errorf("persist identity: %w", err)
	}
	a.log.Info("enrolled", "cluster_id", resp.ClusterId)
	return nil
}

// renewLoop renews the certificate at 2/3 of its lifetime.
func (a *Agent) renewLoop(ctx context.Context, client pb.AgentGatewayClient) {
	for {
		_, leaf := a.id.get()
		life := leaf.NotAfter.Sub(leaf.NotBefore)
		at := leaf.NotBefore.Add(life * 2 / 3)
		wait := time.Until(at)
		if wait < 0 {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		key, csr, err := newKeyAndCSR()
		if err != nil {
			a.log.Error("renew: key generation; retrying in 1m", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			}
			continue
		}
		resp, err := client.RenewCert(ctx, &pb.RenewCertRequest{CsrDer: csr})
		if err != nil {
			a.log.Error("renew certificate failed; retrying in 10m", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Minute):
			}
			continue
		}
		if err := a.id.set(resp.CertDer, key); err != nil {
			a.log.Error("renew: bad certificate; retrying in 10m", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Minute):
			}
			continue
		}
		_, leaf = a.id.get()
		if err := a.ids.save(ctx, leaf.Subject.CommonName, resp.CertDer, key); err != nil {
			a.log.Error("renew: persist identity", "err", err)
		}
		a.log.Info("certificate renewed", "expires", leaf.NotAfter)
	}
}
