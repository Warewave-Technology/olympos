package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// The probe identity (synthetic monitoring, decision 1). olympos-probe has no
// Kubernetes API access: the agent enrolls its mTLS identity, renews it and
// writes it to the Secret cfg.ProbeIdentitySecret, which the probe mounts
// read-only and watches. The agent never touches that Secret for anything
// else, and this file never touches the agent's own Secret.

const (
	// probeRetry is how long the agent waits after a failure, and the longest
	// it sleeps at all, so that a Secret that changes (a new install) is seen.
	probeRetry = 10 * time.Minute
	// probeCallTimeout bounds one Enroll or RenewCert call.
	probeCallTimeout = 30 * time.Second
	probeCNSuffix    = "/probe"
)

// probeEnroller is the server side of the probe identity.
type probeEnroller interface {
	// Enroll trades a bootstrap token for a probe certificate.
	Enroll(ctx context.Context, token string, csr []byte) ([]byte, error)
	// Renew asks ProbeGateway.RenewCert for a new certificate. It is called
	// with the probe's own certificate cur, not the agent's.
	Renew(ctx context.Context, cur tls.Certificate, csr []byte) ([]byte, error)
}

// grpcProbeEnroller is the real probeEnroller.
type grpcProbeEnroller struct{ a *Agent }

func (g *grpcProbeEnroller) Enroll(ctx context.Context, token string, csr []byte) ([]byte, error) {
	conn, err := grpc.NewClient(g.a.cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(g.a.tlsConfig(false))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := pb.NewAgentGatewayClient(conn).Enroll(ctx, &pb.EnrollRequest{
		BootstrapToken: token, CsrDer: csr, AgentVersion: Version, Role: pb.EnrollRole_ENROLL_ROLE_PROBE,
	})
	if err != nil {
		return nil, err
	}
	return resp.CertDer, nil
}

func (g *grpcProbeEnroller) Renew(ctx context.Context, cur tls.Certificate, csr []byte) ([]byte, error) {
	cfg := g.a.tlsConfig(false)
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cur, nil }
	conn, err := grpc.NewClient(g.a.cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := pb.NewProbeGatewayClient(conn).RenewCert(ctx, &pb.RenewCertRequest{CsrDer: csr})
	if err != nil {
		return nil, err
	}
	return resp.CertDer, nil
}

// probeClock lets tests drive the loop.
type probeClock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) bool // false: ctx is done
}

var systemProbeClock = probeClock{
	now: time.Now,
	sleep: func(ctx context.Context, d time.Duration) bool {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	},
}

// probeCreds is an identity that arrived and is not yet in the Secret.
type probeCreds struct {
	clusterID string
	certDER   []byte
	key       *ecdsa.PrivateKey
	what      string // "enrolled" or "renewed", for the log
}

// probeState is what the loop remembers between steps.
type probeState struct {
	// pending is held until it is written: an enrollment's token is spent,
	// and a renewal's old certificate may be superseded by it.
	pending *probeCreds
	// lockedOut: the server refused the current certificate.
	lockedOut bool
}

// startProbeIdentity starts the probe identity loop when the probe is
// enabled. It is independent of the control session: the identity is kept
// whether or not the agent is connected.
func (a *Agent) startProbeIdentity(ctx context.Context, e probeEnroller) bool {
	if !a.cfg.ProbeEnabled {
		return false
	}
	go a.runProbeIdentity(ctx, e)
	return true
}

// runProbeIdentity keeps the probe's identity in its Secret until ctx ends.
func (a *Agent) runProbeIdentity(ctx context.Context, e probeEnroller) {
	a.probeIdentityLoop(ctx, e, systemProbeClock)
}

func (a *Agent) probeIdentityLoop(ctx context.Context, e probeEnroller, c probeClock) {
	store := &identityStore{kube: a.kube, namespace: a.cfg.Namespace, name: a.cfg.ProbeIdentitySecret}
	var st probeState
	for {
		wait := a.probeIdentityStep(ctx, e, store, &st, c.now())
		if !c.sleep(ctx, wait) {
			return
		}
	}
}

// probeIdentityStep does one pass and returns how long to wait for the next.
func (a *Agent) probeIdentityStep(ctx context.Context, e probeEnroller, store *identityStore, st *probeState, now time.Time) time.Duration {
	if st.pending != nil && !a.flushProbeCreds(ctx, store, st) {
		return probeRetry
	}
	data, err := store.load(ctx)
	if err != nil {
		a.log.Error("probe identity: cannot read the Secret; retrying in 10m", "err", err)
		return probeRetry
	}
	var leaf *x509.Certificate
	certDER, key, perr := parseStored(data)
	if perr == nil {
		if leaf, perr = x509.ParseCertificate(certDER); perr != nil {
			leaf = nil
		}
	}
	usable := leaf != nil && now.Before(leaf.NotAfter)

	// A token that is present always means a newer install request (tokens
	// are dropped once used): "Install probe" is how an operator recovers a
	// revoked probe, whose certificate may still look valid. It replaces the
	// current identity at once, valid or not.
	if token := string(data[keyBootstrap]); token != "" {
		a.enrollProbe(ctx, e, store, st, token)
		return probeRetry
	}
	if !usable {
		if leaf != nil {
			a.log.Warn("probe identity: the certificate expired and there is no bootstrap token; generate an Install probe command in Olympos. Checking again in 10m",
				"expired", leaf.NotAfter)
		} else {
			a.log.Warn("probe identity: no certificate and no bootstrap token; generate an Install probe command in Olympos. Checking again in 10m")
		}
		return probeRetry
	}

	renewAt := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
	if now.Before(renewAt) && !st.lockedOut {
		return min(renewAt.Sub(now), probeRetry)
	}
	a.renewProbe(ctx, e, store, st, tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: leaf})
	return probeRetry
}

func (a *Agent) enrollProbe(ctx context.Context, e probeEnroller, store *identityStore, st *probeState, token string) {
	key, csr, err := newKeyAndCSRFor("olympos-probe")
	if err != nil {
		a.log.Error("probe identity: key generation; retrying in 10m", "err", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, probeCallTimeout)
	defer cancel()
	der, err := e.Enroll(cctx, token, csr)
	if c := status.Code(err); c == codes.PermissionDenied || c == codes.NotFound {
		// Invalid, expired or used: it will never work. Drop it so that it
		// is not tried again, and keep the current certificate.
		a.log.Error("probe identity: the bootstrap token was refused (invalid, expired or used); dropping it and keeping the current certificate. Generate a new Install probe command in Olympos if the probe needs a new identity",
			"err", err)
		if derr := store.dropToken(ctx); derr != nil {
			a.log.Error("probe identity: cannot drop the bootstrap token; retrying in 10m", "err", derr)
		}
		return
	}
	if err != nil {
		a.log.Error("probe identity: enrollment failed; if the token is spent or expired, generate an Install probe command in Olympos. Retrying in 10m", "err", err)
		return
	}
	clusterID, err := probeClusterID(der)
	if err != nil {
		a.log.Error("probe identity: enrollment returned a bad certificate; retrying in 10m", "err", err)
		return
	}
	st.pending = &probeCreds{clusterID: clusterID, certDER: der, key: key, what: "enrolled"}
	st.lockedOut = false
	a.flushProbeCreds(ctx, store, st)
}

func (a *Agent) renewProbe(ctx context.Context, e probeEnroller, store *identityStore, st *probeState, cur tls.Certificate) {
	key, csr, err := newKeyAndCSRFor("olympos-probe")
	if err != nil {
		a.log.Error("probe identity: key generation; retrying in 10m", "err", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, probeCallTimeout)
	defer cancel()
	der, err := e.Renew(cctx, cur, csr)
	switch {
	case status.Code(err) == codes.PermissionDenied:
		// The probe's certificate is revoked or superseded: this agent
		// holds nothing the server accepts. The Secret is left as it is.
		st.lockedOut = true
		a.log.Error("probe identity: the server refused the probe certificate (revoked or superseded); the probe is locked out until you generate an Install probe command in Olympos. Checking again in 10m",
			"err", err)
		return
	case err != nil:
		// No answer (timeout, Unavailable, ...). The old certificate stays
		// in the Secret and the next attempt uses it again: the server still
		// accepts it if the lost response had been a success.
		a.log.Warn("probe identity: renewal got no usable answer; retrying with the same certificate in 10m", "err", err)
		return
	}
	clusterID, err := probeClusterID(der)
	if err != nil {
		a.log.Error("probe identity: renewal returned a bad certificate; retrying in 10m", "err", err)
		return
	}
	st.pending = &probeCreds{clusterID: clusterID, certDER: der, key: key, what: "renewed"}
	st.lockedOut = false
	a.flushProbeCreds(ctx, store, st)
}

// flushProbeCreds writes the pending identity to the Secret at once. It keeps
// it, and the caller tries again later, when the write fails.
func (a *Agent) flushProbeCreds(ctx context.Context, store *identityStore, st *probeState) bool {
	p := st.pending
	if err := store.save(ctx, p.clusterID, p.certDER, p.key); err != nil {
		a.log.Error("probe identity: cannot write the Secret; the new certificate is kept in memory, retrying in 10m", "what", p.what, "err", err)
		return false
	}
	st.pending = nil
	leaf, _ := x509.ParseCertificate(p.certDER)
	a.log.Info("probe identity "+p.what, "cluster_id", p.clusterID, "expires", leaf.NotAfter)
	return true
}

// probeClusterID is the cluster of a probe certificate (CN <uuid>/probe).
func probeClusterID(certDER []byte) (string, error) {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	id, ok := strings.CutSuffix(leaf.Subject.CommonName, probeCNSuffix)
	if !ok || id == "" {
		return "", fmt.Errorf("certificate CN %q is not a probe identity", leaf.Subject.CommonName)
	}
	return id, nil
}
