// Package gateway is the server side of the agent protocol (SPEC §4.4, §7):
// enrollment, the mTLS control stream, and the tunnel broker that exposes
// tunnels to workers as net.Conn. The same listener serves ProbeGateway to
// olympos-probe (probe.go). Each client certificate has one role: an agent
// identity may only use AgentGateway, a probe identity only ProbeGateway.
package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/store"
)

const (
	// PingInterval and OfflineAfter implement the heartbeat (SPEC §7).
	PingInterval = 15 * time.Second
	OfflineAfter = 60 * time.Second
	// dialTimeout bounds how long Dial waits for the agent to attach.
	dialTimeout = 20 * time.Second
	maxMsgSize  = 32 << 20
)

// Errors returned by Dial.
var (
	ErrAgentOffline   = errors.New("agent_offline")
	ErrTunnelRejected = errors.New("tunnel rejected by agent")
	ErrTooManyTunnels = errors.New("too many concurrent tunnels for this agent")
)

// Hooks connect the gateway to domain modules. Any hook may be nil.
type Hooks struct {
	Connected     func(ctx context.Context, clusterID uuid.UUID, h *pb.Hello) error
	Disconnected  func(clusterID uuid.UUID)
	Inventory     func(ctx context.Context, clusterID uuid.UUID, s *pb.InventorySnapshot) error
	InventoryDiff func(ctx context.Context, clusterID uuid.UUID, d *pb.InventoryDiff) error
	TargetUpsert  func(ctx context.Context, clusterID uuid.UUID, t *pb.Target) error
	TargetDelete  func(ctx context.Context, clusterID uuid.UUID, targetID string) error
	Report        func(ctx context.Context, clusterID uuid.UUID, r *pb.ResourceReport) error
	BenchStatus   func(ctx context.Context, clusterID uuid.UUID, s *pb.BenchStatus)
	BenchResult   func(ctx context.Context, clusterID uuid.UUID, c *pb.BenchResultChunk)
	// Seen is called (throttled) whenever traffic arrives from an agent.
	Seen func(ctx context.Context, clusterID uuid.UUID)
}

// Gateway implements pb.AgentGatewayServer.
type Gateway struct {
	pb.UnimplementedAgentGatewayServer

	DB     *store.DB
	CA     *pki.CA
	Log    *slog.Logger
	Hooks  Hooks
	Limits struct{ MaxTunnels int }
	// ProbeHooks connect ProbeGateway to the synthetic module.
	ProbeHooks ProbeHooks

	mu       sync.Mutex
	sessions map[uuid.UUID]*session
	// probes holds every probe stream on this replica: a probe may run
	// several replicas, each with its own stream and HPKE key.
	probes      map[uuid.UUID]map[uint64]*probeSession
	probeSeqNum uint64
}

// New returns a gateway; call Serve to start it.
func New(db *store.DB, ca *pki.CA, log *slog.Logger) *Gateway {
	g := &Gateway{DB: db, CA: ca, Log: log, sessions: map[uuid.UUID]*session{},
		probes: map[uuid.UUID]map[uint64]*probeSession{}}
	g.Limits.MaxTunnels = 16
	return g
}

// TLSConfig builds the gateway's server TLS config. Client certificates are
// optional at the TLS layer (Enroll has none) and enforced per RPC.
func (g *Gateway) TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    g.CA.Pool(),
	}
}

// GRPCServer returns a configured grpc.Server with AgentGateway and
// ProbeGateway registered.
func (g *Gateway) GRPCServer(tlsCfg *tls.Config) *grpc.Server {
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	pb.RegisterAgentGatewayServer(s, g)
	pb.RegisterProbeGatewayServer(s, &probeServer{g: g})
	return s
}

// ---------------------------------------------------------------- auth

// authenticate returns the cluster ID from a verified client certificate
// whose role is want. An identity of another role is refused with
// PermissionDenied: an agent certificate never reaches ProbeGateway, a
// probe certificate never reaches AgentGateway. A probe is also refused once
// it was revoked alone (clusters.probe_status = 'revoked').
func (g *Gateway) authenticate(ctx context.Context, want pki.IdentityRole) (uuid.UUID, *x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return uuid.Nil, nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.PeerCertificates) == 0 {
		return uuid.Nil, nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	cert := ti.State.PeerCertificates[0]
	id, role, err := pki.ParseIdentityCN(cert.Subject.CommonName)
	if err != nil {
		return uuid.Nil, nil, status.Error(codes.Unauthenticated, "invalid client certificate subject")
	}
	if role != want {
		g.Log.Warn("identity refused on this service", "cluster_id", id, "role", role, "want", want, "peer", peerAddr(ctx))
		return uuid.Nil, nil, status.Error(codes.PermissionDenied, "this identity may not use this service")
	}
	var revoked bool
	var st, probeSt string
	err = g.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM revoked_certs WHERE serial = $1),
		COALESCE((SELECT status FROM clusters WHERE id = $2), ''), COALESCE((SELECT probe_status FROM clusters WHERE id = $2), '')`,
		pki.SerialHex(cert.SerialNumber), id).Scan(&revoked, &st, &probeSt)
	if err != nil {
		return uuid.Nil, nil, status.Error(codes.Unavailable, "identity check failed")
	}
	if revoked || st == "revoked" || st == "" {
		return uuid.Nil, nil, status.Error(codes.PermissionDenied, "cluster revoked")
	}
	if role == pki.RoleProbe && probeSt == "revoked" {
		return uuid.Nil, nil, status.Error(codes.PermissionDenied, "probe revoked")
	}
	return id, cert, nil
}

// ---------------------------------------------------------------- enroll

// HashToken hashes a bootstrap token for storage/lookup.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Enroll exchanges a one-time bootstrap token for a client certificate of
// the requested role. The token must list the role (enroll_tokens.roles),
// and each role is enrolled at most once per token: an agent and a probe,
// never two of either.
func (g *Gateway) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	if req.BootstrapToken == "" || len(req.CsrDer) == 0 {
		return nil, status.Error(codes.InvalidArgument, "bootstrap token and csr required")
	}
	var role pki.IdentityRole
	switch req.Role {
	case pb.EnrollRole_ENROLL_ROLE_AGENT:
		role = pki.RoleAgent
	case pb.EnrollRole_ENROLL_ROLE_PROBE:
		role = pki.RoleProbe
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown enroll role")
	}
	tx, err := g.DB.Begin(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "database unavailable")
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// The row lock makes a second Enroll for the same role wait, then see
	// the role's used mark and match nothing.
	var tokenID, clusterID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT t.id, t.cluster_id FROM enroll_tokens t JOIN clusters c ON c.id = t.cluster_id
		WHERE t.token_hash = $1 AND $2::text = ANY(t.roles)
		  AND CASE $2::text WHEN 'agent' THEN t.agent_used_at IS NULL WHEN 'probe' THEN t.probe_used_at IS NULL ELSE false END
		  AND t.expires_at > now() AND c.status <> 'revoked'
		FOR UPDATE OF t`, HashToken(req.BootstrapToken), role.String()).Scan(&tokenID, &clusterID)
	if err != nil {
		g.Log.Warn("enroll rejected", "reason", "invalid or expired token", "role", role, "peer", peerAddr(ctx))
		return nil, status.Error(codes.PermissionDenied, "invalid or expired bootstrap token")
	}
	var cert *x509.Certificate
	if role == pki.RoleProbe {
		cert, err = g.enrollProbe(ctx, tx, tokenID, clusterID, req)
	} else {
		cert, err = g.enrollAgent(ctx, tx, tokenID, clusterID, req)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	g.Log.Info(role.String()+" enrolled", "cluster_id", clusterID, "serial", pki.SerialHex(cert.SerialNumber))
	return &pb.EnrollResponse{ClusterId: clusterID.String(), CertDer: cert.Raw, CaDer: g.CA.Cert.Raw}, nil
}

func (g *Gateway) enrollAgent(ctx context.Context, tx store.Querier, tokenID, clusterID uuid.UUID, req *pb.EnrollRequest) (*x509.Certificate, error) {
	cert, err := g.CA.SignAgentCSR(req.CsrDer, clusterID.String(), pki.AgentCertValidity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := tx.Exec(ctx, `UPDATE enroll_tokens SET agent_used_at = now() WHERE id = $1`, tokenID); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	if _, err := tx.Exec(ctx, `UPDATE clusters SET cert_serial = $2, cert_expires_at = $3, agent_version = $4 WHERE id = $1`,
		clusterID, pki.SerialHex(cert.SerialNumber), cert.NotAfter, req.AgentVersion); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO activity_log (actor_kind, action, object_type, object_id, cluster_id, details)
		VALUES ('agent', 'cluster.enrolled', 'cluster', $1, $2, jsonb_build_object('cert_serial', $3::text, 'agent_version', $4::text))`,
		clusterID.String(), clusterID, pki.SerialHex(cert.SerialNumber), req.AgentVersion); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	return cert, nil
}

// enrollProbe issues the probe's identity. The agent asks for it on the
// probe's behalf (decision 1), so the activity is the agent's. The probe's
// version is recorded when it connects, not here.
func (g *Gateway) enrollProbe(ctx context.Context, tx store.Querier, tokenID, clusterID uuid.UUID, req *pb.EnrollRequest) (*x509.Certificate, error) {
	cert, err := g.CA.SignProbeCSR(req.CsrDer, clusterID.String(), pki.ProbeCertValidity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := tx.Exec(ctx, `UPDATE enroll_tokens SET probe_used_at = now() WHERE id = $1`, tokenID); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	if _, err := tx.Exec(ctx, `UPDATE clusters SET probe_cert_serial = $2, probe_cert_expires_at = $3, probe_status = 'pending' WHERE id = $1`,
		clusterID, pki.SerialHex(cert.SerialNumber), cert.NotAfter); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO activity_log (actor_kind, action, object_type, object_id, cluster_id, details)
		VALUES ('agent', 'probe.enrolled', 'cluster', $1, $2, jsonb_build_object('cert_serial', $3::text))`,
		clusterID.String(), clusterID, pki.SerialHex(cert.SerialNumber)); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	return cert, nil
}

// RenewCert issues a new certificate for the authenticated cluster.
func (g *Gateway) RenewCert(ctx context.Context, req *pb.RenewCertRequest) (*pb.RenewCertResponse, error) {
	clusterID, _, err := g.authenticate(ctx, pki.RoleAgent)
	if err != nil {
		return nil, err
	}
	cert, err := g.CA.SignAgentCSR(req.CsrDer, clusterID.String(), pki.AgentCertValidity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := g.DB.Exec(ctx, `UPDATE clusters SET cert_serial = $2, cert_expires_at = $3 WHERE id = $1`,
		clusterID, pki.SerialHex(cert.SerialNumber), cert.NotAfter); err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	g.Log.Info("agent certificate renewed", "cluster_id", clusterID, "serial", pki.SerialHex(cert.SerialNumber))
	return &pb.RenewCertResponse{CertDer: cert.Raw}, nil
}

// Revoke denies both of the cluster's certificates, the agent's and the
// probe's, and drops their open streams.
func (g *Gateway) Revoke(ctx context.Context, q store.Querier, clusterID uuid.UUID) error {
	if _, err := q.Exec(ctx, `INSERT INTO revoked_certs (serial, cluster_id)
		SELECT s.serial, c.id FROM clusters c, LATERAL (VALUES (c.cert_serial), (c.probe_cert_serial)) AS s(serial)
		WHERE c.id = $1 AND s.serial <> '' ON CONFLICT DO NOTHING`, clusterID); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE clusters SET status = 'revoked',
		probe_status = CASE WHEN probe_status = 'not_installed' THEN probe_status ELSE 'revoked' END WHERE id = $1`, clusterID); err != nil {
		return err
	}
	g.Disconnect(clusterID)
	return nil
}

// RevokeProbe denies the probe's certificate alone and drops the probe's
// streams; the agent is untouched. Like Revoke it runs in the caller's
// transaction, so the caller calls DisconnectProbe again after commit (a
// probe reconnecting before the commit still sees the old state). A fresh
// probe enrollment ("Install probe") makes the probe pending again.
func (g *Gateway) RevokeProbe(ctx context.Context, q store.Querier, clusterID uuid.UUID) error {
	if _, err := q.Exec(ctx, `INSERT INTO revoked_certs (serial, cluster_id)
		SELECT probe_cert_serial, id FROM clusters WHERE id = $1 AND probe_cert_serial <> '' ON CONFLICT DO NOTHING`, clusterID); err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE clusters SET probe_status = 'revoked' WHERE id = $1`, clusterID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	g.DisconnectProbe(clusterID)
	return nil
}

// Disconnect drops the agent's control stream and tunnels, and every probe
// stream of the cluster, on this replica.
func (g *Gateway) Disconnect(clusterID uuid.UUID) {
	g.mu.Lock()
	s := g.sessions[clusterID]
	g.mu.Unlock()
	if s != nil {
		s.cancel()
	}
	g.DisconnectProbe(clusterID)
}

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// ---------------------------------------------------------------- dial API

// Connected reports whether the agent's control stream is attached to this
// replica (tunnels can only be opened here when true).
func (g *Gateway) Connected(clusterID uuid.UUID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.sessions[clusterID]
	return ok
}

// Capabilities returns the agent's advertised capabilities, if connected.
func (g *Gateway) Capabilities(clusterID uuid.UUID) (*pb.Capabilities, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[clusterID]
	if !ok {
		return nil, false
	}
	return s.caps, true
}

// Conn is a tunnel to a target, usable with any driver.
type Conn interface {
	net.Conn
	// WireBytes is the number of bytes that crossed the tunnel so far.
	WireBytes() int64
}

// DialOptions tune a tunnel.
type DialOptions struct {
	Compressed bool
}

// Dial opens a tunnel to a target discovered by the agent of clusterID.
// The agent rejects any target_id it did not discover itself.
func (g *Gateway) Dial(ctx context.Context, clusterID uuid.UUID, targetID string, opt DialOptions) (Conn, error) {
	return g.open(ctx, clusterID, &pb.ServerMessage{Msg: &pb.ServerMessage_OpenTunnel{OpenTunnel: &pb.OpenTunnel{
		TargetId: targetID, Compressed: opt.Compressed,
	}}}, opt.Compressed)
}

// DialAPIProxy opens a read-only kube-apiserver proxy tunnel (plain HTTP
// over the tunnel; the agent injects its own ServiceAccount token).
func (g *Gateway) DialAPIProxy(ctx context.Context, clusterID uuid.UUID) (Conn, error) {
	return g.open(ctx, clusterID, &pb.ServerMessage{Msg: &pb.ServerMessage_OpenApiProxy{OpenApiProxy: &pb.OpenAPIProxy{}}}, false)
}

// Send delivers a control message (e.g. RunBench) to a connected agent.
func (g *Gateway) Send(clusterID uuid.UUID, m *pb.ServerMessage) error {
	g.mu.Lock()
	s := g.sessions[clusterID]
	g.mu.Unlock()
	if s == nil {
		return ErrAgentOffline
	}
	return s.send(m)
}

// TunnelCount returns open tunnels on this replica (metrics).
func (g *Gateway) TunnelCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, s := range g.sessions {
		s.mu.Lock()
		n += s.open
		s.mu.Unlock()
	}
	return n
}

// AgentCount returns connected agents on this replica (metrics).
func (g *Gateway) AgentCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}

func (g *Gateway) open(ctx context.Context, clusterID uuid.UUID, msg *pb.ServerMessage, compressed bool) (Conn, error) {
	g.mu.Lock()
	s := g.sessions[clusterID]
	g.mu.Unlock()
	if s == nil {
		return nil, ErrAgentOffline
	}
	tunnelID := uuid.NewString()
	switch m := msg.Msg.(type) {
	case *pb.ServerMessage_OpenTunnel:
		m.OpenTunnel.TunnelId = tunnelID
	case *pb.ServerMessage_OpenApiProxy:
		m.OpenApiProxy.TunnelId = tunnelID
	}
	p, err := s.reserve(tunnelID, g.Limits.MaxTunnels, compressed)
	if err != nil {
		return nil, err
	}
	if err := s.send(msg); err != nil {
		s.release(tunnelID)
		return nil, ErrAgentOffline
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	select {
	case c := <-p.ready:
		return c, nil
	case reason := <-p.rejected:
		s.release(tunnelID)
		return nil, fmt.Errorf("%w: %s", ErrTunnelRejected, reason)
	case <-s.ctx.Done():
		s.release(tunnelID)
		return nil, ErrAgentOffline
	case <-ctx.Done():
		s.release(tunnelID)
		// The agent may have attached just as we gave up.
		select {
		case c := <-p.ready:
			_ = c.Close()
		default:
		}
		return nil, fmt.Errorf("open tunnel: %w", ctx.Err())
	}
}
