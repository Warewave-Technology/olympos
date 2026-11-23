package gateway

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/pki"
)

// Errors returned by SendRun.
var (
	ErrProbeOffline = errors.New("probe_offline")
	ErrProbeBusy    = errors.New("probe_busy")
)

// ProbeHooks connect ProbeGateway to the synthetic module. Any hook may be
// nil.
type ProbeHooks struct {
	// Connected is called for each new probe stream, after its hello and
	// the second identity check, and before SendRun may use the stream. An
	// error refuses the stream.
	Connected func(ctx context.Context, clusterID uuid.UUID, h *pb.ProbeHello) error
	// Disconnected is called when the last probe stream of the cluster on
	// this replica whose Connected was called ends, also when that Connected
	// failed. A stream may connect while it runs: the hook can check
	// ProbeConnected before it marks the probe offline.
	Disconnected func(clusterID uuid.UUID)
	// Result and Rejected receive what a probe reports. The run id comes
	// from the probe, so the hook checks that the run belongs to clusterID.
	// A result may arrive on another stream than the run was sent on (the
	// probe reconnected meanwhile).
	Result   func(ctx context.Context, clusterID uuid.UUID, r *pb.RunResult)
	Rejected func(ctx context.Context, clusterID uuid.UUID, r *pb.RunRejected)
	// Seen is called (throttled) whenever traffic arrives from a probe.
	Seen func(ctx context.Context, clusterID uuid.UUID)
}

// ProbeInfo describes one probe stream.
type ProbeInfo struct {
	// SessionID names the stream on this replica, for RunDone.
	SessionID uint64
	// PublicKey is the stream's HPKE public key (raw X25519): what a run's
	// credentials are sealed to.
	PublicKey      []byte
	Version        string
	MaxConcurrency int
	// InFlight counts the runs sent on the stream and not yet RunDone.
	InFlight int
}

// probeSession is one probe stream on this replica.
type probeSession struct {
	id             uint64
	clusterID      uuid.UUID
	publicKey      []byte
	version        string
	maxConcurrency int
	ctx            context.Context
	cancel         context.CancelFunc

	sendMu sync.Mutex
	stream pb.ProbeGateway_ConnectServer

	// Guarded by Gateway.mu. SendRun picks a stream by inFlight, and only a
	// ready one: its identity was checked again after it was registered and
	// its Connected hook succeeded. hooked says Connected was called.
	inFlight int
	hooked   bool
	ready    bool
}

func (s *probeSession) send(m *pb.ServerProbeMessage) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	return s.stream.Send(m)
}

// info snapshots the session. The caller holds Gateway.mu.
func (s *probeSession) info() ProbeInfo {
	return ProbeInfo{SessionID: s.id, PublicKey: bytes.Clone(s.publicKey), Version: s.version,
		MaxConcurrency: s.maxConcurrency, InFlight: s.inFlight}
}

// probeServer serves ProbeGateway. It is apart from Gateway because both
// services have a RenewCert.
type probeServer struct {
	pb.UnimplementedProbeGatewayServer
	g *Gateway
}

// Connect handles a probe's long-lived stream.
func (p *probeServer) Connect(stream pb.ProbeGateway_ConnectServer) error {
	return p.g.probeConnect(stream)
}

// RenewCert issues a new probe certificate for the authenticated probe. The
// agent calls it with the probe's identity (decision 1). From then on only
// the new certificate may connect (see authenticate): the agent must write
// it to the probe's Secret at once, and the probe reconnects with it as
// soon as the files change.
//
// A renewal whose answer was lost can be retried: until the probe connects
// with the new certificate, the one it replaced
// (clusters.probe_prev_cert_serial) may still renew, and only renew. A
// retry replaces the current serial again and keeps the previous one, so
// the certificate that never arrived is refused from then on.
func (p *probeServer) RenewCert(ctx context.Context, req *pb.RenewCertRequest) (*pb.RenewCertResponse, error) {
	g := p.g
	clusterID, presented, err := g.authenticateProbeRenewal(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := g.CA.SignProbeCSR(req.CsrDer, clusterID.String(), pki.ProbeCertValidity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Renewing with the current certificate makes it the previous one;
	// renewing with the previous one keeps it so. The row is checked again
	// here (all SET expressions read the old row): a probe revoked, renewed
	// or connected since it authenticated may find nothing to replace.
	old := pki.SerialHex(presented.SerialNumber)
	tag, err := g.DB.Exec(ctx, `UPDATE clusters SET
		probe_prev_cert_serial = CASE WHEN probe_cert_serial = $4 THEN $4 ELSE probe_prev_cert_serial END,
		probe_cert_serial = $2, probe_cert_expires_at = $3
		WHERE id = $1 AND status <> 'revoked' AND probe_status <> 'revoked'
		  AND (probe_cert_serial = $4 OR (probe_prev_cert_serial <> '' AND probe_prev_cert_serial = $4))`,
		clusterID, pki.SerialHex(cert.SerialNumber), cert.NotAfter, old)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "database error")
	}
	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.PermissionDenied, "probe revoked or certificate superseded")
	}
	g.Log.Info("probe certificate renewed", "cluster_id", clusterID, "serial", pki.SerialHex(cert.SerialNumber), "replaced", old)
	return &pb.RenewCertResponse{CertDer: cert.Raw}, nil
}

func (g *Gateway) probeConnect(stream pb.ProbeGateway_ConnectServer) error {
	clusterID, cert, err := g.authenticate(stream.Context(), pki.RoleProbe)
	if err != nil {
		return err
	}
	if h := g.testHooks.awaitingHello; h != nil {
		h(pki.RoleProbe)
	}
	first, err := recvFirst(stream.Context(), g.helloTimeout, stream.Recv)
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "first message must be ProbeHello")
	}
	if hello.ClusterId != "" && hello.ClusterId != clusterID.String() {
		return status.Error(codes.PermissionDenied, "hello cluster id does not match certificate")
	}
	// DHKEM(X25519) (decision 2): anything else could not be sealed to.
	if _, err := ecdh.X25519().NewPublicKey(hello.HpkePublicKey); err != nil {
		return status.Error(codes.InvalidArgument, "hpke_public_key must be a raw X25519 public key")
	}
	maxConc := int(hello.MaxConcurrency)
	if maxConc < 1 {
		maxConc = 1
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	s := &probeSession{clusterID: clusterID, publicKey: bytes.Clone(hello.HpkePublicKey), version: hello.ProbeVersion,
		maxConcurrency: maxConc, ctx: ctx, cancel: cancel, stream: stream}

	// The stream attaches in this order, so that a revoke can never miss it
	// and SendRun can never pick it too early:
	//
	//  1. Register it, not ready: DisconnectProbe now sees it, SendRun and
	//     ProbeConnected do not.
	//  2. Check the identity again, in the statement that clears the
	//     previous serial: a revoke or a fresh enrollment that committed
	//     while the probe was sending its hello is seen here (it waits for a
	//     revoke still in progress, which holds the row). A revoke that
	//     commits later finds the stream registered and cancels it.
	//  3. Run the Connected hook.
	//  4. Mark it ready, unless it was cancelled meanwhile.
	//
	// Unlike the agent, every stream is kept: each probe replica has one.
	g.mu.Lock()
	g.probeSeqNum++
	s.id = g.probeSeqNum
	if g.probes[clusterID] == nil {
		g.probes[clusterID] = map[uint64]*probeSession{}
	}
	g.probes[clusterID][s.id] = s
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.probes[clusterID], s.id)
		// Disconnected follows Connected: it runs when the last stream
		// whose Connected ran ends, even if that hook failed.
		last := s.hooked
		for _, o := range g.probes[clusterID] {
			if o.hooked {
				last = false
			}
		}
		if len(g.probes[clusterID]) == 0 {
			delete(g.probes, clusterID)
		}
		g.mu.Unlock()
		if last && g.ProbeHooks.Disconnected != nil {
			g.ProbeHooks.Disconnected(clusterID)
		}
		g.Log.Info("probe disconnected", "cluster_id", clusterID, "session", s.id)
	}()

	// The probe holds the current certificate: the one it replaced may no
	// longer renew.
	var still uuid.UUID
	err = g.DB.QueryRow(ctx, `UPDATE clusters SET probe_prev_cert_serial = ''
		WHERE id = $1 AND status <> 'revoked' AND probe_status <> 'revoked' AND probe_cert_serial = $2
		RETURNING id`, clusterID, pki.SerialHex(cert.SerialNumber)).Scan(&still)
	if errors.Is(err, pgx.ErrNoRows) {
		g.Log.Warn("probe revoked or replaced before it attached", "cluster_id", clusterID)
		return status.Error(codes.PermissionDenied, "probe revoked")
	}
	if err != nil {
		if ctx.Err() != nil {
			return status.Error(codes.Aborted, "session closed")
		}
		return status.Error(codes.Unavailable, "identity check failed")
	}
	if h := g.testHooks.attached; h != nil {
		h(pki.RoleProbe)
	}
	if ctx.Err() != nil {
		return status.Error(codes.Aborted, "session closed")
	}

	g.mu.Lock()
	s.hooked = true
	g.mu.Unlock()
	if g.ProbeHooks.Connected != nil {
		if err := g.ProbeHooks.Connected(ctx, clusterID, hello); err != nil {
			g.Log.Error("probe connect hook", "cluster_id", clusterID, "err", err)
			return status.Error(codes.Unavailable, "server error")
		}
	}
	g.mu.Lock()
	if ctx.Err() != nil {
		g.mu.Unlock()
		return status.Error(codes.Aborted, "session closed")
	}
	s.ready = true
	g.mu.Unlock()
	g.Log.Info("probe connected", "cluster_id", clusterID, "session", s.id, "probe_version", hello.ProbeVersion,
		"max_concurrency", maxConc)

	// Pinger.
	go func() {
		t := time.NewTicker(PingInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := s.send(&pb.ServerProbeMessage{Msg: &pb.ServerProbeMessage_Ping{Ping: &pb.Ping{UnixNano: now.UnixNano()}}}); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Receiver: a watchdog closes the stream after OfflineAfter of silence,
	// as for the agent.
	msgs := make(chan *pb.ProbeMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	var lastSeenWrite time.Time
	idle := time.NewTimer(OfflineAfter)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return status.Error(codes.Aborted, "session closed")
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-idle.C:
			g.Log.Warn("probe silent, dropping stream", "cluster_id", clusterID, "session", s.id)
			return status.Error(codes.DeadlineExceeded, "no traffic")
		case m := <-msgs:
			idle.Reset(OfflineAfter)
			if g.ProbeHooks.Seen != nil && time.Since(lastSeenWrite) > PingInterval/2 {
				lastSeenWrite = time.Now()
				g.ProbeHooks.Seen(ctx, clusterID)
			}
			g.probeDispatch(ctx, s, m)
		}
	}
}

func (g *Gateway) probeDispatch(ctx context.Context, s *probeSession, m *pb.ProbeMessage) {
	switch v := m.Msg.(type) {
	case *pb.ProbeMessage_Result:
		if g.ProbeHooks.Result != nil && v.Result != nil {
			g.ProbeHooks.Result(ctx, s.clusterID, v.Result)
		}
	case *pb.ProbeMessage_Rejected:
		if v.Rejected == nil {
			return
		}
		g.Log.Warn("run rejected by probe", "cluster_id", s.clusterID, "run_id", v.Rejected.RunId, "reason", v.Rejected.Reason)
		if g.ProbeHooks.Rejected != nil {
			g.ProbeHooks.Rejected(ctx, s.clusterID, v.Rejected)
		}
	case *pb.ProbeMessage_Pong, *pb.ProbeMessage_Hello:
	}
}

// pickProbe returns the cluster's ready stream with the fewest runs in flight
// (the newest on a tie: an older one may be a replica going away). With
// needRoom, only a stream below its max_concurrency counts. The caller
// holds g.mu.
func (g *Gateway) pickProbe(clusterID uuid.UUID, needRoom bool) (*probeSession, error) {
	streams := g.probes[clusterID]
	if len(streams) == 0 {
		return nil, ErrProbeOffline
	}
	var best *probeSession
	for _, s := range streams {
		if !s.ready || (needRoom && s.inFlight >= s.maxConcurrency) {
			continue
		}
		if best == nil || s.inFlight < best.inFlight || (s.inFlight == best.inFlight && s.id > best.id) {
			best = s
		}
	}
	if best == nil {
		for _, s := range streams {
			if s.ready {
				return nil, ErrProbeBusy
			}
		}
		return nil, ErrProbeOffline
	}
	return best, nil
}

// ProbeConnected reports whether a probe stream of clusterID is attached to
// this replica, and describes the least loaded one.
func (g *Gateway) ProbeConnected(clusterID uuid.UUID) (ProbeInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, err := g.pickProbe(clusterID, false)
	if err != nil {
		return ProbeInfo{}, false
	}
	return s.info(), true
}

// SendRun sends one run to the least loaded probe stream of clusterID that
// has room. build makes the run for that stream: it seals the credentials
// to info.PublicKey, and the run goes out on that same stream, so the seal
// always matches the key that can open it. The run counts as in flight on
// the stream until RunDone (or the stream's end). The returned info is the
// stream's, with this run counted.
func (g *Gateway) SendRun(clusterID uuid.UUID, build func(ProbeInfo) (*pb.RunScenario, error)) (ProbeInfo, error) {
	g.mu.Lock()
	s, err := g.pickProbe(clusterID, true)
	if err != nil {
		g.mu.Unlock()
		return ProbeInfo{}, err
	}
	s.inFlight++
	info := s.info()
	g.mu.Unlock()

	run, err := build(info)
	if err == nil && run == nil {
		err = errors.New("gateway: build made no run")
	}
	if err != nil {
		g.RunDone(clusterID, info.SessionID)
		return ProbeInfo{}, err
	}
	if err := s.send(&pb.ServerProbeMessage{Msg: &pb.ServerProbeMessage_Run{Run: run}}); err != nil {
		g.RunDone(clusterID, info.SessionID)
		return ProbeInfo{}, ErrProbeOffline
	}
	return info, nil
}

// ProbeSessionAlive reports whether probe stream sessionID of clusterID is
// still open on this replica. A run sent on a stream that is gone gets no
// result: the probe sends a result only on the stream the run came on.
func (g *Gateway) ProbeSessionAlive(clusterID uuid.UUID, sessionID uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.probes[clusterID][sessionID]
	return s != nil && s.ctx.Err() == nil
}

// RunDone releases a run that SendRun counted on stream sessionID: its
// result or rejection arrived, or the caller gave up on it. A stream that
// is gone is ignored.
func (g *Gateway) RunDone(clusterID uuid.UUID, sessionID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s := g.probes[clusterID][sessionID]; s != nil && s.inFlight > 0 {
		s.inFlight--
	}
}

// DisconnectProbe drops every probe stream of clusterID on this replica.
func (g *Gateway) DisconnectProbe(clusterID uuid.UUID) {
	g.mu.Lock()
	streams := make([]*probeSession, 0, len(g.probes[clusterID]))
	for _, s := range g.probes[clusterID] {
		streams = append(streams, s)
	}
	g.mu.Unlock()
	for _, s := range streams {
		s.cancel()
	}
}

// recvFirst waits at most d for a stream's first message, so that an
// authenticated client cannot hold a stream open without saying hello.
// On a timeout the handler returns, which ends the pending Recv.
func recvFirst[M any](ctx context.Context, d time.Duration, recv func() (M, error)) (M, error) {
	type result struct {
		m   M
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := recv()
		ch <- result{m, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	var zero M
	select {
	case r := <-ch:
		return r.m, r.err
	case <-t.C:
		return zero, status.Error(codes.DeadlineExceeded, "no hello in time")
	case <-ctx.Done():
		return zero, status.FromContextError(ctx.Err()).Err()
	}
}
