package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/tunnel"
)

// session is one agent's control stream on this replica.
type session struct {
	clusterID uuid.UUID
	caps      *pb.Capabilities
	ctx       context.Context
	cancel    context.CancelFunc

	sendMu sync.Mutex
	stream pb.AgentGateway_ControlServer

	mu      sync.Mutex
	pending map[string]*pendingTunnel
	open    int

	// Inventory generation of this session (dispatch goroutine only).
	gen        uint64
	resyncSent bool
}

type pendingTunnel struct {
	compressed bool
	ready      chan Conn
	rejected   chan string
	attached   bool
}

func (s *session) send(m *pb.ServerMessage) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.stream.Send(m)
}

func (s *session) reserve(id string, max int, compressed bool) (*pendingTunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caps != nil && s.caps.MaxTunnels > 0 && int(s.caps.MaxTunnels) < max {
		max = int(s.caps.MaxTunnels)
	}
	if s.open >= max {
		return nil, ErrTooManyTunnels
	}
	p := &pendingTunnel{compressed: compressed, ready: make(chan Conn, 1), rejected: make(chan string, 1)}
	s.pending[id] = p
	s.open++
	return p, nil
}

func (s *session) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[id]; ok {
		delete(s.pending, id)
		s.open--
	}
}

// Control handles the agent's long-lived control stream.
func (g *Gateway) Control(stream pb.AgentGateway_ControlServer) error {
	clusterID, _, err := g.authenticate(stream.Context())
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "first message must be Hello")
	}
	if hello.ClusterId != "" && hello.ClusterId != clusterID.String() {
		return status.Error(codes.PermissionDenied, "hello cluster id does not match certificate")
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	s := &session{clusterID: clusterID, caps: hello.Capabilities, ctx: ctx, cancel: cancel,
		stream: stream, pending: map[string]*pendingTunnel{}}
	if s.caps == nil {
		s.caps = &pb.Capabilities{}
	}

	g.mu.Lock()
	if old := g.sessions[clusterID]; old != nil {
		old.cancel() // a newer connection wins
	}
	g.sessions[clusterID] = s
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.sessions[clusterID] == s {
			delete(g.sessions, clusterID)
		}
		g.mu.Unlock()
		if g.Hooks.Disconnected != nil {
			g.Hooks.Disconnected(clusterID)
		}
		g.Log.Info("agent disconnected", "cluster_id", clusterID)
	}()

	if g.Hooks.Connected != nil {
		if err := g.Hooks.Connected(ctx, clusterID, hello); err != nil {
			g.Log.Error("agent connect hook", "cluster_id", clusterID, "err", err)
			return status.Error(codes.Unavailable, "server error")
		}
	}
	g.Log.Info("agent connected", "cluster_id", clusterID, "agent_version", hello.AgentVersion,
		"bench", hello.GetCapabilities().GetBenchEnabled())

	// Pinger.
	go func() {
		t := time.NewTicker(PingInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := s.send(&pb.ServerMessage{Msg: &pb.ServerMessage_Ping{Ping: &pb.Ping{UnixNano: now.UnixNano()}}}); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Receiver: a watchdog closes the stream after OfflineAfter of silence.
	msgs := make(chan *pb.AgentMessage)
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
			g.Log.Warn("agent silent, dropping stream", "cluster_id", clusterID)
			return status.Error(codes.DeadlineExceeded, "no traffic")
		case m := <-msgs:
			idle.Reset(OfflineAfter)
			if g.Hooks.Seen != nil && time.Since(lastSeenWrite) > PingInterval/2 {
				lastSeenWrite = time.Now()
				g.Hooks.Seen(ctx, clusterID)
			}
			g.dispatch(ctx, s, m)
		}
	}
}

func (g *Gateway) dispatch(ctx context.Context, s *session, m *pb.AgentMessage) {
	id := s.clusterID
	var err error
	switch v := m.Msg.(type) {
	case *pb.AgentMessage_Inventory:
		if g.Hooks.Inventory != nil {
			err = g.Hooks.Inventory(ctx, id, v.Inventory)
		}
		if err == nil {
			s.gen, s.resyncSent = v.Inventory.Generation, false
		}
	case *pb.AgentMessage_InventoryDiff:
		if !g.inOrder(s, v.InventoryDiff.Generation) {
			return
		}
		if g.Hooks.InventoryDiff != nil {
			err = g.Hooks.InventoryDiff(ctx, id, v.InventoryDiff)
		}
	case *pb.AgentMessage_TargetUpsert:
		if !g.inOrder(s, v.TargetUpsert.Generation) {
			return
		}
		if g.Hooks.TargetUpsert != nil && v.TargetUpsert.GetTarget() != nil {
			err = g.Hooks.TargetUpsert(ctx, id, v.TargetUpsert.Target)
		}
	case *pb.AgentMessage_TargetDelete:
		if !g.inOrder(s, v.TargetDelete.Generation) {
			return
		}
		if g.Hooks.TargetDelete != nil {
			err = g.Hooks.TargetDelete(ctx, id, v.TargetDelete.TargetId)
		}
	case *pb.AgentMessage_Report:
		if g.Hooks.Report != nil {
			err = g.Hooks.Report(ctx, id, v.Report)
		}
	case *pb.AgentMessage_TunnelRejected:
		s.mu.Lock()
		p := s.pending[v.TunnelRejected.TunnelId]
		s.mu.Unlock()
		if p != nil {
			select {
			case p.rejected <- v.TunnelRejected.Reason:
			default:
			}
		}
		g.Log.Warn("tunnel rejected by agent", "cluster_id", id, "tunnel_id", v.TunnelRejected.TunnelId, "reason", v.TunnelRejected.Reason)
	case *pb.AgentMessage_TunnelAccepted:
		// Informational; the Tunnel RPC attaches the stream.
	case *pb.AgentMessage_BenchStatus:
		if g.Hooks.BenchStatus != nil {
			g.Hooks.BenchStatus(ctx, id, v.BenchStatus)
		}
	case *pb.AgentMessage_BenchResult:
		if g.Hooks.BenchResult != nil {
			g.Hooks.BenchResult(ctx, id, v.BenchResult)
		}
	case *pb.AgentMessage_Pong, *pb.AgentMessage_Hello:
	}
	if err != nil {
		g.Log.Error("agent message handling failed", "cluster_id", id, "err", err)
	}
}

// inOrder applies the generation rule (F18): after a snapshot with
// generation G, each diff/target message must carry the next generation.
// Anything else (a gap, a message before the first snapshot of the session)
// is dropped and the agent is asked once for a fresh snapshot. Generation 0
// is an agent without generations: applied as before.
func (g *Gateway) inOrder(s *session, gen uint64) bool {
	if gen == 0 {
		return true
	}
	if s.gen != 0 && gen == s.gen+1 {
		s.gen = gen
		return true
	}
	if !s.resyncSent {
		s.resyncSent = true
		g.Log.Warn("inventory message out of order; requesting a resync", "cluster_id", s.clusterID, "want", s.gen+1, "got", gen)
		_ = s.send(&pb.ServerMessage{Msg: &pb.ServerMessage_Resync{Resync: &pb.RequestResync{}}})
	}
	return false
}

// Tunnel attaches an agent-opened tunnel stream to a pending Dial.
func (g *Gateway) Tunnel(stream pb.AgentGateway_TunnelServer) error {
	clusterID, _, err := g.authenticate(stream.Context())
	if err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	g.mu.Lock()
	s := g.sessions[clusterID]
	g.mu.Unlock()
	if s == nil {
		return status.Error(codes.FailedPrecondition, "no control stream")
	}
	s.mu.Lock()
	p := s.pending[first.TunnelId]
	if p != nil && p.attached {
		p = nil
	}
	if p != nil {
		p.attached = true
	}
	s.mu.Unlock()
	if p == nil {
		// Unknown tunnel id, or one belonging to another cluster.
		return status.Error(codes.NotFound, "unknown tunnel")
	}
	defer s.release(first.TunnelId)

	app, ours := net.Pipe()
	c := &tunnelConn{Conn: app, counters: &tunnel.Counters{}}
	select {
	case p.ready <- c:
	default:
		return status.Error(codes.Aborted, "dial abandoned")
	}
	// The first frame may already carry data.
	pre := &prefixStream{AgentGateway_TunnelServer: stream, first: first}
	err = tunnel.Bridge(ours, pre, p.compressed, tunnel.Limits{}, c.counters, nil)
	if err != nil && !errors.Is(err, context.Canceled) {
		g.Log.Debug("tunnel closed with error", "cluster_id", clusterID, "err", err)
	}
	return nil
}

// prefixStream replays the first received frame's payload.
type prefixStream struct {
	pb.AgentGateway_TunnelServer
	first *pb.TunnelFrame
}

func (p *prefixStream) Recv() (*pb.TunnelFrame, error) {
	if f := p.first; f != nil {
		p.first = nil
		if len(f.Data) > 0 || f.Close {
			return f, nil
		}
	}
	return p.AgentGateway_TunnelServer.Recv()
}

type tunnelConn struct {
	net.Conn
	counters *tunnel.Counters
}

func (c *tunnelConn) WireBytes() int64 { return c.counters.Total() }

// tunnelAddr stands in for a TCP address. net.Pipe reports "pipe", and some
// drivers send the local address to the server (ClickHouse rejects one
// without a port).
var tunnelAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

func (c *tunnelConn) LocalAddr() net.Addr  { return tunnelAddr }
func (c *tunnelConn) RemoteAddr() net.Addr { return tunnelAddr }
