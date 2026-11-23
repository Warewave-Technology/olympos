package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// Reporter produces ResourceReports (Kyverno, NetworkPolicies, images).
// Each reporter runs for the lifetime of a control session and calls send
// whenever its full report changes.
type Reporter interface {
	Name() string
	Run(ctx context.Context, send func(*pb.ResourceReport)) error
}

// BenchRunner executes kube-bench Jobs (opt-in, SPEC §12.3).
type BenchRunner interface {
	Allowlist() []string
	Run(ctx context.Context, req *pb.RunBench, status func(*pb.BenchStatus), chunk func(*pb.BenchResultChunk))
}

// Agent is the running agent.
type Agent struct {
	cfg  Config
	log  *slog.Logger
	kube kubernetes.Interface
	rest *rest.Config

	ids *identityStore
	id  identity

	caPool *x509.CertPool

	disc      *discovery
	Reporters []Reporter
	Bench     BenchRunner

	sendMu  sync.Mutex
	control pb.AgentGateway_ControlClient
	client  pb.AgentGatewayClient

	tunnels   atomic.Int32
	connected atomic.Bool

	// life is the agent's lifetime context: work that outlives a control
	// session (kube-bench Jobs) runs under it, and its results go through
	// out, re-sent after a reconnect (F18).
	life     context.Context
	out      *outbox
	sessions atomic.Uint64
}

// New builds an agent from in-cluster config.
func New(cfg Config, log *slog.Logger, rc *rest.Config) (*Agent, error) {
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(cfg.ServerCAFile)
	if err != nil {
		return nil, fmt.Errorf("read server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("server CA file contains no certificates")
	}
	a := &Agent{cfg: cfg, log: log, kube: kube, rest: rc, caPool: pool,
		ids: &identityStore{kube: kube, namespace: cfg.Namespace, name: cfg.IdentitySecret}}
	a.disc = newDiscovery(a)
	a.out = newOutbox(DefaultOutboxBytes, log)
	a.life = context.Background()
	return a, nil
}

// tlsConfig pins the Olympos CA. withClient adds the agent certificate.
func (a *Agent) tlsConfig(withClient bool) *tls.Config {
	c := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    a.caPool,
		ServerName: a.cfg.ServerName,
	}
	if withClient {
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, _ := a.id.get()
			return cert, nil
		}
	}
	return c
}

// Run blocks until ctx is cancelled, reconnecting with backoff.
func (a *Agent) Run(ctx context.Context) error {
	a.life = ctx
	go a.serveHealth(ctx)
	a.startProbeIdentity(ctx, &grpcProbeEnroller{a: a})
	if err := a.disc.start(ctx); err != nil {
		return err
	}
	backoff := time.Second
	for {
		if err := a.ensureIdentity(ctx); err != nil {
			a.log.Error("identity", "err", err)
		} else {
			start := time.Now()
			err := a.session(ctx)
			if ctx.Err() != nil {
				return nil
			}
			a.log.Warn("control session ended", "err", err)
			if time.Since(start) > time.Minute {
				backoff = time.Second
			}
		}
		jitter := time.Duration(rand.Int64N(int64(backoff / 2)))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff + jitter):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (a *Agent) session(ctx context.Context) error {
	conn, err := grpc.NewClient(a.cfg.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(a.tlsConfig(true))),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(32<<20), grpc.MaxCallSendMsgSize(32<<20)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := pb.NewAgentGatewayClient(conn)
	stream, err := client.Control(ctx)
	if err != nil {
		return err
	}
	a.sendMu.Lock()
	a.control, a.client = stream, client
	a.sendMu.Unlock()
	_, leaf := a.id.get()

	caps := &pb.Capabilities{MaxTunnels: int32(a.cfg.MaxTunnels), SecretsInventory: a.cfg.SecretsInventory}
	if a.Bench != nil && a.cfg.BenchEnabled {
		caps.BenchEnabled = true
		caps.BenchMaxParallel = int32(a.cfg.BenchMaxParallel)
		caps.BenchAllowlist = a.Bench.Allowlist()
	}
	if err := a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{
		AgentVersion: Version, ClusterId: leaf.Subject.CommonName, Capabilities: caps,
		ProviderOverride: a.cfg.ProviderOverride,
	}}}); err != nil {
		return err
	}
	a.connected.Store(true)
	sess := a.sessions.Add(1)
	defer func() {
		a.connected.Store(false)
		a.out.disconnected(sess)
		a.sendMu.Lock()
		if a.control == stream {
			a.control = nil
		}
		a.sendMu.Unlock()
	}()
	a.log.Info("connected to olympos", "server", a.cfg.Server)
	if n := a.out.connected(sess, a.send); n > 0 {
		a.log.Info("re-sent buffered results", "messages", n)
	}

	go a.renewLoop(ctx, client)
	go a.disc.publish(ctx)
	for _, r := range a.Reporters {
		go func(r Reporter) {
			if err := r.Run(ctx, func(rep *pb.ResourceReport) {
				_ = a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_Report{Report: rep}})
			}); err != nil && ctx.Err() == nil {
				a.log.Error("reporter stopped", "reporter", r.Name(), "err", err)
			}
		}(r)
	}

	for {
		m, err := stream.Recv()
		if err != nil {
			return err
		}
		switch v := m.Msg.(type) {
		case *pb.ServerMessage_Ping:
			_ = a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_Pong{Pong: &pb.Pong{UnixNano: v.Ping.UnixNano}}})
		case *pb.ServerMessage_OpenTunnel:
			go a.openTunnel(ctx, v.OpenTunnel)
		case *pb.ServerMessage_OpenApiProxy:
			go a.openAPIProxy(ctx, v.OpenApiProxy)
		case *pb.ServerMessage_RunBench:
			// Not the session context: the Job keeps running through a
			// disconnect and its results are re-sent afterwards.
			go a.runBench(a.life, v.RunBench)
		case *pb.ServerMessage_Resync:
			a.disc.requestResync()
		}
	}
}

func (a *Agent) send(m *pb.AgentMessage) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	if a.control == nil {
		return errors.New("not connected")
	}
	return a.control.Send(m)
}

func (a *Agent) runBench(ctx context.Context, req *pb.RunBench) {
	status := func(s *pb.BenchStatus) {
		a.out.deliver(&pb.AgentMessage{Msg: &pb.AgentMessage_BenchStatus{BenchStatus: s}}, a.send)
	}
	if a.Bench == nil || !a.cfg.BenchEnabled {
		status(&pb.BenchStatus{RunId: req.RunId, NodeName: req.NodeName, State: "rejected", Message: "kube-bench is not enabled on this agent"})
		return
	}
	var seq uint32 // one Run is one run and node
	a.Bench.Run(ctx, req, status, func(c *pb.BenchResultChunk) {
		seq++
		c.Seq = seq
		a.out.deliver(&pb.AgentMessage{Msg: &pb.AgentMessage_BenchResult{BenchResult: c}}, a.send)
	})
}

// serveHealth exposes /healthz on localhost only.
func (a *Agent) serveHealth(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !a.connected.Load() {
			http.Error(w, "not connected", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: a.cfg.HealthAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.log.Error("health endpoint", "err", err)
	}
}
