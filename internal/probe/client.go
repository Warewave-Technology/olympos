package probe

import (
	"context"
	"crypto/hpke"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// RunRejected reasons.
const (
	RejectBusy                  = "busy"
	RejectAllowlistStale        = "allowlist_stale"
	RejectCredentialsUnreadable = "credentials_unreadable"
	RejectInvalidScenario       = "invalid_scenario"
)

const (
	// SilenceAfter closes a stream on which nothing arrived for this long.
	// The server pings every 15 s and drops a silent probe after the same
	// time (gateway.OfflineAfter).
	SilenceAfter = 60 * time.Second
	// minBackoff and maxBackoff bound the wait before dialing again after
	// a stream failed.
	minBackoff = time.Second
	maxBackoff = time.Minute
	// drainWait is how long a closing stream waits for its cancelled runs.
	drainWait = 10 * time.Second
	// seenRuns is how many run ids are remembered to ignore duplicates.
	seenRuns = 8192
	// maxRunID is the longest run id accepted.
	maxRunID = 128
)

var (
	errIdentityChanged = errors.New("probe identity changed")
	errSilent          = errors.New("no traffic from the server")
)

// Client is olympos-probe's connection to the Olympos gateway. It dials
// ProbeGateway.Connect with the probe identity, and for each stream makes a
// new HPKE key pair whose public half goes in the ProbeHello. It runs the
// RunScenario messages it receives and answers each with a RunResult or a
// RunRejected.
//
// Nothing a run carries is logged: not the scenario (its URLs, headers and
// bodies) and not its credentials, only run ids, reasons and statuses.
type Client struct {
	cfg      Config
	ident    *Identity
	resolver Resolver
	redactor *sensitive.Redactor
	log      *slog.Logger

	// Test seams. net is the runs' Dialer.Net (nil: a net.Dialer).
	net        func(ctx context.Context, network, addr string) (net.Conn, error)
	silence    time.Duration
	minBackoff time.Duration
	// afterRun sees a run's credentials once they were zeroed.
	afterRun func([]spec.RunCredential)

	sem chan struct{} // one token per run in progress, process-wide
	// allowMax is the highest allowlist version seen by this process.
	allowMax  atomic.Int64
	seen      *runIDs
	connected atomic.Bool
}

// NewClient returns a client for cfg. resolver serves the runs' DNS
// (SystemResolver in a pod); redactor scrubs what leaves the probe.
func NewClient(cfg Config, ident *Identity, resolver Resolver, redactor *sensitive.Redactor, log *slog.Logger) *Client {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.MaxConcurrency < 1 {
		cfg.MaxConcurrency = DefaultMaxConcurrency
	}
	return &Client{cfg: cfg, ident: ident, resolver: resolver, redactor: redactor, log: log,
		silence: SilenceAfter, minBackoff: minBackoff,
		sem: make(chan struct{}, cfg.MaxConcurrency), seen: newRunIDs(seenRuns)}
}

// Connected reports whether a stream is open (for /readyz).
func (c *Client) Connected() bool { return c.connected.Load() }

// Run watches the identity files and keeps a stream open until ctx ends.
// It returns nil when ctx ends.
func (c *Client) Run(ctx context.Context) error {
	go c.ident.Watch(ctx)
	backoff := c.minBackoff
	for {
		snap, changed, ok := c.waitIdentity(ctx)
		if !ok {
			return nil
		}
		start := time.Now()
		err := c.stream(ctx, snap, changed)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errIdentityChanged) {
			// The server accepts only the newest certificate: dial again
			// with it at once.
			c.log.Info("reconnecting with the new probe identity")
			backoff = c.minBackoff
			continue
		}
		c.log.Warn("probe stream ended", "err", err)
		if time.Since(start) > time.Minute {
			backoff = c.minBackoff
		}
		wait := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1))
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-changed:
			// A new certificate may be what the server was waiting for.
			backoff = c.minBackoff
		case <-t.C:
			backoff = min(backoff*2, maxBackoff)
		}
		t.Stop()
	}
}

// waitIdentity returns the current identity, waiting for one if none was
// read yet. ok is false when ctx ended.
func (c *Client) waitIdentity(ctx context.Context) (*identitySnapshot, <-chan struct{}, bool) {
	for {
		snap, changed := c.ident.current()
		if snap != nil {
			return snap, changed, true
		}
		select {
		case <-ctx.Done():
			return nil, nil, false
		case <-changed:
		}
	}
}

// probeStream is one Connect stream.
type probeStream struct {
	ctx    context.Context
	mu     sync.Mutex
	stream pb.ProbeGateway_ConnectClient
}

// send sends m unless the stream has ended: a run's result goes out on the
// stream its run came on, or not at all.
func (s *probeStream) send(m *pb.ProbeMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	return s.stream.Send(m)
}

// stream runs one Connect stream until it fails, ctx ends or the identity
// changes.
func (c *Client) stream(ctx context.Context, snap *identitySnapshot, changed <-chan struct{}) error {
	// The stream's key (decision 2): made for this stream only, kept in
	// memory only, and dropped when the stream ends, so a run sealed to it
	// cannot be opened after a reconnect.
	priv, err := spec.GenerateKey()
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              snap.pool,
		ServerName:           c.cfg.ServerName,
		GetClientCertificate: c.ident.GetClientCertificate,
	}
	conn, err := grpc.NewClient(c.cfg.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithUserAgent("olympos-probe/"+Version),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	sctx, cancel := context.WithCancel(ctx)
	var runs sync.WaitGroup
	defer func() {
		// Cancel the stream's runs; their results are never sent on
		// another stream.
		cancel()
		waitRuns(&runs, drainWait)
		priv = nil
	}()
	st, err := pb.NewProbeGatewayClient(conn).Connect(sctx)
	if err != nil {
		return err
	}
	s := &probeStream{ctx: sctx, stream: st}
	// The gateway waits at most 30 s for the hello: it goes first, at once.
	if err := s.send(&pb.ProbeMessage{Msg: &pb.ProbeMessage_Hello{Hello: &pb.ProbeHello{
		ProbeVersion:     Version,
		ClusterId:        snap.clusterID,
		HpkePublicKey:    priv.PublicKey().Bytes(),
		MaxConcurrency:   int32(c.cfg.MaxConcurrency),
		AllowlistVersion: c.allowMax.Load(),
	}}}); err != nil {
		return err
	}
	c.connected.Store(true)
	defer c.connected.Store(false)
	c.log.Info("connected to olympos", "server", c.cfg.Server, "cluster_id", snap.clusterID, "serial", snap.serial)

	msgs := make(chan *pb.ServerProbeMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- m:
			case <-sctx.Done():
				return
			}
		}
	}()
	idle := time.NewTimer(c.silence)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
			return errIdentityChanged
		case err := <-recvErr:
			return err
		case <-idle.C:
			return errSilent
		case m := <-msgs:
			idle.Reset(c.silence)
			switch v := m.Msg.(type) {
			case *pb.ServerProbeMessage_Ping:
				if v.Ping == nil {
					continue
				}
				if err := s.send(&pb.ProbeMessage{Msg: &pb.ProbeMessage_Pong{Pong: &pb.Pong{UnixNano: v.Ping.UnixNano}}}); err != nil {
					return err
				}
			case *pb.ServerProbeMessage_Run:
				if v.Run != nil {
					c.handleRun(s, priv, snap.clusterID, v.Run, &runs)
				}
			}
		}
	}
}

// waitRuns waits for wg, at most d: a run that ignores its cancellation
// must not keep the probe from dialing again. It still holds its
// concurrency slot until it ends, and cannot send its result.
func waitRuns(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}

// handleRun checks a RunScenario and starts it, or rejects it. It runs on
// the stream's receive loop, the only user of the stream's key.
func (c *Client) handleRun(s *probeStream, priv hpke.PrivateKey, clusterID string, run *pb.RunScenario, runs *sync.WaitGroup) {
	id := run.RunId
	if id == "" || len(id) > maxRunID {
		c.log.Warn("run without a valid id ignored")
		return
	}
	if c.seen.has(id) {
		c.log.Info("duplicate run ignored", "run_id", id)
		return
	}
	reject := func(reason string) {
		c.log.Warn("run rejected", "run_id", id, "reason", reason)
		if err := s.send(&pb.ProbeMessage{Msg: &pb.ProbeMessage_Rejected{Rejected: &pb.RunRejected{RunId: id, Reason: reason}}}); err != nil {
			c.log.Warn("cannot send run rejection", "run_id", id, "err", err)
		}
	}
	select {
	case c.sem <- struct{}{}:
	default:
		reject(RejectBusy)
		return
	}
	started := false
	defer func() {
		if !started {
			<-c.sem
		}
	}()
	allow, ok := c.checkAllowlist(run.Allowlist)
	if !ok {
		reject(RejectAllowlistStale)
		return
	}
	sc, fields := parseScenario(run.ScenarioJson)
	if sc == nil {
		// The field paths only, never their values.
		c.log.Warn("invalid scenario", "run_id", id, "fields", fields)
		reject(RejectInvalidScenario)
		return
	}
	creds, err := openCredentials(priv, id, clusterID, run.Credentials)
	if err != nil {
		reject(RejectCredentialsUnreadable)
		return
	}
	c.seen.add(id)
	started = true
	runs.Add(1)
	go func() {
		defer runs.Done()
		defer func() { <-c.sem }()
		c.execute(s, id, sc, allow, creds, run.Test)
	}()
}

// checkAllowlist turns the run's snapshot into a hostallow.List. The
// snapshot must have a version above 0 and at least the highest this
// process has seen, and every rule must be valid.
func (c *Client) checkAllowlist(a *pb.AllowlistSnapshot) (hostallow.List, bool) {
	if a == nil || a.Version <= 0 || a.Version < c.allowMax.Load() {
		return hostallow.List{}, false
	}
	l := hostallow.List{Version: a.Version, Rules: make([]hostallow.Rule, 0, len(a.Rules))}
	for _, r := range a.Rules {
		if r == nil {
			return hostallow.List{}, false
		}
		v, err := hostallow.ValidateRule(hostallow.Rule{Pattern: r.Pattern, Kind: hostallow.Kind(r.Kind)})
		if err != nil {
			return hostallow.List{}, false
		}
		l.Rules = append(l.Rules, v)
	}
	for {
		cur := c.allowMax.Load()
		if a.Version < cur {
			return hostallow.List{}, false
		}
		if a.Version == cur || c.allowMax.CompareAndSwap(cur, a.Version) {
			return l, true
		}
	}
}

// parseScenario decodes and validates scenario_json. When it is invalid,
// it returns the JSON paths of the invalid fields ("json" when it does not
// decode), for the log.
func parseScenario(b []byte) (*spec.Scenario, []string) {
	var s spec.Scenario
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, []string{"json"}
	}
	if f := spec.Validate(&s); len(f) > 0 {
		// A header's key ends in the header's name, which is the
		// scenario's text: it is cut off.
		paths := map[string]bool{}
		for k := range f {
			if i := strings.Index(k, ".headers."); i >= 0 {
				k = k[:i+len(".headers")]
			}
			paths[k] = true
		}
		return nil, slices.Sorted(maps.Keys(paths))
	}
	return &s, nil
}

// openCredentials opens the run's sealed credentials with the stream's key.
// A run without credentials has none.
func openCredentials(priv hpke.PrivateKey, runID, clusterID string, sc *pb.SealedCredentials) ([]spec.RunCredential, error) {
	if sc == nil {
		return nil, nil
	}
	if len(sc.Enc) == 0 || len(sc.Ciphertext) == 0 {
		return nil, errors.New("probe: empty sealed credentials")
	}
	return spec.OpenCredentials(priv, runID, clusterID, sc.Enc, sc.Ciphertext)
}

// execute runs one scenario and sends its result on s, unless s ended
// meanwhile. The credentials are zeroed when it returns, however the run
// ended.
func (c *Client) execute(s *probeStream, id string, sc *spec.Scenario, allow hostallow.List, creds []spec.RunCredential, test bool) {
	if c.afterRun != nil {
		defer c.afterRun(creds)
	}
	defer spec.ZeroCredentials(creds)
	// Runner.Run applies the same deadline; this one also holds if it did
	// not.
	ctx, cancel := context.WithTimeout(s.ctx, time.Duration(sc.TimeoutSeconds)*time.Second)
	defer cancel()
	r := &Runner{
		Dialer:   &Dialer{Allow: allow, Resolver: c.resolver, APIServer: c.cfg.APIServer, Net: c.net},
		Redactor: c.redactor,
	}
	start := time.Now()
	res := r.Run(ctx, sc, creds)
	res.RunId = id
	res.ProbeVersion = Version
	if s.ctx.Err() != nil {
		c.log.Info("run result dropped: its stream ended", "run_id", id)
		return
	}
	if err := s.send(&pb.ProbeMessage{Msg: &pb.ProbeMessage_Result{Result: res}}); err != nil {
		c.log.Warn("cannot send run result", "run_id", id, "err", err)
		return
	}
	c.log.Info("run finished", "run_id", id, "status", res.Status, "failed_step", res.FailedStep,
		"test", test, "duration_ms", time.Since(start).Milliseconds())
}

// runIDs remembers the most recent run ids, at most n.
type runIDs struct {
	mu   sync.Mutex
	set  map[string]struct{}
	ring []string
	next int
}

func newRunIDs(n int) *runIDs {
	return &runIDs{set: make(map[string]struct{}, n), ring: make([]string, n)}
}

func (r *runIDs) has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.set[id]
	return ok
}

// add remembers id, forgetting the oldest when full.
func (r *runIDs) add(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.set[id]; ok {
		return
	}
	if old := r.ring[r.next]; old != "" {
		delete(r.set, old)
	}
	r.ring[r.next] = id
	r.set[id] = struct{}{}
	r.next = (r.next + 1) % len(r.ring)
}

// ServeHealth serves /healthz (the process is up) and /readyz (a stream is
// open) on addr, which must be localhost, until ctx ends.
func ServeHealth(ctx context.Context, addr string, ready func() bool, log *slog.Logger) error {
	if !localhostAddr(addr) {
		return errors.New("probe: health address must be localhost-only")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not connected", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if log != nil {
			log.Error("health endpoint", "err", err)
		}
		return err
	}
	return nil
}
