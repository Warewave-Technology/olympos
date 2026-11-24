package gateway_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func probeHello(t *testing.T, id uuid.UUID) *pb.ProbeMessage {
	t.Helper()
	key, err := spec.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &pb.ProbeMessage{Msg: &pb.ProbeMessage_Hello{Hello: &pb.ProbeHello{ClusterId: id.String(),
		HpkePublicKey: key.PublicKey().Bytes(), MaxConcurrency: 1}}}
}

// recvErr waits for the server to end the stream.
func recvErr(t *testing.T, recv func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for {
			if err := recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("stream not ended by the server")
		return nil
	}
}

// pauseBeforeHello makes the server stop after a stream authenticated and
// before it reads the hello, until the returned release is called.
func pauseBeforeHello(gw *gateway.Gateway) (reached <-chan pki.IdentityRole, release func()) {
	r := make(chan pki.IdentityRole, 1)
	gate := make(chan struct{})
	gateway.SetAttachHooks(gw, func(role pki.IdentityRole) {
		r <- role
		<-gate
	}, nil)
	var once sync.Once
	return r, func() { once.Do(func() { close(gate) }) }
}

func waitReached(t *testing.T, reached <-chan pki.IdentityRole, want pki.IdentityRole) {
	t.Helper()
	select {
	case r := <-reached:
		if r != want {
			t.Fatalf("paused %v, want %v", r, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not authenticate the stream")
	}
}

// A probe authenticates, then is revoked while its hello is on the way:
// the hello must not attach it.
func TestProbeRevokedWhileAwaitingHello(t *testing.T) {
	for _, how := range []string{"probe", "cluster"} {
		t.Run(how, func(t *testing.T) {
			e := start(t)
			n := countConnects(e.gw)
			reached, release := pauseBeforeHello(e.gw)
			defer release()
			id, _, probe := e.enrolled(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			st, err := e.dialProbe(t, probe).Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Send(probeHello(t, id)); err != nil {
				t.Fatal(err)
			}
			waitReached(t, reached, pki.RoleProbe)
			if how == "probe" {
				err = e.gw.RevokeProbe(ctx, e.gw.DB, id)
			} else {
				err = e.gw.Revoke(ctx, e.gw.DB, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			release()

			wantCode(t, "hello after revoke", recvErr(t, func() error { _, err := st.Recv(); return err }), codes.PermissionDenied)
			if _, ok := e.gw.ProbeConnected(id); ok || n.Load() != 0 {
				t.Fatalf("revoked probe attached (connected hooks: %d)", n.Load())
			}
		})
	}
}

// The agent's Control has the same bound: a revoke during the hello wins.
func TestAgentRevokedWhileAwaitingHello(t *testing.T) {
	e := start(t)
	var connects atomic.Int32
	e.gw.Hooks.Connected = func(context.Context, uuid.UUID, *pb.Hello) error { connects.Add(1); return nil }
	reached, release := pauseBeforeHello(e.gw)
	defer release()
	id, agent, _ := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctl, err := e.dial(t, agent).Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{ClusterId: id.String()}}}); err != nil {
		t.Fatal(err)
	}
	waitReached(t, reached, pki.RoleAgent)
	if err := e.gw.Revoke(ctx, e.gw.DB, id); err != nil {
		t.Fatal(err)
	}
	release()
	wantCode(t, "agent hello after revoke", recvErr(t, func() error { _, err := ctl.Recv(); return err }), codes.PermissionDenied)
	if e.gw.Connected(id) || connects.Load() != 0 {
		t.Fatalf("revoked agent attached (connected hooks: %d)", connects.Load())
	}
}

// A revoke that commits just after the stream was registered and checked
// again is caught by DisconnectProbe (Disconnect for the agent): the stream
// never becomes usable and its Connected hook never runs.
func TestRevokeJustAfterAttachIsCaught(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	var agentConnects atomic.Int32
	e.gw.Hooks.Connected = func(context.Context, uuid.UUID, *pb.Hello) error { agentConnects.Add(1); return nil }
	id, agent, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway.SetAttachHooks(e.gw, nil, func(role pki.IdentityRole) {
		var err error
		if role == pki.RoleProbe {
			err = e.gw.RevokeProbe(context.Background(), e.gw.DB, id)
		} else {
			err = e.gw.Revoke(context.Background(), e.gw.DB, id)
		}
		if err != nil {
			t.Error(err)
		}
	})

	st, err := e.dialProbe(t, probe).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(probeHello(t, id)); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "probe revoked after attach", recvErr(t, func() error { _, err := st.Recv(); return err }), codes.Aborted)
	if _, ok := e.gw.ProbeConnected(id); ok || n.Load() != 0 {
		t.Fatalf("probe usable after revoke (connected hooks: %d)", n.Load())
	}
	if _, err := e.gw.SendRun(id, serialOf(t, probe), func(gateway.ProbeInfo) (*pb.RunScenario, error) { return &pb.RunScenario{RunId: "r"}, nil }); !errors.Is(err, gateway.ErrProbeOffline) {
		t.Fatalf("SendRun to a revoked probe: %v", err)
	}

	ctl, err := e.dial(t, agent).Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{ClusterId: id.String()}}}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "agent revoked after attach", recvErr(t, func() error { _, err := ctl.Recv(); return err }), codes.Aborted)
	if e.gw.Connected(id) || agentConnects.Load() != 0 {
		t.Fatalf("agent attached after revoke (connected hooks: %d)", agentConnects.Load())
	}
}

// An authenticated client that never says hello is dropped.
func TestHelloTimeout(t *testing.T) {
	e := start(t)
	gateway.SetHelloTimeout(e.gw, 200*time.Millisecond)
	_, agent, probe := e.enrolled(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := e.dialProbe(t, probe).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := e.dial(t, agent).Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, recv := range map[string]func() error{
		"probe": func() error { _, err := st.Recv(); return err },
		"agent": func() error { _, err := ctl.Recv(); return err },
	} {
		err := recvErr(t, recv)
		if s := status.Convert(err); s.Code() != codes.DeadlineExceeded || s.Message() != "no hello in time" {
			t.Fatalf("%s without hello: %v", name, err)
		}
	}
}

// SendRun never uses a stream whose Connected hook has not run, or failed;
// Disconnected still follows a failed Connected.
func TestProbeUsableOnlyAfterConnectedHook(t *testing.T) {
	e := start(t)
	entered := make(chan struct{}, 2)
	gate := make(chan error)
	e.gw.ProbeHooks.Connected = func(ctx context.Context, _ uuid.UUID, _ *pb.ProbeHello) error {
		entered <- struct{}{}
		select {
		case err := <-gate:
			return err
		case <-ctx.Done(): // the server stops at the end of the test
			return ctx.Err()
		}
	}
	waitEntered := func() {
		t.Helper()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("Connected hook not called")
		}
	}
	disconnected := make(chan struct{}, 2)
	e.gw.ProbeHooks.Disconnected = func(uuid.UUID) { disconnected <- struct{}{} }
	id, _, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc := e.dialProbe(t, probe)

	// A failing hook refuses the stream.
	st, err := pc.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(probeHello(t, id)); err != nil {
		t.Fatal(err)
	}
	waitEntered()
	if _, ok := e.gw.ProbeConnected(id); ok {
		t.Fatal("stream usable while its Connected hook runs")
	}
	if _, err := e.gw.SendRun(id, serialOf(t, probe), func(gateway.ProbeInfo) (*pb.RunScenario, error) {
		t.Error("build called for a stream whose Connected hook has not returned")
		return nil, nil
	}); !errors.Is(err, gateway.ErrProbeOffline) {
		t.Fatalf("SendRun during Connected: %v", err)
	}
	gate <- errors.New("hook failed")
	wantCode(t, "failed Connected hook", recvErr(t, func() error { _, err := st.Recv(); return err }), codes.Unavailable)
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("Disconnected not called after a failed Connected")
	}
	if _, ok := e.gw.ProbeConnected(id); ok {
		t.Fatal("stream with a failed Connected hook usable")
	}

	// A succeeding hook makes it usable.
	if _, err := connectProbe(t, ctx, pc, id.String(), 1); err != nil {
		t.Fatal(err)
	}
	waitEntered()
	gate <- nil
	for i := 0; ; i++ {
		if _, ok := e.gw.ProbeConnected(id); ok {
			break
		}
		if i == 200 {
			t.Fatal("stream not usable after its Connected hook succeeded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A fresh probe enrollment replaces the identity and drops the old streams.
func TestProbeReenrollDropsOldStreams(t *testing.T) {
	e := start(t)
	n := countConnects(e.gw)
	id, _, probe := e.enrolled(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := connectProbe(t, ctx, e.dialProbe(t, probe), id.String(), 1); err != nil {
		t.Fatal(err)
	}
	waitProbes(t, e.gw, id, n, 1)
	if _, _, err := enrollAs(t, e.dial(t, nil), e.newToken(t, id, []string{"probe"}, time.Hour), pb.EnrollRole_ENROLL_ROLE_PROBE); err != nil {
		t.Fatal(err)
	}
	waitGone(t, "old probe stream", probeConnected(e.gw, id))
	wantCode(t, "old identity reconnects", refusedProbe(t, e.dialProbe(t, probe), id.String()), codes.PermissionDenied)
}

// Two probe enrollments at once (two probe-only tokens) run one after the
// other: the later one revokes the earlier one's serial.
func TestConcurrentProbeEnrollments(t *testing.T) {
	e := start(t)
	for i := range 5 {
		id, _ := e.newCluster(t)
		tokens := []string{e.newToken(t, id, []string{"probe"}, time.Hour), e.newToken(t, id, []string{"probe"}, time.Hour)}
		serials := make([]string, 2)
		var wg sync.WaitGroup
		begin := make(chan struct{})
		for j := range 2 {
			wg.Go(func() {
				<-begin
				cert, _, err := enrollAs(t, e.dial(t, nil), tokens[j], pb.EnrollRole_ENROLL_ROLE_PROBE)
				if err != nil {
					t.Error(err)
					return
				}
				serials[j] = serialOf(t, cert)
			})
		}
		close(begin)
		wg.Wait()
		if t.Failed() {
			return
		}
		cur, _ := e.probeSerials(t, id)
		loser := serials[0]
		if cur == serials[0] {
			loser = serials[1]
		} else if cur != serials[1] {
			t.Fatalf("round %d: current serial %q is neither enrollment's", i, cur)
		}
		if !e.isRevoked(t, loser) {
			t.Fatalf("round %d: the earlier enrollment's serial is not revoked", i)
		}
	}
}
