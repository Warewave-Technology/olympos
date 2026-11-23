package synthetic

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
)

func (e *env) probeState(id uuid.UUID) (status string, alerted bool) {
	e.t.Helper()
	if err := e.db.QueryRow(e.ctx, `SELECT probe_status, probe_offline_alerted FROM clusters WHERE id = $1`, id).Scan(&status, &alerted); err != nil {
		e.t.Fatal(err)
	}
	return status, alerted
}

func (e *env) events(eventType string) int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM outbox WHERE event_type = $1`, eventType)
}

func (e *env) checkOffline() {
	e.t.Helper()
	if err := e.svc.CheckProbesOffline(e.ctx); err != nil {
		e.t.Fatal(err)
	}
}

// probe.offline only after 5 minutes offline, once; one probe.online only
// after it; a short blip sends nothing (F18 rules, §5).
func TestProbeOfflineDebounce(t *testing.T) {
	e := newEnv(t)
	cl := e.cluster("ist-lab", ProbePending)
	if err := e.svc.probeConnected(e.ctx, cl, &pb.ProbeHello{ProbeVersion: "0.3.0"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.probeState(cl); st != ProbeOnlineState {
		t.Fatalf("after connect: %s", st)
	}
	var version string
	if err := e.db.QueryRow(e.ctx, `SELECT probe_version FROM clusters WHERE id = $1`, cl).Scan(&version); err != nil || version != "0.3.0" {
		t.Fatalf("version %q (%v)", version, err)
	}

	// Last traffic at t0; offline after gateway.OfflineAfter, silently.
	e.svc.probeSeen(e.ctx, cl)
	e.clock.add(gateway.OfflineAfter - time.Second)
	e.checkOffline()
	if st, _ := e.probeState(cl); st != ProbeOnlineState {
		t.Fatalf("offline too early: %s", st)
	}
	e.clock.add(2 * time.Second)
	e.checkOffline()
	if st, _ := e.probeState(cl); st != ProbeOfflineState || e.events(notify.ProbeOffline) != 0 {
		t.Fatalf("after %s: %s, %d messages", gateway.OfflineAfter, st, e.events(notify.ProbeOffline))
	}
	// 4 minutes after the last traffic: still nothing.
	e.clock.add(4*time.Minute - gateway.OfflineAfter - time.Second)
	e.checkOffline()
	if e.events(notify.ProbeOffline) != 0 {
		t.Fatal("probe.offline before 5 minutes")
	}
	// 5 minutes: one message, however often the check runs.
	e.clock.add(time.Minute + time.Second)
	e.checkOffline()
	e.checkOffline()
	e.clock.add(10 * time.Minute)
	e.checkOffline()
	if n := e.events(notify.ProbeOffline); n != 1 {
		t.Fatalf("%d probe.offline messages", n)
	}
	// Back: one probe.online.
	e.svc.probeSeen(e.ctx, cl)
	if st, alerted := e.probeState(cl); st != ProbeOnlineState || alerted {
		t.Fatalf("after traffic: %s alerted=%v", st, alerted)
	}
	e.svc.probeSeen(e.ctx, cl)
	if err := e.svc.probeConnected(e.ctx, cl, &pb.ProbeHello{ProbeVersion: "0.3.0"}); err != nil {
		t.Fatal(err)
	}
	if n := e.events(notify.ProbeOnline); n != 1 {
		t.Fatalf("%d probe.online messages", n)
	}

	// A short blip, through a reconnect: offline, then back within 5
	// minutes, sends nothing.
	e.clock.add(gateway.OfflineAfter + time.Second)
	e.checkOffline()
	if st, _ := e.probeState(cl); st != ProbeOfflineState {
		t.Fatalf("blip not offline: %s", st)
	}
	e.clock.add(2 * time.Minute)
	if err := e.svc.probeConnected(e.ctx, cl, &pb.ProbeHello{ProbeVersion: "0.3.1"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.probeState(cl); st != ProbeOnlineState {
		t.Fatalf("after the reconnect: %s", st)
	}
	for range 40 { // 10 minutes of traffic every 15 s
		e.clock.add(15 * time.Second)
		e.svc.probeSeen(e.ctx, cl)
		e.checkOffline()
	}
	if st, _ := e.probeState(cl); st != ProbeOnlineState {
		t.Fatalf("with traffic: %s", st)
	}
	if e.events(notify.ProbeOffline) != 1 || e.events(notify.ProbeOnline) != 1 {
		t.Fatalf("blip sent messages: %d offline, %d online", e.events(notify.ProbeOffline), e.events(notify.ProbeOnline))
	}
	if n := e.count(`SELECT count(*) FROM activity_log WHERE action = 'probe.offline' AND cluster_id = $1`, cl); n != 2 {
		t.Fatalf("%d probe.offline activities, want one per outage", n)
	}
}

// The probe offline check waits gateway.OfflineAfter after a server start:
// probes need that long to reconnect.
func TestProbeOfflineWaitsAfterStart(t *testing.T) {
	e := newEnv(t)
	cl := e.cluster("c1", ProbeOnlineState)
	e.exec(`UPDATE clusters SET probe_last_seen_at = $2 WHERE id = $1`, cl, e.clock.now().Add(-time.Hour))
	e.svc.Started = e.clock.now()
	e.clock.add(gateway.OfflineAfter - time.Second)
	e.checkOffline()
	if st, _ := e.probeState(cl); st != ProbeOnlineState {
		t.Fatalf("offline right after start: %s", st)
	}
	e.clock.add(2 * time.Second)
	e.checkOffline()
	var since time.Time
	if err := e.db.QueryRow(e.ctx, `SELECT probe_offline_since FROM clusters WHERE id = $1`, cl).Scan(&since); err != nil {
		t.Fatal(err)
	}
	if !since.Equal(e.svc.Started) {
		t.Fatalf("outage counted from %s, want the start %s", since, e.svc.Started)
	}
}

// A revoked probe stays revoked: its stream is refused, and its traffic
// does not bring it back.
func TestRevokedProbeStaysRevoked(t *testing.T) {
	e := newEnv(t)
	cl := e.cluster("c1", ProbeRevoked)
	if err := e.svc.probeConnected(e.ctx, cl, &pb.ProbeHello{ProbeVersion: "x"}); err == nil {
		t.Fatal("revoked probe connected")
	}
	e.svc.probeSeen(e.ctx, cl)
	e.clock.add(time.Hour)
	e.checkOffline()
	if st, _ := e.probeState(cl); st != ProbeRevoked {
		t.Fatalf("revoked probe is %s", st)
	}
	e.exec(`UPDATE clusters SET status = 'revoked', probe_status = 'online' WHERE id = $1`, cl)
	if err := e.svc.probeConnected(e.ctx, cl, &pb.ProbeHello{}); err == nil {
		t.Fatal("probe of a revoked cluster connected")
	}
}

// InstallHooks wires every hook but Disconnected.
func TestInstallHooks(t *testing.T) {
	e := newEnv(t)
	var h gateway.ProbeHooks
	e.svc.InstallHooks(&h)
	if h.Connected == nil || h.Seen == nil || h.Result == nil || h.Rejected == nil || h.Disconnected != nil {
		t.Fatalf("hooks %+v", h)
	}
}
