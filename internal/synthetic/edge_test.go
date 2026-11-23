package synthetic

import (
	"strings"
	"testing"
	"time"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// Ruling P13: a run due after its scenario was disabled is skipped, not
// sent; a test run is not affected. A credential past its expires_at ends
// the run as an error, and is never sent.
func TestDisabledScenarioAndExpiredCredential(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	cl := e.cluster("c1", ProbeOnlineState)
	e.probes.connect(t, cl, 8)

	sc := e.scenario("s", true, httpStep("https://api.example.com/", nil))
	run := e.schedule(sc, cl, 0)
	e.exec(`UPDATE scenarios SET enabled = false WHERE id = $1`, sc)
	test := e.testRun(cl, spec.Scenario{Name: "t", Type: spec.TypeHTTP, IntervalSeconds: 60, TimeoutSeconds: 5,
		Steps: []spec.Step{httpStep("https://api.example.com/", nil)}})
	if n := e.dispatch(); n != 1 {
		t.Fatalf("sent %d, want only the test run", n)
	}
	e.wantRun(run, StatusSkipped, ReasonScenarioDisabled)
	e.wantRun(test, StatusRunning, "")

	cred := e.credential("old", spec.CredBearer, "x", "expired-secret-555", "suffix:example.com")
	e.exec(`UPDATE synthetic_credentials SET expires_at = $2 WHERE id = $1`, cred, e.clock.now().Add(-time.Minute))
	expired := e.schedule(e.scenario("uses old", true, httpStep("https://api.example.com/", &cred)), cl, 0)
	e.dispatch()
	e.wantRun(expired, StatusError, ReasonCredentialExpired)
	if len(e.probes.messages()) != 1 {
		t.Fatal("a run with an expired credential was sent")
	}
	// Not yet expired: sent.
	e.exec(`UPDATE synthetic_credentials SET expires_at = $2 WHERE id = $1`, cred, e.clock.now().Add(time.Hour))
	fresh := e.schedule(e.scenario("uses fresh", true, httpStep("https://api.example.com/", &cred)), cl, 0)
	e.dispatch()
	e.wantRun(fresh, StatusRunning, "")
}

// Ruling P14: a credential the server cannot resolve (here the envelope
// does not open) skips the run: the fault is not the scenario's.
func TestCredentialUnavailableSkipped(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	cl := e.cluster("c1", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 8)
	cred := e.credential("broken", spec.CredBearer, "x", "unopenable-secret-666", "suffix:example.com")
	e.exec(`UPDATE credentials SET ciphertext = decode('00112233445566778899aabbccddeeff0011223344', 'hex')
		WHERE id = (SELECT credential_id FROM synthetic_credentials WHERE id = $1)`, cred)
	run := e.schedule(e.scenario("s", true, httpStep("https://api.example.com/", &cred)), cl, 0)
	e.dispatch()
	e.wantRun(run, StatusSkipped, ReasonCredentialUnavailable)
	if len(e.probes.messages()) != 0 || e.probes.inFlight(sess) != 0 {
		t.Fatal("run sent or slot kept")
	}
	if o := e.results(); len(o) != 1 || o[0].Status != StatusSkipped {
		t.Fatalf("outcomes %+v", o)
	}
}

// Minor 1: a run whose result came is not skipped because its stream then
// ended; the result is still stored.
func TestReleasedRunNotSkippedOnDisconnect(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	cl := e.cluster("c1", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 8)
	run := e.dispatched(e.scenario("s", true, httpStep("https://api.example.com/", nil)), cl)
	e.svc.release(run, cl) // the result arrived and is being stored
	e.probes.drop(sess)
	e.dispatch()
	e.wantRun(run, StatusRunning, "")
	if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: run.String(), Status: StatusPassed,
		Steps: []*pb.StepResult{{Position: 0, Status: StatusPassed}}}); err != nil {
		t.Fatal(err)
	}
	e.wantRun(run, StatusPassed, "")
	// Had it never been stored, the deadline still ends it.
	sess = e.probes.connect(t, cl, 8)
	late := e.dispatched(e.scenario("t", true, httpStep("https://api.example.com/", nil)), cl)
	e.svc.release(late, cl)
	e.probes.drop(sess)
	e.clock.add(10*time.Second + ResultGrace + time.Second)
	e.dispatch()
	e.wantRun(late, StatusError, ReasonNoResult)
}

// Minor 4: a probe that advertises a huge concurrency gets at most MaxClaim
// runs per pass.
func TestClaimCapped(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	cl := e.cluster("c1", ProbeOnlineState)
	e.probes.connect(t, cl, 1000)
	for range 30 {
		e.schedule(e.scenario("s", true, httpStep("https://api.example.com/", nil)), cl, 0)
	}
	if n := e.dispatch(); n != MaxClaim {
		t.Fatalf("sent %d in one pass, want %d", n, MaxClaim)
	}
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE status = 'scheduled'`); n != 30-MaxClaim {
		t.Fatalf("%d left scheduled", n)
	}
}

// Minor 6: a probe re-enrolled while alerted offline sends its probe.online
// on the first connect; one not alerted sends none. Minor 5: the version is
// bounded.
func TestReenrolledProbeOnline(t *testing.T) {
	e := newEnv(t)
	alerted := e.cluster("alerted", ProbePending)
	e.exec(`UPDATE clusters SET probe_offline_alerted = true, probe_offline_since = $2 WHERE id = $1`, alerted, e.clock.now().Add(-time.Hour))
	quiet := e.cluster("quiet", ProbePending)
	long := "v" + strings.Repeat("x", 100)
	if err := e.svc.probeConnected(e.ctx, alerted, &pb.ProbeHello{ProbeVersion: long}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.probeConnected(e.ctx, quiet, &pb.ProbeHello{ProbeVersion: "0.3.0"}); err != nil {
		t.Fatal(err)
	}
	if n := e.events(notify.ProbeOnline); n != 1 {
		t.Fatalf("%d probe.online, want 1", n)
	}
	if st, a := e.probeState(alerted); st != ProbeOnlineState || a {
		t.Fatalf("alerted probe %s alerted=%v", st, a)
	}
	var v string
	if err := e.db.QueryRow(e.ctx, `SELECT probe_version FROM clusters WHERE id = $1`, alerted).Scan(&v); err != nil || len(v) > maxVersion {
		t.Fatalf("version %d bytes (%v)", len(v), err)
	}
	// A second connect sends nothing more.
	if err := e.svc.probeConnected(e.ctx, alerted, &pb.ProbeHello{ProbeVersion: "0.3.0"}); err != nil {
		t.Fatal(err)
	}
	if n := e.events(notify.ProbeOnline); n != 1 {
		t.Fatalf("%d probe.online after reconnect", n)
	}
}
