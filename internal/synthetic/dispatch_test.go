package synthetic

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// A run's credentials are sealed to the key of the stream it is sent on:
// that key opens them, another key does not, and nor does the same key for
// another run or cluster. The sealed set is exactly the credentials the
// steps name, with their bound hosts in hostallow.FormatRule form.
func TestDispatchSealsToSessionKey(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	e.allow("exact", "api.other.net")
	bearer := e.credential("api-token", spec.CredBearer, "label-not-sent", "bearer-secret-111", "suffix:Example.COM.")
	basic := e.credential("svc-login", spec.CredBasic, "svc-user", "basic-password-222", "exact:api.example.com", "wildcard:*.svc.example.com")
	unused := e.credential("unused", spec.CredBearer, "x", "unused-secret-333", "suffix:example.com")
	sc := e.scenario("login flow", true,
		httpStep("https://api.example.com/login", &bearer),
		httpStep("https://api.example.com/me", &basic),
		httpStep("https://www.example.com/", &bearer),
		spec.Step{Kind: spec.KindDNS, DNS: &spec.DNSSpec{Name: "api.other.net", RecordType: "A"}, Assertions: []spec.Assertion{}, Extracts: []spec.Extract{}},
	)
	cl := e.cluster("ist-lab", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 4)
	other := e.probes.connect(t, uuid.New(), 4)
	run := e.schedule(sc, cl, 0)

	if n := e.dispatch(); n != 1 {
		t.Fatalf("sent %d runs, want 1", n)
	}
	var version int64
	if err := e.db.QueryRow(e.ctx, `SELECT version FROM synthetic_allowlist_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if r := e.run(run); r.Status != StatusRunning || r.AllowVersion != version || r.StartedAt == nil {
		t.Fatalf("run after dispatch: %+v (allowlist version %d)", r, version)
	}
	msgs := e.probes.messages()
	if len(msgs) != 1 || msgs[0].session != sess.id || e.probes.inFlight(sess) != 1 {
		t.Fatalf("messages %+v", msgs)
	}
	m := msgs[0].msg
	if m.RunId != run.String() || m.Test {
		t.Fatalf("run message %s test=%v", m.RunId, m.Test)
	}
	var got spec.Scenario
	if err := json.Unmarshal(m.ScenarioJson, &got); err != nil || len(got.Steps) != 4 || got.Steps[1].HTTP.URL != "https://api.example.com/me" ||
		got.TimeoutSeconds != 10 || !got.StoreResponses || got.ID != sc.String() {
		t.Fatalf("scenario json %s (%v)", m.ScenarioJson, err)
	}
	if f := spec.Validate(&got); len(f) > 0 {
		t.Fatalf("sent scenario does not validate: %v", f)
	}
	if m.Allowlist.GetVersion() != version || len(m.Allowlist.Rules) != 2 {
		t.Fatalf("allowlist %+v", m.Allowlist)
	}

	creds, err := spec.OpenCredentials(sess.key, run.String(), cl.String(), m.Credentials.GetEnc(), m.Credentials.GetCiphertext())
	if err != nil {
		t.Fatalf("the session's key does not open its run: %v", err)
	}
	defer spec.ZeroCredentials(creds)
	if len(creds) != 2 || creds[0].ID != bearer || creds[1].ID != basic {
		t.Fatalf("sealed %v, want exactly the two the steps use, in step order (not %s)", creds, unused)
	}
	if string(creds[0].Secret.Bytes()) != "bearer-secret-111" || creds[0].Username != nil || creds[0].Kind != spec.CredBearer ||
		!slices.Equal(creds[0].BoundHosts, []string{"suffix:example.com"}) {
		t.Fatalf("bearer credential %v hosts %v", creds[0], creds[0].BoundHosts)
	}
	if string(creds[1].Username.Bytes()) != "svc-user" || string(creds[1].Secret.Bytes()) != "basic-password-222" ||
		!slices.Equal(creds[1].BoundHosts, []string{"exact:api.example.com", "wildcard:*.svc.example.com"}) {
		t.Fatalf("basic credential %v hosts %v", creds[1], creds[1].BoundHosts)
	}
	if _, err := spec.OpenCredentials(other.key, run.String(), cl.String(), m.Credentials.Enc, m.Credentials.Ciphertext); err == nil {
		t.Fatal("another stream's key opened the run")
	}
	if _, err := spec.OpenCredentials(sess.key, uuid.NewString(), cl.String(), m.Credentials.Enc, m.Credentials.Ciphertext); err == nil {
		t.Fatal("opened for another run")
	}
	if _, err := spec.OpenCredentials(sess.key, run.String(), uuid.NewString(), m.Credentials.Enc, m.Credentials.Ciphertext); err == nil {
		t.Fatal("opened for another cluster")
	}

	// The run is sent once: later passes do not send it again.
	e.dispatch()
	if len(e.probes.messages()) != 1 {
		t.Fatal("run sent twice")
	}
	// A scenario without credentials carries none.
	plain := e.scenario("plain", true, httpStep("https://www.example.com/", nil))
	e.schedule(plain, cl, 0)
	e.dispatch()
	if msgs := e.probes.messages(); len(msgs) != 2 || msgs[1].msg.Credentials != nil {
		t.Fatalf("plain run %+v", msgs)
	}
}

// A credential that cannot be resolved, or whose bound hosts do not parse,
// ends the run as an error before anything is sent; nothing is left in
// flight.
func TestDispatchCredentialError(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	bad := e.credential("bad-bounds", spec.CredBearer, "x", "secret-xyz-444", "example.com")
	sc := e.scenario("bad", true, httpStep("https://api.example.com/", &bad))
	cl := e.cluster("c1", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 2)
	run := e.schedule(sc, cl, 0)
	if n := e.dispatch(); n != 0 {
		t.Fatalf("sent %d", n)
	}
	e.wantRun(run, StatusError, ReasonCredentialError)
	if len(e.probes.messages()) != 0 || e.probes.inFlight(sess) != 0 {
		t.Fatal("a run went out, or its slot was kept")
	}
	if o := e.results(); len(o) != 1 || o[0].Status != StatusError || o[0].RunID != run {
		t.Fatalf("outcomes %+v", o)
	}
}

// Review Focus 4, server side: a run due while the probe is not online is
// skipped (probe_offline), never failed, and never sent. A probe online in
// the database but connected to no replica keeps its run scheduled until
// the interval passed (not_dispatched).
func TestOfflineProbeRunSkippedNotFailed(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	sc := e.scenario("s", true, httpStep("https://api.example.com/", nil))
	offline := e.cluster("offline", ProbeOfflineState)
	missing := e.cluster("not-installed", ProbeNotInstalled)
	elsewhere := e.cluster("elsewhere", ProbeOnlineState)
	e.probes.connect(t, offline, 2) // a stream is no reason to send: the state is

	due := e.schedule(sc, offline, 0)
	// One open scheduled run per scenario and cluster (synthetic_runs_one_open).
	later := e.schedule(e.scenario("s2", true, httpStep("https://api.example.com/", nil)), offline, time.Minute)
	none := e.schedule(sc, missing, 0)
	wait := e.schedule(sc, elsewhere, 0)
	if n := e.dispatch(); n != 0 {
		t.Fatalf("sent %d", n)
	}
	e.wantRun(due, StatusSkipped, ReasonProbeOffline)
	e.wantRun(none, StatusSkipped, ReasonProbeOffline)
	e.wantRun(later, StatusScheduled, "")
	e.wantRun(wait, StatusScheduled, "")
	if len(e.probes.messages()) != 0 {
		t.Fatal("a run of an offline probe was sent")
	}

	e.clock.add(61 * time.Second)
	e.dispatch()
	e.wantRun(wait, StatusSkipped, ReasonNotDispatched)
	e.wantRun(later, StatusSkipped, ReasonProbeOffline)
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE status IN ('failed','error')`); n != 0 {
		t.Fatalf("%d runs counted as failures", n)
	}
	for _, o := range e.results() {
		if o.Status != StatusSkipped {
			t.Fatalf("outcome %+v", o)
		}
	}
	if len(e.results()) != 4 {
		t.Fatalf("outcomes %+v", e.results())
	}
}

// Review Focus 4, server side: a run whose stream ends before its result is
// skipped (probe_disconnected) and never sent again; a late result changes
// nothing. A stream that stays open without a result past timeout +
// ResultGrace gives error (no_result). A run that may have left when the
// send failed is skipped, and a run no live replica tracks is skipped after
// OrphanGrace more.
func TestDisconnectMidRunSkipped(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	sc := e.scenario("s", true, httpStep("https://api.example.com/", nil))
	cl := e.cluster("c1", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 4)

	// The stream ends mid-run.
	gone := e.schedule(sc, cl, 0)
	e.dispatch()
	e.wantRun(gone, StatusRunning, "")
	e.probes.drop(sess)
	e.dispatch()
	e.wantRun(gone, StatusSkipped, ReasonProbeDisconnected)
	if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: gone.String(), Status: StatusFailed, FailedStep: 0,
		Steps: []*pb.StepResult{{Position: 0, Status: StatusFailed}}}); err != nil {
		t.Fatal(err)
	}
	e.wantRun(gone, StatusSkipped, ReasonProbeDisconnected)

	// The stream stays open, no result comes.
	sess = e.probes.connect(t, cl, 4)
	quiet := e.schedule(sc, cl, 0)
	e.dispatch()
	e.clock.add(10*time.Second + ResultGrace - time.Second)
	e.dispatch()
	e.wantRun(quiet, StatusRunning, "")
	e.clock.add(2 * time.Second)
	e.dispatch()
	e.wantRun(quiet, StatusError, ReasonNoResult)
	if e.probes.inFlight(sess) != 0 {
		t.Fatal("slot of an ended run kept")
	}

	// The send fails after the run was built: it may have left.
	e.probes.failSend = true
	lost := e.schedule(sc, cl, 0)
	e.dispatch()
	e.wantRun(lost, StatusSkipped, ReasonProbeDisconnected)
	e.probes.failSend = false

	// No stream had room before build: the run never left and waits.
	e.probes.busyBeforeBuild = true
	busy := e.schedule(sc, cl, 0)
	e.dispatch()
	if r := e.run(busy); r.Status != StatusScheduled || r.StartedAt != nil {
		t.Fatalf("busy run %+v", r)
	}
	e.probes.busyBeforeBuild = false
	e.dispatch()
	e.wantRun(busy, StatusRunning, "")

	// A running run no replica tracks (its replica restarted). The busy run
	// is still open: another scenario (one open scheduled run per pair).
	orphan := e.schedule(e.scenario("s2", true, httpStep("https://api.example.com/", nil)), cl, 0)
	e.exec(`UPDATE synthetic_runs SET status = 'running', started_at = $2 WHERE id = $1`, orphan, e.clock.now())
	e.clock.add(10*time.Second + ResultGrace + OrphanGrace - time.Second)
	e.svc.untrack(busy) // keep the busy run out of the way
	e.exec(`UPDATE synthetic_runs SET status = 'skipped' WHERE id = $1`, busy)
	e.dispatch()
	e.wantRun(orphan, StatusRunning, "")
	e.clock.add(2 * time.Second)
	e.dispatch()
	e.wantRun(orphan, StatusSkipped, ReasonProbeDisconnected)

	for _, m := range e.probes.messages() {
		n := 0
		for _, o := range e.probes.messages() {
			if o.msg.RunId == m.msg.RunId {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("run %s sent %d times", m.msg.RunId, n)
		}
	}
	if n := e.count(`SELECT count(*) FROM synthetic_runs WHERE status = 'failed'`); n != 0 {
		t.Fatalf("%d runs failed", n)
	}
}

// A probe's rejection ends a running run as the reason says; a rejection of
// a run that was never sent, or of another cluster's run, changes nothing.
func TestRejectedRun(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	sc := e.scenario("s", true, httpStep("https://api.example.com/", nil))
	cl := e.cluster("c1", ProbeOnlineState)
	other := e.cluster("c2", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 8)
	cases := map[string][2]string{
		"busy":                   {StatusSkipped, ReasonProbeBusy},
		"allowlist_stale":        {StatusSkipped, ReasonAllowlistStale},
		"credentials_unreadable": {StatusError, ReasonCredentialsUnreadable},
		"invalid_scenario":       {StatusError, ReasonInvalidScenario},
		"something new":          {StatusError, ReasonRejected},
	}
	runs := map[string]uuid.UUID{}
	for reason := range cases {
		// One open scheduled run per scenario and cluster.
		runs[reason] = e.schedule(e.scenario(reason, true, httpStep("https://api.example.com/", nil)), cl, 0)
	}
	e.dispatch()
	if e.probes.inFlight(sess) != len(cases) {
		t.Fatalf("in flight %d", e.probes.inFlight(sess))
	}
	// Another cluster's probe cannot end the run.
	if err := e.svc.Reject(e.ctx, other, &pb.RunRejected{RunId: runs["busy"].String(), Reason: "busy"}); err != nil {
		t.Fatal(err)
	}
	e.wantRun(runs["busy"], StatusRunning, "")
	for reason, want := range cases {
		if err := e.svc.Reject(e.ctx, cl, &pb.RunRejected{RunId: runs[reason].String(), Reason: reason}); err != nil {
			t.Fatal(err)
		}
		e.wantRun(runs[reason], want[0], want[1])
	}
	if e.probes.inFlight(sess) != 0 {
		t.Fatalf("in flight %d after rejections", e.probes.inFlight(sess))
	}
	waiting := e.schedule(sc, cl, time.Hour)
	if err := e.svc.Reject(e.ctx, cl, &pb.RunRejected{RunId: waiting.String(), Reason: "busy"}); err != nil {
		t.Fatal(err)
	}
	e.wantRun(waiting, StatusScheduled, "")
}
