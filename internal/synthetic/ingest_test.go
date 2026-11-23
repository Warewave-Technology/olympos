package synthetic

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// dispatched schedules a run of sc on cl and sends it.
func (e *env) dispatched(sc, cl uuid.UUID) uuid.UUID {
	e.t.Helper()
	id := e.schedule(sc, cl, 0)
	e.dispatch()
	e.wantRun(id, StatusRunning, "")
	return id
}

// Only a running run of the cluster that reports it changes, once: another
// cluster's probe cannot end it or free its slot, and a second copy of the
// result changes nothing and does not reach OnResult again. failed_step 0 is
// a real step; a runner panic names none.
func TestIngestIdempotentAndClusterBound(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	sc := e.scenario("s", true, httpStep("https://api.example.com/", nil), httpStep("https://api.example.com/2", nil))
	a := e.cluster("a", ProbeOnlineState)
	b := e.cluster("b", ProbeOnlineState)
	sess := e.probes.connect(t, a, 4)
	e.probes.connect(t, b, 4)
	run := e.dispatched(sc, a)

	res := &pb.RunResult{RunId: run.String(), Status: StatusFailed, FailedStep: 0, FailureReason: "assertion_failed: status_code 500, want 200",
		ProbeVersion: "0.3.0", StartedUnixMs: 1_000, FinishedUnixMs: 1_250, ProbeIp: "10.0.0.7",
		Steps: []*pb.StepResult{
			{Position: 0, Status: StatusFailed, StatusCode: 500, RemoteIp: "192.0.2.10", Timings: &pb.StepTimings{TotalUs: 250_000},
				Assertions:     []*pb.AssertionResult{{Subject: "status_code", Operator: "equals", Expected: "200", Actual: "500"}},
				ExtractedNames: []string{"token"}, Error: "assertion_failed: status_code"},
			{Position: 1, Status: StatusSkipped},
		}}
	if err := e.svc.Ingest(e.ctx, b, res); err != nil {
		t.Fatal(err)
	}
	e.wantRun(run, StatusRunning, "")
	if e.probes.inFlight(sess) != 1 {
		t.Fatal("another cluster freed the slot")
	}
	if len(e.results()) != 0 {
		t.Fatal("another cluster's result reached OnResult")
	}

	for range 2 {
		if err := e.svc.Ingest(e.ctx, a, res); err != nil {
			t.Fatal(err)
		}
	}
	r := e.run(run)
	if r.Status != StatusFailed || r.FailedStep == nil || *r.FailedStep != 0 || r.Reason != res.FailureReason {
		t.Fatalf("run %+v", r)
	}
	var total int
	var version, remote, probeIP string
	if err := e.db.QueryRow(e.ctx, `SELECT total_ms, probe_version, remote_ip, probe_ip FROM synthetic_runs WHERE id = $1`, run).
		Scan(&total, &version, &remote, &probeIP); err != nil {
		t.Fatal(err)
	}
	if total != 250 || version != "0.3.0" || remote != "192.0.2.10" || probeIP != "10.0.0.7" {
		t.Fatalf("total %d version %q remote %q probe %q", total, version, remote, probeIP)
	}
	if n := e.count(`SELECT count(*) FROM synthetic_step_results WHERE run_id = $1`, run); n != 2 {
		t.Fatalf("%d step results", n)
	}
	var code int
	var names []string
	var assertions string
	if err := e.db.QueryRow(e.ctx, `SELECT status_code, extracted_names, assertions::text FROM synthetic_step_results WHERE run_id = $1 AND position = 0`, run).
		Scan(&code, &names, &assertions); err != nil {
		t.Fatal(err)
	}
	if code != 500 || len(names) != 1 || names[0] != "token" || !strings.Contains(assertions, `"actual": "500"`) {
		t.Fatalf("step 0: code %d names %v assertions %s", code, names, assertions)
	}
	o := e.results()
	if len(o) != 1 || o[0].RunID != run || o[0].Status != StatusFailed || o[0].FailedStep == nil || *o[0].FailedStep != 0 ||
		o[0].ClusterID != a || o[0].ScenarioID != sc || o[0].Test {
		t.Fatalf("outcomes %+v", o)
	}
	if e.probes.inFlight(sess) != 0 {
		t.Fatal("slot not freed")
	}

	// A runner panic: error, no step.
	panicked := e.dispatched(sc, a)
	if err := e.svc.Ingest(e.ctx, a, &pb.RunResult{RunId: panicked.String(), Status: StatusError, FailedStep: 0, FailureReason: ReasonRunnerPanic}); err != nil {
		t.Fatal(err)
	}
	if r := e.run(panicked); r.Status != StatusError || r.FailedStep != nil || r.Reason != ReasonRunnerPanic {
		t.Fatalf("panicked run %+v", r)
	}
	// A status that is no run status.
	odd := e.dispatched(sc, a)
	if err := e.svc.Ingest(e.ctx, a, &pb.RunResult{RunId: odd.String(), Status: "skipped"}); err != nil {
		t.Fatal(err)
	}
	e.wantRun(odd, StatusError, ReasonInvalidResult)
	// A passed run keeps no reason and no failed step.
	ok := e.dispatched(sc, a)
	if err := e.svc.Ingest(e.ctx, a, &pb.RunResult{RunId: ok.String(), Status: StatusPassed, FailureReason: "ignored",
		Steps: []*pb.StepResult{{Position: 0, Status: StatusPassed}, {Position: 1, Status: StatusPassed}}}); err != nil {
		t.Fatal(err)
	}
	if r := e.run(ok); r.Status != StatusPassed || r.FailedStep != nil || r.Reason != "" {
		t.Fatalf("passed run %+v", r)
	}
	// Garbage ids are ignored.
	if err := e.svc.Ingest(e.ctx, a, &pb.RunResult{RunId: "not-a-uuid", Status: StatusPassed}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Ingest(e.ctx, a, &pb.RunResult{RunId: uuid.NewString(), Status: StatusPassed}); err != nil {
		t.Fatal(err)
	}
}

// Excerpts are dropped when the scenario does not store responses (also
// for a test run), and kept, redacted, when it does.
func TestStoreResponsesFalse(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	cl := e.cluster("c1", ProbeOnlineState)
	e.probes.connect(t, cl, 8)
	excerpt := []byte("HTTP/1.1 200 OK\r\nWWW-Authenticate: Bearer abcdefghijkl\r\n\r\n{\"ok\":true}")
	result := func(id uuid.UUID) *pb.RunResult {
		return &pb.RunResult{RunId: id.String(), Status: StatusPassed,
			Steps: []*pb.StepResult{{Position: 0, Status: StatusPassed, ResponseExcerpt: excerpt}}}
	}
	stored := func(id uuid.UUID) []byte {
		t.Helper()
		var b []byte
		if err := e.db.QueryRow(e.ctx, `SELECT excerpt FROM synthetic_step_results WHERE run_id = $1 AND position = 0`, id).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}

	off := e.dispatched(e.scenario("off", false, httpStep("https://api.example.com/", nil)), cl)
	on := e.dispatched(e.scenario("on", true, httpStep("https://api.example.com/", nil)), cl)
	test := e.testRun(cl, spec.Scenario{Name: "t", Type: spec.TypeHTTP, IntervalSeconds: 60, TimeoutSeconds: 5, StoreResponses: false,
		Steps: []spec.Step{httpStep("https://api.example.com/", nil)}})
	e.dispatch()
	for _, id := range []uuid.UUID{off, on, test} {
		if err := e.svc.Ingest(e.ctx, cl, result(id)); err != nil {
			t.Fatal(err)
		}
	}
	if b := stored(off); b != nil {
		t.Fatalf("store_responses=false kept %q", b)
	}
	if b := stored(test); b != nil {
		t.Fatalf("test run with store_responses=false kept %q", b)
	}
	b := stored(on)
	if !strings.Contains(string(b), `{"ok":true}`) || strings.Contains(string(b), "abcdefghijkl") {
		t.Fatalf("stored excerpt %q", b)
	}
	// Not text: dropped. Too long: cut to the column's bound.
	long := e.dispatched(e.scenario("long", true, httpStep("https://api.example.com/", nil)), cl)
	if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: long.String(), Status: StatusPassed, Steps: []*pb.StepResult{
		{Position: 0, Status: StatusPassed, ResponseExcerpt: []byte(strings.Repeat("é", 3000))},
		{Position: 1, Status: StatusPassed, ResponseExcerpt: []byte{0xff, 0xfe, 0x00}},
	}}); err != nil {
		t.Fatal(err)
	}
	if b := stored(long); len(b) > spec.MaxExcerpt || len(b) < spec.MaxExcerpt-1 {
		t.Fatalf("long excerpt %d bytes", len(b))
	}
	var bin []byte
	if err := e.db.QueryRow(e.ctx, `SELECT excerpt FROM synthetic_step_results WHERE run_id = $1 AND position = 1`, long).Scan(&bin); err != nil || bin != nil {
		t.Fatalf("binary excerpt %q (%v)", bin, err)
	}
}

// A canary credential reaches the probe, sealed, and nowhere else: not in
// any synthetic table, the outbox, the activity log or the server's log,
// also when the probe hands back text with credential shapes in it.
func TestCanaryNotInDBOrLogs(t *testing.T) {
	const canary = "olympos-canary-7f3a9c2e5b1d4e60"
	const canaryUser = "canary-user-0b9e4d"
	e := newEnv(t)
	e.allow("suffix", "example.com")
	bearer := e.credential("api", spec.CredBearer, "label", canary, "suffix:example.com")
	basic := e.credential("login", spec.CredBasic, canaryUser, canary+"-pw", "exact:api.example.com")
	header := e.credential("hdr", spec.CredHeader, "label", canary+"-hdr", "exact:api.example.com")
	sc := e.scenario("s", true, httpStep("https://api.example.com/a", &bearer), httpStep("https://api.example.com/b", &basic),
		httpStep("https://api.example.com/c", &header))
	cl := e.cluster("c1", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 8)

	run := e.dispatched(sc, cl)
	test := e.testRun(cl, spec.Scenario{Name: "t", Type: spec.TypeHTTP, IntervalSeconds: 60, TimeoutSeconds: 5, StoreResponses: true,
		Steps: []spec.Step{httpStep("https://api.example.com/", &bearer)}})
	e.dispatch()
	msgs := e.probes.messages()
	if len(msgs) != 2 {
		t.Fatalf("%d runs sent", len(msgs))
	}
	for _, m := range msgs {
		creds, err := spec.OpenCredentials(sess.key, m.msg.RunId, cl.String(), m.msg.Credentials.Enc, m.msg.Credentials.Ciphertext)
		if err != nil || !strings.HasPrefix(string(creds[0].Secret.Bytes()), canary) {
			t.Fatalf("the probe did not get the canary: %v", err)
		}
		spec.ZeroCredentials(creds)
		if strings.Contains(string(m.msg.ScenarioJson), canary) {
			t.Fatal("canary in scenario_json")
		}
	}

	// What a careless probe might hand back.
	leak := "Authorization: Bearer " + canary
	for _, id := range []uuid.UUID{run, test} {
		if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: id.String(), Status: StatusFailed, FailedStep: 0, FailureReason: "assertion_failed: " + leak,
			Steps: []*pb.StepResult{{Position: 0, Status: StatusFailed, Error: "connect_error: bearer " + canary,
				Assertions:      []*pb.AssertionResult{{Subject: "header:Authorization", Operator: "equals", Expected: "x", Actual: "Bearer " + canary}},
				ResponseExcerpt: []byte("GET /a HTTP/1.1\r\n" + leak + "\r\n")}}}); err != nil {
			t.Fatal(err)
		}
	}
	// And the other paths that write: a disconnect, an offline probe and
	// its message.
	e.dispatched(sc, cl)
	e.probes.drop(sess)
	e.dispatch()
	e.clock.add(6 * time.Minute)
	if err := e.svc.CheckProbesOffline(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.clock.add(time.Minute)
	if err := e.svc.CheckProbesOffline(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.schedule(sc, cl, 0)
	e.dispatch()
	if e.count(`SELECT count(*) FROM outbox`) == 0 {
		t.Fatal("no outbox rows to search")
	}

	forms := []string{canary, canaryUser, hex.EncodeToString([]byte(canary)), base64.StdEncoding.EncodeToString([]byte(canary)),
		base64.StdEncoding.EncodeToString([]byte(canaryUser + ":" + canary + "-pw"))}
	var tables []string
	rows, err := e.db.Query(e.ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'
		AND (tablename LIKE 'synthetic%' OR tablename LIKE 'scenario%' OR tablename IN ('outbox', 'activity_log', 'clusters', 'credentials'))`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if len(tables) < 12 {
		t.Fatalf("searched only %v", tables)
	}
	for _, table := range tables {
		var dump string
		if err := e.db.QueryRow(e.ctx, `SELECT COALESCE(string_agg(t::text, E'\n'), '') FROM `+table+` t`).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		for _, f := range forms {
			if table == "credentials" && f == canaryUser {
				continue // the login's user name is stored in clear, as for every job credential
			}
			if strings.Contains(strings.ToLower(dump), strings.ToLower(f)) {
				t.Errorf("canary form %q in table %s", f, table)
			}
		}
	}
	logs := e.LogBuf.String()
	if logs == "" {
		t.Fatal("nothing logged to search")
	}
	for _, f := range forms {
		if strings.Contains(logs, f) {
			t.Errorf("canary form %q in the log", f)
		}
	}
	// The stored excerpt is still there, with the secret redacted.
	var excerpt []byte
	if err := e.db.QueryRow(e.ctx, `SELECT excerpt FROM synthetic_step_results WHERE run_id = $1`, run).Scan(&excerpt); err != nil ||
		!strings.Contains(string(excerpt), "GET /a HTTP/1.1") {
		t.Fatalf("excerpt %q (%v)", excerpt, err)
	}
}

// A result that came but could not be stored (the transaction failed after
// the slot was released) ends the run skipped (ingest_failed) on the next
// pass: the probe sends a result once, and it was not the scenario's fault.
// It is not left to end error (no_result) at its deadline.
func TestIngestFailureEndsSkipped(t *testing.T) {
	e := newEnv(t)
	e.allow("suffix", "example.com")
	sc := e.scenario("s", true, httpStep("https://api.example.com/", nil))
	cl := e.cluster("a", ProbeOnlineState)
	sess := e.probes.connect(t, cl, 4)
	run := e.dispatched(sc, cl)

	apply := e.svc.OnResult
	e.svc.OnResult = func(context.Context, pgx.Tx, RunOutcome) error { return errors.New("database went away") }
	if err := e.svc.Ingest(e.ctx, cl, &pb.RunResult{RunId: run.String(), Status: StatusPassed}); err == nil {
		t.Fatal("Ingest did not report the failure")
	}
	e.svc.OnResult = apply
	e.wantRun(run, StatusRunning, "")
	if e.probes.inFlight(sess) != 0 {
		t.Fatal("slot not released")
	}
	// Well before the run's deadline.
	e.clock.add(time.Second)
	e.dispatch()
	e.wantRun(run, StatusSkipped, ReasonIngestFailed)
	if rs := e.results(); len(rs) != 1 || rs[0].Status != StatusSkipped || rs[0].Reason != ReasonIngestFailed {
		t.Fatalf("outcomes %+v", rs)
	}

	// A run whose result never came still ends error (no_result) at its
	// deadline.
	other := e.dispatched(sc, cl)
	e.clock.add(10*time.Second + ResultGrace + time.Second)
	e.dispatch()
	e.wantRun(other, StatusError, ReasonNoResult)
}
