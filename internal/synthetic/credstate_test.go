package synthetic

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func TestResolveCause(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("resolve credential c: %w", fmt.Errorf("resolve key vault reference kv://v/s: %w", err))
	}
	for _, c := range []struct {
		name      string
		err       error
		cause     string
		permanent bool
	}{
		{"not found", wrap(secrets.ErrSecretNotFound), CauseNotFound, true},
		{"forbidden", wrap(secrets.ErrSecretForbidden), CauseForbidden, true},
		{"reserved", wrap(secrets.ErrRefReserved), CauseForbidden, true},
		{"not allowed", wrap(secrets.ErrRefNotAllowed), CauseForbidden, true},
		{"decrypt", wrap(secrets.ErrDecrypt), CauseDecrypt, true},
		{"expired", fmt.Errorf("%w: credential c", errCredentialExpired), CauseExpired, true},
		{"empty", fmt.Errorf("%w: credential c is empty", errCredentialEmpty), CauseEmpty, true},
		{"5xx", errors.New("get secret v/s: 503 ServiceUnavailable"), CauseUnavailable, false},
		{"kek unwrap", fmt.Errorf("unwrap dek: %w", errors.New("x")), CauseUnavailable, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cause, permanent := resolveCause(c.err)
			if cause != c.cause || permanent != c.permanent {
				t.Fatalf("got %q, %v; want %q, %v", cause, permanent, c.cause, c.permanent)
			}
		})
	}
}

func TestCredentialReason(t *testing.T) {
	id := uuid.New()
	for _, c := range []struct {
		name           string
		err            error
		status, reason string
	}{
		{"empty", &credentialFailure{id, fmt.Errorf("%w: credential c is empty", errCredentialEmpty)}, StatusError, ReasonCredentialBroken},
		{"not found", &credentialFailure{id, fmt.Errorf("resolve: %w", secrets.ErrSecretNotFound)}, StatusError, ReasonCredentialBroken},
		{"expired", &credentialFailure{id, fmt.Errorf("%w: credential c", errCredentialExpired)}, StatusError, ReasonCredentialExpired},
		{"unavailable", &credentialFailure{id, errors.New("503")}, StatusSkipped, ReasonCredentialUnavailable},
		// The row itself: not a resolution failure, no state.
		{"bad bounds", fmt.Errorf("%w: credential c has no bound hosts", errCredential), StatusError, ReasonCredentialError},
		{"database", errors.New("conn reset"), StatusSkipped, ReasonCredentialUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			if status, reason := credentialReason(c.err); status != c.status || reason != c.reason {
				t.Fatalf("got %s/%s, want %s/%s", status, reason, c.status, c.reason)
			}
		})
	}
}

// A credential that cannot be resolved or has expired says nothing about
// the scenario: its runs move no streak and count in no stat.
func TestCounts(t *testing.T) {
	for _, c := range []struct {
		status, reason string
		want           bool
	}{
		{StatusPassed, "", true},
		{StatusFailed, "assertion_failed", true},
		{StatusError, ReasonNoResult, true},
		{StatusError, ReasonCredentialError, true},
		{StatusError, ReasonCredentialBroken, false},
		{StatusError, ReasonCredentialExpired, false},
		{StatusSkipped, ReasonCredentialUnavailable, false},
	} {
		if got := counts(c.status, c.reason); got != c.want {
			t.Errorf("counts(%s, %s) = %v, want %v", c.status, c.reason, got, c.want)
		}
	}
	if !strings.Contains(countedRunSQL, "'credential_broken','credential_expired'") || !strings.Contains(countedRunSQL, "failure_reason") {
		t.Fatalf("countedRunSQL %s", countedRunSQL)
	}
}

// ---------------------------------------------------------------- dispatch

type credRow struct {
	State          string
	Cause          *string
	Since, Alerted *time.Time
}

func (e *env) credState(id uuid.UUID) credRow {
	e.t.Helper()
	var r credRow
	if err := e.db.QueryRow(e.ctx, `SELECT resolve_state, resolve_cause, resolve_failing_since, resolve_alerted_at
		FROM synthetic_credentials WHERE id = $1`, id).Scan(&r.State, &r.Cause, &r.Since, &r.Alerted); err != nil {
		e.t.Fatal(err)
	}
	return r
}

// credMessages lists the outbox rows of one event type.
func (e *env) credMessages(eventType string) []outboxMsg {
	e.t.Helper()
	var out []outboxMsg
	for _, m := range e.alertMessages() {
		if m.Type == eventType {
			out = append(out, m)
		}
	}
	return out
}

// dispatchRound schedules a run of every scenario on every cluster, sends
// them in one Dispatch pass, then runs Notify. It returns the runs.
func (e *env) dispatchRound(scenarios, clusters []uuid.UUID) []uuid.UUID {
	e.t.Helper()
	e.clock.add(time.Second)
	var runs []uuid.UUID
	for _, sc := range scenarios {
		for _, cl := range clusters {
			runs = append(runs, e.schedule(sc, cl, 0))
		}
	}
	e.dispatch()
	e.notify()
	return runs
}

// credFixture is a Key Vault credential whose secret is missing, used by 3
// scenarios on 3 clusters: pay and refund alert to channel A, invoice to
// the event's routes.
type credFixture struct {
	e                   *env
	cred, chA           uuid.UUID
	scenarios, clusters []uuid.UUID
}

func newCredFixture(t *testing.T) *credFixture {
	t.Helper()
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	f := &credFixture{e: e, chA: e.channel("C-A")}
	f.cred = e.kvCredential("billing-token", spec.CredBearer, "kv://ops-vault/billing-token", "suffix:example.com")
	for i, name := range []string{"pay", "refund", "invoice"} {
		sc := e.scenario(name, true, httpStep("https://api.example.com/"+name, &f.cred))
		if i < 2 {
			r := DefaultAlertRule
			r.ChannelID = &f.chA
			e.alertRule(sc, r)
		}
		f.scenarios = append(f.scenarios, sc)
	}
	for i := range 3 {
		cl := e.cluster(fmt.Sprintf("c%d", i+1), ProbeOnlineState)
		e.probes.connect(t, cl, 20)
		f.clusters = append(f.clusters, cl)
	}
	return f
}

func (f *credFixture) round() []uuid.UUID { return f.e.dispatchRound(f.scenarios, f.clusters) }

// wantRouted checks that msgs went once to channel A and once through the
// routes, with keys of the credential and the episode's start.
func (f *credFixture) wantRouted(msgs []outboxMsg, eventType string, since time.Time) {
	f.e.t.Helper()
	base := fmt.Sprintf("%s:%s:%d:", eventType, f.cred, since.Unix())
	want := map[string]bool{base + f.chA.String(): true, base + "default": false}
	if len(msgs) != 2 {
		f.e.t.Fatalf("%d %s messages, want 2: %+v", len(msgs), eventType, msgs)
	}
	for _, m := range msgs {
		toA, ok := want[m.Key]
		if !ok || toA != (m.Channel != nil && *m.Channel == f.chA) || !toA && m.Channel != nil {
			f.e.t.Fatalf("message %s to %v, want keys %v", m.Key, m.Channel, want)
		}
		delete(want, m.Key)
	}
}

// Review Focus 1 and the dedup test of the design: 9 runs of one broken
// credential in one pass, then two more passes, send one
// synthetic.credential_broken per channel and no synthetic.failing.
func TestCredentialBrokenAlertsOnce(t *testing.T) {
	f := newCredFixture(t)
	e := f.e
	first := f.round()
	for _, run := range first {
		e.wantRun(run, StatusError, ReasonCredentialBroken)
	}
	start := e.clock.now()
	f.round()
	f.round()
	if len(e.probes.messages()) != 0 {
		t.Fatal("a run of a broken credential was sent")
	}
	e.wantMessages(map[string]int{}) // no failing, critical or recovered
	msgs := e.credMessages(notify.SyntheticCredentialBroken)
	f.wantRouted(msgs, notify.SyntheticCredentialBroken, start)
	for _, m := range msgs {
		if m.Title != "Synthetic credential billing-token cannot be resolved" || m.Link != "/settings/synthetic?credential="+f.cred.String() ||
			m.Fields["credential"] != "billing-token" || m.Fields["used by"] != "invoice, pay, refund" || m.Fields["cause"] == "" ||
			m.Payload["credential_id"] != f.cred.String() || m.Payload["cause"] != CauseNotFound ||
			m.Payload["scenario_count"] != float64(3) || m.Payload["transient"] != false {
			t.Fatalf("message %+v", m)
		}
	}
	st := e.credState(f.cred)
	if st.State != "broken" || st.Cause == nil || *st.Cause != CauseNotFound || st.Since == nil || !st.Since.Equal(start) || st.Alerted == nil {
		t.Fatalf("credential state %+v", st)
	}
	for _, sc := range f.scenarios {
		for _, cl := range f.clusters {
			if s := e.streak(sc, cl); s.failures != 0 || s.lastStatus != nil {
				t.Fatalf("streak of %s on %s moved: %+v", sc, cl, s)
			}
		}
	}
}

// Review Focus 1 across replicas: failures of one credential recorded at
// the same moment still send one message per channel, and the recoveries
// one each.
func TestCredentialConcurrentRecordsAlertOnce(t *testing.T) {
	f := newCredFixture(t)
	e := f.e
	at := e.clock.now()
	parallel := func(record func() error) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() { errs <- record() })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	parallel(func() error { return e.svc.recordCredentialFailure(e.ctx, f.cred, CauseNotFound, true) })
	f.wantRouted(e.credMessages(notify.SyntheticCredentialBroken), notify.SyntheticCredentialBroken, at)
	parallel(func() error { return e.svc.recordCredentialOK(e.ctx, []uuid.UUID{f.cred}) })
	f.wantRouted(e.credMessages(notify.SyntheticCredentialRestored), notify.SyntheticCredentialRestored, at)
}

// Putting the secret back sends the runs again and one
// synthetic.credential_restored per channel; the state is ok again.
func TestCredentialRestoredOnce(t *testing.T) {
	const secret = "olympos-canary-restored-7e2a"
	f := newCredFixture(t)
	e := f.e
	f.round()
	since := e.clock.now()
	e.kv.setSecret("ops-vault", "billing-token", secret)
	sent := f.round()
	for _, run := range sent {
		e.wantRun(run, StatusRunning, "")
	}
	if n := len(e.probes.messages()); n != 9 {
		t.Fatalf("%d runs sent, want 9", n)
	}
	msgs := e.credMessages(notify.SyntheticCredentialRestored)
	f.wantRouted(msgs, notify.SyntheticCredentialRestored, since)
	for _, m := range msgs {
		if m.Title != "Synthetic credential billing-token resolves again" || m.Fields["credential"] != "billing-token" ||
			m.Fields["failing since"] != since.UTC().Format(time.RFC3339) || m.Payload["credential_id"] != f.cred.String() ||
			strings.Contains(m.Raw, secret) {
			t.Fatalf("message %+v", m)
		}
	}
	if st := e.credState(f.cred); st != (credRow{State: "ok"}) {
		t.Fatalf("credential state %+v", st)
	}
	for i, run := range sent { // runs of each scenario, cluster by cluster
		if err := e.svc.Ingest(e.ctx, f.clusters[i%len(f.clusters)], &pb.RunResult{RunId: run.String(), Status: StatusPassed,
			Steps: []*pb.StepResult{{Position: 0, Status: StatusPassed}}}); err != nil {
			t.Fatal(err)
		}
	}
	f.round()
	if n, m := len(e.credMessages(notify.SyntheticCredentialRestored)), len(e.credMessages(notify.SyntheticCredentialBroken)); n != 2 || m != 2 {
		t.Fatalf("%d restored and %d broken messages after another pass, want 2 and 2", n, m)
	}
	if strings.Contains(e.LogBuf.String(), secret) {
		t.Fatal("the secret is in the log")
	}
}

// A transient failure (the KEK does not unwrap) skips the runs and alerts
// only once it has lasted UnavailableAlertAfter.
func TestCredentialUnavailableAlertsAfter30m(t *testing.T) {
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	cred := e.credential("kek-bound", spec.CredBearer, "x", "unwrap-secret-31", "suffix:example.com")
	sc := []uuid.UUID{e.scenario("s", true, httpStep("https://api.example.com/", &cred))}
	cl := []uuid.UUID{e.cluster("c1", ProbeOnlineState)}
	e.probes.connect(t, cl[0], 8)
	e.kv.fail(nil, errors.New("kek unavailable"))

	run := e.dispatchRound(sc, cl)[0]
	since := e.clock.now()
	e.wantRun(run, StatusSkipped, ReasonCredentialUnavailable)
	if st := e.credState(cred); st.State != "unavailable" || st.Cause == nil || *st.Cause != CauseUnavailable || st.Alerted != nil {
		t.Fatalf("credential state %+v", st)
	}
	e.clock.add(29 * time.Minute)
	e.dispatchRound(sc, cl)
	if n := e.events(notify.SyntheticCredentialBroken); n != 0 {
		t.Fatalf("%d messages before %s", n, UnavailableAlertAfter)
	}
	e.clock.add(2 * time.Minute)
	e.dispatchRound(sc, cl)
	e.dispatchRound(sc, cl)
	msgs := e.credMessages(notify.SyntheticCredentialBroken)
	if len(msgs) != 1 || msgs[0].Payload["transient"] != true || msgs[0].Payload["cause"] != CauseUnavailable ||
		msgs[0].Title != "Synthetic credential kek-bound has been unavailable for 30 minutes" ||
		msgs[0].Key != fmt.Sprintf("%s:%s:%d:default", notify.SyntheticCredentialBroken, cred, since.Unix()) {
		t.Fatalf("messages %+v", msgs)
	}
	if st := e.credState(cred); st.State != "unavailable" || st.Alerted == nil || !st.Since.Equal(since) {
		t.Fatalf("credential state %+v", st)
	}
}

// Review Focus 2: a permanent failure after a transient episode started
// keeps its start and alerts at once; a transient failure then does not
// downgrade it.
func TestCredentialBrokenAfterUnavailableKeepsSince(t *testing.T) {
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	cred := e.credential("flaky", spec.CredBearer, "x", "flaky-secret-32", "suffix:example.com")
	sc := []uuid.UUID{e.scenario("s", true, httpStep("https://api.example.com/", &cred))}
	cl := []uuid.UUID{e.cluster("c1", ProbeOnlineState)}
	e.probes.connect(t, cl[0], 8)

	e.kv.fail(nil, errors.New("kek unavailable"))
	e.dispatchRound(sc, cl)
	since := e.clock.now()
	e.clock.add(10 * time.Minute)
	e.kv.fail(nil, nil)
	e.exec(`UPDATE credentials SET ciphertext = decode('00112233445566778899aabbccddeeff0011223344', 'hex')
		WHERE id = (SELECT credential_id FROM synthetic_credentials WHERE id = $1)`, cred)
	run := e.dispatchRound(sc, cl)[0]
	e.wantRun(run, StatusError, ReasonCredentialBroken)
	msgs := e.credMessages(notify.SyntheticCredentialBroken)
	if len(msgs) != 1 || msgs[0].Payload["transient"] != false || msgs[0].Payload["cause"] != CauseDecrypt ||
		msgs[0].Key != fmt.Sprintf("%s:%s:%d:default", notify.SyntheticCredentialBroken, cred, since.Unix()) {
		t.Fatalf("messages %+v", msgs)
	}
	want := func() {
		t.Helper()
		if st := e.credState(cred); st.State != "broken" || *st.Cause != CauseDecrypt || !st.Since.Equal(since) || st.Alerted == nil {
			t.Fatalf("credential state %+v", st)
		}
	}
	want()
	e.kv.fail(nil, errors.New("kek unavailable"))
	e.clock.add(time.Minute)
	run = e.dispatchRound(sc, cl)[0]
	e.wantRun(run, StatusSkipped, ReasonCredentialUnavailable)
	want()
	if n := e.events(notify.SyntheticCredentialBroken); n != 1 {
		t.Fatalf("%d messages", n)
	}
}

// Review Focus 4: a scenario with a healthy and a broken credential. Only
// the credentials resolved before the failure are marked ok; the others are
// left as they were.
func TestTwoCredentialsOneBroken(t *testing.T) {
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	good := e.credential("good", spec.CredBearer, "x", "good-secret-33", "suffix:example.com")
	bad := e.kvCredential("bad", spec.CredBearer, "kv://ops-vault/missing", "suffix:example.com")
	cl := []uuid.UUID{e.cluster("c1", ProbeOnlineState)}
	e.probes.connect(t, cl[0], 8)
	badFirst := e.scenario("bad first", true, httpStep("https://api.example.com/a", &bad), httpStep("https://api.example.com/b", &good))
	goodFirst := e.scenario("good first", true, httpStep("https://api.example.com/a", &good), httpStep("https://api.example.com/b", &bad))
	e.exec(`UPDATE synthetic_credentials SET resolve_state = 'unavailable', resolve_cause = 'unavailable', resolve_failing_since = $2
		WHERE id = $1`, good, e.clock.now().Add(-5*time.Minute))

	run := e.dispatchRound([]uuid.UUID{badFirst}, cl)[0]
	e.wantRun(run, StatusError, ReasonCredentialBroken)
	if st := e.credState(good); st.State != "unavailable" {
		t.Fatalf("a credential not resolved was changed: %+v", st)
	}
	run = e.dispatchRound([]uuid.UUID{goodFirst}, cl)[0]
	e.wantRun(run, StatusError, ReasonCredentialBroken)
	if st := e.credState(good); st != (credRow{State: "ok"}) {
		t.Fatalf("a credential resolved is not ok: %+v", st)
	}
	if st := e.credState(bad); st.State != "broken" || *st.Cause != CauseNotFound {
		t.Fatalf("broken credential %+v", st)
	}
	// One message for bad (both scenarios go to the routes); good never
	// alerted, so it has no recovery.
	if b, r := e.events(notify.SyntheticCredentialBroken), e.events(notify.SyntheticCredentialRestored); b != 1 || r != 0 {
		t.Fatalf("%d broken, %d restored messages", b, r)
	}
}

// An expired credential is one message, with cause expired, not one
// synthetic.failing per scenario (supersedes ruling P13's alerting).
func TestExpiredCredentialOneAlert(t *testing.T) {
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	cred := e.credential("old", spec.CredBearer, "x", "expired-secret-34", "suffix:example.com")
	e.exec(`UPDATE synthetic_credentials SET expires_at = $2 WHERE id = $1`, cred, e.clock.now().Add(-time.Minute))
	sc := []uuid.UUID{e.scenario("a", true, httpStep("https://api.example.com/a", &cred)), e.scenario("b", true, httpStep("https://api.example.com/b", &cred))}
	cl := []uuid.UUID{e.cluster("c1", ProbeOnlineState), e.cluster("c2", ProbeOnlineState)}
	for _, c := range cl {
		e.probes.connect(t, c, 8)
	}
	for range DefaultAlertRule.ClusterFailAfter + 1 {
		for _, run := range e.dispatchRound(sc, cl) {
			e.wantRun(run, StatusError, ReasonCredentialExpired)
		}
	}
	e.wantMessages(map[string]int{})
	msgs := e.credMessages(notify.SyntheticCredentialBroken)
	if len(msgs) != 1 || msgs[0].Payload["cause"] != CauseExpired || msgs[0].Payload["scenario_count"] != float64(2) {
		t.Fatalf("messages %+v", msgs)
	}
	if st := e.credState(cred); st.State != "broken" || *st.Cause != CauseExpired {
		t.Fatalf("credential state %+v", st)
	}
}

// Key Vault's own error text (it may carry the response) reaches neither a
// message nor the log: the cause code does.
func TestCredentialFailureNoRawText(t *testing.T) {
	const raw = "AKV10046-raw-response-canary"
	e := newAlertEnv(t)
	e.allow("suffix", "example.com")
	cred := e.kvCredential("denied", spec.CredBearer, "kv://ops-vault/denied", "suffix:example.com")
	e.kv.fail(fmt.Errorf("%w: %s", secrets.ErrSecretForbidden, raw), nil)
	sc := []uuid.UUID{e.scenario("s", true, httpStep("https://api.example.com/", &cred))}
	cl := []uuid.UUID{e.cluster("c1", ProbeOnlineState)}
	e.probes.connect(t, cl[0], 8)
	e.wantRun(e.dispatchRound(sc, cl)[0], StatusError, ReasonCredentialBroken)
	msgs := e.credMessages(notify.SyntheticCredentialBroken)
	if len(msgs) != 1 || msgs[0].Payload["cause"] != CauseForbidden || strings.Contains(msgs[0].Raw, raw) {
		t.Fatalf("messages %+v", msgs)
	}
	if log := e.LogBuf.String(); strings.Contains(log, raw) || !strings.Contains(log, CauseForbidden) {
		t.Fatalf("log %s", log)
	}
}
