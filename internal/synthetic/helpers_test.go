package synthetic

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/config"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// testKV wraps data keys with a fixed key: enough for secrets.Envelope, and
// no dev build needed.
type testKV struct{}

func (testKV) mask() []byte { s := sha256.Sum256([]byte("synthetic-test-kek")); return s[:] }

func (k testKV) WrapKey(_ context.Context, dek []byte) ([]byte, string, error) {
	m := k.mask()
	out := make([]byte, len(dek))
	for i := range dek {
		out[i] = dek[i] ^ m[i%len(m)]
	}
	return out, "v1", nil
}

func (k testKV) UnwrapKey(ctx context.Context, wrapped []byte, _ string) ([]byte, error) {
	b, _, err := k.WrapKey(ctx, wrapped)
	return b, err
}

func (testKV) GetSecret(context.Context, string, string) ([]byte, error) {
	return nil, secrets.ErrSecretNotFound
}

func (testKV) SetSecret(context.Context, string, string, []byte) error {
	return errors.New("read only")
}

// syncBuffer is a log buffer safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeSession is one probe stream with its own HPKE key.
type fakeSession struct {
	id       uint64
	key      hpke.PrivateKey
	pub      []byte
	max      int
	inFlight int
	alive    bool
}

type sentMsg struct {
	cluster uuid.UUID
	session uint64
	msg     *pb.RunScenario
}

// fakeProbes stands in for the gateway's probe streams on this replica.
type fakeProbes struct {
	mu       sync.Mutex
	next     uint64
	sessions map[uuid.UUID][]*fakeSession
	sent     []sentMsg
	// failSend makes the send fail after build ran; busyBeforeBuild makes
	// SendRun refuse before it.
	failSend, busyBeforeBuild bool
}

func (f *fakeProbes) connect(t *testing.T, cluster uuid.UUID, max int) *fakeSession {
	t.Helper()
	key, err := spec.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	s := &fakeSession{id: f.next, key: key, pub: key.PublicKey().Bytes(), max: max, alive: true}
	if f.sessions == nil {
		f.sessions = map[uuid.UUID][]*fakeSession{}
	}
	f.sessions[cluster] = append(f.sessions[cluster], s)
	return s
}

func (f *fakeProbes) drop(s *fakeSession) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.alive = false
}

func (f *fakeProbes) info(s *fakeSession) gateway.ProbeInfo {
	return gateway.ProbeInfo{SessionID: s.id, PublicKey: bytes.Clone(s.pub), Version: "test", MaxConcurrency: s.max, InFlight: s.inFlight}
}

func (f *fakeProbes) pick(cluster uuid.UUID, room bool) *fakeSession {
	var best *fakeSession
	for _, s := range f.sessions[cluster] {
		if !s.alive || room && s.inFlight >= s.max {
			continue
		}
		if best == nil || s.inFlight < best.inFlight {
			best = s
		}
	}
	return best
}

func (f *fakeProbes) ProbeConnected(cluster uuid.UUID) (gateway.ProbeInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.pick(cluster, false)
	if s == nil {
		return gateway.ProbeInfo{}, false
	}
	return f.info(s), true
}

func (f *fakeProbes) SendRun(cluster uuid.UUID, build func(gateway.ProbeInfo) (*pb.RunScenario, error)) (gateway.ProbeInfo, error) {
	f.mu.Lock()
	if f.busyBeforeBuild {
		f.mu.Unlock()
		return gateway.ProbeInfo{}, gateway.ErrProbeBusy
	}
	s := f.pick(cluster, true)
	if s == nil {
		f.mu.Unlock()
		return gateway.ProbeInfo{}, gateway.ErrProbeOffline
	}
	s.inFlight++
	info := f.info(s)
	f.mu.Unlock()
	msg, err := build(info)
	if err == nil && f.failSend {
		err = gateway.ErrProbeOffline
		msg = nil
	}
	if err != nil {
		f.RunDone(cluster, s.id)
		return gateway.ProbeInfo{}, err
	}
	f.mu.Lock()
	f.sent = append(f.sent, sentMsg{cluster: cluster, session: s.id, msg: msg})
	f.mu.Unlock()
	return info, nil
}

func (f *fakeProbes) RunDone(cluster uuid.UUID, session uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions[cluster] {
		if s.id == session && s.inFlight > 0 {
			s.inFlight--
		}
	}
}

func (f *fakeProbes) ProbeSessionAlive(cluster uuid.UUID, session uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions[cluster] {
		if s.id == session {
			return s.alive
		}
	}
	return false
}

func (f *fakeProbes) messages() []sentMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMsg(nil), f.sent...)
}

func (f *fakeProbes) inFlight(s *fakeSession) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return s.inFlight
}

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	svc    *Service
	probes *fakeProbes
	clock  *clock
	// LogBuf holds the service's log, redacted as in production.
	LogBuf *syncBuffer

	slots int

	mu       sync.Mutex
	outcomes []RunOutcome
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), db: testutil.DB(t), probes: &fakeProbes{},
		clock: &clock{t: time.Now().UTC().Truncate(time.Second)}, LogBuf: &syncBuffer{}}
	log := slog.New(secrets.NewRedactingHandler(slog.NewJSONHandler(e.LogBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	kv := testKV{}
	e.svc = &Service{DB: e.db, Log: log, Probes: e.probes, Creds: &backup.Credentials{KV: kv, Envelope: &secrets.Envelope{KV: kv}},
		Cfg: config.Synthetic{ProbeOfflineAlertAfter: 5 * time.Minute}, Now: e.clock.now,
		OnResult: func(_ context.Context, _ pgx.Tx, o RunOutcome) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.outcomes = append(e.outcomes, o)
			return nil
		}}
	return e
}

func (e *env) results() []RunOutcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]RunOutcome(nil), e.outcomes...)
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(e.ctx, sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) cluster(name, probeStatus string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO clusters (name, status, last_seen_at, probe_status, probe_last_seen_at)
		VALUES ($1, 'online', now(), $2, $3) RETURNING id`, name, probeStatus, e.clock.now()).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) allow(kind, pattern string) {
	e.t.Helper()
	e.exec(`INSERT INTO synthetic_allowlist (pattern, kind) VALUES ($1, $2)`, pattern, kind)
}

// credential stores a synthetic credential; boundHosts are stored as given.
func (e *env) credential(name, kind, username, secret string, boundHosts ...string) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error {
		cid, err := e.svc.Creds.Insert(e.ctx, tx, backup.CredentialInput{Source: backup.SourceStored, Username: username, Password: secret})
		if err != nil {
			return err
		}
		var header *string
		if kind == spec.CredHeader {
			h := "X-Token"
			header = &h
		}
		return tx.QueryRow(e.ctx, `INSERT INTO synthetic_credentials (name, kind, bound_hosts, credential_id, header_name)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, name, kind, boundHosts, cid, header).Scan(&id)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func httpStep(url string, cred *uuid.UUID) spec.Step {
	return spec.Step{Kind: spec.KindHTTP, HTTP: &spec.HTTPSpec{Method: "GET", URL: url}, CredentialID: cred,
		Assertions: []spec.Assertion{{Subject: spec.SubjectStatusCode, Operator: spec.OpEquals, Value: "200"}}, Extracts: []spec.Extract{}}
}

// scenario saves a scenario with the given steps.
func (e *env) scenario(name string, storeResponses bool, steps ...spec.Step) uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	err := store.Tx(e.ctx, e.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(e.ctx, `INSERT INTO scenarios (name, type, interval_seconds, timeout_seconds, store_responses)
			VALUES ($1, 'http_flow', 60, 10, $2) RETURNING id`, name, storeResponses).Scan(&id); err != nil {
			return err
		}
		return WriteSteps(e.ctx, tx, id, steps)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// schedule adds a scheduled run due at the clock's time plus at (less a
// millisecond per run so far, so that slots never collide).
func (e *env) schedule(scenarioID, clusterID uuid.UUID, at time.Duration) uuid.UUID {
	e.t.Helper()
	e.slots++
	at -= time.Duration(e.slots) * time.Millisecond
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for) VALUES ($1, $2, $3) RETURNING id`,
		scenarioID, clusterID, e.clock.now().Add(at)).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// testRun adds a scheduled test run of an unsaved scenario.
func (e *env) testRun(clusterID uuid.UUID, sc spec.Scenario) uuid.UUID {
	e.t.Helper()
	b, err := json.Marshal(sc)
	if err != nil {
		e.t.Fatal(err)
	}
	var id uuid.UUID
	if err := e.db.QueryRow(e.ctx, `INSERT INTO synthetic_runs (cluster_id, scheduled_for, test, test_spec) VALUES ($1, $2, true, $3) RETURNING id`,
		clusterID, e.clock.now(), b).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

type runRow struct {
	Status, Reason string
	FailedStep     *int
	AllowVersion   int64
	StartedAt      *time.Time
}

func (e *env) run(id uuid.UUID) runRow {
	e.t.Helper()
	var r runRow
	if err := e.db.QueryRow(e.ctx, `SELECT status, failure_reason, failed_step, allowlist_version, started_at FROM synthetic_runs WHERE id = $1`, id).
		Scan(&r.Status, &r.Reason, &r.FailedStep, &r.AllowVersion, &r.StartedAt); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) wantRun(id uuid.UUID, status, reason string) {
	e.t.Helper()
	if r := e.run(id); r.Status != status || r.Reason != reason {
		e.t.Fatalf("run %s is %s/%q, want %s/%q", id, r.Status, r.Reason, status, reason)
	}
}

func (e *env) dispatch() int {
	e.t.Helper()
	n, err := e.svc.Dispatch(e.ctx)
	if err != nil {
		e.t.Fatalf("Dispatch: %v", err)
	}
	return n
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func ptr[T any](v T) *T { return &v }
