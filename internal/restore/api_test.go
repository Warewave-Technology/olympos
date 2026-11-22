//go:build dev

package restore_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/restore"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// Canaries: they must never appear in a response, a log line, an event, an
// activity row or a request column.
const (
	canaryPassword = "CANARY-restore-pw-7f3a9c-never-shown"
	canaryToken    = "CANARY-vault-token-e81b44-never-shown"
)

// ---------------------------------------------------------------- fakes

// fakeInspector is the engine inspector of the tests (engines register their
// own in later tasks). It records the secret it was given.
type fakeInspector struct {
	mu      sync.Mutex
	report  restore.TargetReport
	err     error
	leak    bool // the error carries the secret
	secrets []string
	calls   int
}

func (f *fakeInspector) InspectRestoreTarget(ctx context.Context, ec backup.EngineContext, dbs []string) (*restore.TargetReport, error) {
	c, err := ec.Credential(ctx)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.secrets = append(f.secrets, string(c.Secret))
	if f.err != nil {
		if f.leak {
			return nil, fmt.Errorf("%w: login failed with password %s", f.err, c.Secret)
		}
		return nil, f.err
	}
	r := f.report
	r.Existing = map[string]bool{}
	for _, d := range dbs {
		if v, ok := f.report.Existing[d]; ok {
			r.Existing[d] = v
		}
	}
	return &r, nil
}

func (f *fakeInspector) set(r restore.TargetReport, err error, leak bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.report, f.err, f.leak = r, err, leak
}

var (
	pgInspector    = &fakeInspector{}
	chInspector    = &fakeInspector{}
	vaultInspector = &fakeInspector{}
)

func init() {
	restore.RegisterInspector("postgresql", pgInspector)
	restore.RegisterInspector("clickhouse", chInspector)
	restore.RegisterInspector("vault", vaultInspector)
}

type fakeDialer struct {
	mu        sync.Mutex
	connected map[uuid.UUID]bool
}

func (d *fakeDialer) Connected(id uuid.UUID) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected[id]
}

func (d *fakeDialer) Dial(context.Context, uuid.UUID, string, gateway.DialOptions) (gateway.Conn, error) {
	return nil, errors.New("the fake dialer does not dial")
}

type memObject struct{ *bytes.Reader }

func (memObject) Close() error { return nil }

// fakeBlobs serves blobs from memory for every destination.
type fakeBlobs struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func (f *fakeBlobs) ReaderFor(context.Context, uuid.UUID) (blob.Reader, error) { return f, nil }

func (f *fakeBlobs) Open(_ context.Context, path string) (blob.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blobs[path]
	if !ok {
		return nil, errors.New("blob not found: " + path)
	}
	return memObject{bytes.NewReader(b)}, nil
}

func (f *fakeBlobs) put(path string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[path] = b
}

// ---------------------------------------------------------------- fixture

type env struct {
	*apitest.Env
	api    *restore.API
	dialer *fakeDialer
	blobs  *fakeBlobs
	now    time.Time

	prod, stage uuid.UUID // clusters: the backup's, the new target's
	dest        uuid.UUID
	pgRun       uuid.UUID // succeeded PostgreSQL run of prod/shop/orders-pg
	pgSource    string
	pgTarget    string // stage/shop/orders-pg-new
	pgTarget2   string // stage/shop/orders-pg-other
	bodies      []string
}

func newEnv(t *testing.T) *env {
	e := &env{now: time.Now(), dialer: &fakeDialer{connected: map[uuid.UUID]bool{}}, blobs: &fakeBlobs{blobs: map[string][]byte{}}}
	e.Env = apitest.New(t, apitest.Options{Modules: func(ae *apitest.Env) []server.Module {
		e.api = &restore.API{DB: ae.DB, Log: ae.Log, Envelope: ae.Envelope, Creds: &backup.Credentials{KV: ae.KV, Envelope: ae.Envelope},
			Dialer: e.dialer, Blobs: e.blobs, Now: func() time.Time { return e.now }}
		return []server.Module{e.api}
	}})
	pgInspector.set(restore.TargetReport{Superuser: true, ServerVersion: "17.2"}, nil, false)
	chInspector.set(restore.TargetReport{ServerVersion: "25.3"}, nil, false)
	vaultInspector.set(restore.TargetReport{Initialized: true, CanSnapshotForce: true, ServerVersion: "1.18.0"}, nil, false)

	e.prod = e.cluster("prod", "prod")
	e.stage = e.cluster("stage", "stage")
	e.dialer.connected[e.stage] = true
	e.exec(`INSERT INTO destinations (name, account, container, prefix, auth) VALUES ('dest', 'acct', 'backups', 'p', 'managed_identity')`)
	e.scan(&e.dest, `SELECT id FROM destinations WHERE name = 'dest'`)
	e.pgSource = e.target(e.prod, "orders-pg", "postgresql", "")
	e.pgTarget = e.target(e.stage, "orders-pg-new", "postgresql", "")
	e.pgTarget2 = e.target(e.stage, "orders-pg-other", "postgresql", "")
	e.pgRun = e.run(e.pgSource, "succeeded", "manual", "zip", map[string]any{"databases": []string{"postgres", "shop", "billing"}})
	return e
}

func (e *env) exec(sql string, args ...any) {
	e.T.Helper()
	if _, err := e.DB.Exec(context.Background(), sql, args...); err != nil {
		e.T.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) scan(dst any, sql string, args ...any) {
	e.T.Helper()
	if err := e.DB.QueryRow(context.Background(), sql, args...).Scan(dst); err != nil {
		e.T.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) cluster(name, envLabel string) uuid.UUID {
	var id uuid.UUID
	e.scan(&id, `INSERT INTO clusters (name, labels, status, last_seen_at) VALUES ($1, $2, 'online', now()) RETURNING id`,
		name, map[string]string{"env": envLabel})
	return id
}

func (e *env) target(cluster uuid.UUID, svc, engine, provider string) string {
	port := map[string]int32{"postgresql": 5432, "clickhouse": 9440, "vault": 8200}[engine]
	id := targetid.Compute(cluster.String(), "shop", svc, port)
	e.exec(`INSERT INTO targets (id, cluster_id, namespace, service, port, engine, vault_provider) VALUES ($1,$2,'shop',$3,$4,$5,$6)`,
		id, cluster, svc, port, engine, provider)
	return id
}

// run inserts a finished run of a job on target with one copy in dest and,
// for a succeeded or partial run, its sidecar manifest with details.
func (e *env) run(target, status, trigger, ext string, details map[string]any) uuid.UUID {
	e.T.Helper()
	var job, run uuid.UUID
	e.scan(&job, `INSERT INTO backup_jobs (target_id, destination_id, cron, timezone) VALUES ($1, $2, '0 2 * * *', 'UTC') RETURNING id`, target, e.dest)
	run = uuid.New()
	path := "p/c/shop/" + run.String() + "." + ext
	e.exec(`INSERT INTO backup_runs (id, job_id, trigger, status, blob_path, sha256, started_at, finished_at, destination_ids)
		VALUES ($1, $2, $3, $4, $5, 'abc', now(), now(), ARRAY[$6::uuid])`, run, job, trigger, status, path, e.dest)
	cs := "succeeded"
	if status == "failed" {
		cs = "failed"
	}
	e.exec(`INSERT INTO backup_run_copies (run_id, destination_id, status, blob_path, sha256) VALUES ($1, $2, $3, $4, 'abc')`, run, e.dest, cs, path)
	m, _ := json.Marshal(map[string]any{"run_id": run, "details": details})
	e.blobs.put(backup.ManifestPath(path, run), m)
	return run
}

func (e *env) do(c *apitest.Client, method, path string, body, out any) int {
	e.T.Helper()
	code, raw := c.Raw(method, path, body)
	e.bodies = append(e.bodies, raw)
	if out != nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), out); err != nil {
			e.T.Fatalf("decode %s: %v", raw, err)
		}
	}
	return code
}

func (e *env) login(name string, grants ...string) *apitest.Client {
	return e.Login(e.Principal(name, "Member", grants...))
}

type errBody struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields"`
}

func (e *env) pgInput(target string) map[string]any {
	return map[string]any{
		"run_id": e.pgRun, "target_id": target, "databases": []string{"shop", "billing"},
		"credential":    map[string]any{"source": "stored", "username": "postgres", "password": canaryPassword},
		"justification": "Disaster recovery of orders after the prod outage",
	}
}

func (e *env) open(c *apitest.Client, in map[string]any) restore.Request {
	e.T.Helper()
	var rq restore.Request
	if code := e.do(c, "POST", "/api/v1/restores", in, &rq); code != http.StatusCreated {
		e.T.Fatalf("open: %d %s", code, e.bodies[len(e.bodies)-1])
	}
	return rq
}

type outboxRow struct {
	Type    string
	Payload map[string]any
}

func (e *env) events(like string) []outboxRow {
	e.T.Helper()
	rows, err := e.DB.Query(context.Background(), `SELECT event_type, payload FROM outbox WHERE event_type LIKE $1 ORDER BY created_at, id`, like)
	if err != nil {
		e.T.Fatal(err)
	}
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		var b []byte
		if err := rows.Scan(&r.Type, &b); err != nil {
			e.T.Fatal(err)
		}
		_ = json.Unmarshal(b, &r.Payload)
		out = append(out, r)
	}
	return out
}

// actions lists the audit actions of a request, sorted (rows of one
// transaction share their timestamp).
func (e *env) actions(objectID uuid.UUID) []string {
	e.T.Helper()
	rows, err := e.DB.Query(context.Background(), `SELECT action FROM activity_log WHERE object_id = $1 ORDER BY at, id`, objectID.String())
	if err != nil {
		e.T.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.T.Fatal(err)
		}
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// secretsOf reports whether the request still holds a sealed token or a
// credential row.
func (e *env) secretsOf(id uuid.UUID) (token bool, cred bool) {
	e.T.Helper()
	var credID *uuid.UUID
	if err := e.DB.QueryRow(context.Background(), `SELECT sealed_token IS NOT NULL OR wrapped_dek IS NOT NULL, credential_id FROM restore_requests WHERE id = $1`, id).
		Scan(&token, &credID); err != nil {
		e.T.Fatal(err)
	}
	// A credentials row no live request points at was not deleted.
	var orphans int
	e.scan(&orphans, `SELECT count(*) FROM credentials WHERE id NOT IN (SELECT credential_id FROM restore_requests WHERE credential_id IS NOT NULL)`)
	return token, credID != nil || orphans > 0
}

// noCanary checks every response, the log, the outbox, the activity log
// and the request rows for the canaries.
func (e *env) noCanary() {
	e.T.Helper()
	ctx := context.Background()
	hay := []string{e.LogBuf.String()}
	hay = append(hay, e.bodies...)
	for _, q := range []string{
		`SELECT COALESCE(string_agg(payload::text, ' '), '') FROM outbox`,
		`SELECT COALESCE(string_agg(details::text, ' '), '') FROM activity_log`,
		`SELECT COALESCE(string_agg(options::text || progress::text || result::text || error || justification || decision_comment, ' '), '') FROM restore_requests`,
		`SELECT COALESCE(string_agg(username || keyvault_name || secret_name, ' '), '') FROM credentials`,
	} {
		var s string
		if err := e.DB.QueryRow(ctx, q).Scan(&s); err != nil {
			e.T.Fatal(err)
		}
		hay = append(hay, s)
	}
	for _, h := range hay {
		for _, c := range []string{canaryPassword, canaryToken} {
			if strings.Contains(h, c) {
				e.T.Fatalf("canary %q leaked: %.300s", c, h)
			}
		}
	}
}

// ---------------------------------------------------------------- tests

func TestOpenApprove(t *testing.T) {
	e := newEnv(t)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	checker := e.login("bob", "operator@env=prod", "operator@env=stage")

	rq := e.open(maker, e.pgInput(e.pgTarget))
	if rq.Status != restore.StatusPending || rq.Engine != "postgresql" || rq.BreakGlass || rq.Checker != nil ||
		strings.Join(rq.Databases, ",") != "shop,billing" || rq.Source.RunID != e.pgRun || rq.Source.CopyRunID != e.pgRun ||
		rq.Source.DestinationID != e.dest || rq.Source.ClusterName != "prod" || rq.Target.ClusterName != "stage" ||
		rq.Target.Service != "orders-pg-new" || rq.Credential == nil || rq.Credential.Username != "postgres" || rq.Credential.Source != "stored" ||
		rq.Options.Superuser == nil || !*rq.Options.Superuser || rq.Options.Globals == nil || !*rq.Options.Globals ||
		rq.Options.ServerVersion != "17.2" || rq.CanApprove || !rq.CanCancel || rq.ApproveDisabledReason == "" {
		t.Fatalf("opened: %+v", rq)
	}
	if !rq.ExpiresAt.Equal(e.now.Add(72*time.Hour).Truncate(time.Microsecond)) && rq.ExpiresAt.Sub(e.now) < 71*time.Hour {
		t.Fatalf("expires_at %s", rq.ExpiresAt)
	}
	// The inspector got the password: the credential is tested at open.
	if pgInspector.secrets[len(pgInspector.secrets)-1] != canaryPassword {
		t.Fatal("the inspector did not get the credential")
	}
	// Stored sealed: the credentials row holds a ciphertext, not the password.
	var ct []byte
	e.scan(&ct, `SELECT c.ciphertext FROM credentials c JOIN restore_requests r ON r.credential_id = c.id WHERE r.id = $1`, rq.ID)
	if len(ct) == 0 || bytes.Contains(ct, []byte(canaryPassword)) {
		t.Fatal("credential not sealed")
	}
	if ev := e.events("restore.%"); len(ev) != 1 || ev[0].Type != "restore.requested" || ev[0].Payload["link"] != "/approvals?restore="+rq.ID.String() {
		t.Fatalf("events: %+v", ev)
	}

	// The maker never approves; a checker lacking operate on either cluster
	// neither; an approver with operate on both does.
	var eb errBody
	if code := e.do(maker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", nil, &eb); code != http.StatusForbidden || eb.Error != "You opened this request" {
		t.Fatalf("maker approves: %d %+v", code, eb)
	}
	for _, half := range []*apitest.Client{
		e.login("carol", "operator@env=prod", "viewer@env=stage"),
		e.login("dave", "viewer@env=prod", "operator@env=stage"),
	} {
		if code := e.do(half, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", nil, &eb); code != http.StatusForbidden {
			t.Fatalf("checker lacking operate: %d %+v", code, eb)
		}
	}
	guest := e.Login(e.Principal("eve", "Guest", "admin"))
	if code := e.do(guest, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", nil, &eb); code != http.StatusForbidden || !strings.Contains(eb.Error, "Guest") {
		t.Fatalf("guest approves: %d %+v", code, eb)
	}

	var view restore.Request
	if code := e.do(checker, "GET", "/api/v1/restores/"+rq.ID.String(), nil, &view); code != 200 || !view.CanApprove {
		t.Fatalf("checker view: %d %+v", code, view)
	}
	var got restore.Request
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", map[string]string{"comment": "ok"}, &got); code != 200 {
		t.Fatalf("approve: %d %s", code, e.bodies[len(e.bodies)-1])
	}
	if got.Status != restore.StatusApproved || got.Checker == nil || got.Checker.DisplayName != "bob" || got.DecidedAt == nil ||
		got.ApprovedExpiresAt == nil || got.ApprovedExpiresAt.Sub(*got.DecidedAt) != 24*time.Hour || got.DecisionComment != "ok" {
		t.Fatalf("approved: %+v", got)
	}
	// Approved: the credential is kept for the executor.
	if _, cred := e.secretsOf(rq.ID); !cred {
		t.Fatal("approved request lost its credential")
	}
	if ev := e.events("restore.%"); len(ev) != 2 || ev[1].Type != "restore.approved" {
		t.Fatalf("events: %+v", ev)
	}
	if a := e.actions(rq.ID); strings.Join(a, ",") != "restore.approved,restore.requested" {
		t.Fatalf("audit: %v", a)
	}
	// Decided: approving again is a conflict.
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", nil, &eb); code != http.StatusConflict {
		t.Fatalf("approve twice: %d", code)
	}

	// One approved or running restore per target.
	rq2 := e.open(maker, e.pgInput(e.pgTarget))
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq2.ID.String()+"/approve", nil, &eb); code != http.StatusConflict || eb.Error != restore.ReasonTargetBusy {
		t.Fatalf("second approval for the target: %d %+v", code, eb)
	}
	if code := e.do(checker, "GET", "/api/v1/restores/"+rq2.ID.String(), nil, &view); code != 200 || view.Status != restore.StatusPending {
		t.Fatalf("still pending: %+v", view)
	}

	// Lists: waiting for me, mine.
	var list struct{ Items []restore.Request }
	if e.do(checker, "GET", "/api/v1/restores?waiting_for_me=1", nil, &list); len(list.Items) != 1 || list.Items[0].ID != rq2.ID {
		t.Fatalf("waiting for the checker: %+v", list.Items)
	}
	if e.do(maker, "GET", "/api/v1/restores?waiting_for_me=1", nil, &list); len(list.Items) != 0 {
		t.Fatalf("waiting for the maker: %+v", list.Items)
	}
	if e.do(maker, "GET", "/api/v1/restores?mine=1", nil, &list); len(list.Items) != 2 {
		t.Fatalf("mine: %+v", list.Items)
	}
	if e.do(checker, "GET", "/api/v1/restores?mine=1", nil, &list); len(list.Items) != 0 {
		t.Fatalf("checker's own: %+v", list.Items)
	}
	if e.do(checker, "GET", "/api/v1/restores?status=approved", nil, &list); len(list.Items) != 1 || list.Items[0].ID != rq.ID {
		t.Fatalf("approved: %+v", list.Items)
	}
	if e.do(checker, "GET", "/api/v1/restores?run_id="+e.pgRun.String(), nil, &list); len(list.Items) != 2 {
		t.Fatalf("by run: %+v", list.Items)
	}
	e.noCanary()
}

func TestRejectCancelWipe(t *testing.T) {
	e := newEnv(t)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	checker := e.login("bob", "operator")
	var eb errBody

	// Reject: a comment is required; the credential is deleted.
	rq := e.open(maker, e.pgInput(e.pgTarget))
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/reject", map[string]string{}, &eb); code != 422 || eb.Fields["comment"] == "" {
		t.Fatalf("reject without comment: %d %+v", code, eb)
	}
	var got restore.Request
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/reject", map[string]string{"comment": "wrong target"}, &got); code != 200 ||
		got.Status != restore.StatusRejected || got.Credential != nil || got.FinishedAt == nil || got.DecisionComment != "wrong target" {
		t.Fatalf("reject: %d %+v", code, got)
	}
	if tok, cred := e.secretsOf(rq.ID); tok || cred {
		t.Fatalf("rejected request keeps secrets: token %v credential %v", tok, cred)
	}
	if ev := e.events("restore.rejected"); len(ev) != 1 {
		t.Fatalf("events: %+v", ev)
	}

	// Cancel: the maker only, pending or approved (frees the target).
	rq = e.open(maker, e.pgInput(e.pgTarget))
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/cancel", nil, &eb); code != http.StatusForbidden {
		t.Fatalf("someone else cancels: %d", code)
	}
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/approve", nil, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if code := e.do(maker, "POST", "/api/v1/restores/"+rq.ID.String()+"/cancel", nil, &got); code != 200 || got.Status != restore.StatusCancelled {
		t.Fatalf("maker cancels an approved request: %d %+v", code, got)
	}
	if tok, cred := e.secretsOf(rq.ID); tok || cred {
		t.Fatal("cancelled request keeps secrets")
	}
	if code := e.do(maker, "POST", "/api/v1/restores/"+rq.ID.String()+"/cancel", nil, &eb); code != http.StatusConflict || !strings.Contains(eb.Error, "cancelled") {
		t.Fatalf("cancel twice: %d %+v", code, eb)
	}
	// The target is free again.
	rq3 := e.open(maker, e.pgInput(e.pgTarget))
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq3.ID.String()+"/approve", nil, nil); code != 200 {
		t.Fatalf("approve after cancel: %d", code)
	}
	if a := e.actions(rq.ID); strings.Join(a, ",") != "restore.approved,restore.cancelled,restore.requested" {
		t.Fatalf("audit: %v", a)
	}
	e.noCanary()
}

func TestExpire(t *testing.T) {
	e := newEnv(t)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	checker := e.login("bob", "operator")
	pending := e.open(maker, e.pgInput(e.pgTarget))
	approved := e.open(maker, e.pgInput(e.pgTarget2))
	if code := e.do(checker, "POST", "/api/v1/restores/"+approved.ID.String()+"/approve", nil, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}

	// Nothing is due yet.
	if n, err := e.api.ExpireDue(context.Background()); err != nil || n != 0 {
		t.Fatalf("expire now: %d %v", n, err)
	}
	// 25 hours later: the approved request did not start; the pending one
	// is still within its 72 h.
	e.now = e.now.Add(25 * time.Hour)
	if n, err := e.api.ExpireDue(context.Background()); err != nil || n != 1 {
		t.Fatalf("expire approved: %d %v", n, err)
	}
	var got restore.Request
	e.do(checker, "GET", "/api/v1/restores/"+approved.ID.String(), nil, &got)
	if got.Status != restore.StatusExpired || got.Credential != nil || got.FinishedAt == nil {
		t.Fatalf("approved not started: %+v", got)
	}
	if tok, cred := e.secretsOf(approved.ID); tok || cred {
		t.Fatal("expired request keeps secrets")
	}
	// Past 72 h: approving expires it on the spot.
	e.now = e.now.Add(48 * time.Hour)
	var eb errBody
	if code := e.do(checker, "POST", "/api/v1/restores/"+pending.ID.String()+"/approve", nil, &eb); code != http.StatusConflict || eb.Error != restore.ReasonExpired {
		t.Fatalf("approve expired: %d %+v", code, eb)
	}
	e.do(checker, "GET", "/api/v1/restores/"+pending.ID.String(), nil, &got)
	if got.Status != restore.StatusExpired {
		t.Fatalf("pending past TTL: %+v", got)
	}
	if tok, cred := e.secretsOf(pending.ID); tok || cred {
		t.Fatal("expired request keeps secrets")
	}
	if a := e.actions(pending.ID); strings.Join(a, ",") != "restore.expired,restore.requested" {
		t.Fatalf("audit: %v", a)
	}
	// The job expires pending requests too.
	p2 := e.open(maker, e.pgInput(e.pgTarget))
	e.now = e.now.Add(73 * time.Hour)
	if n, err := e.api.ExpireDue(context.Background()); err != nil || n != 1 {
		t.Fatalf("expire pending: %d %v", n, err)
	}
	e.do(checker, "GET", "/api/v1/restores/"+p2.ID.String(), nil, &got)
	if got.Status != restore.StatusExpired {
		t.Fatalf("job expiry: %+v", got)
	}
	e.noCanary()
}

func TestBreakGlass(t *testing.T) {
	e := newEnv(t)
	in := e.pgInput(e.pgTarget)
	in["break_glass"] = true
	var eb errBody

	// Not an admin on both clusters: refused.
	for _, c := range []*apitest.Client{
		e.login("ada", "operator"),
		e.login("bob", "admin@env=stage", "viewer@env=prod"),
		e.Login(e.Principal("eve", "Guest", "admin")),
	} {
		if code := e.do(c, "POST", "/api/v1/restores", in, &eb); code != http.StatusForbidden {
			t.Fatalf("break-glass by %s: %d %+v", c.P.DisplayName, code, eb)
		}
	}
	admin := e.login("root", "admin")
	// A justification is mandatory.
	short := e.pgInput(e.pgTarget)
	short["break_glass"], short["justification"] = true, "now"
	if code := e.do(admin, "POST", "/api/v1/restores", short, &eb); code != 422 || eb.Fields["justification"] == "" {
		t.Fatalf("no justification: %d %+v", code, eb)
	}
	if ev := e.events("restore.%"); len(ev) != 0 {
		t.Fatalf("refused requests emitted: %+v", ev)
	}

	rq := e.open(admin, in)
	if rq.Status != restore.StatusApproved || !rq.BreakGlass || rq.Checker != nil || rq.DecidedAt == nil || rq.ApprovedExpiresAt == nil ||
		rq.CanCancel != true {
		t.Fatalf("break-glass: %+v", rq)
	}
	ev := e.events("restore.%")
	if len(ev) != 1 || ev[0].Type != "restore.break_glass" || ev[0].Payload["justification"] != "Disaster recovery of orders after the prod outage" ||
		ev[0].Payload["decided_by"] != admin.P.ID.String() {
		t.Fatalf("events: %+v", ev)
	}
	if a := e.actions(rq.ID); strings.Join(a, ",") != "restore.break_glass,restore.requested" {
		t.Fatalf("audit: %v", a)
	}
	// The target is taken: a second break-glass is a conflict.
	if code := e.do(admin, "POST", "/api/v1/restores", in, &eb); code != http.StatusConflict || eb.Error != restore.ReasonTargetBusy {
		t.Fatalf("second break-glass: %d %+v", code, eb)
	}
	var n int
	e.scan(&n, `SELECT count(*) FROM credentials`)
	if n != 1 {
		t.Fatalf("credentials after a refused insert: %d", n)
	}
	e.noCanary()
}

func TestOpenRules(t *testing.T) {
	e := newEnv(t)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage", "operator@env=prod")
	field := func(in map[string]any, key, want string) {
		t.Helper()
		var eb errBody
		code := e.do(maker, "POST", "/api/v1/restores", in, &eb)
		if code != 422 || !strings.Contains(eb.Fields[key], want) {
			t.Fatalf("%s: want 422 with %s ~ %q, got %d %+v", key, key, want, code, eb)
		}
	}
	with := func(k string, v any) map[string]any {
		in := e.pgInput(e.pgTarget)
		in[k] = v
		return in
	}

	// The source run.
	failed := e.run(e.pgSource, "failed", "manual", "zip", nil)
	field(with("run_id", failed), "run_id", "this run is failed")
	dry := e.run(e.pgSource, "succeeded", "test", "zip", map[string]any{"databases": []string{"shop"}})
	field(with("run_id", dry), "run_id", "dry run")
	field(with("run_id", uuid.New()), "run_id", "unknown run")
	field(with("copy_destination_id", uuid.New()), "copy_destination_id", "no successful copy")

	// The target.
	field(with("target_id", e.pgSource), "target_id", "own target")
	ch := e.target(e.stage, "events-ch", "clickhouse", "")
	field(with("target_id", ch), "target_id", "the target is ClickHouse, the backup is PostgreSQL")
	gone := e.target(e.stage, "orders-pg-gone", "postgresql", "")
	e.exec(`UPDATE targets SET status = 'gone' WHERE id = $1`, gone)
	field(with("target_id", gone), "target_id", "gone")
	field(with("target_id", "nope"), "target_id", "unknown target")
	other := e.cluster("other", "other")
	hidden := e.target(other, "orders-pg-x", "postgresql", "")
	field(with("target_id", hidden), "target_id", "unknown target")

	// Input.
	field(with("databases", []string{"shop", "nope"}), "databases", "not in the backup: nope")
	field(with("credential", nil), "credential", "required")
	field(with("credential", map[string]any{"source": "stored", "username": "postgres"}), "credential.password", "required")
	field(with("vault_token", canaryToken), "vault_token", "only for a Vault")
	field(with("tls_ca_pem", "not a pem"), "tls_ca_pem", "no PEM")
	field(with("justification", "short"), "justification", "at least")

	// Inspector findings: a database with data is never overwritten.
	pgInspector.set(restore.TargetReport{Superuser: true, Existing: map[string]bool{"shop": true, "postgres": false}}, nil, false)
	field(e.pgInput(e.pgTarget), "databases", "already exist on the target with data in them (nothing is overwritten): shop")
	// An existing empty database is restored into; no superuser: no globals.
	pgInspector.set(restore.TargetReport{Superuser: false, Existing: map[string]bool{"postgres": false}}, nil, false)
	all := e.pgInput(e.pgTarget)
	delete(all, "databases")
	rq := e.open(maker, all)
	if strings.Join(rq.Databases, ",") != "postgres,shop,billing" || rq.Options.Globals == nil || *rq.Options.Globals ||
		len(rq.Options.Notes) != 2 || !strings.Contains(rq.Options.Notes[0], "postgres") || !strings.Contains(rq.Options.Notes[1], "superuser") {
		t.Fatalf("defaults and notes: %+v", rq)
	}
	pgInspector.set(restore.TargetReport{Superuser: true}, nil, false)

	// The target's check failed: the error is scrubbed of the password.
	pgInspector.set(restore.TargetReport{}, errors.New("FATAL: password authentication failed"), true)
	var eb errBody
	if code := e.do(maker, "POST", "/api/v1/restores", e.pgInput(e.pgTarget2), &eb); code != 422 ||
		!strings.Contains(eb.Fields["target_id"], "password authentication failed") {
		t.Fatalf("inspector error: %d %+v", code, eb)
	}
	pgInspector.set(restore.TargetReport{Superuser: true}, nil, false)

	// The target's agent is not connected here.
	e.dialer.mu.Lock()
	e.dialer.connected[e.stage] = false
	e.dialer.mu.Unlock()
	field(e.pgInput(e.pgTarget2), "target_id", "agent_offline")
	e.dialer.mu.Lock()
	e.dialer.connected[e.stage] = true
	e.dialer.mu.Unlock()

	// No inspector for the engine yet.
	restore.UnregisterInspectorForTest(t, "postgresql")
	field(e.pgInput(e.pgTarget2), "target_id", "restores of PostgreSQL are not available yet")

	// Permissions: read on the run's cluster and operate on the target's.
	if code := e.do(e.login("vic", "viewer"), "POST", "/api/v1/restores", e.pgInput(e.pgTarget2), &eb); code != http.StatusForbidden {
		t.Fatalf("viewer opens: %d %+v", code, eb)
	}
	if code := e.do(e.login("sam", "operator@env=stage"), "POST", "/api/v1/restores", e.pgInput(e.pgTarget2), &eb); code != 422 || eb.Fields["run_id"] != "unknown run" {
		t.Fatalf("no read on the run's cluster: %d %+v", code, eb)
	}
	e.noCanary()
}

func TestVaultRequest(t *testing.T) {
	e := newEnv(t)
	src := e.target(e.prod, "vault", "vault", "hashicorp")
	run := e.run(src, "succeeded", "manual", "snap", nil)
	tgt := e.target(e.stage, "vault-new", "vault", "hashicorp")
	configured := e.target(e.stage, "vault-live", "vault", "hashicorp")
	e.exec(`INSERT INTO vaults (target_id, provider, status) VALUES ($1, 'hashicorp', 'configured')`, configured)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	checker := e.login("bob", "operator")
	in := map[string]any{"run_id": run, "target_id": tgt, "vault_token": canaryToken, "justification": "Restore the vault after the outage"}

	field := func(in map[string]any, key, want string) {
		t.Helper()
		var eb errBody
		if code := e.do(maker, "POST", "/api/v1/restores", in, &eb); code != 422 || !strings.Contains(eb.Fields[key], want) {
			t.Fatalf("%s: %d %+v", key, code, eb)
		}
	}
	bad := map[string]any{"run_id": run, "target_id": configured, "vault_token": canaryToken, "justification": "Restore the vault after the outage"}
	field(bad, "target_id", "configured in Olympos")
	bad = map[string]any{"run_id": run, "target_id": tgt, "justification": "Restore the vault after the outage", "databases": []string{"x"},
		"credential": map[string]any{"source": "stored", "username": "u", "password": canaryPassword}}
	field(bad, "vault_token", "required")
	field(bad, "credential", "not used")
	field(bad, "databases", "whole snapshot")
	vaultInspector.set(restore.TargetReport{Initialized: true, Sealed: true, CanSnapshotForce: true}, nil, false)
	field(in, "target_id", "sealed")
	vaultInspector.set(restore.TargetReport{Initialized: true}, nil, false)
	field(in, "vault_token", "snapshot-force")
	vaultInspector.set(restore.TargetReport{Initialized: true, CanSnapshotForce: true}, nil, false)

	rq := e.open(maker, in)
	if rq.Engine != "vault" || !rq.HasVaultToken || rq.Credential != nil || len(rq.Databases) != 0 || rq.Options.Superuser != nil {
		t.Fatalf("vault request: %+v", rq)
	}
	if vaultInspector.secrets[len(vaultInspector.secrets)-1] != canaryToken {
		t.Fatal("the inspector did not get the token")
	}
	// Sealed with AAD restore_requests:<id>, and only that AAD opens it.
	var s secrets.Sealed
	if err := e.DB.QueryRow(context.Background(), `SELECT sealed_token, wrapped_dek, kek_version FROM restore_requests WHERE id = $1`, rq.ID).
		Scan(&s.Ciphertext, &s.WrappedDEK, &s.KEKVersion); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, []byte(canaryToken)) {
		t.Fatal("token stored in clear")
	}
	if b, err := e.Envelope.Open(context.Background(), s, []byte("restore_requests:"+rq.ID.String())); err != nil || string(b) != canaryToken {
		t.Fatalf("open sealed token: %v", err)
	}
	if _, err := e.Envelope.Open(context.Background(), s, []byte("restore_requests:"+uuid.NewString())); err == nil {
		t.Fatal("token opens under another request's AAD")
	}
	var got restore.Request
	if code := e.do(checker, "POST", "/api/v1/restores/"+rq.ID.String()+"/reject", map[string]string{"comment": "use the DR vault"}, &got); code != 200 ||
		got.HasVaultToken {
		t.Fatalf("reject: %d %+v", code, got)
	}
	if tok, _ := e.secretsOf(rq.ID); tok {
		t.Fatal("rejected request keeps its token")
	}
	e.noCanary()
}

func TestClickHouseDatabasesFromArchive(t *testing.T) {
	e := newEnv(t)
	src := e.target(e.prod, "events-ch", "clickhouse", "")
	run := e.run(src, "succeeded", "manual", "zip", nil)
	var path string
	e.scan(&path, `SELECT blob_path FROM backup_runs WHERE id = $1`, run)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("analytics/schema.sql")
	_, _ = w.Write([]byte("CREATE DATABASE analytics"))
	w, _ = zw.Create("manifest.json")
	_, _ = w.Write([]byte(`{"format":"olympos.clickhouse.v1","databases":[{"name":"analytics"},{"name":"default"}]}`))
	_ = zw.Close()
	e.blobs.put(path, buf.Bytes())
	tgt := e.target(e.stage, "events-ch-new", "clickhouse", "")
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")

	var res restore.CheckResult
	in := map[string]any{"run_id": run, "target_id": tgt, "credential": map[string]any{"source": "stored", "username": "default", "password": canaryPassword}}
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != 200 || !res.OK ||
		strings.Join(res.DatabasesInBackup, ",") != "analytics,default" || strings.Join(res.Databases, ",") != "analytics,default" {
		t.Fatalf("check: %d %+v", code, res)
	}
	in["databases"] = []string{"analytics", "events"}
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != 200 || res.OK || !strings.Contains(res.Fields["databases"], "events") {
		t.Fatalf("check unknown database: %d %+v", code, res)
	}
	// A corrupted archive is reported, not trusted.
	e.blobs.put(path, []byte("not a zip"))
	delete(in, "databases")
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != 200 || res.OK || !strings.Contains(res.Fields["copy_destination_id"], "manifest") {
		t.Fatalf("corrupted archive: %d %+v", code, res)
	}
	e.noCanary()
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	in := e.pgInput(e.pgTarget)
	delete(in, "justification")

	var res restore.CheckResult
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != 200 || !res.OK || res.Engine != "postgresql" ||
		strings.Join(res.DatabasesInBackup, ",") != "postgres,shop,billing" || res.Report == nil || !res.Report.Superuser ||
		res.CopyDestinationID == nil || *res.CopyDestinationID != e.dest || res.CopyRunID == nil || *res.CopyRunID != e.pgRun {
		t.Fatalf("check: %d %+v", code, res)
	}
	// Nothing is created.
	var n int
	e.scan(&n, `SELECT count(*) FROM restore_requests`)
	if n != 0 {
		t.Fatalf("check created %d requests", n)
	}
	e.scan(&n, `SELECT count(*) FROM credentials`)
	if n != 0 {
		t.Fatalf("check stored %d credentials", n)
	}
	if ev := e.events("%"); len(ev) != 0 {
		t.Fatalf("check emitted: %+v", ev)
	}
	e.scan(&n, `SELECT count(*) FROM activity_log WHERE action = 'restore.checked'`)
	if n != 1 {
		t.Fatalf("check audit rows: %d", n)
	}

	// Findings come back as ok=false with fields, for the dialog.
	pgInspector.set(restore.TargetReport{Superuser: true, Existing: map[string]bool{"shop": true}}, nil, false)
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != 200 || res.OK || !strings.Contains(res.Fields["databases"], "shop") ||
		res.Report == nil || !res.Report.Existing["shop"] {
		t.Fatalf("check with data on the target: %d %+v", code, res)
	}
	// Input problems found before the target is contacted: the databases
	// in the backup are still listed, the inspector is not called.
	pgInspector.set(restore.TargetReport{Superuser: true}, nil, false)
	calls := pgInspector.calls
	noCred := e.pgInput(e.pgTarget)
	delete(noCred, "credential")
	if code := e.do(maker, "POST", "/api/v1/restores/check", noCred, &res); code != 200 || res.OK || res.Fields["credential"] == "" ||
		len(res.DatabasesInBackup) != 3 || pgInspector.calls != calls {
		t.Fatalf("check without credential: %d %+v", code, res)
	}
	// Callers who may not open the request get an error, not a report.
	var eb errBody
	if code := e.do(e.login("vic", "viewer"), "POST", "/api/v1/restores/check", in, &eb); code != http.StatusForbidden {
		t.Fatalf("viewer check: %d %+v", code, eb)
	}
	if code := e.do(e.login("out", "operator@env=other"), "POST", "/api/v1/restores/check", in, &eb); code != 422 || eb.Fields["run_id"] != "unknown run" {
		t.Fatalf("out of scope check: %d %+v", code, eb)
	}
	// A password in an inspector error is scrubbed.
	pgInspector.set(restore.TargetReport{}, errors.New("auth failed"), true)
	if code := e.do(maker, "POST", "/api/v1/restores/check", in, &res); code != 200 || res.OK || !strings.Contains(res.Fields["target_id"], "auth failed") {
		t.Fatalf("check inspector error: %d %+v", code, res)
	}
	e.noCanary()
}

func TestVisibility(t *testing.T) {
	e := newEnv(t)
	maker := e.login("ada", "viewer@env=prod", "operator@env=stage")
	rq := e.open(maker, e.pgInput(e.pgTarget))
	id := rq.ID.String()
	var list struct{ Items []restore.Request }
	for name, grant := range map[string]string{"run-side": "viewer@env=prod", "target-side": "viewer@env=stage"} {
		c := e.login(name, grant)
		if code := e.do(c, "GET", "/api/v1/restores/"+id, nil, nil); code != 200 {
			t.Fatalf("%s reader: %d", name, code)
		}
		if e.do(c, "GET", "/api/v1/restores", nil, &list); len(list.Items) != 1 {
			t.Fatalf("%s list: %+v", name, list.Items)
		}
	}
	out := e.login("out", "admin@env=other")
	for _, p := range []string{"", "/approve", "/reject", "/cancel"} {
		method := "POST"
		if p == "" {
			method = "GET"
		}
		if code := e.do(out, method, "/api/v1/restores/"+id+p, map[string]string{"comment": "x"}, nil); code != http.StatusNotFound {
			t.Fatalf("out of scope %s %s: %d", method, p, code)
		}
	}
	if code, body := out.Raw("GET", "/api/v1/restores", nil); code != 200 || strings.Contains(body, id) {
		t.Fatalf("out of scope list: %d %s", code, body)
	}
	// Viewers see the request but may not decide it.
	var got restore.Request
	e.do(e.login("vic", "viewer"), "GET", "/api/v1/restores/"+id, nil, &got)
	if got.CanApprove || got.CanCancel || got.ApproveDisabledReason == "" {
		t.Fatalf("viewer: %+v", got)
	}
}
