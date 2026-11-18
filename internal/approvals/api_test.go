package approvals_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/targetid"
)

// Canary values: they must never appear in any response, log line, event,
// activity row or change event.
const (
	canaryA = "CANARY-a1b2c3-value-never-shown"
	canaryB = "CANARY-z9y8x7-value-never-shown"
)

type fakeApplier struct {
	mu     sync.Mutex
	calls  int32
	plans  [][]approvals.Write
	values []string
	fail   error
	delay  time.Duration
	next   int
}

func (f *fakeApplier) Apply(_ context.Context, _ uuid.UUID, writes []approvals.Write) ([]approvals.Applied, error) {
	atomic.AddInt32(&f.calls, 1)
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans = append(f.plans, writes)
	for _, w := range writes {
		for _, v := range w.Set {
			f.values = append(f.values, string(v))
		}
	}
	if f.fail != nil {
		return nil, f.fail
	}
	var out []approvals.Applied
	for _, w := range writes {
		f.next++
		v := f.next
		if w.Kind == approvals.WriteDestroy {
			v = 0
		}
		out = append(out, approvals.Applied{Mount: w.Mount, Path: w.Path, Kind: w.Kind, Version: v})
	}
	return out, nil
}

type env struct {
	*apitest.Env
	api     *approvals.API
	applier *fakeApplier
	prod    uuid.UUID // vault in cluster env=prod
	dev     uuid.UUID // vault in cluster env=dev
	now     time.Time
	bodies  []string
}

func seedVault(t *testing.T, db *store.DB, name string, labels map[string]string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var cid uuid.UUID
	lb, _ := json.Marshal(labels)
	if err := db.QueryRow(ctx, `INSERT INTO clusters (name, labels, status) VALUES ($1, $2, 'online') RETURNING id`, name, lb).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	tid := targetid.Compute(cid.String(), "vault", "vault", 8200)
	if _, err := db.Exec(ctx, `INSERT INTO targets (id, cluster_id, namespace, service, port, engine, vault_provider, status)
		VALUES ($1, $2, 'vault', 'vault', 8200, 'vault', 'hashicorp', 'configured')`, tid, cid); err != nil {
		t.Fatal(err)
	}
	var vid uuid.UUID
	mounts := `[{"path":"secret/","version":2,"managed":true},{"path":"legacy/","version":1,"managed":false}]`
	if err := db.QueryRow(ctx, `INSERT INTO vaults (target_id, provider, status, kv_mounts, role_id, secret_id_ref, configured_at)
		VALUES ($1, 'hashicorp', 'configured', $2, 'role', 'kv://local/x', now()) RETURNING id`, tid, mounts).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	return vid
}

func newEnv(t *testing.T) *env {
	e := &env{applier: &fakeApplier{}, now: time.Now()}
	e.Env = apitest.New(t, apitest.Options{Modules: func(ae *apitest.Env) []server.Module {
		e.api = &approvals.API{DB: ae.DB, Log: ae.Log, Envelope: ae.Envelope, HMAC: ae.HMAC, Applier: e.applier,
			Now: func() time.Time { return e.now }}
		return []server.Module{e.api}
	}})
	e.prod = seedVault(t, e.DB, "prod-1", map[string]string{"env": "prod"})
	e.dev = seedVault(t, e.DB, "dev-1", map[string]string{"env": "dev"})
	return e
}

func (e *env) do(c *apitest.Client, method, path string, body any, out any) int {
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

func (e *env) open(c *apitest.Client, vault uuid.UUID) approvals.ChangeRequest {
	e.T.Helper()
	var cr approvals.ChangeRequest
	code := e.do(c, "POST", "/api/v1/change-requests", map[string]any{
		"vault_id": vault, "justification": "Rotate the database password (INC-42)",
		"items": []map[string]any{
			{"mount": "secret/", "path": "app/db", "key": "PASSWORD", "op": "replace", "base_version": 3, "value": canaryA},
			{"mount": "secret/", "path": "app/db", "key": "API_KEY", "op": "create", "base_version": 3, "value": canaryB},
			{"mount": "secret/", "path": "app/db", "key": "OLD", "op": "delete", "base_version": 3},
		}}, &cr)
	if code != http.StatusCreated {
		e.T.Fatalf("open change request: %d %v", code, e.bodies[len(e.bodies)-1])
	}
	return cr
}

func (e *env) sealedCount(id uuid.UUID) (int, int) {
	e.T.Helper()
	var sealed, dek int
	if err := e.DB.QueryRow(context.Background(), `SELECT count(sealed_value), count(wrapped_dek) FROM change_items WHERE cr_id = $1`, id).
		Scan(&sealed, &dek); err != nil {
		e.T.Fatal(err)
	}
	return sealed, dek
}

func (e *env) assertScrubbed(id uuid.UUID) {
	e.T.Helper()
	if s, d := e.sealedCount(id); s != 0 || d != 0 {
		e.T.Fatalf("cr %s terminal but %d sealed values / %d wrapped DEKs remain", id, s, d)
	}
}

// assertNoCanary greps responses, logs and every audit-ish table.
func (e *env) assertNoCanary() {
	e.T.Helper()
	for _, b := range e.bodies {
		if strings.Contains(b, canaryA) || strings.Contains(b, canaryB) {
			e.T.Fatalf("secret value in API response: %s", b)
		}
	}
	if l := e.LogBuf.String(); strings.Contains(l, canaryA) || strings.Contains(l, canaryB) {
		e.T.Fatal("secret value in logs")
	}
	for _, tbl := range []string{"change_requests", "change_items", "change_events", "activity_log", "outbox", "findings"} {
		var n int
		if err := e.DB.QueryRow(context.Background(), `SELECT count(*) FROM `+tbl+` t WHERE t::text LIKE '%' || $1 || '%' OR t::text LIKE '%' || $2 || '%'`,
			canaryA, canaryB).Scan(&n); err != nil {
			e.T.Fatal(err)
		}
		if n > 0 {
			e.T.Fatalf("secret value stored in plaintext in %s", tbl)
		}
	}
}

func TestMakerCannotApproveOwnRequestAdminIncluded(t *testing.T) {
	e := newEnv(t)
	admin := e.Login(e.Principal("ada", "Member", "admin"))
	cr := e.open(admin, e.prod)
	if cr.CanApprove || cr.ApproveDisabledReason != approvals.ReasonOwnRequest || !cr.CanCancel {
		t.Fatalf("maker view: can_approve=%v reason=%q can_cancel=%v", cr.CanApprove, cr.ApproveDisabledReason, cr.CanCancel)
	}
	var body map[string]any
	if code := e.do(admin, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, &body); code != http.StatusForbidden {
		t.Fatalf("admin approving own request: %d", code)
	}
	if body["error"] != approvals.ReasonOwnRequest {
		t.Fatalf("reason: %v", body)
	}
	if code := e.do(admin, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/reject", map[string]any{"comment": "no"}, nil); code != http.StatusForbidden {
		t.Fatalf("admin rejecting own request: %d", code)
	}
	// Same Entra identity, second principal row cannot exist (unique), and
	// the DB CHECK refuses checker = maker even if the code were bypassed.
	_, err := e.DB.Exec(context.Background(), `UPDATE change_requests SET checker_principal_id = maker_principal_id WHERE id = $1`, cr.ID)
	if err == nil {
		t.Fatal("DB must refuse checker = maker")
	}
	if atomic.LoadInt32(&e.applier.calls) != 0 {
		t.Fatal("nothing must be applied")
	}
	e.assertNoCanary()
}

func TestApproveAppliesAndScrubs(t *testing.T) {
	e := newEnv(t)
	maker := e.Login(e.Principal("ada", "Member", "vault-maker@env=prod"))
	checker := e.Login(e.Principal("bob", "Member", "vault-approver@env=prod"))
	cr := e.open(maker, e.prod)
	if s, d := e.sealedCount(cr.ID); s != 2 || d != 2 {
		t.Fatalf("pending request must hold 2 sealed values, got %d/%d", s, d)
	}
	for _, it := range cr.Items {
		if it.Op != approvals.OpDelete && !strings.HasPrefix(it.Fingerprint, "hm:") {
			t.Fatalf("fingerprint missing: %+v", it)
		}
	}
	// Checker's view: can approve, sees fingerprints, never values.
	var view approvals.ChangeRequest
	if code := e.do(checker, "GET", "/api/v1/change-requests/"+cr.ID.String(), nil, &view); code != 200 || !view.CanApprove {
		t.Fatalf("checker view: %d %+v", code, view)
	}
	var waiting struct{ Items []approvals.ChangeRequest }
	e.do(checker, "GET", "/api/v1/change-requests?waiting_for_me=true", nil, &waiting)
	if len(waiting.Items) != 1 {
		t.Fatalf("waiting_for_me: %d", len(waiting.Items))
	}
	e.do(maker, "GET", "/api/v1/change-requests?waiting_for_me=true", nil, &waiting)
	if len(waiting.Items) != 0 {
		t.Fatal("own request is not waiting for the maker")
	}
	e.do(maker, "GET", "/api/v1/change-requests?mine=true", nil, &waiting)
	if len(waiting.Items) != 1 {
		t.Fatal("mine")
	}

	var done approvals.ChangeRequest
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{"comment": "ok"}, &done); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if done.Status != approvals.StatusApplied || done.Checker == nil || done.Checker.ID != checker.P.ID {
		t.Fatalf("after approve: %+v", done)
	}
	// One path → one merged write with the plaintext values.
	if len(e.applier.plans) != 1 || len(e.applier.plans[0]) != 1 {
		t.Fatalf("plan: %+v", e.applier.plans)
	}
	w := e.applier.plans[0][0]
	if w.Kind != approvals.WritePatch || w.BaseVersion != 3 || len(w.Set) != 2 || len(w.Delete) != 1 {
		t.Fatalf("write: %+v", w)
	}
	if got := strings.Join(e.applier.values, ","); !strings.Contains(got, canaryA) || !strings.Contains(got, canaryB) {
		t.Fatal("applier must receive the unsealed values")
	}
	e.assertScrubbed(cr.ID)
	var managed int
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM vault_managed_versions WHERE cr_id = $1`, cr.ID).Scan(&managed)
	if managed != 1 {
		t.Fatalf("managed versions recorded: %d", managed)
	}
	// Trail: opened, approved, applied.
	var full approvals.ChangeRequest
	e.do(checker, "GET", "/api/v1/change-requests/"+cr.ID.String(), nil, &full)
	var kinds []string
	for _, ev := range full.Events {
		kinds = append(kinds, ev.Kind)
	}
	if strings.Join(kinds, ",") != "opened,approved,applied" {
		t.Fatalf("events: %v", kinds)
	}
	// Second decision is impossible.
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, nil); code != http.StatusConflict {
		t.Fatalf("second approve: %d", code)
	}
	// Activity + outbox.
	var acts, opened int
	var openedPayload []byte
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM activity_log WHERE object_id = $1 AND action IN ('cr.opened','cr.approved','cr.applied')`, cr.ID.String()).Scan(&acts)
	if acts != 3 {
		t.Fatalf("activity rows: %d", acts)
	}
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*), max(payload::text)::bytea FROM outbox WHERE event_type = 'cr.opened'`).Scan(&opened, &openedPayload)
	if opened != 1 {
		t.Fatalf("cr.opened events: %d", opened)
	}
	var p map[string]any
	_ = json.Unmarshal(openedPayload, &p)
	if p["link"] != approvals.Link(cr.ID) || p["fields"] != nil {
		t.Fatalf("cr.opened must carry a link only: %v", p)
	}
	e.assertNoCanary()
}

func TestDoubleApproveRace(t *testing.T) {
	e := newEnv(t)
	e.applier.delay = 300 * time.Millisecond
	maker := e.Login(e.Principal("ada", "Member", "vault-maker"))
	c1 := e.Login(e.Principal("bob", "Member", "vault-approver"))
	c2 := e.Login(e.Principal("cid", "Member", "admin"))
	cr := e.open(maker, e.prod)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, c := range []*apitest.Client{c1, c2} {
		wg.Add(1)
		go func(i int, c *apitest.Client) {
			defer wg.Done()
			codes[i], _ = c.Raw("POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{})
		}(i, c)
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 409:
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("codes: %v", codes)
	}
	if n := atomic.LoadInt32(&e.applier.calls); n != 1 {
		t.Fatalf("applied %d times", n)
	}
	var approvedEvents int
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM change_events WHERE cr_id = $1 AND kind = 'approved'`, cr.ID).Scan(&approvedEvents)
	if approvedEvents != 1 {
		t.Fatalf("approved events: %d", approvedEvents)
	}
}

func TestGuestNeverApproves(t *testing.T) {
	e := newEnv(t)
	maker := e.Login(e.Principal("ada", "Member", "vault-maker"))
	guest := e.Login(e.Principal("eve", "Guest", "admin", "vault-approver"))
	ext := e.Login(e.Principal("mallory_fabrikam.com#EXT#", "Member", "vault-approver"))
	cr := e.open(maker, e.prod)
	for _, c := range []*apitest.Client{guest, ext} {
		var view approvals.ChangeRequest
		e.do(c, "GET", "/api/v1/change-requests/"+cr.ID.String(), nil, &view)
		if view.CanApprove {
			t.Fatal("guest can_approve")
		}
		if code := e.do(c, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, nil); code != http.StatusForbidden {
			t.Fatalf("guest approve: %d", code)
		}
	}
	if s, _ := e.sealedCount(cr.ID); s != 2 {
		t.Fatal("still pending")
	}
}

func TestScopeAndRoles(t *testing.T) {
	e := newEnv(t)
	devMaker := e.Login(e.Principal("dave", "Member", "vault-maker@env=dev"))
	viewer := e.Login(e.Principal("vic", "Member", "viewer"))
	prodMaker := e.Login(e.Principal("pat", "Member", "vault-maker@env=prod"))
	devApprover := e.Login(e.Principal("dan", "Member", "vault-approver@env=dev"))
	body := map[string]any{"vault_id": e.prod, "justification": "Rotate the database password",
		"items": []map[string]any{{"mount": "secret/", "path": "a", "key": "K", "op": "replace", "base_version": 1, "value": canaryA}}}
	// Outside scope: 404, never 403.
	if code := e.do(devMaker, "POST", "/api/v1/change-requests", body, nil); code != http.StatusNotFound {
		t.Fatalf("maker outside scope: %d", code)
	}
	// Viewer in scope: 403.
	if code := e.do(viewer, "POST", "/api/v1/change-requests", body, nil); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	// Validation.
	short := map[string]any{"vault_id": e.prod, "justification": "short", "items": body["items"]}
	var fe struct{ Fields map[string]string }
	if code := e.do(prodMaker, "POST", "/api/v1/change-requests", short, &fe); code != 422 || fe.Fields["justification"] == "" {
		t.Fatalf("short justification: %d %v", code, fe)
	}
	withValue := map[string]any{"vault_id": e.prod, "justification": "Remove the legacy key",
		"items": []map[string]any{{"mount": "secret/", "path": "a", "key": "K", "op": "delete", "base_version": 1, "value": canaryB}}}
	if code := e.do(prodMaker, "POST", "/api/v1/change-requests", withValue, nil); code != 422 {
		t.Fatalf("value on delete: %d", code)
	}
	kv1 := map[string]any{"vault_id": e.prod, "justification": "Write to the KV v1 mount",
		"items": []map[string]any{{"mount": "legacy/", "path": "a", "key": "K", "op": "create", "value": canaryB}}}
	if code := e.do(prodMaker, "POST", "/api/v1/change-requests", kv1, nil); code != 422 {
		t.Fatalf("kv v1 mount: %d", code)
	}
	cr := e.open(prodMaker, e.prod)
	for _, c := range []*apitest.Client{devMaker, devApprover} {
		if code := e.do(c, "GET", "/api/v1/change-requests/"+cr.ID.String(), nil, nil); code != http.StatusNotFound {
			t.Fatalf("get outside scope: %d", code)
		}
		if code := e.do(c, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, nil); code != http.StatusNotFound {
			t.Fatalf("approve outside scope: %d", code)
		}
		var list struct{ Items []approvals.ChangeRequest }
		e.do(c, "GET", "/api/v1/change-requests", nil, &list)
		if len(list.Items) != 0 {
			t.Fatal("list leaks requests outside scope")
		}
	}
	// Viewer in scope sees it but cannot act.
	var view approvals.ChangeRequest
	if code := e.do(viewer, "GET", "/api/v1/change-requests/"+cr.ID.String(), nil, &view); code != 200 || view.CanApprove || view.CanCancel {
		t.Fatalf("viewer: %d %+v", code, view)
	}
	if code := e.do(viewer, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, nil); code != http.StatusForbidden {
		t.Fatalf("viewer approve: %d", code)
	}
	e.assertNoCanary()
}

func TestRejectCancelExpireFailScrub(t *testing.T) {
	e := newEnv(t)
	maker := e.Login(e.Principal("ada", "Member", "vault-maker"))
	checker := e.Login(e.Principal("bob", "Member", "vault-approver"))

	// Reject needs a comment.
	cr := e.open(maker, e.prod)
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/reject", map[string]any{}, nil); code != 422 {
		t.Fatalf("reject without comment: %d", code)
	}
	var out approvals.ChangeRequest
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/reject", map[string]any{"comment": "wrong ticket"}, &out); code != 200 || out.Status != approvals.StatusRejected {
		t.Fatalf("reject: %d %s", code, out.Status)
	}
	e.assertScrubbed(cr.ID)

	// Cancel: maker only.
	cr = e.open(maker, e.prod)
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/cancel", nil, nil); code != http.StatusForbidden {
		t.Fatalf("cancel by checker: %d", code)
	}
	if code := e.do(maker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/cancel", nil, &out); code != 200 || out.Status != approvals.StatusCancelled {
		t.Fatalf("cancel: %d %s", code, out.Status)
	}
	e.assertScrubbed(cr.ID)

	// Expiry job.
	cr = e.open(maker, e.prod)
	e.now = e.now.Add(approvals.DefaultTTL + time.Minute)
	n, err := e.api.ExpireDue(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	e.do(maker, "GET", "/api/v1/change-requests/"+cr.ID.String(), nil, &out)
	if out.Status != approvals.StatusExpired || out.CanApprove {
		t.Fatalf("expired: %+v", out.Status)
	}
	e.assertScrubbed(cr.ID)
	var expiredEvents int
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE event_type = 'cr.expired'`).Scan(&expiredEvents)
	if expiredEvents != 1 {
		t.Fatal("cr.expired event")
	}

	// Approving after the TTL (before the job ran) expires it: 409.
	cr = e.open(maker, e.prod)
	e.now = e.now.Add(approvals.DefaultTTL + time.Minute)
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, nil); code != http.StatusConflict {
		t.Fatalf("approve expired: %d", code)
	}
	e.assertScrubbed(cr.ID)

	// Apply failure (cas conflict) → failed, scrubbed, cr.failed.
	e.applier.fail = &approvals.SafeError{Msg: "check-and-set conflict on secret/app/db"}
	cr = e.open(maker, e.prod)
	if code := e.do(checker, "POST", "/api/v1/change-requests/"+cr.ID.String()+"/approve", map[string]any{}, &out); code != 200 {
		t.Fatalf("approve (fails): %d", code)
	}
	if out.Status != approvals.StatusFailed || !strings.Contains(out.Failure, "check-and-set") {
		t.Fatalf("failed: %s %q", out.Status, out.Failure)
	}
	e.assertScrubbed(cr.ID)
	var failed int
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE event_type = 'cr.failed'`).Scan(&failed)
	if failed != 1 {
		t.Fatal("cr.failed event")
	}

	// Every terminal state, checked at the DB level: no sealed value left.
	var leftovers int
	_ = e.DB.QueryRow(context.Background(), `SELECT count(*) FROM change_items i JOIN change_requests c ON c.id = i.cr_id
		WHERE c.status IN ('applied','rejected','expired','failed','cancelled') AND (i.sealed_value IS NOT NULL OR i.wrapped_dek IS NOT NULL)`).Scan(&leftovers)
	if leftovers != 0 {
		t.Fatalf("%d sealed values in terminal requests", leftovers)
	}
	// change_events is append-only.
	if _, err := e.DB.Exec(context.Background(), `DELETE FROM change_events`); err == nil {
		t.Fatal("change_events must be append-only")
	}
	e.assertNoCanary()
}

func TestTerminalTriggerScrubs(t *testing.T) {
	// Defense in depth: even a bare status update drops the sealed values.
	e := newEnv(t)
	maker := e.Login(e.Principal("ada", "Member", "vault-maker"))
	for _, st := range []string{"applied", "rejected", "expired", "failed", "cancelled"} {
		cr := e.open(maker, e.prod)
		if _, err := e.DB.Exec(context.Background(), `UPDATE change_requests SET status = $2 WHERE id = $1`, cr.ID, st); err != nil {
			t.Fatal(err)
		}
		e.assertScrubbed(cr.ID)
	}
}
