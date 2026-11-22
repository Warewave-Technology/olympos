//go:build dev

package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/apitest"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/server"
)

const canaryPW = "Canary-Stored-Pw-4b7e19"

type apiEnv struct {
	e      *apitest.Env
	dialer *fakeDialer
	prod   fixture
	dev    fixture
}

func newAPI(t *testing.T) *apiEnv {
	t.Helper()
	a := &apiEnv{dialer: newDialer()}
	a.e = apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&backup.API{DB: e.DB, Log: e.Log, Dialer: a.dialer, Creds: &backup.Credentials{KV: e.KV, Envelope: e.Envelope}}}
	}})
	a.prod = seed(t, a.e.DB, "prod-aks", map[string]string{"env": "prod"}, "online")
	a.dev = seed(t, a.e.DB, "dev-kind", map[string]string{"env": "dev"}, "online")
	a.dialer.connected[a.prod.ClusterID] = true
	// Prod operators may reference kv-test secrets (security review #2).
	if err := secrets.ConfigureRefPolicy([]secrets.RefRule{{Ref: "kv-test/*", Scope: "env=prod"}}, []secrets.Ref{{Vault: "kv-test", Secret: "olympos-hmac"}}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secrets.ConfigureRefPolicy(nil, nil, nil) })
	return a
}

// Security review #2: a Key Vault reference is resolved with Olympos'
// identity, so who may enter one is limited, and Olympos' own secrets are
// never resolved for a user.
func TestKeyVaultReferencePolicy(t *testing.T) {
	a := newAPI(t)
	e := a.e
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	devOp := e.Login(e.Principal("dev", "Member", "operator@env=dev"))
	admin := e.Login(e.Principal("root", "Member", "admin"))
	job := func(target string, dest uuid.UUID, ref string) map[string]any {
		return map[string]any{"target_id": target, "destination_id": dest, "cron": "0 2 * * *",
			"credential": map[string]any{"source": "keyvault_ref", "ref": ref, "username": "backup"}}
	}
	var verr struct{ Fields map[string]string }
	for _, c := range []struct {
		name string
		as   *apitest.Client
		in   map[string]any
		want string
	}{
		{"dev operator, no rule for dev", devOp, job(a.dev.TargetID, a.dev.DestID, "kv://kv-test/pg"), "not allowed"},
		{"prod operator, other vault", op, job(a.prod.TargetID, a.prod.DestID, "kv://kv-corp/prod-db-password"), "not allowed"},
		{"prod operator, Olympos HMAC key", op, job(a.prod.TargetID, a.prod.DestID, "kv://kv-test/olympos-hmac"), "used by Olympos itself"},
		{"admin, AppRole secret_id", admin, job(a.prod.TargetID, a.prod.DestID, "kv://kv-test/olympos-vault-0b1d-secret-id"), "used by Olympos itself"},
	} {
		verr.Fields = nil
		if code := c.as.Do("POST", "/api/v1/backup/jobs", c.in, &verr); code != http.StatusUnprocessableEntity || !strings.Contains(verr.Fields["credential.ref"], c.want) {
			t.Errorf("%s: %d %+v", c.name, code, verr.Fields)
		}
	}
	if code := admin.Do("POST", "/api/v1/backup/jobs", job(a.dev.TargetID, a.dev.DestID, "kv://kv-corp/dev-db"), nil); code != http.StatusCreated {
		t.Fatalf("global admin may reference any other secret: %d", code)
	}
	if code := op.Do("POST", "/api/v1/backup/jobs", job(a.prod.TargetID, a.prod.DestID, "kv://KV-TEST/pg"), nil); code != http.StatusCreated {
		t.Fatalf("rule match (case-insensitive): %d", code)
	}

	// A stored reference to a now-reserved secret is not resolved at use.
	if err := e.KV.SetSecret(context.Background(), "kv-test", "olympos-hmac", []byte("k")); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.ResolveUserRef(context.Background(), e.KV, "kv://kv-test/olympos-hmac"); err != secrets.ErrRefReserved {
		t.Fatalf("reserved resolve: %v", err)
	}
}

func TestJobsAPI(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	devOp := e.Login(e.Principal("dev", "Member", "operator@env=dev"))
	viewer := e.Login(e.Principal("vic", "Member", "viewer@env=prod"))
	ch := addChannel(t, e.DB)
	var bodies []string

	// Validation.
	var verr struct {
		Error  string
		Fields map[string]string
	}
	code := op.Do("POST", "/api/v1/backup/jobs", map[string]any{"target_id": a.prod.TargetID, "destination_id": a.prod.DestID,
		"cron": "61 * * * *", "credential": map[string]any{"source": "stored", "username": "backup"}}, &verr)
	if code != http.StatusUnprocessableEntity || verr.Fields["cron"] == "" || verr.Fields["credential.password"] == "" {
		t.Fatalf("validation: %d %+v", code, verr)
	}

	// Create with a stored credential.
	input := map[string]any{"target_id": a.prod.TargetID, "destination_id": a.prod.DestID, "cron": "0 2 * * *", "timezone": "Europe/Istanbul",
		"credential":        map[string]any{"source": "stored", "username": "backup", "password": canaryPW},
		"engine_options":    map[string]any{"databases": []string{"a"}},
		"notify_channel_id": ch.String(), "enabled": true}
	code, raw := op.Raw("POST", "/api/v1/backup/jobs", input)
	bodies = append(bodies, raw)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var job backup.JobView
	_, raw = op.Raw("GET", "/api/v1/backup/jobs?target_id="+a.prod.TargetID, nil)
	bodies = append(bodies, raw)
	var list struct{ Items []backup.JobView }
	op.Do("GET", "/api/v1/backup/jobs", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: %+v", list)
	}
	job = list.Items[0]
	if job.Credential == nil || job.Credential.Source != "stored" || job.Credential.Username != "backup" || job.NextRunAt == nil ||
		job.Target.Status != "configured" || job.Destination.Name != "dest" || job.NotifyChannelID == nil || *job.NotifyChannelID != ch {
		t.Fatalf("job: %+v", job)
	}
	// 02:00 Istanbul = 23:00 UTC.
	if job.NextRunAt.UTC().Hour() != 23 {
		t.Fatalf("next run %v", job.NextRunAt)
	}
	jobPath := "/api/v1/backup/jobs/" + job.ID.String()

	// Scope: other env operator sees 404 everywhere; viewer can read, not change.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", jobPath, nil}, {"PATCH", jobPath, map[string]any{"enabled": false}}, {"DELETE", jobPath, nil},
		{"POST", jobPath + "/run", map[string]any{}},
		{"POST", "/api/v1/backup/jobs", map[string]any{"target_id": a.prod.TargetID, "destination_id": a.prod.DestID, "cron": "0 2 * * *",
			"credential": map[string]any{"source": "stored", "username": "x", "password": "y"}}},
		{"POST", "/api/v1/backup/test-connection", map[string]any{"target_id": a.prod.TargetID,
			"credential": map[string]any{"source": "stored", "username": "x", "password": "y"}}},
	} {
		if code := devOp.Do(c.method, c.path, c.body, nil); code != http.StatusNotFound {
			t.Fatalf("dev operator %s %s: %d", c.method, c.path, code)
		}
	}
	var devList struct{ Items []backup.JobView }
	devOp.Do("GET", "/api/v1/backup/jobs", nil, &devList)
	if len(devList.Items) != 0 {
		t.Fatal("out-of-scope job listed")
	}
	if code := viewer.Do("GET", jobPath, nil, nil); code != http.StatusOK {
		t.Fatalf("viewer get: %d", code)
	}
	if code := viewer.Do("PATCH", jobPath, map[string]any{"enabled": false}, nil); code != http.StatusForbidden {
		t.Fatalf("viewer patch: %d", code)
	}
	if code := op.Do("GET", "/api/v1/backup/jobs/"+uuid.NewString(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("missing job: %d", code)
	}

	// Patch: switch to a Key Vault reference; the stored row is removed.
	oldCred := job.Credential.ID
	if err := e.KV.SetSecret(ctx, "kv-test", "orders-pg", []byte(canaryPW+"\n")); err != nil {
		t.Fatal(err)
	}
	var patched backup.JobView
	code = op.Do("PATCH", jobPath, map[string]any{"cron": "0 3 * * *", "notify_channel_id": nil,
		"credential": map[string]any{"source": "keyvault_ref", "ref": "kv://kv-test/orders-pg", "username": "backup"}}, &patched)
	if code != http.StatusOK || patched.Cron != "0 3 * * *" || patched.NotifyChannelID != nil || patched.Credential.Source != "keyvault_ref" ||
		patched.Credential.Ref != "kv://kv-test/orders-pg" {
		t.Fatalf("patch: %d %+v", code, patched)
	}
	var n int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE id = $1`, oldCred).Scan(&n)
	if n != 0 {
		t.Fatal("replaced stored credential not deleted")
	}
	if code := op.Do("PATCH", jobPath, map[string]any{"target_id": a.dev.TargetID}, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("target change: %d", code)
	}

	// Estimates: avg wire bytes of recent runs × runs/month, cost from the cluster rate.
	for _, wb := range []int64{1 << 30, 3 << 30} {
		if _, err := e.DB.Exec(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, wire_bytes, bytes)
			VALUES ($1, 'schedule', 'succeeded', now(), now(), $2, $2)`, job.ID, wb); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.DB.Exec(ctx, `UPDATE clusters SET egress_rate_per_gb = 0.09 WHERE id = $1`, a.prod.ClusterID); err != nil {
		t.Fatal(err)
	}
	var est backup.JobView
	op.Do("GET", jobPath, nil, &est)
	if est.EstimatedMonthlyBytes != 60<<30 || est.EstimatedMonthlyCost == nil || *est.EstimatedMonthlyCost != 5.4 || est.LastRun == nil {
		t.Fatalf("estimate: %d %v %+v", est.EstimatedMonthlyBytes, est.EstimatedMonthlyCost, est.LastRun)
	}

	// Manual run / dry run.
	var run backup.Run
	if code := op.Do("POST", jobPath+"/run", map[string]any{"trigger": "test"}, &run); code != http.StatusAccepted || run.Status != "queued" || run.Trigger != "test" {
		t.Fatalf("run: %d %+v", code, run)
	}
	if code := op.Do("POST", jobPath+"/run", nil, nil); code != http.StatusConflict {
		t.Fatalf("second run: %d", code)
	}
	var got backup.Run
	if code := op.Do("GET", "/api/v1/backup/runs/"+run.ID.String(), nil, &got); code != http.StatusOK || got.ID != run.ID || got.ClusterName != "prod-aks" {
		t.Fatalf("get run: %d %+v", code, got)
	}
	if code := devOp.Do("GET", "/api/v1/backup/runs/"+run.ID.String(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("dev get run: %d", code)
	}
	var runs struct{ Items []backup.Run }
	op.Do("GET", "/api/v1/backup/runs?job_id="+job.ID.String(), nil, &runs)
	if len(runs.Items) != 3 || runs.Items[0].ID != run.ID {
		t.Fatalf("runs: %+v", runs.Items)
	}
	devOp.Do("GET", "/api/v1/backup/runs", nil, &runs)
	if len(runs.Items) != 0 {
		t.Fatal("dev operator sees prod runs")
	}

	// Activity for every change.
	var acts int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE action LIKE 'backup.%'`).Scan(&acts)
	if acts < 3 {
		t.Fatalf("activity entries: %d", acts)
	}

	// Delete: soft delete, credential row removed, queued run failed, target back to candidate.
	if code := op.Do("DELETE", jobPath, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code := op.Do("GET", jobPath, nil, nil); code != http.StatusNotFound {
		t.Fatalf("deleted job visible: %d", code)
	}
	var st string
	_ = e.DB.QueryRow(ctx, `SELECT status FROM targets WHERE id = $1`, a.prod.TargetID).Scan(&st)
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM credentials`).Scan(&n)
	if st != "candidate" || n != 0 {
		t.Fatalf("after delete: target=%s credentials=%d", st, n)
	}
	_ = e.DB.QueryRow(ctx, `SELECT status FROM backup_runs WHERE id = $1`, run.ID).Scan(&st)
	if st != "failed" {
		t.Fatalf("queued run after delete: %s", st)
	}

	// The stored password never appears in responses, logs or the DB in clear.
	for _, b := range bodies {
		if strings.Contains(b, canaryPW) {
			t.Fatal("password in API response")
		}
	}
	if strings.Contains(e.LogBuf.String(), canaryPW) {
		t.Fatal("password in logs")
	}
}

func TestStoredCredentialEncrypted(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	code, raw := op.Raw("POST", "/api/v1/backup/jobs", map[string]any{"target_id": a.prod.TargetID, "destination_id": a.prod.DestID,
		"cron": "@daily", "credential": map[string]any{"source": "stored", "username": "backup", "password": canaryPW}})
	if code != http.StatusCreated || strings.Contains(raw, canaryPW) || strings.Contains(raw, "password") {
		t.Fatalf("create: %d %s", code, raw)
	}
	var ct, dek []byte
	var id uuid.UUID
	if err := e.DB.QueryRow(ctx, `SELECT id, ciphertext, wrapped_dek FROM credentials`).Scan(&id, &ct, &dek); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte(canaryPW)) || len(dek) == 0 {
		t.Fatal("credential not encrypted")
	}
	creds := &backup.Credentials{KV: e.KV, Envelope: e.Envelope}
	c, err := creds.Resolve(ctx, e.DB, id)
	if err != nil || string(c.Secret) != canaryPW {
		t.Fatalf("resolve: %v", err)
	}
	// AAD binds the ciphertext to its row: moving it to another row fails.
	other := uuid.New()
	if _, err := e.DB.Exec(ctx, `INSERT INTO credentials (id, kind, ciphertext, wrapped_dek, username) SELECT $1, kind, ciphertext, wrapped_dek, username FROM credentials WHERE id = $2`, other, id); err != nil {
		t.Fatal(err)
	}
	if _, err := creds.Resolve(ctx, e.DB, other); err == nil {
		t.Fatal("swapped ciphertext decrypted")
	}
}

func TestConnectionTestAPI(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	cred := map[string]any{"source": "stored", "username": "backup", "password": canaryPW}

	// Target without TLS → tls_ok=false + tls.missing finding; error text scrubbed.
	var ct backup.ConnectionTest
	code := op.Do("POST", "/api/v1/backup/test-connection", map[string]any{"target_id": a.prod.TargetID, "credential": cred,
		"engine_options": map[string]any{"no_tls": true, "leak_secret": true}}, &ct)
	if code != http.StatusOK || ct.TLS || ct.ServerVersion != "fake 1.0" || strings.Contains(ct.Error, canaryPW) || !strings.Contains(ct.Error, "REDACTED") {
		t.Fatalf("test: %d %+v", code, ct)
	}
	var tlsOK *bool
	var ver string
	_ = e.DB.QueryRow(ctx, `SELECT tls_ok, detected_version FROM targets WHERE id = $1`, a.prod.TargetID).Scan(&tlsOK, &ver)
	if tlsOK == nil || *tlsOK || ver != "fake 1.0" {
		t.Fatalf("target: %v %q", tlsOK, ver)
	}
	var open int
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE source = 'tls' AND control_id = 'tls.missing' AND status = 'open' AND cluster_id = $1`,
		a.prod.ClusterID).Scan(&open)
	if open != 1 {
		t.Fatalf("tls.missing findings: %d", open)
	}
	// TLS now → resolved.
	code = op.Do("POST", "/api/v1/backup/test-connection", map[string]any{"target_id": a.prod.TargetID, "credential": cred}, &ct)
	if code != http.StatusOK || !ct.OK || !ct.TLS {
		t.Fatalf("tls test: %d %+v", code, ct)
	}
	_ = e.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE control_id = 'tls.missing' AND status = 'open'`).Scan(&open)
	if open != 0 {
		t.Fatal("tls.missing not resolved")
	}
	// Key Vault reference resolved at use time.
	if err := e.KV.SetSecret(ctx, "kv-test", "pg", []byte(canaryPW)); err != nil {
		t.Fatal(err)
	}
	code = op.Do("POST", "/api/v1/backup/test-connection", map[string]any{"target_id": a.prod.TargetID,
		"credential": map[string]any{"source": "keyvault_ref", "ref": "kv://kv-test/pg", "username": "backup"}}, &ct)
	if code != http.StatusOK || !ct.OK {
		t.Fatalf("kv test: %d %+v", code, ct)
	}
	// Credential ID of a job on another target is refused.
	var dummy uuid.UUID
	if err := e.DB.QueryRow(ctx, `INSERT INTO credentials (kind, keyvault_name, secret_name, username) VALUES ('keyvault_ref','kv-test','pg','x') RETURNING id`).Scan(&dummy); err != nil {
		t.Fatal(err)
	}
	if code := op.Do("POST", "/api/v1/backup/test-connection", map[string]any{"target_id": a.prod.TargetID, "credential_id": dummy}, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("foreign credential_id: %d", code)
	}
	// Agent not connected here.
	a.dialer.mu.Lock()
	a.dialer.connected[a.prod.ClusterID] = false
	a.dialer.mu.Unlock()
	op.Do("POST", "/api/v1/backup/test-connection", map[string]any{"target_id": a.prod.TargetID, "credential": cred}, &ct)
	if ct.OK || !strings.Contains(ct.Error, "agent_offline") {
		t.Fatalf("offline: %+v", ct)
	}
	if strings.Contains(e.LogBuf.String(), canaryPW) {
		t.Fatal("password in logs")
	}
}

func TestSchedulePreviewAPI(t *testing.T) {
	a := newAPI(t)
	c := a.e.Login(a.e.Principal("vic", "Member", "viewer@env=prod"))
	var out struct {
		Next        []time.Time
		Description string
	}
	if code := c.Do("GET", "/api/v1/backup/schedule-preview?cron=0+2+*+*+*&timezone=Europe/Istanbul&count=3", nil, &out); code != 200 {
		t.Fatal(code)
	}
	if len(out.Next) != 3 || out.Next[0].UTC().Hour() != 23 || out.Next[1].Sub(out.Next[0]) != 24*time.Hour || out.Description != "At 02:00 every day (Europe/Istanbul)" {
		t.Fatalf("preview: %+v", out)
	}
	var verr struct{ Fields map[string]string }
	if code := c.Do("GET", "/api/v1/backup/schedule-preview?cron=0+2+*+*+*&timezone=Mars/Base", nil, &verr); code != 422 || verr.Fields["timezone"] == "" {
		t.Fatalf("bad tz: %d %+v", code, verr)
	}
	if code := c.Do("GET", "/api/v1/backup/schedule-preview?cron=nope", nil, &verr); code != 422 || verr.Fields["cron"] == "" {
		t.Fatalf("bad cron: %d %+v", code, verr)
	}
}

// destWith adds a destination whose container is distinct, so a restore
// guide shows which destination it was built from.
func destWith(t *testing.T, a *apiEnv, name, container string) uuid.UUID {
	t.Helper()
	id := addDest(t, a.e.DB, name)
	if _, err := a.e.DB.Exec(context.Background(), `UPDATE destinations SET container = $2 WHERE id = $1`, id, container); err != nil {
		t.Fatal(err)
	}
	return id
}

type seedCopy struct {
	dest   uuid.UUID
	status string
	blob   string
}

// seedRun inserts a finished run with the given copies (in destination_ids order).
func seedRun(t *testing.T, a *apiEnv, jobID uuid.UUID, status string, repairOf *uuid.UUID, copies ...seedCopy) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var ids []uuid.UUID
	blob, sum := "", ""
	for _, c := range copies {
		ids = append(ids, c.dest)
		if c.status == "succeeded" && blob == "" {
			blob, sum = c.blob, "sum-"+c.blob
		}
	}
	var id uuid.UUID
	if err := a.e.DB.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, blob_path, sha256, bytes, repair_of, destination_ids)
		VALUES ($1, 'manual', $2, now(), now(), $3, $4, 10, $5, $6) RETURNING id`, jobID, status, blob, sum, repairOf, ids).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, c := range copies {
		sum := ""
		if c.blob != "" {
			sum = "sum-" + c.blob
		}
		if _, err := a.e.DB.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, blob_path, bytes, sha256, tier, error)
			VALUES ($1,$2,$3,$4,10,$5,'daily',$6)`, id, c.dest, c.status, c.blob, sum, map[string]string{"failed": "upload manifest: boom"}[c.status]); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func guideCommands(g *backup.RestoreGuide) string {
	var b strings.Builder
	for _, s := range g.Steps {
		b.WriteString(s.Commands + "\n")
	}
	return b.String()
}

type runBody struct {
	backup.Run
	Restore *backup.RestoreGuide `json:"restore"`
	Error   string               `json:"error"`
	Fields  map[string]string    `json:"fields"`
}

// Destination groups: create and patch validation, the job view shapes, and
// the PATCH of destination_id on a group job (it used to hit the CHECK).
func TestJobsAPIGroups(t *testing.T) {
	a := newAPI(t)
	e := a.e
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	d1, d2 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2")
	g := addGroup(t, e.DB, "pair", d1, d2)
	cred := map[string]any{"source": "stored", "username": "backup", "password": canaryPW}
	create := func(extra map[string]any) (int, string) {
		in := map[string]any{"target_id": a.prod.TargetID, "cron": "0 2 * * *", "credential": cred}
		for k, v := range extra {
			in[k] = v
		}
		return op.Raw("POST", "/api/v1/backup/jobs", in)
	}
	var verr struct{ Fields map[string]string }
	for _, c := range []struct {
		name  string
		extra map[string]any
		field string
		want  string
	}{
		{"neither", nil, "destination_id", "choose a destination or a destination group"},
		{"both", map[string]any{"destination_id": d1, "destination_group_id": g}, "destination_id", "choose a destination or a destination group"},
		{"unknown group", map[string]any{"destination_group_id": uuid.New()}, "destination_group_id", "unknown destination group"},
		{"unknown destination", map[string]any{"destination_id": uuid.New()}, "destination_id", "unknown destination"},
	} {
		verr.Fields = nil
		code, raw := create(c.extra)
		_ = json.Unmarshal([]byte(raw), &verr)
		if code != http.StatusUnprocessableEntity || verr.Fields[c.field] != c.want {
			t.Errorf("%s: %d %s", c.name, code, raw)
		}
	}

	code, raw := create(map[string]any{"destination_group_id": g})
	if code != http.StatusCreated {
		t.Fatalf("create group job: %d %s", code, raw)
	}
	var shape map[string]json.RawMessage
	_ = json.Unmarshal([]byte(raw), &shape)
	if string(shape["destination"]) != "null" {
		t.Fatalf("destination of a group job: %s", shape["destination"])
	}
	var job backup.JobView
	_ = json.Unmarshal([]byte(raw), &job)
	if job.Destination != nil || job.DestinationGroup == nil || job.DestinationGroup.ID != g || job.DestinationGroup.Name != "pair" ||
		strings.Join(job.DestinationGroup.Members, ",") != "d1,d2" {
		t.Fatalf("group job view: %+v", job)
	}
	path := "/api/v1/backup/jobs/" + job.ID.String()

	// Switching to one destination clears the group, and back.
	var v backup.JobView
	if code := op.Do("PATCH", path, map[string]any{"destination_id": d1}, &v); code != http.StatusOK ||
		v.DestinationGroup != nil || v.Destination == nil || v.Destination.ID != d1 || v.Destination.Name != "d1" {
		t.Fatalf("patch to destination: %d %+v", code, v)
	}
	if code := op.Do("PATCH", path, map[string]any{"destination_id": d2}, &v); code != http.StatusOK || v.Destination == nil || v.Destination.ID != d2 {
		t.Fatalf("patch destination: %d %+v", code, v)
	}
	v = backup.JobView{}
	if code := op.Do("PATCH", path, map[string]any{"destination_group_id": g}, &v); code != http.StatusOK ||
		v.Destination != nil || v.DestinationGroup == nil || v.DestinationGroup.ID != g {
		t.Fatalf("patch to group: %d %+v", code, v)
	}
	// PATCH destination_id on a group job (the CHECK used to turn this into a 500).
	if code := op.Do("PATCH", path, map[string]any{"destination_id": d1}, &v); code != http.StatusOK || v.DestinationGroup != nil {
		t.Fatalf("patch destination of a group job: %d %+v", code, v)
	}
	op.Do("PATCH", path, map[string]any{"destination_group_id": g}, nil)
	verr.Fields = nil
	if code := op.Do("PATCH", path, map[string]any{"destination_id": d1, "destination_group_id": g}, &verr); code != http.StatusUnprocessableEntity ||
		verr.Fields["destination_id"] != "choose a destination or a destination group" {
		t.Fatalf("patch both: %d %+v", code, verr)
	}
	verr.Fields = nil
	if code := op.Do("PATCH", path, map[string]any{"destination_group_id": uuid.New()}, &verr); code != http.StatusUnprocessableEntity ||
		verr.Fields["destination_group_id"] != "unknown destination group" {
		t.Fatalf("patch unknown group: %d %+v", code, verr)
	}
	// An unrelated patch leaves the group alone.
	v = backup.JobView{}
	if code := op.Do("PATCH", path, map[string]any{"enabled": false}, &v); code != http.StatusOK || v.DestinationGroup == nil || v.Destination != nil {
		t.Fatalf("patch enabled: %d %+v", code, v)
	}
}

// Runs carry their copies; the restore guide is built from a succeeded copy
// of the run, never from a failed one and never from the job's current
// destination.
func TestRunCopiesAndRestoreGuide(t *testing.T) {
	a := newAPI(t)
	e := a.e
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	devOp := e.Login(e.Principal("dev", "Member", "operator@env=dev"))
	d1, d2 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2")
	g := addGroup(t, e.DB, "pair", d1, d2)
	job := addJob(t, e.DB, a.prod, jobOpts{group: &g})
	get := func(id uuid.UUID, query string) (int, runBody) {
		var b runBody
		code := op.Do("GET", "/api/v1/backup/runs/"+id.String()+query, nil, &b)
		return code, b
	}

	// Partial: the first copy failed after its data blob landed (manifest
	// failed), only the second one is a restore source.
	partial := seedRun(t, a, job, "partial", nil,
		seedCopy{d1, "failed", "olympos/p.tar"}, seedCopy{d2, "succeeded", "olympos/p.tar"})
	code, b := get(partial, "")
	if code != http.StatusOK || len(b.Copies) != 2 || b.Copies[0].DestinationID != d1 || b.Copies[0].DestinationName != "d1" ||
		b.Copies[0].DestinationKind != "azure_blob" || b.Copies[0].Status != "failed" || b.Copies[0].Error != "upload manifest: boom" ||
		b.Copies[1].DestinationID != d2 || b.Copies[1].Status != "succeeded" || b.Copies[1].Tier != "daily" || b.Copies[1].Bytes != 10 {
		t.Fatalf("copies: %d %+v", code, b.Copies)
	}
	if b.DestinationName != "pair" || b.RepairOf != nil {
		t.Fatalf("run: %q %v", b.DestinationName, b.RepairOf)
	}
	if b.Restore == nil || !strings.Contains(guideCommands(b.Restore), "--container-name 'c2'") || strings.Contains(guideCommands(b.Restore), "'c1'") {
		t.Fatalf("partial guide: %+v", b.Restore)
	}
	if len(b.Restore.Copies) != 1 || b.Restore.Copies[0].DestinationID != d2 || !b.Restore.Copies[0].Selected {
		t.Fatalf("partial guide copies: %+v", b.Restore.Copies)
	}
	// The failed copy is not a source, even when named.
	code, b = get(partial, "?copy="+d1.String())
	if code != http.StatusUnprocessableEntity || !strings.Contains(b.Error, "no successful copy in that destination") {
		t.Fatalf("copy=failed: %d %+v", code, b)
	}
	if code, _ := get(partial, "?copy="+uuid.NewString()); code != http.StatusUnprocessableEntity {
		t.Fatalf("copy=unrelated: %d", code)
	}
	if code, _ := get(partial, "?copy=nope"); code != http.StatusUnprocessableEntity {
		t.Fatalf("copy=garbage: %d", code)
	}

	// Succeeded on both: the first in member order is the default, ?copy= picks the other.
	both := seedRun(t, a, job, "succeeded", nil,
		seedCopy{d1, "succeeded", "olympos/b1.tar"}, seedCopy{d2, "succeeded", "olympos/b2.tar"})
	_, b = get(both, "")
	if b.Restore == nil || !strings.Contains(guideCommands(b.Restore), "--container-name 'c1'") || !strings.Contains(guideCommands(b.Restore), "olympos/b1.tar") ||
		len(b.Restore.Copies) != 2 || !b.Restore.Copies[0].Selected || b.Restore.Copies[1].Selected {
		t.Fatalf("default copy: %+v", b.Restore)
	}
	code, b = get(both, "?copy="+d2.String())
	if code != http.StatusOK || b.Restore == nil || !strings.Contains(guideCommands(b.Restore), "--container-name 'c2'") ||
		!strings.Contains(guideCommands(b.Restore), "olympos/b2.tar") || !strings.Contains(guideCommands(b.Restore), "sum-olympos/b2.tar") ||
		b.Restore.Copies[0].Selected || !b.Restore.Copies[1].Selected {
		t.Fatalf("?copy=: %d %+v", code, b.Restore)
	}

	// A failed run has no guide.
	failed := seedRun(t, a, job, "failed", nil, seedCopy{d1, "failed", ""}, seedCopy{d2, "failed", ""})
	if _, b = get(failed, ""); b.Restore != nil {
		t.Fatalf("failed run guide: %+v", b.Restore)
	}

	// A repair run points at its original.
	rep := seedRun(t, a, job, "succeeded", &partial, seedCopy{d1, "succeeded", "olympos/r.tar"})
	_, b = get(rep, "")
	if b.RepairOf == nil || *b.RepairOf != partial || b.DestinationName != "d1" {
		t.Fatalf("repair run: %v %q", b.RepairOf, b.DestinationName)
	}

	// The list carries copies too.
	var list struct{ Items []backup.Run }
	op.Do("GET", "/api/v1/backup/runs?job_id="+job.String(), nil, &list)
	n := map[uuid.UUID]int{}
	for _, r := range list.Items {
		if r.Copies == nil {
			t.Errorf("run %s: copies is null", r.ID)
		}
		n[r.ID] = len(r.Copies)
	}
	if len(list.Items) != 4 || n[partial] != 2 || n[both] != 2 || n[rep] != 1 {
		t.Fatalf("list copies: %v", n)
	}
	// Scope is unchanged.
	if code := devOp.Do("GET", "/api/v1/backup/runs/"+partial.String(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("dev operator: %d", code)
	}
}

// Review Focus 4: a run from before destination groups (no copy rows) keeps
// today's guide, and a new run keeps its own destination after the job moved.
func TestRestoreGuideAfterJobMoved(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	d1, d2 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2")
	job := addJob(t, e.DB, a.prod, jobOpts{})
	if _, err := e.DB.Exec(ctx, `UPDATE backup_jobs SET destination_id = $2 WHERE id = $1`, job, d1); err != nil {
		t.Fatal(err)
	}
	// Old run: no copy rows, no destination_ids.
	var old uuid.UUID
	if err := e.DB.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, blob_path, sha256, bytes)
		VALUES ($1, 'schedule', 'succeeded', now(), now(), 'olympos/old.tar', 'oldsum', 10) RETURNING id`, job).Scan(&old); err != nil {
		t.Fatal(err)
	}
	fresh := seedRun(t, a, job, "succeeded", nil, seedCopy{d1, "succeeded", "olympos/new.tar"})

	var b runBody
	op.Do("GET", "/api/v1/backup/runs/"+old.String(), nil, &b)
	if b.Restore == nil || !strings.Contains(guideCommands(b.Restore), "--container-name 'c1'") || len(b.Copies) != 0 || b.Copies == nil ||
		b.DestinationName != "d1" || len(b.Restore.Copies) != 1 || b.Restore.Copies[0].DestinationID != d1 || !b.Restore.Copies[0].Selected {
		t.Fatalf("old run: %+v %+v", b.Restore, b.Copies)
	}
	if code := op.Do("GET", "/api/v1/backup/runs/"+old.String()+"?copy="+d2.String(), nil, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("old run, other destination: %d", code)
	}

	// Move the job to d2: the new run still restores from d1, and says so.
	if code := op.Do("PATCH", "/api/v1/backup/jobs/"+job.String(), map[string]any{"destination_id": d2}, nil); code != http.StatusOK {
		t.Fatalf("move job: %d", code)
	}
	b = runBody{}
	op.Do("GET", "/api/v1/backup/runs/"+fresh.String(), nil, &b)
	if b.Restore == nil || !strings.Contains(guideCommands(b.Restore), "--container-name 'c1'") || b.DestinationName != "d1" {
		t.Fatalf("new run after move: %+v %q", b.Restore, b.DestinationName)
	}
}
