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

func newAPI(t *testing.T) *apiEnv { return newAPIIngest(t, false) }

// newAPIIngest is newAPI with the ingest endpoint of native backups on or off.
func newAPIIngest(t *testing.T, ingest bool) *apiEnv {
	t.Helper()
	a := &apiEnv{dialer: newDialer()}
	a.e = apitest.New(t, apitest.Options{Modules: func(e *apitest.Env) []server.Module {
		return []server.Module{&backup.API{DB: e.DB, Log: e.Log, Dialer: a.dialer, Creds: &backup.Credentials{KV: e.KV, Envelope: e.Envelope},
			IngestEnabled: ingest}}
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

// Native jobs need the ingest endpoint: create and update refuse them while
// it is off (R14), and the settings tell the wizard whether it is on.
func TestJobsAPINativeMethod(t *testing.T) {
	for _, ingest := range []bool{false, true} {
		a := newAPIIngest(t, ingest)
		e := a.e
		op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
		viewer := e.Login(e.Principal("vic", "Member", "viewer@env=prod"))
		create := func(opts any) (int, map[string]string) {
			var verr struct{ Fields map[string]string }
			code := op.Do("POST", "/api/v1/backup/jobs", map[string]any{"target_id": a.prod.TargetID, "destination_id": a.prod.DestID,
				"cron": "0 2 * * *", "credential": map[string]any{"source": "stored", "username": "backup", "password": "pw"},
				"engine_options": opts}, &verr)
			return code, verr.Fields
		}
		var settings struct {
			IngestEnabled bool `json:"ingest_enabled"`
		}
		if code := viewer.Do("GET", "/api/v1/backup/settings", nil, &settings); code != http.StatusOK || settings.IngestEnabled != ingest {
			t.Fatalf("ingest %v: settings %d %+v", ingest, code, settings)
		}

		// Existing jobs have no method: they keep working with the endpoint off.
		for _, opts := range []any{nil, map[string]any{}, map[string]any{"method": "logical"}} {
			if code, f := create(opts); code != http.StatusCreated {
				t.Fatalf("ingest %v: logical job %v: %d %v", ingest, opts, code, f)
			}
		}
		if code, f := create(map[string]any{"method": "fast"}); code != http.StatusUnprocessableEntity || f["method"] == "" {
			t.Fatalf("ingest %v: unknown method: %d %v", ingest, code, f)
		}
		code, f := create(map[string]any{"method": "native", "incremental": "weekly_full_daily"})
		if ingest {
			if code != http.StatusCreated {
				t.Fatalf("native with ingest on: %d %v", code, f)
			}
		} else if code != http.StatusUnprocessableEntity || f["method"] == "" {
			t.Fatalf("native with ingest off: %d %v", code, f)
		}

		// Update: a job that is logical now cannot become native without the endpoint.
		var job struct{ ID string }
		if code := op.Do("POST", "/api/v1/backup/jobs", map[string]any{"target_id": a.prod.TargetID, "destination_id": a.prod.DestID,
			"cron": "0 2 * * *", "credential": map[string]any{"source": "stored", "username": "backup", "password": "pw"}}, &job); code != http.StatusCreated {
			t.Fatalf("job: %d", code)
		}
		var verr struct{ Fields map[string]string }
		code = op.Do("PATCH", "/api/v1/backup/jobs/"+job.ID, map[string]any{"engine_options": map[string]any{"method": "native"}}, &verr)
		if ingest {
			if code != http.StatusOK {
				t.Fatalf("patch native with ingest on: %d", code)
			}
		} else if code != http.StatusUnprocessableEntity || verr.Fields["method"] == "" {
			t.Fatalf("patch native with ingest off: %d %v", code, verr.Fields)
		}
		// Changes that do not touch the options never trip over the endpoint
		// being off, for a native job that was created while it was on.
		if _, err := e.DB.Exec(context.Background(), `UPDATE backup_jobs SET engine_options = '{"method":"native"}' WHERE id = $1`, job.ID); err != nil {
			t.Fatal(err)
		}
		if code := op.Do("PATCH", "/api/v1/backup/jobs/"+job.ID, map[string]any{"enabled": false}, nil); code != http.StatusOK {
			t.Fatalf("ingest %v: patch of a native job without options: %d", ingest, code)
		}
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
	Restore      *backup.RestoreGuide `json:"restore"`
	NextRepairAt *time.Time           `json:"next_repair_at"`
	Error        string               `json:"error"`
	Fields       map[string]string    `json:"fields"`
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

// A partial run's detail says when its queued repair is due
// (next_repair_at, the repair's not_before), and a repair waiting for its
// not_before does not block Run now or a dry run.
func TestRunNextRepairAt(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	d1, d2 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2")
	g := addGroup(t, e.DB, "pair", d1, d2)
	job := addJob(t, e.DB, a.prod, jobOpts{group: &g})
	partial := seedRun(t, a, job, "partial", nil, seedCopy{d1, "succeeded", "olympos/p1.tar"}, seedCopy{d2, "failed", ""})
	get := func(id uuid.UUID) runBody {
		var b runBody
		if code := op.Do("GET", "/api/v1/backup/runs/"+id.String(), nil, &b); code != http.StatusOK {
			t.Fatalf("get %s: %d", id, code)
		}
		return b
	}
	if b := get(partial); b.NextRepairAt != nil || b.NotBefore != nil {
		t.Fatalf("no repair queued: %v %v", b.NextRepairAt, b.NotBefore)
	}
	due := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	var rep uuid.UUID
	if err := e.DB.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, attempt, repair_of, destination_ids, not_before)
		VALUES ($1, 'manual', 'queued', 2, $2, $3, $4) RETURNING id`, job, partial, []uuid.UUID{d2}, due).Scan(&rep); err != nil {
		t.Fatal(err)
	}
	if b := get(partial); b.NextRepairAt == nil || !b.NextRepairAt.Equal(due) {
		t.Fatalf("next_repair_at: %v, want %s", b.NextRepairAt, due)
	}
	if b := get(rep); b.NotBefore == nil || !b.NotBefore.Equal(due) || b.NextRepairAt != nil {
		t.Fatalf("repair not_before: %v (next_repair_at %v)", b.NotBefore, b.NextRepairAt)
	}
	var list struct{ Items []backup.Run }
	op.Do("GET", "/api/v1/backup/runs?job_id="+job.String(), nil, &list)
	if len(list.Items) != 2 || list.Items[0].ID != rep || list.Items[0].NotBefore == nil {
		t.Fatalf("list: %+v", list.Items)
	}
	// The job's last run is the partial one, not the repair waiting to start.
	var jv backup.JobView
	if code := op.Do("GET", "/api/v1/backup/jobs/"+job.String(), nil, &jv); code != http.StatusOK || jv.LastRun == nil || jv.LastRun.ID != partial {
		t.Fatalf("last run: %d %+v", code, jv.LastRun)
	}

	// The waiting repair does not make the job busy; a run that is due does.
	var run backup.Run
	if code := op.Do("POST", "/api/v1/backup/jobs/"+job.String()+"/run", map[string]any{"trigger": "test"}, &run); code != http.StatusAccepted {
		t.Fatalf("dry run while a repair waits: %d", code)
	}
	if code := op.Do("POST", "/api/v1/backup/jobs/"+job.String()+"/run", nil, nil); code != http.StatusConflict {
		t.Fatalf("second run: %d", code)
	}
	if _, err := e.DB.Exec(ctx, `UPDATE backup_runs SET status = 'succeeded', finished_at = now() WHERE id = $1`, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(ctx, `UPDATE backup_runs SET not_before = now() - interval '1 second' WHERE id = $1`, rep); err != nil {
		t.Fatal(err)
	}
	if code := op.Do("POST", "/api/v1/backup/jobs/"+job.String()+"/run", nil, nil); code != http.StatusConflict {
		t.Fatalf("run while a due repair is queued: %d", code)
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

// The self-backup takes a destination or a destination group, like a job:
// exactly one, an unknown group is a field error, choosing one clears the
// other and an unrelated change keeps it.
func TestSelfBackupAPIGroups(t *testing.T) {
	a := newAPI(t)
	e := a.e
	admin := e.Login(e.Principal("root", "Member", "admin"))
	d1, d2 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2")
	g := addGroup(t, e.DB, "pair", d1, d2)
	put := func(in map[string]any) (int, backup.SelfView, map[string]string) {
		var b struct {
			backup.SelfView
			Fields map[string]string `json:"fields"`
		}
		code := admin.Do("PUT", "/api/v1/backup/self", in, &b)
		return code, b.SelfView, b.Fields
	}
	for _, c := range []struct {
		name  string
		in    map[string]any
		field string
		want  string
	}{
		{"neither", map[string]any{}, "destination_id", "Choose where the Olympos database is backed up."},
		{"both", map[string]any{"destination_id": d1, "destination_group_id": g}, "destination_id", "Choose a destination or a destination group, not both."},
		{"unknown group", map[string]any{"destination_group_id": uuid.New()}, "destination_group_id", "Unknown destination group."},
		{"unknown destination", map[string]any{"destination_id": uuid.New()}, "destination_id", "Unknown destination."},
	} {
		if code, _, fields := put(c.in); code != http.StatusUnprocessableEntity || fields[c.field] != c.want {
			t.Errorf("%s: %d %v", c.name, code, fields)
		}
	}

	code, v, _ := put(map[string]any{"destination_group_id": g})
	if code != http.StatusOK || v.Job == nil || v.Job.DestinationID != nil || v.Job.DestinationGroupID == nil || *v.Job.DestinationGroupID != g ||
		v.Job.DestinationName != "pair" {
		t.Fatalf("configure with a group: %d %+v", code, v.Job)
	}
	if code, v, _ = put(map[string]any{"cron": "0 3 * * *"}); code != http.StatusOK || v.Job.DestinationGroupID == nil || v.Job.Cron != "0 3 * * *" {
		t.Fatalf("unrelated change: %d %+v", code, v.Job)
	}
	if code, _, fields := put(map[string]any{"destination_id": d1, "destination_group_id": g}); code != http.StatusUnprocessableEntity ||
		fields["destination_id"] != "Choose a destination or a destination group, not both." {
		t.Fatalf("both on update: %d %v", code, fields)
	}
	if code, v, _ = put(map[string]any{"destination_id": d1}); code != http.StatusOK || v.Job.DestinationGroupID != nil ||
		v.Job.DestinationID == nil || *v.Job.DestinationID != d1 || v.Job.DestinationName != "d1" {
		t.Fatalf("switch to a destination: %d %+v", code, v.Job)
	}
	if code, v, _ = put(map[string]any{"destination_group_id": g}); code != http.StatusOK || v.Job.DestinationID != nil || v.Job.DestinationGroupID == nil {
		t.Fatalf("switch back to the group: %d %+v", code, v.Job)
	}
	var details []byte
	if err := e.DB.QueryRow(context.Background(), `SELECT details FROM activity_log WHERE action = 'backup.self_updated' ORDER BY at DESC LIMIT 1`).
		Scan(&details); err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(details), `"destination_group_id": "`+g.String()+`"`)

	// ?copy= picks the copy the restore guide is built from.
	run := seedRun(t, a, v.Job.ID, "succeeded", nil, seedCopy{d1, "succeeded", "p/a.zip"}, seedCopy{d2, "succeeded", "p/b.zip"})
	var sv backup.SelfView
	if code := admin.Do("GET", "/api/v1/backup/self?copy="+d2.String(), nil, &sv); code != http.StatusOK || sv.Restore == nil ||
		!sv.Restore.Copies[1].Selected || !strings.Contains(guideCommands(sv.Restore), "p/b.zip") {
		t.Fatalf("self restore from the second copy: %d %+v", code, sv.Restore)
	}
	if len(sv.Runs) != 1 || sv.Runs[0].ID != run || len(sv.Runs[0].Copies) != 2 {
		t.Fatalf("self runs: %+v", sv.Runs)
	}
	if code := admin.Do("GET", "/api/v1/backup/self?copy="+uuid.New().String(), nil, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("copy without a succeeded copy there: %d", code)
	}
}

// The guide of an original run also offers the copies its repairs wrote:
// for that destination they are the only copy of this activation. Each copy
// names the run that wrote it and when that run started.
func TestRestoreGuideRepairCopies(t *testing.T) {
	a := newAPI(t)
	e := a.e
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	d1, d2 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2")
	g := addGroup(t, e.DB, "pair", d1, d2)
	job := addJob(t, e.DB, a.prod, jobOpts{group: &g})
	orig := seedRun(t, a, job, "partial", nil, seedCopy{d1, "succeeded", "p1/orig.zip"}, seedCopy{d2, "failed", ""})
	rep := seedRun(t, a, job, "succeeded", &orig, seedCopy{d2, "succeeded", "p2/rep.zip"})
	var repStarted time.Time
	if err := e.DB.QueryRow(context.Background(), `SELECT started_at FROM backup_runs WHERE id = $1`, rep).Scan(&repStarted); err != nil {
		t.Fatal(err)
	}
	get := func(id uuid.UUID, query string) runBody {
		t.Helper()
		var b runBody
		if code := op.Do("GET", "/api/v1/backup/runs/"+id.String()+query, nil, &b); code != http.StatusOK {
			t.Fatalf("GET run %s%s: %d %+v", id, query, code, b)
		}
		return b
	}

	b := get(orig, "")
	c := b.Restore.Copies
	if len(c) != 2 || c[0].DestinationID != d1 || c[0].RunID != orig || !c[0].Selected || c[0].TakenAt == nil ||
		c[1].DestinationID != d2 || c[1].RunID != rep || c[1].Selected || c[1].TakenAt == nil || !c[1].TakenAt.Equal(repStarted) {
		t.Fatalf("copies: %+v", c)
	}
	mustContain(t, guideCommands(b.Restore), "p1/orig.zip")
	mustContain(t, guideCommands(b.Restore), backup.ManifestPath("p1/orig.zip", orig))

	// ?copy= on the repaired destination: the repair's blob and manifest.
	b = get(orig, "?copy="+d2.String())
	cmds := guideCommands(b.Restore)
	if !b.Restore.Copies[1].Selected || b.Restore.Copies[0].Selected || strings.Contains(cmds, "orig.zip") {
		t.Fatalf("copy=d2: %+v\n%s", b.Restore.Copies, cmds)
	}
	mustContain(t, cmds, "p2/rep.zip")
	mustContain(t, cmds, backup.ManifestPath("p2/rep.zip", rep))
	mustContain(t, cmds, "'c2'")

	// The repair's own detail lists its own copy only.
	b = get(rep, "")
	if len(b.Restore.Copies) != 1 || b.Restore.Copies[0].RunID != rep || b.Restore.Copies[0].DestinationID != d2 {
		t.Fatalf("repair guide: %+v", b.Restore.Copies)
	}

	// Two repair copies on one destination: ?copy= takes the newest.
	rep2 := seedRun(t, a, job, "succeeded", &orig, seedCopy{d2, "succeeded", "p2/rep2.zip"})
	b = get(orig, "?copy="+d2.String())
	if c := b.Restore.Copies; len(c) != 3 || c[1].RunID != rep || c[2].RunID != rep2 || !c[2].Selected {
		t.Fatalf("copies with two repairs: %+v", c)
	}
	mustContain(t, guideCommands(b.Restore), backup.ManifestPath("p2/rep2.zip", rep2))
}

// The job (and the self-backup) shows, per current destination in member
// order, when it last wrote a successful copy there: repairs count, dry
// runs do not, a destination the job no longer uses is not listed, and a
// single-destination job counts its runs from before destination groups.
func TestJobDestinationsLastSuccess(t *testing.T) {
	a := newAPI(t)
	e, ctx := a.e, context.Background()
	op := e.Login(e.Principal("ada", "Member", "operator@env=prod"))
	admin := e.Login(e.Principal("root", "Member", "admin"))
	d1, d2, d3 := destWith(t, a, "d1", "c1"), destWith(t, a, "d2", "c2"), destWith(t, a, "d3", "c3")
	g := addGroup(t, e.DB, "pair", d1, d2)
	job := addJob(t, e.DB, a.prod, jobOpts{group: &g})
	now := time.Now().UTC().Truncate(time.Second)
	at := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	run := func(job uuid.UUID, trigger, status string, repairOf *uuid.UUID, finished time.Time, copies map[uuid.UUID]string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := e.DB.QueryRow(ctx, `INSERT INTO backup_runs (job_id, trigger, status, started_at, finished_at, repair_of) VALUES ($1, $2, $3, $4, $4, $5) RETURNING id`,
			job, trigger, status, finished, repairOf).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for d, st := range copies {
			if _, err := e.DB.Exec(ctx, `INSERT INTO backup_run_copies (run_id, destination_id, status, finished_at) VALUES ($1, $2, $3, $4)`, id, d, st, finished); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	type entry struct {
		ID   uuid.UUID
		Name string
		At   *time.Time
	}
	flat := func(ls []backup.DestinationLastSuccess) []entry {
		out := []entry{}
		for _, l := range ls {
			out = append(out, entry{l.DestinationID, l.Name, l.LastSuccessAt})
		}
		return out
	}
	check := func(what string, got []backup.DestinationLastSuccess, want ...entry) {
		t.Helper()
		g := flat(got)
		if len(g) != len(want) {
			t.Fatalf("%s: %+v, want %+v", what, g, want)
		}
		for i := range want {
			if g[i].ID != want[i].ID || g[i].Name != want[i].Name || (g[i].At == nil) != (want[i].At == nil) ||
				g[i].At != nil && !g[i].At.Equal(*want[i].At) {
				t.Fatalf("%s: %+v, want %+v", what, g, want)
			}
		}
	}
	getJob := func(id uuid.UUID) backup.JobView {
		t.Helper()
		var jv backup.JobView
		if code := op.Do("GET", "/api/v1/backup/jobs/"+id.String(), nil, &jv); code != http.StatusOK {
			t.Fatalf("get job: %d", code)
		}
		return jv
	}

	check("no runs", getJob(job).DestinationsLastSuccess, entry{d1, "d1", nil}, entry{d2, "d2", nil})

	partial := run(job, "manual", "partial", nil, at(5), map[uuid.UUID]string{d1: "succeeded", d2: "failed"})
	run(job, "manual", "succeeded", &partial, at(4), map[uuid.UUID]string{d2: "succeeded"})
	run(job, "test", "succeeded", nil, at(1), map[uuid.UUID]string{d1: "succeeded", d2: "succeeded"})
	run(job, "manual", "failed", nil, at(2), map[uuid.UUID]string{d1: "failed", d2: "failed"})
	run(job, "manual", "succeeded", nil, at(6), map[uuid.UUID]string{d3: "succeeded"}) // d3 left the group
	check("group job", getJob(job).DestinationsLastSuccess, entry{d1, "d1", ptr(at(5))}, entry{d2, "d2", ptr(at(4))})

	var list struct{ Items []backup.JobView }
	op.Do("GET", "/api/v1/backup/jobs", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: %d jobs", len(list.Items))
	}
	check("list", list.Items[0].DestinationsLastSuccess, entry{d1, "d1", ptr(at(5))}, entry{d2, "d2", ptr(at(4))})

	// A single-destination job: its runs from before destination groups
	// (no copy rows) count for its destination.
	single := addJob(t, e.DB, a.prod, jobOpts{})
	if _, err := e.DB.Exec(ctx, `UPDATE backup_jobs SET destination_id = $2 WHERE id = $1`, single, d3); err != nil {
		t.Fatal(err)
	}
	run(single, "schedule", "succeeded", nil, at(8), nil)
	run(single, "schedule", "failed", nil, at(7), nil)
	check("single legacy", getJob(single).DestinationsLastSuccess, entry{d3, "d3", ptr(at(8))})
	run(single, "manual", "succeeded", nil, at(3), map[uuid.UUID]string{d3: "succeeded"})
	check("single", getJob(single).DestinationsLastSuccess, entry{d3, "d3", ptr(at(3))})

	// The self-backup card shows the same.
	var sv backup.SelfView
	if code := admin.Do("PUT", "/api/v1/backup/self", map[string]any{"destination_group_id": g}, &sv); code != http.StatusOK {
		t.Fatalf("configure self: %d", code)
	}
	run(sv.Job.ID, "schedule", "partial", nil, at(2), map[uuid.UUID]string{d1: "failed", d2: "succeeded"})
	if code := admin.Do("GET", "/api/v1/backup/self", nil, &sv); code != http.StatusOK {
		t.Fatalf("get self: %d", code)
	}
	check("self", sv.DestinationsLastSuccess, entry{d1, "d1", nil}, entry{d2, "d2", ptr(at(2))})
}
