//go:build dev

package destinations_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/destinations"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

func TestSASExpiringJob(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	env := &secrets.Envelope{KV: kv}
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	tok := func(exp time.Time) string {
		return "sv=2022-11-02&sr=c&sp=rcwt&se=" + exp.UTC().Format(time.RFC3339) + "&sig=EXPIRYCANARYSIG"
	}
	mk := func(name string, exp time.Time, kvRef bool, dbExp time.Time) uuid.UUID {
		credID := uuid.New()
		if kvRef {
			_ = kv.SetSecret(ctx, "kv", "sas-"+name, []byte(tok(exp)))
			if _, err := db.Exec(ctx, `INSERT INTO credentials (id, kind, keyvault_name, secret_name) VALUES ($1,'keyvault_ref','kv',$2)`, credID, "sas-"+name); err != nil {
				t.Fatal(err)
			}
		} else {
			s, _ := env.Seal(ctx, []byte(tok(exp)), []byte("credentials:"+credID.String()))
			if _, err := db.Exec(ctx, `INSERT INTO credentials (id, kind, ciphertext, wrapped_dek, kek_version) VALUES ($1,'stored',$2,$3,$4)`,
				credID, s.Ciphertext, s.WrappedDEK, s.KEKVersion); err != nil {
				t.Fatal(err)
			}
		}
		var id uuid.UUID
		if err := db.QueryRow(ctx, `INSERT INTO destinations (name, account, container, auth, sas_credential_id, sas_expires_at, sas_permissions)
			VALUES ($1, 'acct', 'backups', 'sas_token', $2, $3, 'rcwt') RETURNING id`, name, credID, dbExp).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	expA := now.Add(10 * 24 * time.Hour)
	a := mk("a", expA, false, expA)
	far := now.Add(30 * 24 * time.Hour)
	mk("far", far, false, far)
	// Key Vault reference rotated to a token that expires in 2 days; the DB
	// still has the old 60-day expiry.
	expK := now.Add(2*24*time.Hour + time.Hour)
	k := mk("kv", expK, true, now.Add(60*24*time.Hour))
	if _, err := db.Exec(ctx, `INSERT INTO destinations (name, account, container, auth) VALUES ('mi', 'acct', 'backups', 'managed_identity')`); err != nil {
		t.Fatal(err)
	}

	clock := now
	job := &destinations.ExpiryJob{DB: db, KV: kv, Env: env, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return clock }}
	keys := func() []string {
		rows, err := db.Query(ctx, `SELECT idempotency_key FROM outbox WHERE event_type = $1 ORDER BY idempotency_key`, notify.SASExpiring)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		return out
	}
	has := func(ks []string, k string) bool {
		for _, x := range ks {
			if x == k {
				return true
			}
		}
		return false
	}

	for i := 0; i < 2; i++ { // second tick is idempotent
		if err := job.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ks := keys()
	if len(ks) != 2 || !has(ks, destinations.ExpiryKey(a, 14, expA)) || !has(ks, destinations.ExpiryKey(k, 3, expK)) {
		t.Fatalf("first ticks: %v", ks)
	}
	var dbExp time.Time
	_ = db.QueryRow(ctx, `SELECT sas_expires_at FROM destinations WHERE id = $1`, k).Scan(&dbExp)
	if !dbExp.Equal(expK) {
		t.Fatalf("kv-ref expiry not refreshed: %s", dbExp)
	}

	clock = expA.Add(-2 * 24 * time.Hour)
	_ = job.Tick(ctx)
	if ks = keys(); !has(ks, destinations.ExpiryKey(a, 3, expA)) {
		t.Fatalf("3-day: %v", ks)
	}
	clock = expA.Add(time.Hour)
	_ = job.Tick(ctx)
	_ = job.Tick(ctx)
	if ks = keys(); !has(ks, destinations.ExpiryKey(a, 0, expA)) || len(ks) != 5 {
		// a: 14, 3, 0 days; kv: 3, 0 days; far: 19 days left → none.
		t.Fatalf("expired: %v", ks)
	}

	var payload, title string
	_ = db.QueryRow(ctx, `SELECT payload::text, payload->>'title' FROM outbox WHERE idempotency_key = $1`, destinations.ExpiryKey(a, 14, expA)).Scan(&payload, &title)
	if !strings.Contains(title, "destination a expires in 10 days") || !strings.Contains(payload, `"link": "/settings/destinations?id=`) {
		t.Fatalf("payload: %s", payload)
	}
	var all string
	_ = db.QueryRow(ctx, `SELECT string_agg(payload::text, ' ') FROM outbox`).Scan(&all)
	if strings.Contains(all, "EXPIRYCANARYSIG") {
		t.Fatal("SAS in outbox payload")
	}
}
