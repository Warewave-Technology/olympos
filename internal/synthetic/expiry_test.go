package synthetic

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

func TestExpiryThreshold(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		remaining time.Duration
		want      int
	}{
		{20 * day, -1}, {14*day + time.Second, -1}, {14 * day, 14}, {4 * day, 14}, {3 * day, 3}, {time.Hour, 3}, {0, -1}, {-day, -1},
	} {
		if got := expiryThreshold(c.remaining); got != c.want {
			t.Errorf("expiryThreshold(%v) = %d, want %d", c.remaining, got, c.want)
		}
	}
}

// synthetic.credential_expiring fires once at 14 days and once at 3, with
// the credential's name and the scenarios using it but never its value; a
// rotated credential (a new expires_at) starts a new series.
func TestCredentialExpiry(t *testing.T) {
	const secret = "olympos-canary-expiry-4c1d9e"
	e := newEnv(t)
	e.allow("suffix", "example.com")
	cred := e.credential("billing-token", spec.CredBearer, "label", secret, "suffix:example.com")
	e.credential("no-expiry", spec.CredBearer, "label", secret+"-2", "suffix:example.com") // never sends
	e.scenario("billing", true, httpStep("https://api.example.com/bill", &cred))
	day := 24 * time.Hour
	expires := e.clock.now().Add(20 * day)
	e.exec(`UPDATE synthetic_credentials SET expires_at = $2 WHERE id = $1`, cred, expires)

	check := func(want int) {
		t.Helper()
		if err := e.svc.CheckCredentialExpiry(e.ctx); err != nil {
			t.Fatal(err)
		}
		if n := e.events(notify.SyntheticCredentialExpiring); n != want {
			t.Fatalf("%d messages, want %d", n, want)
		}
	}
	check(0)
	e.clock.add(6*day + 12*time.Hour) // 13.5 days left
	check(1)
	check(1)
	e.clock.add(day)
	check(1)
	e.clock.add(10 * day) // 2.5 days left
	check(2)
	check(2)
	e.clock.add(3 * day) // expired
	check(2)

	type row struct {
		key, payload string
		routed       bool
	}
	rows, err := e.db.Query(e.ctx, `SELECT idempotency_key, payload::text, channel_id IS NULL FROM outbox WHERE event_type = $1 ORDER BY created_at`,
		notify.SyntheticCredentialExpiring)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.key, &x.payload, &x.routed)
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, x := range got {
		keys = append(keys, x.key)
		if strings.Contains(x.payload, secret) || strings.Contains(x.payload, "label") || !strings.Contains(x.payload, "billing-token") ||
			!strings.Contains(x.payload, `"used by": "billing"`) || !x.routed {
			t.Fatalf("payload %s routed=%v", x.payload, x.routed)
		}
	}
	want := []string{
		"synthetic.credential_expiring:" + cred.String() + ":14d:" + strconv.FormatInt(expires.Unix(), 10),
		"synthetic.credential_expiring:" + cred.String() + ":3d:" + strconv.FormatInt(expires.Unix(), 10),
	}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("keys %v, want %v", keys, want)
	}

	// Rotated with a new expiry: a new series.
	e.exec(`UPDATE synthetic_credentials SET expires_at = $2, rotated_at = $3 WHERE id = $1`, cred, e.clock.now().Add(10*day), e.clock.now())
	check(3)
	check(3)
}
