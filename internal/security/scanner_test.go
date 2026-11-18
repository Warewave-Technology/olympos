package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

const (
	canaryStored = "stored-canary-pw-9f8e7d"
	canaryKV     = "kv-canary-pw-1a2b3c"
	dg4          = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	dg5          = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
)

type scanCall struct{ ref, user, pass string }

type fakeRunner struct {
	mu       sync.Mutex
	hasDB    bool
	dbAt     time.Time
	updateOK bool
	updates  int
	calls    []scanCall
	// out returns the result for a ref; default: the fixture.
	out func(ref string) ([]byte, error)
}

func (f *fakeRunner) UpdateDB(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	if !f.updateOK {
		return errors.New("mirror unreachable")
	}
	f.hasDB, f.dbAt = true, time.Now()
	return nil
}

func (f *fakeRunner) DBUpdatedAt() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dbAt, f.hasDB
}

func (f *fakeRunner) Scan(_ context.Context, ref string, auth *Auth) ([]byte, error) {
	f.mu.Lock()
	c := scanCall{ref: ref}
	if auth != nil {
		c.user, c.pass = auth.Username, string(auth.Password)
	}
	f.calls = append(f.calls, c)
	out := f.out
	f.mu.Unlock()
	if out != nil {
		return out(ref)
	}
	return fixture(nil)
}

func (f *fakeRunner) callsFor(digest string) []scanCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []scanCall
	for _, c := range f.calls {
		if strings.HasSuffix(c.ref, "@"+digest) {
			out = append(out, c)
		}
	}
	return out
}

// fixture returns the trivy fixture, optionally edited.
func fixture(edit func(rep map[string]any)) ([]byte, error) {
	b, err := os.ReadFile("testdata/trivy-report.json")
	if err != nil || edit == nil {
		return b, err
	}
	var rep map[string]any
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, err
	}
	edit(rep)
	return json.Marshal(rep)
}

type scanEnv struct {
	db      *store.DB
	scanner *Scanner
	runner  *fakeRunner
	kv      *secrets.LocalKeyVault
	logs    *bytes.Buffer
	cluster uuid.UUID
}

func newScanEnv(t *testing.T) *scanEnv {
	t.Helper()
	db := testutil.DB(t)
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	buf := &bytes.Buffer{}
	log := slog.New(secrets.NewRedactingHandler(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	r := &fakeRunner{hasDB: true, dbAt: time.Now(), updateOK: true}
	e := &scanEnv{db: db, runner: r, kv: kv, logs: buf, cluster: mkCluster(t, db, "prod-1", nil)}
	e.scanner = &Scanner{DB: db, Log: log, KV: kv, Envelope: &secrets.Envelope{KV: kv}, Runner: r, Concurrency: 3}
	return e
}

func (e *scanEnv) report(t *testing.T, uses ...*pb.ImageUse) {
	t.Helper()
	in := &Ingester{DB: e.db, Log: quiet}
	if err := in.Report(context.Background(), e.cluster, imageReport(uses...)); err != nil {
		t.Fatal(err)
	}
}

func (e *scanEnv) registry(t *testing.T, pattern, user string, src *SecretSource) {
	t.Helper()
	ctx := context.Background()
	var credID *uuid.UUID
	if src != nil {
		id, err := createCredential(ctx, e.db, e.scanner.Envelope, user, *src)
		if err != nil {
			t.Fatal(err)
		}
		credID = &id
	}
	if _, err := e.db.Exec(ctx, `INSERT INTO registries (host_pattern, credential_id) VALUES ($1, $2)`, pattern, credID); err != nil {
		t.Fatal(err)
	}
}

func (e *scanEnv) status(t *testing.T, digest string) (string, string) {
	t.Helper()
	var st, msg string
	if err := e.db.QueryRow(context.Background(), `SELECT scan_status, scan_error FROM images WHERE digest = $1`, digest).Scan(&st, &msg); err != nil {
		t.Fatal(err)
	}
	return st, msg
}

func (e *scanEnv) criticalKeys(t *testing.T) []string {
	t.Helper()
	rows, err := e.db.Query(context.Background(), `SELECT idempotency_key FROM outbox WHERE event_type = 'vuln.critical' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		out = append(out, k)
	}
	return out
}

func TestScannerCredentialsAndStatuses(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t)
	if err := e.kv.SetSecret(ctx, "kv-test", "quay-pull", []byte(canaryKV+"\n")); err != nil {
		t.Fatal(err)
	}
	e.registry(t, "acr.contoso.io", "robot", &SecretSource{Source: "stored", Value: canaryStored})
	e.registry(t, "*.contoso.io", "wrong", &SecretSource{Source: "stored", Value: "less-specific"})
	e.registry(t, "quay.io/legacy/*", "legacy", &SecretSource{Source: "keyvault_ref", Ref: "kv://kv-test/quay-pull"})
	e.registry(t, "internal.example.com", "", nil) // known registry, anonymous pull
	e.report(t,
		use("acr.contoso.io/erp/api:2.14.1", dg1, "erp", "Deployment", "api", "api"),
		use("harbor.factory.local/mes/line-agent:3.2", dg2, "mes", "Deployment", "line", "agent"),
		use("nginx:1.25", dg3, "web", "Deployment", "front", "nginx"),
		use("quay.io/legacy/report-gen:0.9", dg4, "rep", "CronJob", "nightly", "gen"),
		use("ghcr.io/org/app:1", dg5, "app", "Deployment", "app", "app"),
	)
	e.runner.out = func(ref string) ([]byte, error) {
		switch {
		case strings.HasPrefix(ref, "docker.io/library/nginx@"):
			return nil, &ScanError{Auth: true, Msg: "UNAUTHORIZED: authentication required"}
		case strings.HasPrefix(ref, "ghcr.io/"):
			return nil, &ScanError{Msg: "MANIFEST_UNKNOWN: manifest unknown"}
		}
		return fixture(nil)
	}
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}

	// Stored credential, most specific pattern wins, passed to the runner.
	if st, _ := e.status(t, dg1); st != "scanned" {
		t.Errorf("acr image status = %s", st)
	}
	if c := e.runner.callsFor(dg1); len(c) != 1 || c[0].user != "robot" || c[0].pass != canaryStored ||
		c[0].ref != "acr.contoso.io/erp/api@"+dg1 {
		t.Errorf("acr calls = %+v", c)
	}
	// Private host without a match: missing_credential, never contacted.
	if st, msg := e.status(t, dg2); st != "missing_credential" || !strings.Contains(msg, "harbor.factory.local") {
		t.Errorf("harbor = %s %q", st, msg)
	}
	if c := e.runner.callsFor(dg2); len(c) != 0 {
		t.Errorf("harbor was scanned: %+v", c)
	}
	// Public host, anonymous, registry says auth required → missing_credential.
	if st, _ := e.status(t, dg3); st != "missing_credential" {
		t.Errorf("docker hub = %s", st)
	}
	if c := e.runner.callsFor(dg3); len(c) != 1 || c[0].user != "" || c[0].pass != "" {
		t.Errorf("docker hub calls = %+v", c)
	}
	// Key Vault reference resolved at use (trailing newline trimmed).
	if c := e.runner.callsFor(dg4); len(c) != 1 || c[0].user != "legacy" || c[0].pass != canaryKV {
		t.Errorf("quay calls = %+v", c)
	}
	// Other trivy errors → failed with the message.
	if st, msg := e.status(t, dg5); st != "failed" || !strings.Contains(msg, "MANIFEST_UNKNOWN") {
		t.Errorf("ghcr = %s %q", st, msg)
	}
	for _, canary := range []string{canaryStored, canaryKV} {
		if strings.Contains(e.logs.String(), canary) {
			t.Errorf("canary %q in logs", canary)
		}
		var n int
		_ = e.db.QueryRow(ctx, `SELECT count(*) FROM images WHERE scan_error LIKE '%' || $1 || '%'`, canary).Scan(&n)
		if n > 0 {
			t.Errorf("canary %q in scan_error", canary)
		}
	}
	// The stored credential is envelope-encrypted with AAD credentials:<id>.
	var ct []byte
	var id uuid.UUID
	_ = e.db.QueryRow(ctx, `SELECT c.id, c.ciphertext FROM credentials c JOIN registries r ON r.credential_id = c.id WHERE r.host_pattern = 'acr.contoso.io'`).Scan(&id, &ct)
	if bytes.Contains(ct, []byte(canaryStored)) {
		t.Error("credential stored in plaintext")
	}
	if _, err := ResolveCredential(ctx, e.db, &secrets.Envelope{KV: e.kv}, e.kv, id); err != nil {
		t.Errorf("resolve: %v", err)
	}

	// Adding a registry for harbor requeues it.
	e.registry(t, "harbor.factory.local", "", nil)
	if err := RequeueUnscanned(ctx, e.db); err != nil {
		t.Fatal(err)
	}
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.status(t, dg2); st != "scanned" {
		t.Errorf("harbor after registry = %s", st)
	}
}

func TestScannerVulnsFirstSeenAndCriticalEvents(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t)
	e.report(t, use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"))
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var crit, high, med, low int
	_ = e.db.QueryRow(ctx, `SELECT critical, high, medium, low FROM images WHERE digest = $1`, dg1).Scan(&crit, &high, &med, &low)
	if crit != 2 || high != 1 || med != 1 || low != 1 {
		t.Errorf("counts = %d %d %d %d", crit, high, med, low)
	}
	var n int
	_ = e.db.QueryRow(ctx, `SELECT count(*) FROM image_vulns WHERE digest = $1`, dg1).Scan(&n)
	if n != 7 {
		t.Errorf("vulns = %d", n)
	}
	wantKeys := []string{"vuln.critical:" + dg1 + ":CVE-2024-45337", "vuln.critical:" + dg1 + ":CVE-2024-5535"}
	if k := e.criticalKeys(t); strings.Join(k, ",") != strings.Join(wantKeys, ",") {
		t.Errorf("events = %v", k)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _ = e.db.Exec(ctx, `UPDATE image_vulns SET first_seen_at = $1`, old)

	rescan := func() {
		t.Helper()
		if _, err := e.db.Exec(ctx, `UPDATE images SET scan_status = 'pending'`); err != nil {
			t.Fatal(err)
		}
		if err := e.scanner.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Identical rescan: first_seen_at stable, no new events.
	rescan()
	_ = e.db.QueryRow(ctx, `SELECT count(*) FROM image_vulns WHERE digest = $1 AND first_seen_at = $2`, dg1, old).Scan(&n)
	if n != 7 {
		t.Errorf("first_seen_at changed on rescan: %d stable", n)
	}
	if k := e.criticalKeys(t); len(k) != 2 {
		t.Errorf("events after identical rescan = %v", k)
	}

	// New DB finds a new critical; one critical is fixed upstream (gone).
	e.runner.out = func(string) ([]byte, error) {
		return fixture(func(rep map[string]any) {
			res := rep["Results"].([]any)[0].(map[string]any)
			var kept []any
			for _, v := range res["Vulnerabilities"].([]any) {
				if v.(map[string]any)["VulnerabilityID"] != "CVE-2024-5535" {
					kept = append(kept, v)
				}
			}
			kept = append(kept, map[string]any{"VulnerabilityID": "CVE-2099-0001", "PkgName": "musl", "InstalledVersion": "1.2.4-r1",
				"Severity": "CRITICAL", "Title": "musl: new"})
			res["Vulnerabilities"] = kept
		})
	}
	rescan()
	if k := e.criticalKeys(t); len(k) != 3 || !strings.Contains(strings.Join(k, ","), "CVE-2099-0001") {
		t.Errorf("events after new critical = %v", k)
	}
	var ids []string
	rows, _ := e.db.Query(ctx, `SELECT cve_id FROM image_vulns WHERE digest = $1 AND first_seen_at > $2`, dg1, old)
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if strings.Join(ids, ",") != "CVE-2099-0001" {
		t.Errorf("new vulns = %v", ids)
	}
	_ = e.db.QueryRow(ctx, `SELECT count(*) FROM image_vulns WHERE digest = $1 AND cve_id = 'CVE-2024-5535'`, dg1).Scan(&n)
	if n != 0 {
		t.Error("fixed CVE still listed")
	}

	// The CVE comes back: same idempotency key → no second notification.
	e.runner.out = nil
	rescan()
	if k := e.criticalKeys(t); len(k) != 3 {
		t.Errorf("events after flap = %v", k)
	}
}

func TestScannerDailyDBUpdateAndRescan(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t)
	e.runner.hasDB, e.runner.updateOK = false, false
	e.report(t, use("nginx:1.25", dg1, "web", "Deployment", "front", "nginx"))

	// No DB and the mirror is down: nothing scanned, image stays pending.
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.status(t, dg1); st != "pending" || len(e.runner.calls) != 0 {
		t.Fatalf("status %s, calls %d", st, len(e.runner.calls))
	}
	// Mirror back (the hourly retry guard is reset for the test).
	e.runner.updateOK = true
	e.scanner.lastDBAttempt = time.Time{}
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.status(t, dg1); st != "scanned" || e.runner.updates != 2 || len(e.runner.calls) != 1 {
		t.Fatalf("status %s, updates %d, calls %d", st, e.runner.updates, len(e.runner.calls))
	}
	// Fresh DB, rescan done today: idle tick.
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if e.runner.updates != 2 || len(e.runner.calls) != 1 {
		t.Errorf("idle tick: updates %d calls %d", e.runner.updates, len(e.runner.calls))
	}
	// A day later: DB updated, every in-use digest rescanned.
	e.runner.mu.Lock()
	e.runner.dbAt = time.Now().Add(-25 * time.Hour)
	e.runner.mu.Unlock()
	e.scanner.lastDBAttempt = time.Now().Add(-2 * time.Hour)
	if err := setSetting(ctx, e.db, settingRescanAt, time.Now().Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if e.runner.updates != 3 || len(e.runner.calls) != 2 {
		t.Errorf("daily: updates %d calls %d", e.runner.updates, len(e.runner.calls))
	}
	// Images no longer running are not rescanned.
	_, _ = e.db.Exec(ctx, `DELETE FROM image_usage`)
	_ = setSetting(ctx, e.db, settingRescanAt, time.Now().Add(-25*time.Hour))
	if err := e.scanner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.runner.calls) != 2 {
		t.Errorf("unused image rescanned: %d calls", len(e.runner.calls))
	}
}

func TestScannerConcurrentClaims(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t)
	var uses []*pb.ImageUse
	var digests []string
	for i := 0; i < 12; i++ {
		d := "sha256:" + strings.Repeat(string("abcdef0123456789"[i]), 64)
		digests = append(digests, d)
		uses = append(uses, use("nginx:1.25", d, "web", "Deployment", "w"+string(rune('a'+i)), "c"))
	}
	e.report(t, uses...)
	e.scanner.Concurrency = 4
	if err := e.scanner.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, c := range e.runner.calls {
		refs = append(refs, c.ref)
	}
	sort.Strings(refs)
	if len(refs) != 12 {
		t.Fatalf("scans = %d", len(refs))
	}
	for i := 1; i < len(refs); i++ {
		if refs[i] == refs[i-1] {
			t.Errorf("digest scanned twice: %s", refs[i])
		}
	}
}
