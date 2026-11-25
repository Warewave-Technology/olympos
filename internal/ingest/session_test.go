package ingest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/ingest"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// clock is a settable time source for the registry.
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

type nopSink struct{}

func (nopSink) Put(context.Context, string, io.Reader) (ingest.ObjectRecord, error) {
	return ingest.ObjectRecord{}, nil
}

type nopSource struct{}

func (nopSource) Open(context.Context, string) (io.ReadCloser, ingest.ObjectRecord, error) {
	return nil, ingest.ObjectRecord{}, errors.New("nop")
}

func (nopSource) List(context.Context, string) ([]ingest.ObjectRecord, error) { return nil, nil }

func newRegistry(t *testing.T, maxRuns int) (*ingest.Registry, *store.DB, *secrets.Fingerprinter, *clock) {
	t.Helper()
	db := testutil.DB(t)
	fp, err := secrets.NewFingerprinter(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)}
	return ingest.NewRegistry(db, fp, maxRuns, c.now), db, fp, c
}

func backupOptions() ingest.OpenOptions {
	run := uuid.New()
	return ingest.OpenOptions{
		RunID: run, Kind: "backup", Scope: ingest.Scope{Write: run.String() + "/"},
		TTL: time.Hour, Sink: nopSink{}, MaxBytes: 1 << 30,
	}
}

func open(t *testing.T, reg *ingest.Registry, o ingest.OpenOptions) (*ingest.Session, ingest.Credential) {
	t.Helper()
	s, cred, err := reg.Open(context.Background(), o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, cred
}

// credentialRow is the audit row of one access key.
type credentialRow struct {
	RunID, Kind, Fingerprint string
	Scope                    ingest.Scope
	Expires                  time.Time
	Revoked                  *time.Time
	Reason                   *string
}

func row(t *testing.T, db *store.DB, key string) credentialRow {
	t.Helper()
	var r credentialRow
	var scope []byte
	err := db.QueryRow(context.Background(), `SELECT run_id::text, kind, scope, fingerprint, expires_at, revoked_at, reason
		FROM ingest_credentials WHERE access_key = $1`, key).
		Scan(&r.RunID, &r.Kind, &scope, &r.Fingerprint, &r.Expires, &r.Revoked, &r.Reason)
	if err != nil {
		t.Fatalf("row %s: %v", key, err)
	}
	if err := json.Unmarshal(scope, &r.Scope); err != nil {
		t.Fatalf("scope %s: %v", scope, err)
	}
	return r
}

var accessKeyRE = regexp.MustCompile(`^OLY[A-Z2-7]{17}$`)

func TestOpenMintsScopedCredential(t *testing.T) {
	reg, db, fp, c := newRegistry(t, 4)
	o := backupOptions()
	base := uuid.NewString() + "/"
	o.Scope.Read = []string{base}
	o.Source = nopSource{}
	s, cred := open(t, reg, o)

	if !accessKeyRE.MatchString(cred.AccessKey) {
		t.Errorf("access key %q does not match %s", cred.AccessKey, accessKeyRE)
	}
	if len(cred.Secret) != 40 {
		t.Errorf("secret has %d characters, want 40", len(cred.Secret))
	}
	if s.RunID() != o.RunID || s.Kind() != "backup" {
		t.Errorf("session is %s %s", s.RunID(), s.Kind())
	}

	r := row(t, db, cred.AccessKey)
	if r.RunID != o.RunID.String() || r.Kind != "backup" {
		t.Errorf("row is %s %s", r.RunID, r.Kind)
	}
	if r.Scope.Write != o.Scope.Write || len(r.Scope.Read) != 1 || r.Scope.Read[0] != base {
		t.Errorf("row scope is %+v", r.Scope)
	}
	if want := fp.Fingerprint([]byte(cred.Secret)); r.Fingerprint != want || !strings.HasPrefix(r.Fingerprint, "hm:") {
		t.Errorf("fingerprint %q, want %q", r.Fingerprint, want)
	}
	if !r.Expires.Equal(c.now().Add(time.Hour)) || r.Revoked != nil || r.Reason != nil {
		t.Errorf("row expires %s, revoked %v, reason %v", r.Expires, r.Revoked, r.Reason)
	}

	// No column of any row holds the secret, in any form Postgres prints.
	rows, err := db.Query(context.Background(), `SELECT row_to_json(c)::text FROM ingest_credentials c`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var all string
		if err := rows.Scan(&all); err != nil {
			t.Fatal(err)
		}
		n++
		if strings.Contains(all, cred.Secret) {
			t.Errorf("a column holds the secret: %s", all)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d rows, want 1", n)
	}

	got, secret, ok := reg.Lookup(cred.AccessKey)
	if !ok || got != s || secret != cred.Secret {
		t.Errorf("lookup = %v, %v", got, ok)
	}

	// Every open mints its own key and secret.
	_, other := open(t, reg, backupOptions())
	if other.AccessKey == cred.AccessKey || other.Secret == cred.Secret {
		t.Error("two opens minted the same credential")
	}
}

func TestOpenRefusesBadOptions(t *testing.T) {
	reg, _, _, _ := newRegistry(t, 4)
	restore := func() ingest.OpenOptions {
		return ingest.OpenOptions{
			RunID: uuid.New(), Kind: "restore", Scope: ingest.Scope{Read: []string{uuid.NewString() + "/"}},
			TTL: time.Hour, Source: nopSource{},
		}
	}
	if _, _, err := reg.Open(context.Background(), restore()); err != nil {
		t.Fatalf("a valid restore: %v", err)
	}
	for name, change := range map[string]func(*ingest.OpenOptions){
		"no run id":              func(o *ingest.OpenOptions) { o.RunID = uuid.Nil },
		"unknown kind":           func(o *ingest.OpenOptions) { o.Kind = "copy" },
		"no ttl":                 func(o *ingest.OpenOptions) { o.TTL = 0 },
		"backup writes another":  func(o *ingest.OpenOptions) { o.Scope.Write = uuid.NewString() + "/" },
		"backup without a sink":  func(o *ingest.OpenOptions) { o.Sink = nil },
		"backup without a quota": func(o *ingest.OpenOptions) { o.MaxBytes = 0 },
		"read without a source":  func(o *ingest.OpenOptions) { o.Scope.Read = []string{uuid.NewString() + "/"} },
		"read prefix without /":  func(o *ingest.OpenOptions) { o.Source = nopSource{}; o.Scope.Read = []string{"abc"} },
		"read prefix is root":    func(o *ingest.OpenOptions) { o.Source = nopSource{}; o.Scope.Read = []string{"/"} },
		"read prefix climbs":     func(o *ingest.OpenOptions) { o.Source = nopSource{}; o.Scope.Read = []string{"../x/"} },
	} {
		o := backupOptions()
		change(&o)
		if _, _, err := reg.Open(context.Background(), o); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	for name, change := range map[string]func(*ingest.OpenOptions){
		"restore writes":         func(o *ingest.OpenOptions) { o.Scope.Write = o.RunID.String() + "/" },
		"restore reads nothing":  func(o *ingest.OpenOptions) { o.Scope.Read = nil },
		"restore without source": func(o *ingest.OpenOptions) { o.Source = nil },
	} {
		o := restore()
		change(&o)
		if _, _, err := reg.Open(context.Background(), o); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestLookupExpiredOrRevoked(t *testing.T) {
	reg, db, _, c := newRegistry(t, 4)
	if _, _, ok := reg.Lookup("OLYAAAAAAAAAAAAAAAAA"); ok {
		t.Error("an unknown key is found")
	}

	revoked, rc := open(t, reg, backupOptions())
	revoked.Revoke("run finished")
	if _, _, ok := reg.Lookup(rc.AccessKey); ok {
		t.Error("a revoked key is found")
	}
	r := row(t, db, rc.AccessKey)
	if r.Revoked == nil || !r.Revoked.Equal(c.now()) || r.Reason == nil || *r.Reason != "run finished" {
		t.Errorf("revoked row: %v %v", r.Revoked, r.Reason)
	}
	// The first reason stays.
	c.add(time.Minute)
	revoked.Revoke("again")
	if r := row(t, db, rc.AccessKey); !r.Revoked.Equal(c.now().Add(-time.Minute)) || *r.Reason != "run finished" {
		t.Errorf("second revoke changed the row: %v %v", r.Revoked, *r.Reason)
	}

	stopped, sc := open(t, reg, backupOptions())
	stopped.Stop("bad digest")
	if _, _, ok := reg.Lookup(sc.AccessKey); ok {
		t.Error("a stopped session's key is found")
	}

	o := backupOptions()
	o.TTL = 10 * time.Minute
	_, ec := open(t, reg, o)
	c.add(10*time.Minute - time.Nanosecond)
	if _, _, ok := reg.Lookup(ec.AccessKey); !ok {
		t.Error("a key is not found before its expiry")
	}
	c.add(time.Nanosecond)
	if _, _, ok := reg.Lookup(ec.AccessKey); ok {
		t.Error("an expired key is found")
	}
}

func TestMaxRuns(t *testing.T) {
	reg, _, _, c := newRegistry(t, 4)
	var sessions []*ingest.Session
	for range 4 {
		s, _ := open(t, reg, backupOptions())
		sessions = append(sessions, s)
	}
	if _, _, err := reg.Open(context.Background(), backupOptions()); !errors.Is(err, ingest.ErrTooManyRuns) {
		t.Fatalf("fifth open: %v, want ErrTooManyRuns", err)
	}
	// A stopped session still holds its slot until its run revokes it.
	sessions[0].Stop("quota")
	if _, _, err := reg.Open(context.Background(), backupOptions()); !errors.Is(err, ingest.ErrTooManyRuns) {
		t.Fatalf("open after a stop: %v, want ErrTooManyRuns", err)
	}
	sessions[0].Revoke("run failed")
	open(t, reg, backupOptions())

	// An expired session frees its slot: its key cannot be used again.
	c.add(time.Hour)
	for range 4 {
		open(t, reg, backupOptions())
	}
}

// Opens racing for the last slots never exceed maxRuns.
func TestMaxRunsConcurrent(t *testing.T) {
	reg, _, _, _ := newRegistry(t, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	opened, refused := 0, 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := reg.Open(context.Background(), backupOptions())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				opened++
			case errors.Is(err, ingest.ErrTooManyRuns):
				refused++
			default:
				t.Errorf("open: %v", err)
			}
		}()
	}
	wg.Wait()
	if opened != 4 || refused != 8 {
		t.Errorf("opened %d, refused %d; want 4 and 8", opened, refused)
	}
}

func TestMarkInterrupted(t *testing.T) {
	reg, db, fp, c := newRegistry(t, 4)
	done, dc := open(t, reg, backupOptions())
	done.Revoke("run finished")
	_, lc := open(t, reg, backupOptions())
	o := backupOptions()
	o.TTL = time.Minute
	_, xc := open(t, reg, o)

	// The next server start.
	c.add(2 * time.Hour)
	next := ingest.NewRegistry(db, fp, 4, c.now)
	if err := next.MarkInterrupted(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{lc.AccessKey, xc.AccessKey} {
		r := row(t, db, key)
		if r.Revoked == nil || !r.Revoked.Equal(c.now()) || r.Reason == nil || *r.Reason != "server restart" {
			t.Errorf("%s: revoked %v, reason %v", key, r.Revoked, r.Reason)
		}
	}
	if r := row(t, db, dc.AccessKey); *r.Reason != "run finished" || !r.Revoked.Equal(c.now().Add(-2*time.Hour)) {
		t.Errorf("a revoked row changed: %v %v", r.Revoked, *r.Reason)
	}
}

func TestCaptureLimits(t *testing.T) {
	reg, _, _, _ := newRegistry(t, 4)
	s, _ := open(t, reg, backupOptions())
	run := s.RunID().String() + "/"
	const mib = 1 << 20
	for _, tc := range []struct {
		key   string
		limit int64
		size  int
		kept  bool
	}{
		{run + ".backup", mib, mib, true},
		{run + "metadata/db1.sql", mib, 100, true},
		{run + "metadata/db1/events.sql", mib, mib, true},
		{run + "data/db1/events/all_1_1_0/count.txt", 64, 6, true},
		{run + "data/db1/events/all_2_2_0/count.txt", 64, 64, true},

		{run + ".backup.tmp", 0, 10, false},
		{run + "metadata/db1/huge.sql", mib, mib + 1, false},
		{run + "data/db1/events/all_3_3_0/count.txt", 64, 65, false},
		{run + "data/db1/events/all_1_1_0/data.bin", 0, 10, false},
		{run + "data/db1/events/all_1_1_0/checksums.txt", 0, 10, false},
		{run + "metadata/db1/notes.txt", 0, 10, false},
		{run + "x/.backup", 0, 10, false},
		{run + ".lock", 0, 10, false},
		{uuid.NewString() + "/.backup", 0, 10, false},
		{".backup", 0, 10, false},
	} {
		if got := s.CaptureLimit(tc.key); got != tc.limit {
			t.Errorf("CaptureLimit(%s) = %d, want %d", tc.key, got, tc.limit)
		}
		body := bytes.Repeat([]byte("x"), tc.size)
		if kept := s.Capture(tc.key, body); kept != tc.kept {
			t.Errorf("Capture(%s, %d bytes) = %v, want %v", tc.key, tc.size, kept, tc.kept)
		}
		got, ok := s.Captured(tc.key)
		if ok != tc.kept || (ok && !bytes.Equal(got, body)) {
			t.Errorf("Captured(%s) = %d bytes, %v", tc.key, len(got), ok)
		}
	}

	// Captured returns a copy.
	got, _ := s.Captured(run + ".backup")
	got[0] = 'y'
	if again, _ := s.Captured(run + ".backup"); again[0] != 'x' {
		t.Error("Captured returned the kept body itself")
	}

	// A restore writes nothing, so it keeps nothing.
	rs, _ := open(t, reg, ingest.OpenOptions{
		RunID: uuid.New(), Kind: "restore", Scope: ingest.Scope{Read: []string{run}}, TTL: time.Hour, Source: nopSource{},
	})
	if rs.CaptureLimit(run+".backup") != 0 || rs.Capture(run+".backup", []byte("x")) {
		t.Error("a restore session captures")
	}
}

func TestSessionHooks(t *testing.T) {
	reg, _, _, _ := newRegistry(t, 4)
	o := backupOptions()
	o.MaxBytes = 100
	s, _ := open(t, reg, o)
	run := s.RunID().String() + "/"

	// Objects, in the order they were recorded, as a copy.
	a := ingest.ObjectRecord{Key: run + "data/a", Size: 1, SHA256: "aa"}
	b := ingest.ObjectRecord{Key: run + ".backup", Size: 2, SHA256: "bb"}
	s.RecordObject(a)
	s.RecordObject(b)
	objs := s.Objects()
	if len(objs) != 2 || objs[0] != a || objs[1] != b {
		t.Errorf("objects = %+v", objs)
	}
	objs[0].Key = "changed"
	if s.Objects()[0] != a {
		t.Error("Objects returned the session's slice")
	}

	// The lock lives in memory, under the run's own prefix.
	if s.LockKey() != run+".lock" {
		t.Errorf("lock key %q", s.LockKey())
	}
	if _, ok := s.Lock(); ok {
		t.Error("a lock before PutLock")
	}
	s.PutLock([]byte("lock body"))
	if body, ok := s.Lock(); !ok || string(body) != "lock body" {
		t.Errorf("lock = %q, %v", body, ok)
	}
	if !s.DeleteLock() || s.DeleteLock() {
		t.Error("DeleteLock should be true once, then false")
	}
	if _, ok := s.Lock(); ok {
		t.Error("a lock after DeleteLock")
	}

	// The byte quota stops the session once, with the first reason.
	if err := s.AddBytes(60); err != nil {
		t.Fatal(err)
	}
	if err := s.AddBytes(40); err != nil {
		t.Fatalf("exactly MaxBytes: %v", err)
	}
	select {
	case r := <-s.Stopped():
		t.Fatalf("stopped early: %s", r)
	default:
	}
	if err := s.AddBytes(1); !errors.Is(err, ingest.ErrQuota) {
		t.Fatalf("over MaxBytes: %v, want ErrQuota", err)
	}
	s.Stop("bad digest")
	select {
	case r := <-s.Stopped():
		if r != ingest.ReasonQuota {
			t.Errorf("stop reason %q, want %q", r, ingest.ReasonQuota)
		}
	case <-time.After(time.Second):
		t.Fatal("not stopped")
	}
}

// Neither a credential nor a session prints its secret.
func TestSecretNotPrinted(t *testing.T) {
	reg, _, _, _ := newRegistry(t, 4)
	s, cred := open(t, reg, backupOptions())
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, nil))
	log.Info("x", "cred", cred, "session", s)
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "cred", cred, "session", s)
	for _, out := range []string{
		fmt.Sprint(cred), fmt.Sprintf("%+v", cred), fmt.Sprintf("%#v", cred),
		fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), logged.String(),
	} {
		if strings.Contains(out, cred.Secret) {
			t.Errorf("printed the secret: %s", out)
		}
	}
	if !strings.Contains(fmt.Sprint(cred), cred.AccessKey) {
		t.Errorf("the access key is not printed: %s", cred)
	}
}
