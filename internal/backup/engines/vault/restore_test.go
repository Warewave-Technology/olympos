package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
)

const (
	testToken = "hvs.CANARY-restore-token-5e1f"
	// bodyCanary is in every error body the fake returns: it must never
	// reach an error, item or note.
	bodyCanary = "CANARY-server-body-9b2c"
)

// fakeVault is a Vault API with the calls a restore makes.
type fakeVault struct {
	mu          sync.Mutex
	initialized bool
	sealed      bool
	storage     string
	caps        []string
	capsStatus  int // non-zero: sys/capabilities-self answers this
	forceStatus int // non-zero: snapshot-force answers this (after reading the body)
	// sealedAfter: seal-status answers 503 after a successful restore.
	sealedAfter bool
	// standby: sys/leader says HA and not the active node.
	standby bool
	// redirectTo: non-empty: snapshot-force answers 307 to this URL.
	redirectTo string

	restored  bool
	received  []byte
	tokens    []string // X-Vault-Token of each authenticated request
	capBodies []string
	forced    int
}

func (f *fakeVault) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	errBody := func(w http.ResponseWriter, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"errors":["`+bodyCanary+` token `+testToken+`"]}`)
	}
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.restored && f.sealedAfter {
			errBody(w, http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "shamir", "initialized": f.initialized, "sealed": f.sealed,
			"t": 1, "n": 1, "version": "1.20.0", "storage_type": f.storage})
	})
	mux.HandleFunc("/v1/sys/leader", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ha_enabled": true, "is_self": !f.standby, "active_time": "0001-01-01T00:00:00Z",
			"leader_address": "http://127.0.0.1:8200", "leader_cluster_address": "https://127.0.0.1:8201", "raft_committed_index": 1})
	})
	mux.HandleFunc("/v1/sys/capabilities-self", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		f.capBodies = append(f.capBodies, string(b))
		f.tokens = append(f.tokens, r.Header.Get("X-Vault-Token"))
		if f.capsStatus != 0 {
			errBody(w, f.capsStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{SnapshotForcePath: f.caps, "capabilities": f.caps}})
	})
	mux.HandleFunc("/v1/sys/storage/raft/snapshot-force", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("snapshot-force: method %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.forced++
		f.received = b
		f.tokens = append(f.tokens, r.Header.Get("X-Vault-Token"))
		if f.redirectTo != "" {
			http.Redirect(w, r, f.redirectTo, http.StatusTemporaryRedirect)
			return
		}
		if f.forceStatus != 0 {
			errBody(w, f.forceStatus)
			return
		}
		f.restored = true
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})
	return mux
}

func okVault() *fakeVault {
	return &fakeVault{initialized: true, storage: "raft", caps: []string{"create", "update", "sudo"}}
}

// start serves f and returns an EngineContext that dials it (plain HTTP,
// as in compressed transfer mode).
func start(t *testing.T, f *fakeVault) backup.EngineContext {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return backup.EngineContext{
		Target: backup.TargetInfo{ID: "t1", Namespace: "lab", Service: "vault-new"},
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		Credential: func(context.Context) (backup.Credential, error) {
			return backup.Credential{Secret: []byte(testToken)}, nil
		},
	}
}

// noSecrets fails when s carries the token or the fake's response body.
func noSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, c := range []string{testToken, "CANARY-restore-token", bodyCanary} {
		if strings.Contains(s, c) {
			t.Errorf("%s carries %q: %s", what, c, s)
		}
	}
}

func TestInspectRestoreTarget(t *testing.T) {
	cases := []struct {
		name  string
		mod   func(*fakeVault)
		check func(t *testing.T, r *restore.TargetReport)
		// field is the refusal restore.CheckReport derives ("": none).
		field string
	}{
		{"ok", func(*fakeVault) {}, func(t *testing.T, r *restore.TargetReport) {
			if !r.Initialized || r.Sealed || !r.CanSnapshotForce || r.ServerVersion != "1.20.0" {
				t.Errorf("report %+v", r)
			}
		}, ""},
		{"root token", func(f *fakeVault) { f.caps = []string{"root"} }, func(t *testing.T, r *restore.TargetReport) {
			if !r.CanSnapshotForce {
				t.Errorf("root: %+v", r)
			}
		}, ""},
		{"sudo only", func(f *fakeVault) { f.caps = []string{"sudo"} }, func(t *testing.T, r *restore.TargetReport) {
			if r.CanSnapshotForce {
				t.Errorf("sudo only: %+v", r)
			}
		}, "vault_token"},
		{"update only", func(f *fakeVault) { f.caps = []string{"create", "update"} }, func(t *testing.T, r *restore.TargetReport) {
			if r.CanSnapshotForce {
				t.Errorf("update only: %+v", r)
			}
		}, "vault_token"},
		{"standby", func(f *fakeVault) { f.standby = true }, func(t *testing.T, r *restore.TargetReport) {
			if !r.Standby || r.CanSnapshotForce {
				t.Errorf("standby: %+v", r)
			}
		}, "target_id"},
		{"uninitialized", func(f *fakeVault) { f.initialized, f.sealed = false, true }, func(t *testing.T, r *restore.TargetReport) {
			if r.Initialized || r.CanSnapshotForce {
				t.Errorf("report %+v", r)
			}
		}, "target_id"},
		{"sealed", func(f *fakeVault) { f.sealed = true }, func(t *testing.T, r *restore.TargetReport) {
			if !r.Sealed || r.CanSnapshotForce {
				t.Errorf("report %+v", r)
			}
		}, "target_id"},
		{"missing capability", func(f *fakeVault) { f.caps = []string{"read", "list"} }, func(t *testing.T, r *restore.TargetReport) {
			if r.CanSnapshotForce {
				t.Errorf("report %+v", r)
			}
		}, "vault_token"},
		{"no capabilities", func(f *fakeVault) { f.caps = []string{"deny"} }, func(t *testing.T, r *restore.TargetReport) {
			if r.CanSnapshotForce {
				t.Errorf("report %+v", r)
			}
		}, "vault_token"},
		{"invalid token", func(f *fakeVault) { f.capsStatus = http.StatusForbidden }, func(t *testing.T, r *restore.TargetReport) {
			if r.CanSnapshotForce || !r.CapabilitiesDenied {
				t.Errorf("report %+v", r)
			}
		}, "vault_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := okVault()
			tc.mod(f)
			ec := start(t, f)
			r, err := Engine{}.InspectRestoreTarget(context.Background(), ec, nil)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			tc.check(t, r)
			fields, _ := restore.CheckReport("vault", nil, r)
			switch {
			case tc.field == "" && len(fields) > 0:
				t.Errorf("refused: %v", fields)
			case tc.field != "" && fields[tc.field] == "":
				t.Errorf("want a refusal on %s, got %v", tc.field, fields)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.forced != 0 {
				t.Error("the inspector called snapshot-force")
			}
			for _, b := range f.capBodies {
				noSecrets(t, "capabilities-self body", b)
			}
			for _, tok := range f.tokens {
				if tok != testToken {
					t.Errorf("token header %q", tok)
				}
			}
			if (f.initialized && !f.sealed && !f.standby) != (len(f.capBodies) == 1) {
				t.Errorf("capabilities read %d times (initialized %v, sealed %v)", len(f.capBodies), f.initialized, f.sealed)
			}
		})
	}
}

func TestInspectRestoreTargetErrors(t *testing.T) {
	t.Run("not raft", func(t *testing.T) {
		f := okVault()
		f.storage = "file"
		_, err := Engine{}.InspectRestoreTarget(context.Background(), start(t, f), nil)
		if err == nil || !strings.Contains(err.Error(), "raft") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("capabilities server error is scrubbed", func(t *testing.T) {
		f := okVault()
		f.capsStatus = http.StatusInternalServerError
		_, err := Engine{}.InspectRestoreTarget(context.Background(), start(t, f), nil)
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("err %v", err)
		}
		noSecrets(t, "error", err.Error())
	})
	t.Run("no token", func(t *testing.T) {
		ec := start(t, okVault())
		ec.Credential = func(context.Context) (backup.Credential, error) { return backup.Credential{}, nil }
		if _, err := (Engine{}).InspectRestoreTarget(context.Background(), ec, nil); err == nil {
			t.Fatal("no error without a token")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		ec := start(t, okVault())
		ec.Dial = func(context.Context) (net.Conn, error) { return nil, errors.New("tunnel closed") }
		_, err := Engine{}.InspectRestoreTarget(context.Background(), ec, nil)
		if err == nil {
			t.Fatal("no error")
		}
		noSecrets(t, "error", err.Error())
	})
}

func restoreContext(ec backup.EngineContext, snap []byte) (backup.RestoreContext, *[]backup.Progress) {
	var seen []backup.Progress
	return backup.RestoreContext{EngineContext: ec, RequestID: "req-1", Snapshot: bytes.NewReader(snap), Databases: []string{},
		Progress: func(p backup.Progress) { seen = append(seen, p) }}, &seen
}

func checkResult(t *testing.T, res *backup.RestoreResult, err error) {
	t.Helper()
	if err != nil {
		noSecrets(t, "error", err.Error())
	}
	if res == nil {
		t.Fatal("nil result")
	}
	for _, it := range res.Items {
		noSecrets(t, "item error", it.Error)
	}
	for _, n := range res.Notes {
		noSecrets(t, "note", n)
	}
}

func TestRestoreSuccess(t *testing.T) {
	snap := bytes.Repeat([]byte("raft-snapshot-bytes "), 50000) // ~1 MB
	for _, sealedAfter := range []bool{false, true} {
		f := okVault()
		f.sealedAfter = sealedAfter
		rc, seen := restoreContext(start(t, f), snap)
		res, err := Engine{}.Restore(context.Background(), rc)
		checkResult(t, res, err)
		if err != nil {
			t.Fatalf("restore: %v", err)
		}
		if !bytes.Equal(f.received, snap) {
			t.Fatalf("received %d bytes, want %d", len(f.received), len(snap))
		}
		if len(res.Items) != 1 || res.Items[0].Name != SnapshotItem || res.Items[0].Status != "succeeded" || res.Items[0].Bytes != int64(len(snap)) {
			t.Fatalf("items %+v", res.Items)
		}
		if len(res.Created) != 0 {
			t.Errorf("created %v", res.Created)
		}
		all := strings.Join(res.Notes, "\n")
		for _, want := range []string{"SOURCE", "unseal keys", "auto-unseal", "root token", "policies", "auth methods", "no longer works"} {
			if !strings.Contains(all, want) {
				t.Errorf("notes lack %q:\n%s", want, all)
			}
		}
		if sealedAfter && !strings.Contains(all, "HTTP 503") {
			t.Errorf("notes do not report the post-restore 503:\n%s", all)
		}
		if len(*seen) == 0 || (*seen)[0].Phase != "restore" {
			t.Errorf("progress %+v", *seen)
		}
		for _, tok := range f.tokens {
			if tok != testToken {
				t.Errorf("token header %q", tok)
			}
		}
	}
}

func TestRestoreServerErrorScrubbed(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		f := okVault()
		f.forceStatus = code
		rc, _ := restoreContext(start(t, f), []byte("snapshot"))
		res, err := Engine{}.Restore(context.Background(), rc)
		checkResult(t, res, err)
		if err == nil {
			t.Fatalf("%d: no error", code)
		}
		if !strings.Contains(err.Error(), "HTTP "+strconv.Itoa(code)) {
			t.Errorf("%d: %v", code, err)
		}
		if len(res.Items) != 1 || res.Items[0].Status != "failed" || res.Items[0].Error == "" {
			t.Fatalf("%d: items %+v", code, res.Items)
		}
		if !strings.Contains(res.Items[0].Error, "received the whole snapshot") {
			t.Errorf("%d: item error %q", code, res.Items[0].Error)
		}
		for _, n := range res.Notes {
			if strings.Contains(n, "SOURCE") {
				t.Errorf("%d: success note on a failure: %s", code, n)
			}
		}
	}
}

func TestRestorePreflightWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*fakeVault)
		want string
	}{
		{"sealed", func(f *fakeVault) { f.sealed = true }, "sealed"},
		{"uninitialized", func(f *fakeVault) { f.initialized, f.sealed = false, true }, "not initialized"},
		{"missing capability", func(f *fakeVault) { f.caps = []string{"read"} }, "update and sudo on " + SnapshotForcePath},
		{"update only", func(f *fakeVault) { f.caps = []string{"update"} }, "update and sudo on " + SnapshotForcePath},
		{"sudo only", func(f *fakeVault) { f.caps = []string{"sudo"} }, "update and sudo on " + SnapshotForcePath},
		{"invalid token", func(f *fakeVault) { f.capsStatus = http.StatusForbidden }, "default policy"},
		{"standby", func(f *fakeVault) { f.standby = true }, "active node"},
		{"capabilities error", func(f *fakeVault) { f.capsStatus = http.StatusBadGateway }, "HTTP 502"},
		{"not raft", func(f *fakeVault) { f.storage = "consul" }, "raft"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := okVault()
			tc.mod(f)
			rc, _ := restoreContext(start(t, f), []byte("snapshot"))
			res, err := Engine{}.Restore(context.Background(), rc)
			checkResult(t, res, err)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing was written") {
				t.Fatalf("err %v", err)
			}
			if f.forced != 0 {
				t.Fatal("snapshot-force was called")
			}
		})
	}
}

func TestRestoreRefusesDatabases(t *testing.T) {
	f := okVault()
	rc, _ := restoreContext(start(t, f), []byte("snapshot"))
	rc.Databases = []string{"secret"}
	_, err := Engine{}.Restore(context.Background(), rc)
	if err == nil || !strings.Contains(err.Error(), "whole snapshot") {
		t.Fatalf("err %v", err)
	}
	rc.Databases, rc.Snapshot = nil, nil
	if _, err := (Engine{}).Restore(context.Background(), rc); err == nil {
		t.Fatal("no error without a snapshot")
	}
	if f.forced != 0 {
		t.Fatal("snapshot-force was called")
	}
}

// failingReader returns data, then an error (a backup read failure).
type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n > 0 {
		k := min(r.n, len(p))
		r.n -= k
		return k, nil
	}
	return 0, errors.New("storage read failed")
}

func TestRestoreBackupReadError(t *testing.T) {
	f := okVault()
	rc, _ := restoreContext(start(t, f), nil)
	rc.Snapshot = &failingReader{n: 4096}
	res, err := Engine{}.Restore(context.Background(), rc)
	checkResult(t, res, err)
	if err == nil || !strings.Contains(err.Error(), "read the backup copy: storage read failed; the snapshot was not fully sent") {
		t.Fatalf("err %v", err)
	}
	if len(res.Items) != 1 || res.Items[0].Status != "failed" {
		t.Fatalf("items %+v", res.Items)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, "SOURCE") {
			t.Errorf("success note on a failure: %s", n)
		}
	}
}

func TestRegistered(t *testing.T) {
	if r, ok := backup.RestorerFor("vault"); !ok || r == nil {
		t.Error("no restorer for vault")
	}
	if i, ok := restore.InspectorFor("vault"); !ok || i == nil {
		t.Error("no inspector for vault")
	}
}

func TestRestoreDoesNotFollowRedirect(t *testing.T) {
	// The active node the standby points at: it must never be contacted.
	var other int
	active := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer active.Close()
	f := okVault()
	f.redirectTo = active.URL + "/v1/" + SnapshotForcePath
	rc, _ := restoreContext(start(t, f), []byte("snapshot"))
	res, err := Engine{}.Restore(context.Background(), rc)
	checkResult(t, res, err)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || !strings.Contains(err.Error(), "active node") {
		t.Fatalf("err %v", err)
	}
	if f.forced != 1 || other != 0 {
		t.Fatalf("snapshot-force called %d times, redirect target %d times", f.forced, other)
	}
	if len(res.Items) != 1 || res.Items[0].Status != "failed" || !strings.Contains(res.Items[0].Error, "307") {
		t.Fatalf("items %+v", res.Items)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, "SOURCE") {
			t.Errorf("success note on a redirect: %s", n)
		}
	}
}

func TestAllowsForce(t *testing.T) {
	for _, c := range []struct {
		caps []string
		ok   bool
	}{
		{[]string{"root"}, true},
		{[]string{"update", "sudo"}, true},
		{[]string{"create", "read", "update", "sudo"}, true},
		{[]string{"update"}, false},
		{[]string{"sudo"}, false},
		{[]string{"create", "sudo"}, false},
		{[]string{"deny"}, false},
		{nil, false},
	} {
		if got := allowsForce(c.caps); got != c.ok {
			t.Errorf("%v: %v", c.caps, got)
		}
	}
}
