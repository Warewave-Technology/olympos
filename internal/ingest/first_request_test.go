package ingest_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// TestFirstRequest: a session that gets no signed request within
// FirstRequest stops with ReasonNoRequest, a backup's as a restore's. A
// ClickHouse that cannot reach the endpoint (no egress, an untrusted
// certificate) then ends its run instead of holding it until the TTL. A
// request whose signature does not verify does not count; one that does,
// even when refused afterwards, does.
func TestFirstRequest(t *testing.T) {
	e := newEnv(t)
	const wait = 300 * time.Millisecond
	first := func(o *ingest.OpenOptions) { o.FirstRequest = wait }

	idle := e.backup(t, first)
	bad := e.backup(t, first)
	forged := bad.cred
	forged.Secret = "not the secret"
	wantRefused(t, e.do(t, forged, http.MethodGet, "/olympos/"+bad.prefix+".backup", ""), http.StatusForbidden, "SignatureDoesNotMatch")
	busy := e.backup(t, first)
	e.do(t, busy.cred, http.MethodGet, "/olympos/"+busy.prefix+".backup", "") // signed, whatever the answer
	refused := e.backup(t, first)
	wantStatus(t, e.do(t, refused.cred, http.MethodDelete, "/olympos/"+refused.prefix+"data/x.bin", ""), http.StatusForbidden)
	none := e.backup(t)

	if r := stopReason(t, idle.s); r != ingest.ReasonNoRequest {
		t.Errorf("a session without requests stopped with %q, want %q", r, ingest.ReasonNoRequest)
	}
	if r := stopReason(t, bad.s); r != ingest.ReasonNoRequest {
		t.Errorf("a session with a forged request stopped with %q, want %q", r, ingest.ReasonNoRequest)
	}
	time.Sleep(2 * wait)
	notStopped(t, busy.s)
	notStopped(t, refused.s)
	notStopped(t, none.s)
	if got := idle.s.StopReason(); got != ingest.ReasonNoRequest {
		t.Errorf("StopReason of the idle session: %q", got)
	}

	idleRestore, _, err := e.reg.Open(t.Context(), ingest.OpenOptions{RunID: uuid.New(), Kind: ingest.KindRestore,
		Scope: ingest.Scope{Read: []string{uuid.NewString() + "/"}}, TTL: time.Hour, Source: &fakeSource{}, FirstRequest: wait})
	if err != nil {
		t.Fatal(err)
	}
	if r := stopReason(t, idleRestore); r != ingest.ReasonNoRequest {
		t.Errorf("a restore session without requests stopped with %q", r)
	}

	// A revoked session's timer does not fire.
	revoked := e.backup(t, first)
	revoked.s.Revoke("run ended")
	time.Sleep(2 * wait)
	if got := revoked.s.StopReason(); got != "" {
		t.Errorf("a revoked session stopped with %q", got)
	}
}
