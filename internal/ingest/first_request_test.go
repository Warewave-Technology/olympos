package ingest_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/ingest"
)

// TestFirstRequest: a session that gets no signed request within
// FirstRequest of Sent stops with ReasonNoRequest, a backup's as a
// restore's. A ClickHouse that cannot reach the endpoint (no egress, an
// untrusted certificate) then ends its run instead of holding it until the
// TTL. The window starts at Sent, when the statement goes to the target, so
// the work before it (connecting, reading sizes, creating databases) does not
// count. A request whose signature does not verify does not count; one that
// does, even when refused afterwards, does.
func TestFirstRequest(t *testing.T) {
	e := newEnv(t)
	const wait = 300 * time.Millisecond
	first := func(o *ingest.OpenOptions) { o.FirstRequest = wait }

	idle := e.backup(t, first)
	bad := e.backup(t, first)
	forged := bad.cred
	forged.Secret = "not the secret"
	busy := e.backup(t, first)
	refused := e.backup(t, first)
	none := e.backup(t)
	unsent := e.backup(t, first)
	for _, r := range []*run{idle, bad, busy, refused, none} {
		r.s.Sent()
	}
	wantRefused(t, e.do(t, forged, http.MethodGet, "/olympos/"+bad.prefix+".backup", ""), http.StatusForbidden, "SignatureDoesNotMatch")
	e.do(t, busy.cred, http.MethodGet, "/olympos/"+busy.prefix+".backup", "") // signed, whatever the answer
	wantStatus(t, e.do(t, refused.cred, http.MethodDelete, "/olympos/"+refused.prefix+"data/x.bin", ""), http.StatusForbidden)

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
	notStopped(t, unsent.s)
	if got := idle.s.StopReason(); got != ingest.ReasonNoRequest {
		t.Errorf("StopReason of the idle session: %q", got)
	}

	// Sent long after the open: the window is still whole from then on.
	start := time.Now()
	unsent.s.Sent()
	unsent.s.Sent() // only the first call counts
	time.Sleep(wait / 2)
	notStopped(t, unsent.s)
	if r := stopReason(t, unsent.s); r != ingest.ReasonNoRequest || time.Since(start) < wait {
		t.Errorf("a session sent late stopped with %q after %s", r, time.Since(start))
	}

	idleRestore, _, err := e.reg.Open(t.Context(), ingest.OpenOptions{RunID: uuid.New(), Kind: ingest.KindRestore,
		Scope: ingest.Scope{Read: []string{uuid.NewString() + "/"}}, TTL: time.Hour, Source: &fakeSource{}, FirstRequest: wait})
	if err != nil {
		t.Fatal(err)
	}
	idleRestore.Sent()
	if r := stopReason(t, idleRestore); r != ingest.ReasonNoRequest {
		t.Errorf("a restore session without requests stopped with %q", r)
	}

	// A revoked session's timer does not fire, and a stop after Revoke does
	// not count.
	revoked := e.backup(t, first)
	revoked.s.Sent()
	revoked.s.Revoke("run ended")
	revoked.s.Stop(ingest.ReasonNoRequest)
	revoked.s.Sent()
	time.Sleep(2 * wait)
	if got := revoked.s.StopReason(); got != "" {
		t.Errorf("a revoked session stopped with %q", got)
	}
}
