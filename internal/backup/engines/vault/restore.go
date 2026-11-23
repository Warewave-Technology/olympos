package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/restore"
	"github.com/Warewave-Technology/olympos/internal/vaults/vclient"
)

var (
	_ backup.Restorer         = Engine{}
	_ restore.TargetInspector = Engine{}
)

func init() {
	backup.RegisterRestorer("vault", Engine{})
	restore.RegisterInspector("vault", Engine{})
}

// SnapshotForcePath is the only path a restore writes.
const SnapshotForcePath = "sys/storage/raft/snapshot-force"

// SnapshotItem names the one RestoreItem of a Vault restore.
const SnapshotItem = "snapshot"

// RestoreNote is the result note of every successful Vault restore
// (docs/design/ui-restore.md "Goals").
const RestoreNote = "The snapshot replaced all of the target's data. The target must now be unsealed with the SOURCE " +
	"Vault's unseal keys (or by the source's auto-unseal, with access to the same seal key); its own unseal keys no longer " +
	"apply. Its root token, policies, auth methods and secrets are now the source's. The token given for this request " +
	"most likely no longer works."

// postRestoreTimeout bounds the seal-status read after the restore.
const postRestoreTimeout = 10 * time.Second

// errDatabases: a snapshot is all or nothing (restore.CheckDatabases
// refuses databases for Vault before a request is opened).
var errDatabases = errors.New("a Vault/OpenBao restore loads the whole snapshot; no databases are selected; nothing was written")

// targetCheck is what the inspector and the restore's preflight read.
type targetCheck struct {
	health vclient.Health
	// standby: an HA node that is not the active one (sys/leader).
	standby bool
	// capsDenied: sys/capabilities-self answered 401/403.
	capsDenied bool
	// canForce: the token holds update and sudo (or root) on
	// SnapshotForcePath, as Vault enforces for the restore. Only read on an
	// initialized, unsealed, active node.
	canForce bool
}

func (c targetCheck) report() *restore.TargetReport {
	return &restore.TargetReport{Existing: map[string]bool{}, Initialized: c.health.Initialized, Sealed: c.health.Sealed,
		Standby: c.standby, CapabilitiesDenied: c.capsDenied, CanSnapshotForce: c.canForce, ServerVersion: c.health.Version}
}

// refusal is why the target cannot take the snapshot ("": it can), in
// restore.CheckReport's words.
func (c targetCheck) refusal() string {
	fields, _ := restore.CheckReport("vault", nil, c.report())
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fields[k]
	}
	return strings.Join(parts, "; ")
}

// allowsForce: Vault requires both update (POST) and sudo (a
// root-protected path) on SnapshotForcePath; root allows everything.
func allowsForce(caps []string) bool {
	return slices.Contains(caps, "root") || (slices.Contains(caps, "update") && slices.Contains(caps, "sudo"))
}

// session is a client of the restore target and the request's token. The
// token is not set on the client: only the capabilities read and the
// snapshot POST carry it; seal-status and sys/leader go without.
type session struct {
	c     *vclient.Client
	token string
}

// open builds the target's client (TLS, server name, CA bundle as for the
// backup engine) and keeps the request's token. The token is never logged
// or put in an error.
func (e Engine) open(ctx context.Context, ec backup.EngineContext, scrub *backup.SecretScrubber) (*session, error) {
	if ec.Credential == nil {
		return nil, errors.New("no Vault token for this restore")
	}
	cred, err := ec.Credential(ctx)
	if err != nil {
		return nil, fmt.Errorf("the Vault token: %w", err)
	}
	if scrub != nil {
		scrub.Track(cred)
	}
	if len(cred.Secret) == 0 {
		return nil, errors.New("no Vault token for this restore")
	}
	c, err := e.client(ctx, ec)
	if err != nil {
		return nil, err
	}
	// The caller zeroes cred.Secret; the session keeps its own string.
	return &session{c: c, token: string(cred.Secret)}, nil
}

func (s *session) close() {
	s.token = ""
	s.c.Close()
}

// check reads the seal status and sys/leader (unauthenticated endpoints,
// read without the token) and, on an
// initialized, unsealed, active node, the token's capabilities on
// SnapshotForcePath. It writes nothing. A target without integrated storage is an error: it cannot take
// a raft snapshot whatever the token may do.
func (s *session) check(ctx context.Context) (targetCheck, error) {
	var tc targetCheck
	h, err := s.sealStatus(ctx)
	if err != nil {
		return tc, safeError("read the target's seal status", err)
	}
	tc.health = h
	if !h.Initialized || h.Sealed {
		return tc, nil
	}
	if h.StorageType != "" && h.StorageType != "raft" {
		return tc, fmt.Errorf("the target Vault uses %s storage; a raft snapshot is restored into integrated (raft) storage only", h.StorageType)
	}
	l, err := s.c.Sys().LeaderWithContext(ctx)
	if err != nil {
		return tc, safeError("read the target's leader status", err)
	}
	if l.HAEnabled && !l.IsSelf {
		// The POST would be redirected or forwarded to another node.
		tc.standby = true
		return tc, nil
	}
	caps, err := s.capabilities(ctx)
	if err != nil {
		if code := vclient.StatusCode(err); code == http.StatusForbidden || code == http.StatusUnauthorized {
			// An invalid token, or one without the default policy: a
			// refusal, not a failed check.
			tc.capsDenied = true
			return tc, nil
		}
		return tc, safeError("read the token's capabilities", err)
	}
	tc.canForce = allowsForce(caps)
	return tc, nil
}

// sealStatus reads sys/seal-status (no token needed). Unlike
// vclient.SealStatus it keeps the *vaultapi.ResponseError, so that only its
// status code is ever relayed (safeError), not the server's text.
func (s *session) sealStatus(ctx context.Context) (vclient.Health, error) {
	st, err := s.c.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return vclient.Health{}, err
	}
	return vclient.Health{Version: st.Version, Sealed: st.Sealed, Initialized: st.Initialized, StorageType: st.StorageType}, nil
}

// capabilities asks sys/capabilities-self for SnapshotForcePath. The token
// goes in the header only (the API client's CapabilitiesSelf also puts it
// in the body).
func (s *session) capabilities(ctx context.Context) ([]string, error) {
	r := s.c.NewRequest(http.MethodPost, "/v1/sys/capabilities-self")
	r.ClientToken = s.token
	if err := r.SetJSONBody(map[string]any{"paths": []string{SnapshotForcePath}}); err != nil {
		return nil, err
	}
	resp, err := s.c.RawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	sec, err := vaultapi.ParseSecret(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, errors.New("the target's capabilities answer could not be read")
	}
	if sec == nil || sec.Data == nil {
		return nil, errors.New("the target's capabilities answer is empty")
	}
	for _, k := range []string{SnapshotForcePath, "capabilities"} {
		if raw, ok := sec.Data[k].([]any); ok {
			out := make([]string, 0, len(raw))
			for _, v := range raw {
				if s, ok := v.(string); ok {
					out = append(out, s)
				}
			}
			return out, nil
		}
	}
	return []string{}, nil
}

// InspectRestoreTarget implements restore.TargetInspector: the target is
// initialized and unsealed, and the request's token may call
// sys/storage/raft/snapshot-force (sys/capabilities-self). It writes
// nothing. databases is not used: a snapshot is all or nothing, and
// restore.CheckDatabases refuses a Vault request that names any.
func (e Engine) InspectRestoreTarget(ctx context.Context, ec backup.EngineContext, _ []string) (*restore.TargetReport, error) {
	scrub := &backup.SecretScrubber{}
	s, err := e.open(ctx, ec, scrub)
	if err != nil {
		return nil, errors.New(scrub.Scrub(err.Error()))
	}
	defer s.close()
	tc, err := s.check(ctx)
	if err != nil {
		return nil, errors.New(scrub.Scrub(err.Error()))
	}
	return tc.report(), nil
}

// Restore implements backup.Restorer (docs/design/ui-restore.md
// "Engines"): the snapshot is streamed to POST
// /v1/sys/storage/raft/snapshot-force with the request's token. The
// executor verified the copy's SHA-256 before calling it. The target is
// checked again first (initialized, unsealed, raft storage, the token's
// capabilities); nothing is sent before that passed. After a successful
// restore the target is usually sealed (it now holds the source's
// keyring): its status is reported in a note, never as a failure.
func (e Engine) Restore(ctx context.Context, rc backup.RestoreContext) (_ *backup.RestoreResult, err error) {
	res := &backup.RestoreResult{Items: []backup.RestoreItem{}, Notes: []string{}, Created: []string{}}
	scrub := &backup.SecretScrubber{}
	defer func() {
		if err != nil {
			err = errors.New(scrub.Scrub(err.Error()))
		}
		for i := range res.Items {
			res.Items[i].Error = scrub.Scrub(res.Items[i].Error)
		}
		for i := range res.Notes {
			res.Notes[i] = scrub.Scrub(res.Notes[i])
		}
	}()
	if len(rc.Databases) > 0 {
		return res, errDatabases
	}
	if rc.Snapshot == nil {
		return res, errors.New("no snapshot to restore; nothing was written")
	}
	progress := rc.Progress
	if progress == nil {
		progress = func(backup.Progress) {}
	}
	s, err := e.open(ctx, rc.EngineContext, scrub)
	if err != nil {
		return res, err
	}
	defer s.close()

	// Preflight: time passed since the approval.
	tc, err := s.check(ctx)
	if err != nil {
		return res, fmt.Errorf("%w; nothing was written", err)
	}
	if msg := tc.refusal(); msg != "" {
		return res, errors.New(msg + "; nothing was written")
	}

	progress(backup.Progress{Phase: "restore", Database: SnapshotItem})
	start := time.Now()
	item := backup.RestoreItem{Name: SnapshotItem, Status: "failed"}
	sent, werr := s.snapshotForce(ctx, rc.Snapshot)
	item.Bytes, item.Duration = sent.n, time.Since(start).Seconds()
	if msg := uploadFailure(werr, sent, ctx.Err() != nil); msg != "" {
		item.Error = msg
		res.Items = append(res.Items, item)
		return res, errors.New(msg)
	}
	item.Status = "succeeded"
	res.Items = append(res.Items, item)
	res.Notes = append(res.Notes, RestoreNote)
	res.Notes = append(res.Notes, s.afterRestore(ctx))
	progress(backup.Progress{Phase: "restore", Bytes: sent.n, Done: []string{SnapshotItem}})
	return res, nil
}

// uploadFailure is why the snapshot POST did not restore ("": it did).
// werr is snapshotForce's error, sent how the body was read, cancelled
// whether the restore's context ended. A 2xx counts only when the whole
// snapshot was read without error. Whether the target may have installed
// the snapshot is decided on sent.eof alone: once the whole body was sent,
// a later failure or cancellation can leave the target replaced (and
// sealed).
func uploadFailure(werr error, sent bodyState, cancelled bool) string {
	var redirect *redirectError
	if errors.As(werr, &redirect) {
		return redirect.Error()
	}
	if werr == nil {
		switch {
		case sent.err != nil:
			return fmt.Sprintf("the target answered success, but the backup could not be read to its end (%d bytes sent): "+
				"check the target, it may have installed a partial upload or nothing", sent.n)
		case !sent.eof:
			return fmt.Sprintf("the target answered success before it read the whole snapshot (%d bytes sent): check the "+
				"target, it may have installed a partial upload or nothing", sent.n)
		}
		return ""
	}
	msg := safeError("snapshot-force", werr).Error()
	if sent.err != nil {
		// The backup copy could not be read (the transport reports it as
		// its own failure).
		msg = fmt.Sprintf("read the backup copy: %v", sent.err)
	}
	switch {
	case sent.eof && cancelled:
		msg += "; the whole snapshot was sent before the restore was cancelled: check whether the target installed it " +
			"(it may now be sealed)"
	case sent.eof:
		msg += "; the target received the whole snapshot: check whether it installed it (it may now be sealed)"
	default:
		msg += "; the snapshot was not fully sent"
	}
	return msg
}

// snapshotForce streams body to POST /v1/sys/storage/raft/snapshot-force
// (the request vaultapi's RaftSnapshotRestoreWithContext(ctx, r, true)
// makes) over the target's transport, without following redirects: the
// API client follows one redirect itself and would resend the consumed
// body to another node. A 3xx is a *redirectError, another non-2xx a
// *vaultapi.ResponseError with the status only (the body is discarded).
//
// It returns only after net/http let go of the body (closed it), or after
// bodyReleaseTimeout; in either case the body reads nothing more, so the
// returned bodyState is final.
func (s *session) snapshotForce(ctx context.Context, snapshot io.Reader) (bodyState, error) {
	body := newTrackedBody(snapshot)
	defer body.release()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.c.Address()+"/v1/"+SnapshotForcePath, body)
	if err != nil {
		return body.state(), err
	}
	req.Header.Set(vaultapi.AuthHeaderName, s.token)
	req.Header.Set(vaultapi.RequestHeaderName, "true")
	resp, err := s.c.NoRedirectHTTP().Do(req)
	if err != nil {
		body.release()
		return body.state(), err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	body.release()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return body.state(), nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return body.state(), &redirectError{code: resp.StatusCode}
	}
	return body.state(), &vaultapi.ResponseError{HTTPMethod: http.MethodPost, StatusCode: resp.StatusCode}
}

// bodyReleaseTimeout bounds the wait for net/http to close the request
// body after the response (it may still be writing on an early answer).
const bodyReleaseTimeout = 10 * time.Second

// errBodyReleased ends a body net/http still reads after the response.
var errBodyReleased = errors.New("the request was answered; the snapshot upload stopped")

// bodyState is how the snapshot was read for the POST.
type bodyState struct {
	n   int64
	eof bool  // read to its end
	err error // the snapshot's own read error (not errBodyReleased)
}

// trackedBody is the POST's body. net/http reads and closes it from its
// write goroutine, which can outlive Do on an early response; the state is
// guarded by a mutex, and release stops further reads and waits for Close.
type trackedBody struct {
	r      io.Reader
	mu     sync.Mutex
	st     bodyState
	done   bool // released: reads fail
	closed chan struct{}
	once   sync.Once
}

func newTrackedBody(r io.Reader) *trackedBody {
	return &trackedBody{r: r, closed: make(chan struct{})}
}

func (b *trackedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return 0, errBodyReleased
	}
	if b.st.eof {
		return 0, io.EOF
	}
	n, err := b.r.Read(p)
	b.st.n += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		b.st.eof = true
	case err != nil && b.st.err == nil:
		b.st.err = err
	}
	return n, err
}

// Close is called by net/http when it no longer reads the body.
func (b *trackedBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// release makes further reads fail and waits (bounded) for net/http to
// close the body. Calls after the first return at once.
func (b *trackedBody) release() {
	b.mu.Lock()
	again := b.done
	b.done = true
	b.mu.Unlock()
	if again {
		return
	}
	t := time.NewTimer(bodyReleaseTimeout)
	defer t.Stop()
	select {
	case <-b.closed:
	case <-t.C:
	}
}

func (b *trackedBody) state() bodyState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st
}

// redirectError: the target redirected the snapshot (a standby pointing
// at the active node). Olympos does not follow it.
type redirectError struct{ code int }

func (e *redirectError) Error() string {
	return fmt.Sprintf("snapshot-force: the target answered HTTP %d, a redirect to another node, which Olympos does not "+
		"follow: the target is not the active node and did not install the snapshot; point the target at the active node", e.code)
}

// afterRestore reads the seal status once (no token) and describes it. A
// sealed or unanswering target is expected right after snapshot-force.
func (s *session) afterRestore(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postRestoreTimeout)
	defer cancel()
	h, err := s.sealStatus(cctx)
	switch {
	case err != nil:
		if code := vclient.StatusCode(err); code != 0 {
			return fmt.Sprintf("After the restore the target answered HTTP %d to a seal-status read; this is expected while it "+
				"restarts or is sealed. Unseal it with the source's keys.", code)
		}
		return "After the restore the target's seal status could not be read; this is expected while it restarts or is sealed. " +
			"Unseal it with the source's keys."
	case h.Sealed:
		return "After the restore the target reports sealed, as expected: unseal it with the source's unseal keys."
	}
	return "Right after the restore the target still reported unsealed. A Vault with Shamir keys seals itself shortly after " +
		"a forced restore (one with the source's auto-unseal unseals again): check its status, and unseal it with the source's " +
		"keys when it is sealed."
}

// safeError maps a Vault or transport error to one without the server's
// response text or the request: an answered request gives its HTTP status
// and a short generic reason only.
func safeError(op string, err error) error {
	var re *vaultapi.ResponseError
	if errors.As(err, &re) {
		return fmt.Errorf("%s: the target Vault returned HTTP %d (%s)", op, re.StatusCode, statusReason(re.StatusCode))
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: cancelled", op)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: timed out", op)
	}
	// Transport errors (TLS verification, plain HTTP, unreachable): no
	// response body exists; vclient keeps the first line without the URL.
	return fmt.Errorf("%s: %w", op, vclient.Sanitize(err))
}

func statusReason(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "the request or the snapshot was refused as invalid"
	case http.StatusUnauthorized, http.StatusForbidden:
		return "permission denied: the token is invalid or not allowed"
	case http.StatusNotFound:
		return "the endpoint does not exist on the target"
	case http.StatusMethodNotAllowed:
		return "the endpoint does not accept this request"
	case http.StatusTooManyRequests:
		return "the target is a standby or rate limited"
	case http.StatusInternalServerError:
		return "the target failed to process the request"
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return "the target could not be reached through a proxy"
	case http.StatusServiceUnavailable:
		return "the target is sealed or unavailable"
	}
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "unexpected status"
}
