package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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
	// canForce: the token's capabilities on SnapshotForcePath allow the
	// restore (only read when the target is initialized and unsealed).
	canForce bool
}

func (c targetCheck) report() *restore.TargetReport {
	return &restore.TargetReport{Existing: map[string]bool{}, Initialized: c.health.Initialized, Sealed: c.health.Sealed,
		CanSnapshotForce: c.canForce, ServerVersion: c.health.Version}
}

// refusal is why the target cannot take the snapshot ("": it can), as
// restore.CheckReport words it.
func (c targetCheck) refusal() string {
	switch {
	case !c.health.Initialized:
		return "the target Vault is not initialized"
	case c.health.Sealed:
		return "the target Vault is sealed; unseal it before the restore"
	case !c.canForce:
		return "the token cannot call " + SnapshotForcePath + " on the target"
	}
	return ""
}

// session is a client of the restore target with the request's token set.
type session struct {
	c *vclient.Client
}

// open builds the target's client (TLS, server name, CA bundle as for the
// backup engine) and sets the request's token on it. The token is never
// logged or put in an error.
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
	// The caller zeroes cred.Secret; the client keeps its own string.
	c.SetToken(string(cred.Secret))
	return &session{c: c}, nil
}

func (s *session) close() {
	s.c.ClearToken()
	s.c.Close()
}

// check reads the seal status (no token) and, on an initialized and
// unsealed target, the token's capabilities on SnapshotForcePath. It writes
// nothing. A target without integrated storage is an error: it cannot take
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
	caps, err := s.capabilities(ctx)
	if err != nil {
		if code := vclient.StatusCode(err); code == http.StatusForbidden || code == http.StatusUnauthorized {
			// An invalid or expired token: a refusal, not a failed check.
			return tc, nil
		}
		return tc, safeError("read the token's capabilities", err)
	}
	tc.canForce = slices.Contains(caps, "root") || slices.Contains(caps, "update") || slices.Contains(caps, "sudo")
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
	body := &countReader{r: rc.Snapshot}
	item := backup.RestoreItem{Name: SnapshotItem, Status: "failed"}
	werr := s.c.Sys().RaftSnapshotRestoreWithContext(ctx, body, true)
	item.Bytes, item.Duration = body.n, time.Since(start).Seconds()
	if werr != nil {
		msg := safeError("snapshot-force", werr).Error()
		if body.err != nil {
			// The backup copy could not be read (the transport reports it
			// as its own failure).
			msg = fmt.Sprintf("read the backup copy: %v", body.err)
		}
		if body.eof && ctx.Err() == nil {
			msg += "; the target received the whole snapshot: check whether it was installed (the target may now be sealed)"
		} else {
			msg += "; the snapshot was not fully sent"
		}
		item.Error = msg
		res.Items = append(res.Items, item)
		return res, errors.New(msg)
	}
	if body.err != nil {
		// Vault answered 2xx although the backup copy could not be read
		// to its end. Never report that as a restore.
		item.Error = fmt.Sprintf("the backup could not be read to its end (%d bytes sent); check the target, it may have "+
			"installed a partial upload or nothing", body.n)
		res.Items = append(res.Items, item)
		return res, errors.New(item.Error)
	}
	item.Status = "succeeded"
	res.Items = append(res.Items, item)
	res.Notes = append(res.Notes, RestoreNote)
	res.Notes = append(res.Notes, s.afterRestore(ctx))
	progress(backup.Progress{Phase: "restore", Bytes: body.n, Done: []string{SnapshotItem}})
	return res, nil
}

// afterRestore reads the seal status once (no token) and describes it. A
// sealed or unanswering target is expected right after snapshot-force.
func (s *session) afterRestore(ctx context.Context) string {
	s.c.ClearToken()
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

// countReader counts the bytes read and remembers how reading ended.
type countReader struct {
	r   io.Reader
	n   int64
	eof bool
	err error
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		c.eof = true
	case err != nil && c.err == nil:
		c.err = err
	}
	return n, err
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
