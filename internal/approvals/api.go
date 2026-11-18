package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Applier writes a plan to the vault (implemented by internal/vaults). It
// returns the writes that reached Vault even when it fails part-way, and
// errors that are *SafeError when their message may be shown.
type Applier interface {
	Apply(ctx context.Context, vaultID uuid.UUID, writes []Write) ([]Applied, error)
}

// DefaultTTL is the change request lifetime when none is configured (§11.4).
const DefaultTTL = 72 * time.Hour

// applyTimeout bounds the Vault calls of one approval.
const applyTimeout = 90 * time.Second

// API serves /change-requests.
type API struct {
	DB       *store.DB
	Log      *slog.Logger
	Envelope *secrets.Envelope
	HMAC     *secrets.Fingerprinter
	Applier  Applier
	// Inspector reads KV metadata for ReconcileApplying (optional).
	Inspector Inspector
	TTL       time.Duration
	Now       func() time.Time
	// OnApplied is called after a commit in which Vault was written (e.g. to
	// refresh the index of that vault). Optional.
	OnApplied func(vaultID uuid.UUID)

	// Faults is fault injection for tests only (nil in production).
	Faults *Faults
}

// Faults stops an apply where a crash would: BeforeVault right before the
// Vault call, AfterVault right after it (before transaction 2).
type Faults struct {
	BeforeVault, AfterVault func() error
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Get("/change-requests", a.list)
	r.Post("/change-requests", a.create)
	r.Get("/change-requests/{id}", a.get)
	r.Post("/change-requests/{id}/approve", a.approve)
	r.Post("/change-requests/{id}/reject", a.reject)
	r.Post("/change-requests/{id}/cancel", a.cancel)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) ttl() time.Duration {
	if a.TTL > 0 {
		return a.TTL
	}
	return DefaultTTL
}

// Link is the UI path of a change request (notifications carry links only).
func Link(id uuid.UUID) string { return "/approvals/" + id.String() }

// ---------------------------------------------------------------- input

// secretValue decodes a JSON string into bytes so the plaintext can be
// zeroed after sealing (best effort: the request body buffer is not ours).
type secretValue []byte

func (s *secretValue) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return errors.New("value must be a string")
	}
	*s = []byte(str)
	return nil
}

type itemInput struct {
	Mount       string       `json:"mount"`
	Path        string       `json:"path"`
	Key         string       `json:"key"`
	Op          string       `json:"op"`
	Value       *secretValue `json:"value"`
	BaseVersion int          `json:"base_version"`
	Versions    []int        `json:"versions"`
}

type createInput struct {
	VaultID       uuid.UUID   `json:"vault_id"`
	Justification string      `json:"justification"`
	Items         []itemInput `json:"items"`
}

func zeroItems(items []Item) {
	for i := range items {
		secrets.Zero(items[i].Value)
	}
}

// ---------------------------------------------------------------- handlers

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	sub := httpx.Subject(r)
	q := r.URL.Query()
	f := Filter{Status: q.Get("status"), WaitingForMe: q.Get("waiting_for_me") == "true"}
	if q.Get("mine") == "true" {
		id := sub.Principal.ID
		f.MakerID = &id
	}
	if v := q.Get("vault_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.FieldErrors(w, "invalid filter", map[string]string{"vault_id": "must be a UUID"})
			return
		}
		f.VaultID = &id
	}
	if f.WaitingForMe {
		f.Status = string(StatusPending)
	}
	f.Limit = httpx.IntQuery(r, "limit", 200)
	items, err := ListRequests(r.Context(), a.DB, sub, f, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	cr, err := GetRequest(r.Context(), a.DB, httpx.Subject(r), id, a.now())
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, cr)
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	sub := httpx.Subject(r)
	ctx := r.Context()
	var in createInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	items := make([]Item, len(in.Items))
	for i, x := range in.Items {
		items[i] = Item{Mount: x.Mount, Path: x.Path, Key: x.Key, Op: Op(x.Op), BaseVersion: x.BaseVersion, Versions: x.Versions}
		if x.Value != nil {
			items[i].Value = []byte(*x.Value)
		}
	}
	defer func() {
		zeroItems(items)
		for _, x := range in.Items {
			if x.Value != nil {
				secrets.Zero(*x.Value)
			}
		}
	}()

	v, err := LoadVault(ctx, a.DB, in.VaultID)
	if errors.Is(err, store.ErrNotFound) || err == nil && !sub.Can(authz.PermRead, v.Labels) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if err := CheckOpen(sub, v.Labels); err != nil {
		httpx.Forbidden(w, err.Error())
		return
	}
	if v.Status != "configured" {
		httpx.Error(w, http.StatusConflict, "this vault is not configured")
		return
	}
	fields := ValidateItems(items, v.Mounts)
	if msg := ValidateJustification(in.Justification); msg != "" {
		fields["justification"] = msg
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid change request", fields)
		return
	}
	if _, err := Plan(items); err != nil {
		httpx.FieldErrors(w, "invalid change request", map[string]string{"items": err.Error()})
		return
	}

	crID := uuid.New()
	type sealedItem struct {
		id     uuid.UUID
		sealed secrets.Sealed
		fp     string
	}
	sealed := make([]sealedItem, len(items))
	for i := range items {
		sealed[i].id = uuid.New()
		if len(items[i].Value) == 0 {
			continue
		}
		s, err := a.Envelope.Seal(ctx, items[i].Value, []byte("change_items:"+sealed[i].id.String()))
		if err != nil {
			httpx.Internal(w, r, a.Log, fmt.Errorf("seal change item: %w", err))
			return
		}
		sealed[i].sealed = s
		sealed[i].fp = a.HMAC.Fingerprint(items[i].Value)
		secrets.Zero(items[i].Value)
	}
	now := a.now()
	actor := sub.Principal.ID
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO change_requests (id, vault_id, maker_principal_id, justification, status, expires_at, created_at)
			VALUES ($1, $2, $3, $4, 'pending', $5, $6)`, crID, v.ID, actor, strings.TrimSpace(in.Justification), now.Add(a.ttl()), now); err != nil {
			return err
		}
		ops := make([]map[string]any, len(items))
		for i, it := range items {
			var key *string
			if it.Op != OpDestroyHistory {
				k := it.Key
				key = &k
			}
			var ct, dek []byte
			if len(sealed[i].sealed.Ciphertext) > 0 {
				ct, dek = sealed[i].sealed.Ciphertext, sealed[i].sealed.WrappedDEK
			}
			versions := it.Versions
			if versions == nil {
				versions = []int{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO change_items (id, cr_id, mount, path, key, op, base_version, versions,
				sealed_value, wrapped_dek, kek_version, hmac_fingerprint) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
				sealed[i].id, crID, it.Mount, it.Path, key, string(it.Op), it.BaseVersion, versions,
				ct, dek, sealed[i].sealed.KEKVersion, sealed[i].fp); err != nil {
				return err
			}
			ops[i] = map[string]any{"op": it.Op, "ref": it.Mount + it.Path, "key": it.Key, "fingerprint": sealed[i].fp}
		}
		if err := addEvent(ctx, tx, crID, &actor, EventKind(StatusPending), map[string]any{"items": len(items)}); err != nil {
			return err
		}
		if err := httpx.Record(r, tx, "cr.opened", "change_request", crID.String(), &v.ClusterID,
			map[string]any{"vault_id": v.ID, "vault": v.Name, "items": ops}); err != nil {
			return err
		}
		// Slack gets a link only (§11.4): no values, no buttons.
		return notify.Emit(ctx, tx, notify.Event{Type: notify.CROpened, Key: notify.CROpened + ":" + crID.String(),
			Title: "Change request waiting for approval", Link: Link(crID)})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.Log.Info("change request opened", "cr_id", crID, "vault_id", v.ID, "items", len(items))
	cr, err := GetRequest(ctx, a.DB, sub, crID, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, cr)
}

type decisionInput struct {
	Comment string `json:"comment"`
}

func (a *API) decodeDecision(w http.ResponseWriter, r *http.Request) (decisionInput, bool) {
	var in decisionInput
	if r.ContentLength != 0 {
		if err := httpx.Decode(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
			return in, false
		}
	}
	in.Comment = strings.TrimSpace(in.Comment)
	if len(in.Comment) > MaxJustification {
		httpx.FieldErrors(w, "invalid comment", map[string]string{"comment": "too long"})
		return in, false
	}
	return in, true
}

// writeDeny maps rule errors to HTTP (403 role, 409 state).
func writeDeny(w http.ResponseWriter, err error) bool {
	var de *DenyError
	if !errors.As(err, &de) {
		return false
	}
	if de.Conflict {
		httpx.Error(w, http.StatusConflict, de.Reason)
	} else {
		httpx.Forbidden(w, de.Reason)
	}
	return true
}

// errHandled marks an error already written to the response.
var errHandled = errors.New("handled")

func (a *API) approve(w http.ResponseWriter, r *http.Request) { a.decide(w, r, EvApprove) }
func (a *API) reject(w http.ResponseWriter, r *http.Request)  { a.decide(w, r, EvReject) }

func (a *API) decide(w http.ResponseWriter, r *http.Request, ev Event) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	in, ok := a.decodeDecision(w, r)
	if !ok {
		return
	}
	if ev == EvReject && in.Comment == "" {
		httpx.FieldErrors(w, "a comment is required to reject", map[string]string{"comment": "required"})
		return
	}
	sub := httpx.Subject(r)
	ctx := r.Context()
	var wrote bool
	var vaultID uuid.UUID
	var pa *pendingApply
	expired := false
	if ev == EvApprove {
		// The vault lock is held from transaction 1 until the outcome is
		// recorded, so drift never sees a half-recorded write.
		if err := a.DB.QueryRow(ctx, `SELECT vault_id FROM change_requests WHERE id = $1`, id).Scan(&vaultID); err == nil {
			unlock, err := lockVaultSession(ctx, a.DB, vaultID)
			if err != nil {
				httpx.Internal(w, r, a.Log, err)
				return
			}
			defer unlock()
		}
	}
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		c, err := lockCR(ctx, tx, id)
		if errors.Is(err, errNotFound) {
			httpx.NotFound(w)
			return errHandled
		}
		if err != nil {
			return err
		}
		vaultID = c.VaultID
		v, err := LoadVault(ctx, tx, c.VaultID)
		if errors.Is(err, store.ErrNotFound) || err == nil && !sub.Can(authz.PermRead, v.Labels) {
			httpx.NotFound(w)
			return errHandled
		}
		if err != nil {
			return err
		}
		maker, err := authz.GetPrincipal(ctx, tx, c.MakerID)
		if err != nil {
			return err
		}
		now := a.now()
		if err := CheckDecide(sub, maker, v.Labels, c.Status, c.ExpiresAt, now); err != nil {
			var de *DenyError
			if errors.As(err, &de) && de.Reason == ReasonExpired && c.Status == StatusPending {
				// Expire it now (and commit) rather than leave it to the job.
				if err := a.expireOne(ctx, tx, c, v); err != nil {
					return err
				}
				expired = true
				return nil
			}
			writeDeny(w, err)
			return errHandled
		}
		actor := sub.Principal.ID
		if ev == EvReject {
			return a.rejectTx(ctx, r, tx, c, v, actor, in.Comment)
		}
		pa, err = a.approveTx(ctx, r, tx, c, v, actor, in.Comment)
		return err
	})
	if errors.Is(err, errHandled) {
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if expired {
		httpx.Error(w, http.StatusConflict, ReasonExpired)
		return
	}
	if pa != nil {
		wrote = a.apply(ctx, pa)
	}
	if wrote && a.OnApplied != nil {
		a.OnApplied(vaultID)
	}
	cr, err := GetRequest(ctx, a.DB, sub, id, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, cr)
}

func (a *API) rejectTx(ctx context.Context, r *http.Request, tx pgx.Tx, c lockedCR, v VaultInfo, actor uuid.UUID, comment string) error {
	to, err := Next(c.Status, EvReject)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, checker_principal_id = $3, decided_at = $4, decision_comment = $5
		WHERE id = $1`, c.ID, string(to), actor, a.now(), comment); err != nil {
		return err
	}
	if err := scrub(ctx, tx, c.ID); err != nil {
		return err
	}
	if err := addEvent(ctx, tx, c.ID, &actor, EventKind(to), map[string]any{"comment": comment}); err != nil {
		return err
	}
	if err := httpx.Record(r, tx, "cr.rejected", "change_request", c.ID.String(), &v.ClusterID, map[string]any{"vault_id": v.ID}); err != nil {
		return err
	}
	return notify.Emit(ctx, tx, notify.Event{Type: notify.CRRejected, Key: notify.CRRejected + ":" + c.ID.String(),
		Title: "Change request rejected", Link: Link(c.ID), Fields: map[string]string{"Vault": v.Name}})
}

// pendingApply is an approved request committed as 'applying', with its
// unsealed plan in memory (zeroed after the Vault call).
type pendingApply struct {
	crID  uuid.UUID
	v     VaultInfo
	items []Item
	plan  []Write
}

// approveTx is transaction 1: it records the approval and moves the request
// to 'applying', and unseals the plan. Vault is called only after commit.
func (a *API) approveTx(ctx context.Context, r *http.Request, tx pgx.Tx, c lockedCR, v VaultInfo, actor uuid.UUID, comment string) (*pendingApply, error) {
	to, err := Next(c.Status, EvApprove)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, checker_principal_id = $3, decided_at = $4, decision_comment = $5
		WHERE id = $1`, c.ID, string(to), actor, a.now(), comment); err != nil {
		return nil, err
	}
	if err := addEvent(ctx, tx, c.ID, &actor, EventKind(to), map[string]any{"comment": comment}); err != nil {
		return nil, err
	}
	if err := httpx.Record(r, tx, "cr.approved", "change_request", c.ID.String(), &v.ClusterID, map[string]any{"vault_id": v.ID}); err != nil {
		return nil, err
	}
	if err := notify.Emit(ctx, tx, notify.Event{Type: notify.CRApproved, Key: notify.CRApproved + ":" + c.ID.String(),
		Title: "Change request approved", Link: Link(c.ID), Fields: map[string]string{"Vault": v.Name}}); err != nil {
		return nil, err
	}
	items, err := a.unsealItems(ctx, tx, c.ID)
	if err != nil {
		zeroItems(items)
		return nil, err
	}
	plan, err := Plan(items)
	if err != nil {
		zeroItems(items)
		return nil, err
	}
	if to, err = Next(to, EvApplyStart); err != nil {
		zeroItems(items)
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, applying_at = now() WHERE id = $1`, c.ID, string(to)); err != nil {
		zeroItems(items)
		return nil, err
	}
	if err := addEvent(ctx, tx, c.ID, nil, EventKind(to), map[string]any{"writes": len(plan)}); err != nil {
		zeroItems(items)
		return nil, err
	}
	return &pendingApply{crID: c.ID, v: v, items: items, plan: plan}, nil
}

// apply calls Vault (cas) and runs transaction 2. A failure to record the
// outcome leaves the request in 'applying' for ReconcileApplying. It reports
// whether Vault was written.
func (a *API) apply(ctx context.Context, p *pendingApply) bool {
	defer zeroItems(p.items)
	ctx = context.WithoutCancel(ctx) // a closed browser tab must not abort a write half-way
	if a.Faults != nil && a.Faults.BeforeVault != nil {
		if err := a.Faults.BeforeVault(); err != nil {
			a.Log.Error("change request apply interrupted before the vault call", "cr_id", p.crID, "err", err)
			return false
		}
	}
	actx, cancel := context.WithTimeout(ctx, applyTimeout)
	applied, applyErr := a.Applier.Apply(actx, p.v.ID, p.plan)
	cancel()
	zeroItems(p.items)
	if a.Faults != nil && a.Faults.AfterVault != nil {
		if err := a.Faults.AfterVault(); err != nil {
			a.Log.Error("change request outcome not recorded; the reconciler will settle it", "cr_id", p.crID, "err", err)
			return len(applied) > 0
		}
	}
	code := ""
	if applyErr != nil {
		code = FailApplyError
	}
	fctx, fcancel := context.WithTimeout(ctx, 30*time.Second)
	defer fcancel()
	err := store.Tx(fctx, a.DB, func(tx pgx.Tx) error {
		return a.finishApply(fctx, tx, p.crID, p.v, applied, applyErr, code, len(p.plan), false)
	})
	if err != nil {
		a.Log.Error("change request outcome not recorded; the reconciler will settle it", "cr_id", p.crID, "err", err)
	}
	return len(applied) > 0
}

// finishApply is transaction 2 (and the reconciler's): it records the
// versions Olympos produced and moves 'applying' to 'applied' or 'failed'.
// A request no longer in 'applying' was settled already: nothing happens.
func (a *API) finishApply(ctx context.Context, tx pgx.Tx, crID uuid.UUID, v VaultInfo, applied []Applied, applyErr error,
	code string, planLen int, reconciled bool) error {
	c, err := lockCR(ctx, tx, crID)
	if err != nil {
		return err
	}
	if c.Status != StatusApplying {
		return nil
	}
	produced := []map[string]any{}
	for _, ap := range applied {
		if ap.Kind != WriteDestroy && ap.Version > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO vault_managed_versions (vault_id, mount, path, version, cr_id) VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT DO NOTHING`, v.ID, ap.Mount, ap.Path, ap.Version, crID); err != nil {
				return err
			}
		}
		produced = append(produced, map[string]any{"ref": ap.Mount + ap.Path, "kind": ap.Kind, "version": ap.Version})
	}
	if applyErr != nil {
		msg := SafeMessage(applyErr)
		if len(applied) > 0 {
			msg = fmt.Sprintf("%s (%d of %d writes were applied before the failure)", msg, len(applied), planLen)
		}
		a.Log.Warn("change request apply failed", "cr_id", crID, "vault_id", v.ID, "failure", msg, "code", code, "reconciled", reconciled)
		to, err := Next(StatusApplying, EvApplyErr)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, failure = $3, failure_code = $4 WHERE id = $1`,
			crID, string(to), msg, code); err != nil {
			return err
		}
		if err := scrub(ctx, tx, crID); err != nil {
			return err
		}
		details := map[string]any{"failure": msg, "code": code, "applied": produced}
		if reconciled {
			details["reconciled"] = true
		}
		if err := addEvent(ctx, tx, crID, nil, EventKind(to), details); err != nil {
			return err
		}
		if err := activity.Record(ctx, tx, activity.Entry{Action: "cr.failed", ObjectType: "change_request", ObjectID: crID.String(),
			ClusterID: &v.ClusterID, Details: map[string]any{"vault_id": v.ID, "failure": msg, "code": code, "applied": produced, "reconciled": reconciled}}); err != nil {
			return err
		}
		return notify.Emit(ctx, tx, notify.Event{Type: notify.CRFailed, Key: notify.CRFailed + ":" + crID.String(),
			Title: "Change request failed to apply", Link: Link(crID), Fields: map[string]string{"Vault": v.Name}})
	}
	to, err := Next(StatusApplying, EvApplyOK)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, applied_at = $3 WHERE id = $1`, crID, string(to), a.now()); err != nil {
		return err
	}
	if err := scrub(ctx, tx, crID); err != nil {
		return err
	}
	details := map[string]any{"applied": produced}
	action := "cr.applied"
	if reconciled {
		details["reconciled"] = true
		action = "cr.applied_reconciled"
	}
	if err := addEvent(ctx, tx, crID, nil, EventKind(to), details); err != nil {
		return err
	}
	if err := activity.Record(ctx, tx, activity.Entry{Action: action, ObjectType: "change_request", ObjectID: crID.String(),
		ClusterID: &v.ClusterID, Details: map[string]any{"vault_id": v.ID, "applied": produced}}); err != nil {
		return err
	}
	a.Log.Info("change request applied", "cr_id", crID, "vault_id", v.ID, "writes", planLen, "reconciled", reconciled)
	return nil
}

func (a *API) unsealItems(ctx context.Context, tx pgx.Tx, crID uuid.UUID) ([]Item, error) {
	rows, err := tx.Query(ctx, `SELECT id, mount, path, COALESCE(key, ''), op, base_version, versions, sealed_value, wrapped_dek, kek_version
		FROM change_items WHERE cr_id = $1 ORDER BY created_at, id`, crID)
	if err != nil {
		return nil, err
	}
	type row struct {
		id uuid.UUID
		it Item
		s  secrets.Sealed
	}
	var rs []row
	for rows.Next() {
		var x row
		var op string
		if err := rows.Scan(&x.id, &x.it.Mount, &x.it.Path, &x.it.Key, &op, &x.it.BaseVersion, &x.it.Versions,
			&x.s.Ciphertext, &x.s.WrappedDEK, &x.s.KEKVersion); err != nil {
			rows.Close()
			return nil, err
		}
		x.it.Op = Op(op)
		rs = append(rs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(rs))
	for _, x := range rs {
		if x.it.Op == OpCreate || x.it.Op == OpReplace {
			val, err := a.Envelope.Open(ctx, x.s, []byte("change_items:"+x.id.String()))
			if err != nil {
				zeroItems(items)
				return nil, fmt.Errorf("unseal change item %s: %w", x.id, err)
			}
			x.it.Value = val
		}
		items = append(items, x.it)
	}
	return items, nil
}

func (a *API) cancel(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	ctx := r.Context()
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		c, err := lockCR(ctx, tx, id)
		if errors.Is(err, errNotFound) {
			httpx.NotFound(w)
			return errHandled
		}
		if err != nil {
			return err
		}
		v, err := LoadVault(ctx, tx, c.VaultID)
		if errors.Is(err, store.ErrNotFound) || err == nil && !sub.Can(authz.PermRead, v.Labels) {
			httpx.NotFound(w)
			return errHandled
		}
		if err != nil {
			return err
		}
		maker, err := authz.GetPrincipal(ctx, tx, c.MakerID)
		if err != nil {
			return err
		}
		if err := CheckCancel(sub, maker, c.Status); err != nil {
			writeDeny(w, err)
			return errHandled
		}
		to, err := Next(c.Status, EvCancel)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, decided_at = $3 WHERE id = $1`, c.ID, string(to), a.now()); err != nil {
			return err
		}
		if err := scrub(ctx, tx, c.ID); err != nil {
			return err
		}
		actor := sub.Principal.ID
		if err := addEvent(ctx, tx, c.ID, &actor, EventKind(to), nil); err != nil {
			return err
		}
		return httpx.Record(r, tx, "cr.cancelled", "change_request", c.ID.String(), &v.ClusterID, map[string]any{"vault_id": v.ID})
	})
	if errors.Is(err, errHandled) {
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	cr, err := GetRequest(ctx, a.DB, sub, id, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, cr)
}

// ---------------------------------------------------------------- expiry

func (a *API) expireOne(ctx context.Context, tx pgx.Tx, c lockedCR, v VaultInfo) error {
	to, err := Next(c.Status, EvExpire)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status = $2, decided_at = $3 WHERE id = $1`, c.ID, string(to), a.now()); err != nil {
		return err
	}
	if err := scrub(ctx, tx, c.ID); err != nil {
		return err
	}
	if err := addEvent(ctx, tx, c.ID, nil, EventKind(to), nil); err != nil {
		return err
	}
	if err := activity.Record(ctx, tx, activity.Entry{Action: "cr.expired", ObjectType: "change_request", ObjectID: c.ID.String(),
		ClusterID: clusterRef(v), Details: map[string]any{"vault_id": v.ID}}); err != nil {
		return err
	}
	return notify.Emit(ctx, tx, notify.Event{Type: notify.CRExpired, Key: notify.CRExpired + ":" + c.ID.String(),
		Title: "Change request expired", Link: Link(c.ID), Fields: map[string]string{"Vault": v.Name}})
}

// ExpireDue moves pending requests past their TTL to expired (job, every
// minute on the leader). Returns how many expired.
func (a *API) ExpireDue(ctx context.Context) (int, error) {
	n := 0
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM change_requests WHERE status = 'pending' AND expires_at <= $1
			ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED`, a.now())
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			c, err := lockCR(ctx, tx, id)
			if err != nil {
				return err
			}
			v, err := LoadVault(ctx, tx, c.VaultID)
			if errors.Is(err, store.ErrNotFound) {
				// Cluster revoked: still expire, without vault details.
				v = VaultInfo{ID: c.VaultID}
			} else if err != nil {
				return err
			}
			if err := a.expireOne(ctx, tx, c, v); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if n > 0 {
		a.Log.Info("change requests expired", "count", n)
	}
	return n, err
}

func clusterRef(v VaultInfo) *uuid.UUID {
	if v.ClusterID == uuid.Nil {
		return nil
	}
	id := v.ClusterID
	return &id
}
