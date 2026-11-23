package restore

import (
	"archive/zip"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/activity"
	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/notify"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /api/v1/restores.
type API struct {
	DB       *store.DB
	Log      *slog.Logger
	Envelope *secrets.Envelope
	Creds    *backup.Credentials
	Dialer   backup.Dialer
	// Blobs reads the backup's manifest (the databases it holds).
	Blobs blob.ReaderResolver
	// TTL of a pending request (changeRequests.ttl; default
	// approvals.DefaultTTL).
	TTL time.Duration
	Now func() time.Time
	// InspectTimeout bounds the open-time check of the target (default 60 s).
	InspectTimeout time.Duration
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Get("/restores", a.list)
	r.Post("/restores", a.create)
	r.Post("/restores/check", a.check)
	r.Get("/restores/{id}", a.get)
	r.Post("/restores/{id}/approve", a.approve)
	r.Post("/restores/{id}/reject", a.reject)
	r.Post("/restores/{id}/cancel", a.cancel)
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
	return approvals.DefaultTTL
}

// Limits of the input.
const (
	maxCAPEM      = 64 << 10
	maxVaultToken = 8 << 10
	// The sidecar manifest is small; a ClickHouse manifest.json carries the
	// create statements of every table.
	maxSidecarManifest = 8 << 20
	maxArchiveManifest = 64 << 20
)

// errHandled marks an error already written to the response.
var errHandled = errors.New("handled")

// ---------------------------------------------------------------- reads

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	sub := httpx.Subject(r)
	q := r.URL.Query()
	yes := func(k string) bool { v := q.Get(k); return v == "1" || v == "true" }
	f := Filter{Status: q.Get("status"), WaitingForMe: yes("waiting_for_me"), Limit: httpx.IntQuery(r, "limit", 200)}
	if yes("mine") {
		id := sub.Principal.ID
		f.MakerID = &id
	}
	if v := q.Get("run_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.FieldErrors(w, "invalid filter", map[string]string{"run_id": "must be a UUID"})
			return
		}
		f.RunID = &id
	}
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
	rq, err := GetRequest(r.Context(), a.DB, httpx.Subject(r), id, a.now())
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, rq)
}

// ---------------------------------------------------------------- open-time checks

// sourceRun is the backup run a request restores.
type sourceRun struct {
	status, trigger string
	targetID        *string // nil: olympos-self
	engine          string
	clusterID       uuid.UUID
	labels          map[string]string
}

// targetInfo is the target a request restores into.
type targetInfo struct {
	clusterID     uuid.UUID
	labels        map[string]string
	clusterStatus string
	engine        string
	status        string
	vaultStatus   string
}

// evaluation is what the open-time checks found. It is filled as far as the
// checks got, so /restores/check can show it even when a check failed.
type evaluation struct {
	run      sourceRun
	target   targetInfo
	clusters Clusters
	// mayOpen: the caller passed CheckOpen; later failures are explained.
	mayOpen  bool
	src      *backup.RestoreSource
	inBackup []string
	// details: the backup's engine metadata (manifest details; PostgreSQL
	// only), for BackupChecker.
	details   map[string]any
	databases []string
	opts      Options
	report    *TargetReport
}

// evalError is a failed check: code 422 with fields, or 403/404/500.
type evalError struct {
	code   int
	msg    string
	fields map[string]string
	err    error // 500: logged, never shown
}

func invalid(msg string, fields map[string]string) *evalError {
	return &evalError{code: http.StatusUnprocessableEntity, msg: msg, fields: fields}
}

func (e *evalError) write(w http.ResponseWriter, r *http.Request, log *slog.Logger) {
	switch {
	case e.err != nil:
		httpx.Internal(w, r, log, e.err)
	case e.code == http.StatusUnprocessableEntity:
		httpx.FieldErrors(w, e.msg, e.fields)
	case e.code == http.StatusForbidden:
		httpx.Forbidden(w, e.msg)
	default:
		httpx.Error(w, e.code, e.msg)
	}
}

func internalErr(err error) *evalError {
	return &evalError{code: http.StatusInternalServerError, err: err}
}

// evaluate runs every rule of a request that can be checked before it is
// stored (docs/design/ui-restore.md "Rules checked when a request is
// opened"). Nothing is sent to the target unless the caller may open the
// request and every input check passed; the target is then inspected with
// the given credential, without writing anything, and the check is
// recorded (restore.checked). open: the request is being opened, so the
// justification is checked too (before the target is contacted). tr tracks
// the secrets handed to the inspector (the caller zeroes them).
func (a *API) evaluate(ctx context.Context, sub *authz.Subject, in *Input, open bool, tr *backup.SecretScrubber) (*evaluation, *evalError) {
	ev := &evaluation{}
	unknownRun := invalid("invalid restore request", map[string]string{"run_id": "unknown run"})
	var err error
	ev.run, err = loadSourceRun(ctx, a.DB, in.RunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ev, unknownRun
	}
	if err != nil {
		return ev, internalErr(err)
	}
	if ev.run.targetID == nil {
		if !sub.CanGlobal(authz.PermRead) {
			return ev, unknownRun
		}
		return ev, invalid("invalid restore request", map[string]string{"run_id": selfRunMessage})
	}
	if !sub.Can(authz.PermRead, ev.run.labels) {
		return ev, unknownRun
	}

	unknownTarget := invalid("invalid restore request", map[string]string{"target_id": "unknown target"})
	ev.target, err = loadTargetInfo(ctx, a.DB, in.TargetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ev, unknownTarget
	}
	if err != nil {
		return ev, internalErr(err)
	}
	if ev.target.clusterStatus == "revoked" || !sub.Can(authz.PermRead, ev.target.labels) {
		return ev, unknownTarget
	}
	ev.clusters = Clusters{Run: ev.run.labels, Target: ev.target.labels}
	if err := CheckOpen(sub, ev.clusters, in.BreakGlass); err != nil {
		return ev, &evalError{code: http.StatusForbidden, msg: err.Error()}
	}
	ev.mayOpen = true

	// From here on the caller may open the request: say what is wrong.
	engine := ev.run.engine
	fields := map[string]string{}
	src, err := sourceRules(ctx, a.DB, ev.run, in.RunID, in.CopyDestinationID, fields)
	if err != nil {
		return ev, internalErr(err)
	}
	ev.src = src
	targetRules(ev.run, ev.target, in.TargetID, fields)
	if engine == "vault" {
		if in.Credential != nil {
			fields["credential"] = "not used for a Vault restore; give a token of the new Vault"
		}
		switch {
		case in.VaultToken == "":
			fields["vault_token"] = "required"
		case len(in.VaultToken) > maxVaultToken:
			fields["vault_token"] = "too long"
		}
	} else {
		if in.VaultToken != "" {
			fields["vault_token"] = "only for a Vault restore"
		}
		if in.Credential == nil {
			fields["credential"] = "required: the target's admin login"
		} else {
			use, err := a.refUse(ctx, sub, ev.target.clusterID)
			if err != nil {
				return ev, internalErr(err)
			}
			for k, v := range in.Credential.Validate("credential.", use) {
				fields[k] = v
			}
		}
	}
	if in.Globals != nil && engine != "postgresql" {
		fields["globals"] = "only for PostgreSQL"
	}
	if pem := in.TLSCAPEM; pem != "" {
		if len(pem) > maxCAPEM {
			fields["tls_ca_pem"] = "too long"
		} else if !x509.NewCertPool().AppendCertsFromPEM([]byte(pem)) {
			fields["tls_ca_pem"] = "contains no PEM certificate"
		}
	}
	ev.opts = Options{TLSCAPEM: in.TLSCAPEM}

	// The databases the backup holds (read from the copy).
	if ev.src != nil && hasDatabases(engine) {
		dbs, details, err := a.backupDatabases(ctx, engine, ev.src)
		if err != nil {
			a.Log.Warn("restore: backup manifest not readable", "run_id", in.RunID, "destination_id", ev.src.DestinationID, "err", err.Error())
			fields["copy_destination_id"] = "the backup's manifest could not be read: " + err.Error()
		} else {
			ev.inBackup, ev.details = dbs, details
		}
	}
	if ev.src != nil && (ev.inBackup != nil || !hasDatabases(engine)) {
		dbs, msg := CheckDatabases(engine, in.Databases, ev.inBackup)
		if msg != "" {
			fields["databases"] = msg
		}
		ev.databases = dbs
	}
	if open {
		if msg := approvals.ValidateJustification(in.Justification); msg != "" {
			fields["justification"] = msg
		}
	}
	if len(fields) > 0 {
		return ev, invalid("invalid restore request", fields)
	}

	if _, ok := InspectorFor(engine); !ok {
		msg := noInspectorMessage(engine)
		return ev, invalid(msg, map[string]string{"target_id": msg})
	}
	if !a.Dialer.Connected(ev.target.clusterID) {
		msg := "agent_offline: the target cluster's agent is not connected to this server"
		return ev, invalid(msg, map[string]string{"target_id": msg})
	}
	cred := func(ctx context.Context) (backup.Credential, error) {
		if engine == "vault" {
			return tr.Track(backup.Credential{Secret: []byte(in.VaultToken)}), nil
		}
		c, err := a.Creds.FromInput(ctx, *in.Credential)
		return tr.Track(c), err
	}
	ec, _, err := backup.TargetEngineContext(ctx, a.DB, a.Dialer, in.TargetID, EngineOptions(engine, ev.opts), cred)
	if err != nil {
		return ev, internalErr(err)
	}
	rep, fields, notes, err := inspectTarget(ctx, engine, ec, ev.databases, a.InspectTimeout)
	if err != nil {
		msg := "the target check failed: " + tr.Scrub(err.Error())
		a.Log.Warn("restore: target check failed", "target_id", in.TargetID, "err", msg)
		if rerr := a.recordCheck(ctx, sub, in, ev, open, msg); rerr != nil {
			return ev, internalErr(rerr)
		}
		return ev, invalid(msg, map[string]string{"target_id": msg})
	}
	if msg := checkBackup(engine, ev.details, rep); msg != "" {
		if prev := fields["target_id"]; prev != "" {
			msg = prev + "; " + msg
		}
		fields["target_id"] = msg
	}
	ev.report = rep
	ev.opts.ServerVersion = rep.ServerVersion
	ev.opts.Notes = notes
	if engine == "postgresql" {
		su := rep.Superuser
		g := su && (in.Globals == nil || *in.Globals)
		ev.opts.Superuser, ev.opts.Globals = &su, &g
	}
	problem := ""
	if len(fields) > 0 {
		problem = "the target cannot take this restore"
	}
	if err := a.recordCheck(ctx, sub, in, ev, open, problem); err != nil {
		return ev, internalErr(err)
	}
	if problem != "" {
		return ev, invalid(problem, fields)
	}
	return ev, nil
}

// ---------------------------------------------------------------- rules core
//
// The rules of a request that both the open-time check (evaluate, with
// HTTP errors) and the start-time re-check (Executor) apply.

// selfRunMessage: olympos-self runs are not restored from the UI.
const selfRunMessage = "Olympos' own database is restored with the server stopped (docs/restore-olympos.md)"

func noInspectorMessage(engine string) string {
	return "restores of " + engineName(engine) + " are not available yet"
}

// loadSourceRun loads the run a request restores (pgx.ErrNoRows when it
// does not exist). targetID is nil for an olympos-self run.
func loadSourceRun(ctx context.Context, q store.Querier, runID uuid.UUID) (sourceRun, error) {
	var run sourceRun
	err := q.QueryRow(ctx, `SELECT r.status, r.trigger, j.target_id, COALESCE(t.engine, ''), COALESCE(t.cluster_id, '00000000-0000-0000-0000-000000000000'),
		COALESCE(c.labels, '{}')
		FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id LEFT JOIN targets t ON t.id = j.target_id LEFT JOIN clusters c ON c.id = t.cluster_id
		WHERE r.id = $1`, runID).Scan(&run.status, &run.trigger, &run.targetID, &run.engine, &run.clusterID, &run.labels)
	return run, err
}

// loadTargetInfo loads the target a request restores into (pgx.ErrNoRows
// when it does not exist).
func loadTargetInfo(ctx context.Context, q store.Querier, targetID string) (targetInfo, error) {
	var t targetInfo
	err := q.QueryRow(ctx, `SELECT t.cluster_id, c.labels, c.status, t.engine, t.status, COALESCE(v.status, '')
		FROM targets t JOIN clusters c ON c.id = t.cluster_id LEFT JOIN vaults v ON v.target_id = t.id WHERE t.id = $1`, targetID).
		Scan(&t.clusterID, &t.labels, &t.clusterStatus, &t.engine, &t.status, &t.vaultStatus)
	return t, err
}

// sourceRules: the run is succeeded or partial and not a test run, and the
// chosen copy is a succeeded copy of it or of one of its repairs (as the
// restore guide offers). Broken rules are added to fields; the copy is
// returned when it was found. err is an internal error only.
func sourceRules(ctx context.Context, q store.Querier, run sourceRun, runID uuid.UUID, destID *uuid.UUID, fields map[string]string) (*backup.RestoreSource, error) {
	switch {
	case run.trigger == "test":
		fields["run_id"] = "a dry run holds no data to restore"
	case run.status != "succeeded" && run.status != "partial":
		fields["run_id"] = "only a succeeded or partial run can be restored (this run is " + run.status + ")"
	default:
		src, err := backup.FindRestoreSource(ctx, q, runID, destID)
		switch {
		case errors.Is(err, backup.ErrNoSuccessfulCopy):
			fields["copy_destination_id"] = err.Error()
		case errors.Is(err, backup.ErrNotRestorable):
			fields["run_id"] = err.Error()
		case err != nil:
			return nil, err
		default:
			return src, nil
		}
	}
	return nil, nil
}

// targetRules: the target has the run's engine, is not the run's own
// target, is discovered (not gone) and, for Vault, is not a Vault
// configured in Olympos. Broken rules are added to fields.
func targetRules(run sourceRun, t targetInfo, targetID string, fields map[string]string) {
	switch {
	case run.targetID != nil && targetID == *run.targetID:
		fields["target_id"] = "a restore never writes to the backup's own target; choose a new target"
	case t.engine != run.engine:
		fields["target_id"] = fmt.Sprintf("the target is %s, the backup is %s", engineName(t.engine), engineName(run.engine))
	case t.status == "gone":
		fields["target_id"] = "the target is gone"
	case run.engine == "vault" && t.vaultStatus == "configured":
		fields["target_id"] = "this Vault is configured in Olympos; a snapshot is restored into a new Vault only"
	}
}

// errNoInspector: no inspector is registered for the engine.
var errNoInspector = errors.New("no restore inspector")

// inspectTarget runs the engine's inspector on the target (reads only,
// with the request's credential, bounded by timeout; default 60 s) and
// applies CheckReport. err is the inspector's error, unscrubbed: the caller
// scrubs it with the scrubber that tracked the credential.
func inspectTarget(ctx context.Context, engine string, ec backup.EngineContext, databases []string, timeout time.Duration) (*TargetReport, map[string]string, []string, error) {
	insp, ok := InspectorFor(engine)
	if !ok {
		return nil, nil, nil, errNoInspector
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ictx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rep, err := insp.InspectRestoreTarget(ictx, ec, databases)
	if err != nil {
		return nil, nil, nil, err
	}
	if rep.Existing == nil {
		rep.Existing = map[string]bool{}
	}
	fields, notes := CheckReport(engine, databases, rep)
	return rep, fields, notes, nil
}

// recordCheck writes restore.checked: the request's credential reached the
// target (it was tested), whatever the outcome. problem is the scrubbed
// reason the check failed ("" when it passed). The row is written even when
// the client went away meanwhile: the target was contacted all the same.
func (a *API) recordCheck(ctx context.Context, sub *authz.Subject, in *Input, ev *evaluation, open bool, problem string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	d := map[string]any{"run_id": in.RunID, "ok": problem == "", "opening": open}
	if problem != "" {
		d["error"] = problem
	}
	if ev.report != nil {
		d["server_version"] = ev.report.ServerVersion
	}
	actor := sub.Principal.ID
	return store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		return activity.Record(ctx, tx, activity.Entry{ActorID: &actor, Action: "restore.checked", ObjectType: "target",
			ObjectID: in.TargetID, ClusterID: &ev.run.clusterID, Details: d})
	})
}

func engineName(e string) string {
	switch e {
	case "postgresql":
		return "PostgreSQL"
	case "clickhouse":
		return "ClickHouse"
	case "vault":
		return "Vault/OpenBao"
	case "":
		return "an unknown engine"
	}
	return e
}

// refUse describes who enters a Key Vault reference for the target's
// cluster (as for job credentials).
func (a *API) refUse(ctx context.Context, sub *authz.Subject, clusterID uuid.UUID) (secrets.RefUse, error) {
	labels, err := httpx.ClusterLabels(ctx, a.DB, clusterID)
	if err != nil {
		return secrets.RefUse{}, err
	}
	return secrets.RefUse{GlobalAdmin: sub.CanGlobal(authz.PermAdmin), Labels: labels}, nil
}

// backupDatabases lists the databases in the copy: PostgreSQL from the
// sidecar manifest (details.databases, with the details returned too),
// ClickHouse from manifest.json in the archive. Errors are already scrubbed
// by the blob reader.
func (a *API) backupDatabases(ctx context.Context, engine string, src *backup.RestoreSource) ([]string, map[string]any, error) {
	rd, err := a.Blobs.ReaderFor(ctx, src.DestinationID)
	if err != nil {
		return nil, nil, err
	}
	switch engine {
	case "postgresql":
		o, err := rd.Open(ctx, backup.ManifestPath(src.BlobPath, src.CopyRunID))
		if err != nil {
			return nil, nil, err
		}
		defer o.Close()
		if o.Size() > maxSidecarManifest {
			return nil, nil, errors.New("the manifest is too large")
		}
		b, err := io.ReadAll(io.NewSectionReader(o, 0, o.Size()))
		if err != nil {
			return nil, nil, err
		}
		var m struct {
			Details struct {
				Databases []string `json:"databases"`
			} `json:"details"`
		}
		var all struct {
			Details map[string]any `json:"details"`
		}
		if json.Unmarshal(b, &m) != nil || json.Unmarshal(b, &all) != nil {
			return nil, nil, errors.New("the manifest is not valid JSON")
		}
		return nonNil(m.Details.Databases), all.Details, nil
	case "clickhouse":
		o, err := rd.Open(ctx, src.BlobPath)
		if err != nil {
			return nil, nil, err
		}
		defer o.Close()
		zr, err := zip.NewReader(o, o.Size())
		if err != nil {
			return nil, nil, fmt.Errorf("the backup is not a readable zip archive: %s", err.Error())
		}
		for _, f := range zr.File {
			if f.Name != "manifest.json" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, nil, err
			}
			defer rc.Close()
			// Read to the end so the zip reader checks the entry's CRC.
			b, err := io.ReadAll(io.LimitReader(rc, maxArchiveManifest+1))
			if err != nil {
				return nil, nil, fmt.Errorf("manifest.json: %s", err.Error())
			}
			if len(b) > maxArchiveManifest {
				return nil, nil, errors.New("manifest.json is too large")
			}
			var m struct {
				Databases []struct {
					Name string `json:"name"`
				} `json:"databases"`
			}
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, nil, errors.New("manifest.json is not valid JSON")
			}
			out := []string{}
			for _, d := range m.Databases {
				out = append(out, d.Name)
			}
			return out, nil, nil
		}
		return nil, nil, errors.New("the archive has no manifest.json")
	}
	return []string{}, nil, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---------------------------------------------------------------- check

// CheckResult answers POST /restores/check: the open-time checks for the
// restore dialog, without storing anything.
type CheckResult struct {
	OK     bool              `json:"ok"`
	Error  string            `json:"error,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
	Engine string            `json:"engine"`
	// Copy is the copy the restore would read.
	CopyDestinationID *uuid.UUID `json:"copy_destination_id"`
	CopyRunID         *uuid.UUID `json:"copy_run_id"`
	// DatabasesInBackup: what the copy holds (PostgreSQL, ClickHouse);
	// Databases: what would be restored.
	DatabasesInBackup []string      `json:"databases_in_backup"`
	Databases         []string      `json:"databases"`
	Options           Options       `json:"options"`
	Report            *TargetReport `json:"report"`
}

func (a *API) decodeInput(w http.ResponseWriter, r *http.Request) (*Input, bool) {
	var in Input
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return nil, false
	}
	in.TargetID = strings.TrimSpace(in.TargetID)
	// Inspected and sealed as given, without surrounding whitespace.
	in.VaultToken = strings.TrimSpace(in.VaultToken)
	return &in, true
}

func (a *API) check(w http.ResponseWriter, r *http.Request) {
	in, ok := a.decodeInput(w, r)
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	ctx := r.Context()
	tr := &backup.SecretScrubber{}
	defer tr.Zero()
	ev, eerr := a.evaluate(ctx, sub, in, false, tr)
	// Who may not open this request learns nothing more than an error.
	if eerr != nil && (eerr.code != http.StatusUnprocessableEntity || !ev.mayOpen) {
		eerr.write(w, r, a.Log)
		return
	}
	res := CheckResult{OK: eerr == nil, Engine: ev.run.engine, DatabasesInBackup: ev.inBackup, Databases: ev.databases,
		Options: ev.opts, Report: ev.report}
	if eerr != nil {
		res.Error, res.Fields = eerr.msg, eerr.fields
	}
	if ev.src != nil {
		res.CopyDestinationID, res.CopyRunID = &ev.src.DestinationID, &ev.src.CopyRunID
	}
	httpx.JSON(w, http.StatusOK, res)
}

// ---------------------------------------------------------------- open

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	in, ok := a.decodeInput(w, r)
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	ctx := r.Context()
	tr := &backup.SecretScrubber{}
	defer tr.Zero()
	ev, eerr := a.evaluate(ctx, sub, in, true, tr)
	if eerr != nil {
		eerr.write(w, r, a.Log)
		return
	}

	id := uuid.New()
	var sealed secrets.Sealed
	if ev.run.engine == "vault" {
		tok := []byte(in.VaultToken)
		s, err := a.Envelope.Seal(ctx, tok, TokenAAD(id))
		secrets.Zero(tok)
		if err != nil {
			httpx.Internal(w, r, a.Log, fmt.Errorf("seal restore token: %w", err))
			return
		}
		sealed = s
	}
	opts, err := json.Marshal(ev.opts)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	now := a.now()
	actor := sub.Principal.ID
	status := StatusPending
	var decidedAt, approvedExpires *time.Time
	if in.BreakGlass {
		status = StatusApproved
		ae := now.Add(ApprovedTTL)
		decidedAt, approvedExpires = &now, &ae
	}
	busy := false
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		var credID *uuid.UUID
		if in.Credential != nil {
			cid, err := a.Creds.Insert(ctx, tx, *in.Credential)
			if err != nil {
				return fmt.Errorf("store restore credential: %w", err)
			}
			credID = &cid
		}
		var tok, dek []byte
		if len(sealed.Ciphertext) > 0 {
			tok, dek = sealed.Ciphertext, sealed.WrappedDEK
		}
		_, err := tx.Exec(ctx, `INSERT INTO restore_requests (id, source_run_id, source_destination_id, source_copy_run_id, engine, target_id,
			databases, options, credential_id, sealed_token, wrapped_dek, kek_version, maker_principal_id, justification, break_glass,
			status, expires_at, decided_at, approved_expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
			id, in.RunID, ev.src.DestinationID, ev.src.CopyRunID, ev.run.engine, in.TargetID, ev.databases, opts, credID,
			tok, dek, sealed.KEKVersion, actor, strings.TrimSpace(in.Justification), in.BreakGlass,
			string(status), now.Add(a.ttl()), decidedAt, approvedExpires, now)
		if isTargetBusy(err) {
			busy = true
			return errHandled
		}
		if err != nil {
			return err
		}
		details := map[string]any{"run_id": in.RunID, "copy_run_id": ev.src.CopyRunID, "destination_id": ev.src.DestinationID,
			"source_cluster_id": ev.run.clusterID, "target_id": in.TargetID, "engine": ev.run.engine, "databases": ev.databases,
			"break_glass": in.BreakGlass}
		// Every audit row and event of a restore is on the backup's cluster:
		// they name its run and databases, which a reader of the target's
		// cluster only must not see.
		if err := httpx.Record(r, tx, "restore.requested", "restore_request", id.String(), &ev.run.clusterID, details); err != nil {
			return err
		}
		rq, err := loadRequest(ctx, tx, id)
		if err != nil {
			return err
		}
		fields := summary(rq)
		fields["Maker"] = displayName(sub.Principal)
		payload := eventPayload(rq)
		if !in.BreakGlass {
			return notify.Emit(ctx, tx, notify.Event{Type: notify.RestoreRequested, Key: notify.RestoreRequested + ":" + id.String(),
				Title: "Restore request waiting for approval", Link: Link(id), Fields: fields, Payload: payload})
		}
		// Break-glass: the maker is the decider, recorded here and in the
		// event; checker_principal_id stays NULL.
		just := strings.TrimSpace(in.Justification)
		if err := httpx.Record(r, tx, "restore.break_glass", "restore_request", id.String(), &ev.run.clusterID,
			map[string]any{"run_id": in.RunID, "target_id": in.TargetID, "decided_by": actor, "justification": just}); err != nil {
			return err
		}
		fields["Justification"] = just
		payload["decided_by"] = actor
		payload["justification"] = just
		return notify.Emit(ctx, tx, notify.Event{Type: notify.RestoreBreakGlass, Key: notify.RestoreBreakGlass + ":" + id.String(),
			Title: "Break-glass restore started without approval", Link: Link(id), Fields: fields, Payload: payload})
	})
	if busy {
		httpx.Error(w, http.StatusConflict, ReasonTargetBusy)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.Log.Info("restore request opened", "restore_id", id, "run_id", in.RunID, "target_id", in.TargetID, "break_glass", in.BreakGlass)
	rq, err := GetRequest(ctx, a.DB, sub, id, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, rq)
}

// TokenAAD binds a sealed Vault token to its request.
func TokenAAD(id uuid.UUID) []byte { return []byte("restore_requests:" + id.String()) }

// ReasonTargetBusy: the one-at-a-time rule per target.
const ReasonTargetBusy = "another restore into this target is approved or running; try again when it has ended"

func isTargetBusy(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "restore_requests_target_active"
}

func displayName(p authz.Principal) string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.UPN
}

// ---------------------------------------------------------------- decide

type decisionInput struct {
	Comment string `json:"comment"`
}

func decodeDecision(w http.ResponseWriter, r *http.Request) (decisionInput, bool) {
	var in decisionInput
	if r.ContentLength != 0 {
		if err := httpx.Decode(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
			return in, false
		}
	}
	in.Comment = strings.TrimSpace(in.Comment)
	if len(in.Comment) > approvals.MaxJustification {
		httpx.FieldErrors(w, "invalid comment", map[string]string{"comment": "too long"})
		return in, false
	}
	return in, true
}

// writeDeny maps rule errors to HTTP (403 role, 409 state).
func writeDeny(w http.ResponseWriter, err error) bool {
	var de *approvals.DenyError
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

func (a *API) approve(w http.ResponseWriter, r *http.Request) { a.decide(w, r, true) }
func (a *API) reject(w http.ResponseWriter, r *http.Request)  { a.decide(w, r, false) }

func (a *API) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	in, ok := decodeDecision(w, r)
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	ctx := r.Context()
	expired, busy := false, false
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		l, err := lockRequest(ctx, tx, id)
		if errors.Is(err, errNotFound) || err == nil && !visible(sub, l.Clusters) {
			httpx.NotFound(w)
			return errHandled
		}
		if err != nil {
			return err
		}
		maker, err := authz.GetPrincipal(ctx, tx, l.MakerID)
		if err != nil {
			return err
		}
		now := a.now()
		if l.Status == StatusPending && Due(l.Status, l.ExpiresAt, l.ApprovedExpiresAt, now) {
			// Expire it now (and commit) rather than leave it to the job.
			if err := a.expireTx(ctx, tx, l); err != nil {
				return err
			}
			expired = true
			return nil
		}
		if err := CheckDecide(sub, maker, l.Clusters, l.Status, l.ExpiresAt, now); err != nil {
			writeDeny(w, err)
			return errHandled
		}
		if !approve && in.Comment == "" {
			httpx.FieldErrors(w, "a comment is required to reject", map[string]string{"comment": "required"})
			return errHandled
		}
		actor := sub.Principal.ID
		rq, err := loadRequest(ctx, tx, id)
		if err != nil {
			return err
		}
		fields := summary(rq)
		fields["Checker"] = displayName(sub.Principal)
		payload := eventPayload(rq)
		if !approve {
			if _, err := tx.Exec(ctx, `UPDATE restore_requests SET status = 'rejected', checker_principal_id = $2, decided_at = $3,
				decision_comment = $4, finished_at = $3 WHERE id = $1`, id, actor, now, in.Comment); err != nil {
				return err
			}
			if err := Wipe(ctx, tx, id); err != nil {
				return err
			}
			if err := httpx.Record(r, tx, "restore.rejected", "restore_request", id.String(), &l.SourceClusterID,
				map[string]any{"comment": in.Comment, "target_id": l.TargetID}); err != nil {
				return err
			}
			return notify.Emit(ctx, tx, notify.Event{Type: notify.RestoreRejected, Key: notify.RestoreRejected + ":" + id.String(),
				Title: "Restore request rejected", Link: Link(id), Fields: fields, Payload: payload})
		}
		_, err = tx.Exec(ctx, `UPDATE restore_requests SET status = 'approved', checker_principal_id = $2, decided_at = $3,
			decision_comment = $4, approved_expires_at = $5 WHERE id = $1`, id, actor, now, in.Comment, now.Add(ApprovedTTL))
		if isTargetBusy(err) {
			busy = true
			return errHandled
		}
		if err != nil {
			return err
		}
		if err := httpx.Record(r, tx, "restore.approved", "restore_request", id.String(), &l.SourceClusterID,
			map[string]any{"comment": in.Comment, "target_id": l.TargetID}); err != nil {
			return err
		}
		return notify.Emit(ctx, tx, notify.Event{Type: notify.RestoreApproved, Key: notify.RestoreApproved + ":" + id.String(),
			Title: "Restore request approved", Link: Link(id), Fields: fields, Payload: payload})
	})
	if busy {
		httpx.Error(w, http.StatusConflict, ReasonTargetBusy)
		return
	}
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
	a.Log.Info("restore request decided", "restore_id", id, "approved", approve)
	a.writeRequest(w, r, id, http.StatusOK)
}

func (a *API) writeRequest(w http.ResponseWriter, r *http.Request, id uuid.UUID, code int) {
	rq, err := GetRequest(r.Context(), a.DB, httpx.Subject(r), id, a.now())
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, code, rq)
}

func (a *API) cancel(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	ctx := r.Context()
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		l, err := lockRequest(ctx, tx, id)
		if errors.Is(err, errNotFound) || err == nil && !visible(sub, l.Clusters) {
			httpx.NotFound(w)
			return errHandled
		}
		if err != nil {
			return err
		}
		maker, err := authz.GetPrincipal(ctx, tx, l.MakerID)
		if err != nil {
			return err
		}
		if err := CheckCancel(sub, maker, l.Status); err != nil {
			writeDeny(w, err)
			return errHandled
		}
		now := a.now()
		if _, err := tx.Exec(ctx, `UPDATE restore_requests SET status = 'cancelled', decided_at = COALESCE(decided_at, $2), finished_at = $2
			WHERE id = $1`, id, now); err != nil {
			return err
		}
		if err := Wipe(ctx, tx, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "restore.cancelled", "restore_request", id.String(), &l.SourceClusterID,
			map[string]any{"target_id": l.TargetID, "was": string(l.Status)})
	})
	if errors.Is(err, errHandled) {
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.writeRequest(w, r, id, http.StatusOK)
}

// ---------------------------------------------------------------- expiry

// expireTx moves a locked pending or approved request to expired and wipes
// its secrets.
func (a *API) expireTx(ctx context.Context, tx pgx.Tx, l lockedRequest) error {
	if _, err := tx.Exec(ctx, `UPDATE restore_requests SET status = 'expired', finished_at = $2 WHERE id = $1`, l.ID, a.now()); err != nil {
		return err
	}
	if err := Wipe(ctx, tx, l.ID); err != nil {
		return err
	}
	reason := "not decided within the request lifetime"
	if l.Status == StatusApproved {
		reason = "approved but not started within 24 hours"
	}
	return activity.Record(ctx, tx, activity.Entry{Action: "restore.expired", ObjectType: "restore_request", ObjectID: l.ID.String(),
		ClusterID: &l.SourceClusterID, Details: map[string]any{"target_id": l.TargetID, "was": string(l.Status), "reason": reason}})
}

// ExpireDue expires pending requests past their TTL and approved requests
// that did not start within ApprovedTTL. It returns how many expired.
func (a *API) ExpireDue(ctx context.Context) (int, error) {
	n := 0
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM restore_requests
			WHERE status = 'pending' AND expires_at <= $1 OR status = 'approved' AND approved_expires_at <= $1
			ORDER BY created_at LIMIT 200 FOR UPDATE SKIP LOCKED`, a.now())
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
			l, err := lockRequest(ctx, tx, id)
			if err != nil {
				return err
			}
			if !Due(l.Status, l.ExpiresAt, l.ApprovedExpiresAt, a.now()) {
				continue
			}
			if err := a.expireTx(ctx, tx, l); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if n > 0 {
		a.Log.Info("restore requests expired", "count", n)
	}
	return n, err
}

// RunExpiry runs ExpireDue every minute on the leader.
func (a *API) RunExpiry(ctx context.Context) {
	schedule.RunLeader(ctx, a.DB, schedule.LockRestores, time.Minute, a.Log, func(ctx context.Context) error {
		_, err := a.ExpireDue(ctx)
		return err
	})
}
