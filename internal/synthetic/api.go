package synthetic

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /api/v1/synthetic: scenarios, their results and alerts, test
// runs, and the settings (host allowlist, credentials).
//
// Who sees what:
//   - a cluster is seen by whoever may read it (PermRead on its labels),
//     and a revoked cluster by nobody here;
//   - a scenario is seen by a reader with scope all, and by anyone who may
//     read a cluster it runs on now (its targets, excluded ones left out);
//     results and alerts are shown for the clusters the caller sees;
//   - a run is seen by whoever may read its cluster;
//   - the allowlist and the credentials (never their secrets) are seen by
//     editors (who pick from them) and by readers with scope all.
//
// Who changes what: scenarios need PermSyntheticEdit, with scope all for a
// scenario that runs on all clusters and on every cluster its selector
// matches otherwise (decision 4); the allowlist and the credentials need
// PermAdmin with scope all.
type API struct {
	Svc *Service
	Log *slog.Logger
	// TestRunsPerMinute caps the test runs one user starts per minute on
	// this replica (default 6): TestRun has no rate guard of its own.
	TestRunsPerMinute int
	// RunNowPerMinute caps the Run now requests one user makes per minute
	// on this replica (default 6), whatever the number of clusters each
	// runs on.
	RunNowPerMinute int

	testRuns, manualRuns rateWindow
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Route("/synthetic", func(r chi.Router) {
		r.Get("/overview", a.overview)
		r.Get("/scenarios", a.listScenarios)
		r.Post("/scenarios", a.createScenario)
		r.Post("/scenarios/preview", a.preview)
		r.Get("/scenarios/{id}", a.getScenario)
		r.Put("/scenarios/{id}", a.updateScenario)
		r.Patch("/scenarios/{id}", a.patchScenario)
		r.Delete("/scenarios/{id}", a.deleteScenario)
		r.Post("/scenarios/{id}/run", a.runScenario)
		r.Get("/scenarios/{id}/clusters", a.scenarioClusters)
		r.Get("/scenarios/{id}/alerts", a.scenarioAlerts)
		r.Post("/test-runs", a.testRun)
		r.Get("/runs", a.listRuns)
		r.Get("/runs/{id}", a.getRun)
		r.Get("/allowlist", a.listAllowlist)
		r.Post("/allowlist", a.addRule)
		r.Post("/allowlist/check", a.checkHost)
		r.Delete("/allowlist/{id}", a.removeRule)
		r.Get("/credentials", a.listCredentials)
		r.Post("/credentials", a.createCredential)
		r.Put("/credentials/{id}", a.updateCredential)
		r.Delete("/credentials/{id}", a.deleteCredential)
	})
}

func (a *API) db() *store.DB { return a.Svc.DB }

func (a *API) now() time.Time { return a.Svc.now() }

// ---------------------------------------------------------------- errors

// apiError is a refusal: 422 with fields, or another code with a message.
// extra is merged into the body of a 409 (the scenarios that use a rule).
type apiError struct {
	code   int
	msg    string
	fields map[string]string
	extra  map[string]any
}

func (e *apiError) Error() string { return e.msg }

func invalid(msg string, fields map[string]string) *apiError {
	return &apiError{code: http.StatusUnprocessableEntity, msg: msg, fields: fields}
}

func refused(code int, msg string) *apiError { return &apiError{code: code, msg: msg} }

// fail writes err: an *apiError as itself, store.ErrNotFound as 404, and
// anything else as a logged 500.
func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		switch {
		case ae.code == http.StatusUnprocessableEntity:
			httpx.FieldErrors(w, ae.msg, ae.fields)
		case ae.code == http.StatusForbidden:
			httpx.Forbidden(w, ae.msg)
		case len(ae.extra) > 0:
			body := map[string]any{"error": ae.msg}
			for k, v := range ae.extra {
				body[k] = v
			}
			httpx.JSON(w, ae.code, body)
		default:
			httpx.Error(w, ae.code, ae.msg)
		}
	case errors.Is(err, store.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		httpx.NotFound(w)
	default:
		httpx.Internal(w, r, a.Log, err)
	}
}

// txRetry runs fn in a transaction, again (up to three times in all) when
// Postgres picked it as a deadlock victim: the ingestion of a result locks
// its run and then its scenario, the API the scenario first.
func txRetry(ctx context.Context, db *store.DB, fn func(tx pgx.Tx) error) error {
	var err error
	for range 3 {
		err = store.Tx(ctx, db, fn)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40P01" {
			return err
		}
	}
	return err
}

func isFKViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503"
}

// ---------------------------------------------------------------- clusters

// apiCluster is a cluster as this API shows it.
type apiCluster struct {
	ID              uuid.UUID
	Name            string
	Labels          map[string]string
	ProbeStatus     string
	ProbeVersion    string
	ProbeLastSeenAt *time.Time
}

func (c apiCluster) info() ClusterInfo {
	return ClusterInfo{ID: c.ID, Name: c.Name, Labels: c.Labels, ProbeStatus: c.ProbeStatus}
}

// fleet is every cluster that is not revoked, by name, and which of them
// the caller may read.
type fleet struct {
	all      []apiCluster
	byID     map[uuid.UUID]apiCluster
	readable map[uuid.UUID]bool
}

func loadFleet(ctx context.Context, q store.Querier, sub *authz.Subject) (*fleet, error) {
	rows, err := q.Query(ctx, `SELECT id, name, labels, probe_status, probe_version, probe_last_seen_at
		FROM clusters WHERE status <> 'revoked' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	cs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (apiCluster, error) {
		var c apiCluster
		err := r.Scan(&c.ID, &c.Name, &c.Labels, &c.ProbeStatus, &c.ProbeVersion, &c.ProbeLastSeenAt)
		if c.Labels == nil {
			c.Labels = map[string]string{}
		}
		return c, err
	})
	if err != nil {
		return nil, err
	}
	f := &fleet{all: cs, byID: make(map[uuid.UUID]apiCluster, len(cs)), readable: map[uuid.UUID]bool{}}
	for _, c := range cs {
		f.byID[c.ID] = c
		if sub.Can(authz.PermRead, c.Labels) {
			f.readable[c.ID] = true
		}
	}
	return f, nil
}

func (f *fleet) infos() []ClusterInfo {
	out := make([]ClusterInfo, len(f.all))
	for i, c := range f.all {
		out[i] = c.info()
	}
	return out
}

// visible returns the clusters the caller may read, by name.
func (f *fleet) visible() []apiCluster {
	var out []apiCluster
	for _, c := range f.all {
		if f.readable[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

func (f *fleet) readableIDs() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(f.readable))
	for _, c := range f.all {
		if f.readable[c.ID] {
			out = append(out, c.ID)
		}
	}
	return out
}

// targets resolves t over the fleet: each cluster with the scenario's
// state on it.
func (f *fleet) targets(t Targeting) []TargetCluster { return Resolve(t, f.infos()) }

// ---------------------------------------------------------------- scope

// canSee reports whether sub sees a scenario with targeting t: with read on
// all clusters, or on one of the clusters it runs on now.
func canSee(sub *authz.Subject, t Targeting, f *fleet) bool {
	if sub.CanGlobal(authz.PermRead) {
		return true
	}
	for _, tc := range f.targets(t) {
		if tc.State != TargetExcluded && f.readable[tc.ID] {
			return true
		}
	}
	return false
}

// editRefusal says why sub may not have a scenario with targeting t, or
// "" when it may (decision 4): run_on all needs PermSyntheticEdit with
// scope all; a selector needs it on every cluster the scenario runs on now,
// and at least one. owner_selector plays no part: it is a label.
func editRefusal(sub *authz.Subject, t Targeting, f *fleet) string {
	if sub.CanGlobal(authz.PermSyntheticEdit) {
		return ""
	}
	if !sub.CanAny(authz.PermSyntheticEdit) {
		return "your role does not allow this action"
	}
	if t.RunOn != RunOnSelector {
		return "A scenario that runs on all clusters needs the synthetic-editor role with scope all. Choose clusters matching labels in your scope."
	}
	n, outside := 0, 0
	for _, tc := range f.targets(t) {
		if tc.State == TargetExcluded {
			continue
		}
		n++
		if !sub.Can(authz.PermSyntheticEdit, tc.Labels) {
			outside++
		}
	}
	switch {
	case n == 0:
		return "The selector matches no cluster now. A scenario on a selector must run on at least one cluster in your scope."
	case outside > 0:
		return plural(outside, "The scenario would run on 1 cluster outside your synthetic-editor scope.",
			"The scenario would run on "+strconv.Itoa(outside)+" clusters outside your synthetic-editor scope.") +
			" Narrow the selector or exclude those clusters."
	}
	return ""
}

// ---------------------------------------------------------------- rate of test runs and Run now

// rateWindow counts events per key over the last minute.
type rateWindow struct {
	mu   sync.Mutex
	hits map[uuid.UUID][]time.Time
}

// allow records an event of key at now when fewer than n happened in the
// minute before, and reports whether it did. undo takes the recorded event
// back.
func (w *rateWindow) allow(key uuid.UUID, now time.Time, n int) (time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hits == nil {
		w.hits = map[uuid.UUID][]time.Time{}
	}
	keep := w.hits[key][:0]
	for _, t := range w.hits[key] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= n {
		w.hits[key] = keep
		return time.Time{}, false
	}
	w.hits[key] = append(keep, now)
	// Forget keys with nothing in the window, so the map stays small.
	for k, ts := range w.hits {
		if k != key && (len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= time.Minute) {
			delete(w.hits, k)
		}
	}
	return now, true
}

// undo removes one event of key recorded at t.
func (w *rateWindow) undo(key uuid.UUID, t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ts := w.hits[key]
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(t) {
			w.hits[key] = append(ts[:i], ts[i+1:]...)
			return
		}
	}
}

func (a *API) testRunsPerMinute() int {
	if a.TestRunsPerMinute > 0 {
		return a.TestRunsPerMinute
	}
	return 6
}

func (a *API) runNowPerMinute() int {
	if a.RunNowPerMinute > 0 {
		return a.RunNowPerMinute
	}
	return 6
}

// ---------------------------------------------------------------- small helpers

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
