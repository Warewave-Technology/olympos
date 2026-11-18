package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/findings"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /audit/* and /findings.
type API struct {
	DB  *store.DB
	Log *slog.Logger
	Now func() time.Time
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(httpx.RequireAny(authz.PermRead))
		r.Get("/audit/schedules", a.listSchedules)
		r.Post("/audit/schedules", a.createSchedule)
		r.Patch("/audit/schedules/{id}", a.patchSchedule)
		r.Delete("/audit/schedules/{id}", a.deleteSchedule)
		r.Post("/audit/schedules/{id}/run", a.runSchedule)
		r.Get("/audit/clusters", a.listClusterSummaries)
		r.Get("/audit/runs", a.listRuns)
		r.Get("/audit/runs/{id}", a.getRun)
		r.Get("/findings", a.listFindings)
	})
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// ---------------------------------------------------------------- schedules

// Schedule is the API shape of an audit schedule.
type Schedule struct {
	ID              uuid.UUID  `json:"id"`
	Tool            string     `json:"tool"`
	Frameworks      []string   `json:"frameworks"`
	ScopeSelector   string     `json:"scope_selector"`
	Cron            string     `json:"cron"`
	Timezone        string     `json:"timezone"`
	Enabled         bool       `json:"enabled"`
	NotifyChannelID *uuid.UUID `json:"notify_channel_id"`
	NextRunAt       *time.Time `json:"next_run_at"`
	Clusters        int        `json:"clusters"`
	LastRun         *Run       `json:"last_run"`
	CreatedAt       time.Time  `json:"created_at"`
}

type scheduleInput struct {
	Tool            *string         `json:"tool"`
	Frameworks      *[]string       `json:"frameworks"`
	ScopeSelector   *string         `json:"scope_selector"`
	Cron            *string         `json:"cron"`
	Timezone        *string         `json:"timezone"`
	Enabled         *bool           `json:"enabled"`
	NotifyChannelID json.RawMessage `json:"notify_channel_id"`
}

func loadSchedule(ctx context.Context, q store.Querier, id uuid.UUID) (Schedule, error) {
	var s Schedule
	err := q.QueryRow(ctx, `SELECT id, tool, frameworks, scope_selector, cron, timezone, enabled, notify_channel_id, created_at
		FROM audit_schedules WHERE id = $1`, id).Scan(&s.ID, &s.Tool, &s.Frameworks, &s.ScopeSelector, &s.Cron, &s.Timezone,
		&s.Enabled, &s.NotifyChannelID, &s.CreatedAt)
	return s, store.NotFound(err)
}

// decorate fills next_run_at, clusters and last_run (within the caller's scope).
func (a *API) decorate(ctx context.Context, sub *authz.Subject, s *Schedule, visible []uuid.UUID) error {
	if s.Frameworks == nil {
		s.Frameworks = []string{}
	}
	if spec, err := schedule.Parse(s.Cron, s.Timezone); err == nil && s.Enabled {
		t := spec.Next(a.now())
		s.NextRunAt = &t
	}
	ids, err := MatchingClusters(ctx, a.DB, s.ScopeSelector, s.Tool)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if slices.Contains(visible, id) {
			s.Clusters++
		}
	}
	rows, err := a.DB.Query(ctx, runSelect+` WHERE r.schedule_id = $1 AND r.cluster_id = ANY($2) ORDER BY r.created_at DESC LIMIT 1`, s.ID, visible)
	if err != nil {
		return err
	}
	runs, err := scanRuns(rows)
	if err != nil {
		return err
	}
	if len(runs) > 0 {
		s.LastRun = &runs[0]
	}
	return nil
}

func (a *API) listSchedules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub := httpx.Subject(r)
	visible, err := httpx.ScopedClusters(ctx, a.DB, sub, authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, `SELECT id FROM audit_schedules ORDER BY tool, created_at`)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	items := []Schedule{}
	for _, id := range ids {
		s, err := loadSchedule(ctx, a.DB, id)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if err := a.decorate(ctx, sub, &s, visible); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		items = append(items, s)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// apply validates in onto s; returns field errors.
func (a *API) apply(ctx context.Context, s *Schedule, in scheduleInput, create bool) (map[string]string, error) {
	fe := map[string]string{}
	if in.Tool != nil {
		if !create && *in.Tool != s.Tool {
			fe["tool"] = "the tool of a schedule cannot be changed; create a new schedule"
		} else {
			s.Tool = *in.Tool
		}
	}
	switch s.Tool {
	case ToolKubescape, ToolPolaris, ToolKubeBench:
	default:
		fe["tool"] = "must be kubescape, polaris or kube-bench"
	}
	if in.Frameworks != nil {
		s.Frameworks = *in.Frameworks
	}
	if s.Tool == ToolKubescape {
		if len(s.Frameworks) == 0 {
			s.Frameworks = slices.Clone(Frameworks)
		}
		var norm []string
		for _, f := range s.Frameworks {
			f = strings.ToLower(strings.TrimSpace(f))
			if !slices.Contains(Frameworks, f) {
				fe["frameworks"] = "allowed: nsa, cis, mitre"
				break
			}
			if !slices.Contains(norm, f) {
				norm = append(norm, f)
			}
		}
		s.Frameworks = norm
	} else if len(s.Frameworks) > 0 {
		fe["frameworks"] = "frameworks apply to kubescape only"
	}
	if s.Frameworks == nil {
		s.Frameworks = []string{}
	}
	if in.ScopeSelector != nil {
		s.ScopeSelector = *in.ScopeSelector
	}
	if sc, err := authz.ParseScope(s.ScopeSelector); err != nil {
		fe["scope_selector"] = err.Error()
	} else {
		s.ScopeSelector = sc.String()
	}
	if in.Cron != nil {
		s.Cron = strings.TrimSpace(*in.Cron)
	}
	if in.Timezone != nil {
		s.Timezone = *in.Timezone
	}
	if s.Timezone == "" {
		s.Timezone = "UTC"
	}
	if s.Cron == "" {
		fe["cron"] = "required"
	} else if _, err := schedule.Parse(s.Cron, s.Timezone); err != nil {
		if strings.Contains(err.Error(), "time zone") {
			fe["timezone"] = err.Error()
		} else {
			fe["cron"] = err.Error()
		}
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if len(in.NotifyChannelID) > 0 {
		var v *string
		if err := json.Unmarshal(in.NotifyChannelID, &v); err != nil {
			fe["notify_channel_id"] = "must be a channel id or null"
		} else if v == nil || *v == "" {
			s.NotifyChannelID = nil
		} else if id, err := uuid.Parse(*v); err != nil {
			fe["notify_channel_id"] = "must be a channel id or null"
		} else {
			var ok bool
			if err := a.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_channels WHERE id = $1)`, id).Scan(&ok); err != nil {
				return nil, err
			}
			if !ok {
				fe["notify_channel_id"] = "unknown notification channel"
			}
			s.NotifyChannelID = &id
		}
	}
	return fe, nil
}

func (a *API) createSchedule(w http.ResponseWriter, r *http.Request) {
	sub := httpx.Subject(r)
	if !sub.CanGlobal(authz.PermOperate) {
		httpx.Forbidden(w, "audit schedules need the operator role with scope all")
		return
	}
	var in scheduleInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s := Schedule{ScopeSelector: "all", Enabled: true}
	if in.Tool == nil {
		httpx.FieldErrors(w, "invalid schedule", map[string]string{"tool": "required"})
		return
	}
	fe, err := a.apply(r.Context(), &s, in, true)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if len(fe) > 0 {
		httpx.FieldErrors(w, "invalid schedule", fe)
		return
	}
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `INSERT INTO audit_schedules (tool, frameworks, scope_selector, cron, timezone, enabled, notify_channel_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`, s.Tool, s.Frameworks, s.ScopeSelector, s.Cron, s.Timezone,
			s.Enabled, s.NotifyChannelID).Scan(&s.ID, &s.CreatedAt); err != nil {
			return err
		}
		return httpx.Record(r, tx, "audit.schedule_created", "audit_schedule", s.ID.String(), nil, scheduleDetails(s))
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.respondSchedule(w, r, s, http.StatusCreated)
}

func scheduleDetails(s Schedule) map[string]any {
	return map[string]any{"tool": s.Tool, "frameworks": s.Frameworks, "scope_selector": s.ScopeSelector, "cron": s.Cron,
		"timezone": s.Timezone, "enabled": s.Enabled}
}

func (a *API) respondSchedule(w http.ResponseWriter, r *http.Request, s Schedule, code int) {
	sub := httpx.Subject(r)
	visible, err := httpx.ScopedClusters(r.Context(), a.DB, sub, authz.PermRead)
	if err == nil {
		err = a.decorate(r.Context(), sub, &s, visible)
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, code, s)
}

func (a *API) patchSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	if !httpx.Subject(r).CanGlobal(authz.PermOperate) {
		httpx.Forbidden(w, "audit schedules need the operator role with scope all")
		return
	}
	var in scheduleInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s, err := loadSchedule(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	fe, err := a.apply(r.Context(), &s, in, false)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if len(fe) > 0 {
		httpx.FieldErrors(w, "invalid schedule", fe)
		return
	}
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		// Changing the cron restarts the schedule from now (no catch-up).
		if _, err := tx.Exec(r.Context(), `UPDATE audit_schedules SET frameworks = $2, scope_selector = $3, timezone = $5, enabled = $6,
			notify_channel_id = $7,
			last_scheduled_for = CASE WHEN cron <> $4 OR timezone <> $5 OR (NOT enabled AND $6) THEN now() ELSE last_scheduled_for END,
			cron = $4 WHERE id = $1`,
			id, s.Frameworks, s.ScopeSelector, s.Cron, s.Timezone, s.Enabled, s.NotifyChannelID); err != nil {
			return err
		}
		return httpx.Record(r, tx, "audit.schedule_updated", "audit_schedule", id.String(), nil, scheduleDetails(s))
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.respondSchedule(w, r, s, http.StatusOK)
}

func (a *API) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	if !httpx.Subject(r).CanGlobal(authz.PermOperate) {
		httpx.Forbidden(w, "audit schedules need the operator role with scope all")
		return
	}
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		s, err := loadSchedule(r.Context(), tx, id)
		if err != nil {
			return err
		}
		// Run history stays (detached from the schedule); queued runs are dropped.
		if _, err := tx.Exec(r.Context(), `UPDATE audit_runs SET status = 'failed', error = 'schedule deleted', finished_at = now()
			WHERE schedule_id = $1 AND status = 'queued'`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `UPDATE audit_runs SET schedule_id = NULL WHERE schedule_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM audit_schedules WHERE id = $1`, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "audit.schedule_deleted", "audit_schedule", id.String(), nil, scheduleDetails(s))
	})
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// runSchedule queues manual runs: one cluster (operator on it) or every
// cluster in the schedule scope on which the caller is operator.
func (a *API) runSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	var in struct {
		ClusterID string `json:"cluster_id"`
	}
	if r.ContentLength != 0 {
		if err := httpx.Decode(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	s, err := loadSchedule(ctx, a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var targets []uuid.UUID
	if in.ClusterID != "" {
		cid, err := uuid.Parse(in.ClusterID)
		if err != nil {
			httpx.NotFound(w)
			return
		}
		allowed, visible, err := httpx.CanCluster(ctx, a.DB, sub, cid, authz.PermOperate)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if !visible {
			httpx.NotFound(w)
			return
		}
		if !allowed {
			httpx.Forbidden(w, "")
			return
		}
		var status string
		var bench bool
		if err := a.DB.QueryRow(ctx, `SELECT status, bench_enabled FROM clusters WHERE id = $1`, cid).Scan(&status, &bench); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if status == "pending" || status == "revoked" {
			httpx.FieldErrors(w, "this cluster's agent is not enrolled", map[string]string{"cluster_id": "cluster is " + status})
			return
		}
		if s.Tool == ToolKubeBench && !bench {
			httpx.FieldErrors(w, "kube-bench is not enabled on this cluster's agent",
				map[string]string{"cluster_id": "the agent did not advertise the kube-bench capability; set bench.enabled=true in the olympos-agent Helm values"})
			return
		}
		targets = []uuid.UUID{cid}
	} else {
		if !sub.CanAny(authz.PermOperate) {
			httpx.Forbidden(w, "")
			return
		}
		matched, err := MatchingClusters(ctx, a.DB, s.ScopeSelector, s.Tool)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		operable, err := httpx.ScopedClusters(ctx, a.DB, sub, authz.PermOperate)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		for _, c := range matched {
			if slices.Contains(operable, c) {
				targets = append(targets, c)
			}
		}
		if len(targets) == 0 {
			msg := "no cluster in this schedule's scope that you can operate"
			if s.Tool == ToolKubeBench {
				msg += " has kube-bench enabled"
			}
			httpx.FieldErrors(w, msg, map[string]string{"cluster_id": msg})
			return
		}
	}
	var ids []uuid.UUID
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		for _, c := range targets {
			var rid uuid.UUID
			// One pending manual run per (schedule, cluster) at a time.
			err := tx.QueryRow(ctx, `SELECT id FROM audit_runs WHERE schedule_id = $1 AND cluster_id = $2 AND status IN ('queued','running')
				ORDER BY created_at DESC LIMIT 1`, id, c).Scan(&rid)
			if errors.Is(err, pgx.ErrNoRows) {
				if err := tx.QueryRow(ctx, `INSERT INTO audit_runs (schedule_id, tool, cluster_id, status, details)
					VALUES ($1, $2, $3, 'queued', jsonb_build_object('trigger', 'manual', 'frameworks', $4::text[], 'requested_by', $5::text))
					RETURNING id`, id, s.Tool, c, s.Frameworks, sub.Principal.ID.String()).Scan(&rid); err != nil {
					return err
				}
				cc := c
				if err := httpx.Record(r, tx, "audit.run_requested", "audit_run", rid.String(), &cc,
					map[string]any{"schedule_id": id.String(), "tool": s.Tool}); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			ids = append(ids, rid)
		}
		return nil
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, runSelect+` WHERE r.id = ANY($1) ORDER BY c.name`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	runs, err := scanRuns(rows)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"items": runs})
}

// ---------------------------------------------------------------- runs

func optUUID(r *http.Request, name string) (*uuid.UUID, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, true
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, false
	}
	return &id, true
}

func (a *API) listRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	visible, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	schedID, ok1 := optUUID(r, "schedule_id")
	clusterID, ok2 := optUUID(r, "cluster_id")
	if !ok1 || !ok2 {
		httpx.JSON(w, http.StatusOK, map[string]any{"items": []Run{}})
		return
	}
	limit := httpx.IntQuery(r, "limit", 50)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := a.DB.Query(ctx, runSelect+` WHERE r.cluster_id = ANY($1) AND ($2::uuid IS NULL OR r.schedule_id = $2)
		AND ($3::uuid IS NULL OR r.cluster_id = $3) AND ($4 = '' OR r.tool = $4)
		ORDER BY r.created_at DESC LIMIT $5`, visible, schedID, clusterID, r.URL.Query().Get("tool"), limit)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	runs, err := scanRuns(rows)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": runs})
}

func (a *API) getRun(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	run, err := GetRun(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	_, visible, err := httpx.CanCluster(r.Context(), a.DB, httpx.Subject(r), run.ClusterID, authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !visible {
		httpx.NotFound(w)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// ---------------------------------------------------------------- findings

func (a *API) listFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	visible, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	f := findings.Filter{Source: q.Get("source"), Status: q.Get("status"), ClusterIDs: visible, Limit: httpx.IntQuery(r, "limit", 200)}
	empty := func() { httpx.JSON(w, http.StatusOK, map[string]any{"items": []findings.Finding{}}) }
	if c := q.Get("cluster"); c != "" {
		id, err := uuid.Parse(c)
		if err != nil {
			// Accept a cluster name too.
			if err := a.DB.QueryRow(ctx, `SELECT id FROM clusters WHERE name = $1`, c).Scan(&id); err != nil {
				empty()
				return
			}
		}
		if !slices.Contains(visible, id) {
			empty()
			return
		}
		f.ClusterID = &id
	}
	if v := q.Get("run_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			empty()
			return
		}
		f.RunID = &id
	}
	items, err := findings.List(ctx, a.DB, f)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if items == nil {
		items = []findings.Finding{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}
