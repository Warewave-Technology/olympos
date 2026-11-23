package synthetic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// The caps of §6.3 and decision 4, when the configuration leaves them at
// zero (config.Synthetic sets the same defaults).
const (
	DefaultMaxRequestsPerMinutePerCluster  = 600
	DefaultMaxRequestsPerMinutePerScenario = 120
)

// BlockedRateLimit is synthetic_state.blocked_reason of a scenario the
// scheduler does not run on a cluster because of a cap.
const BlockedRateLimit = "rate_limit"

// ErrRateLimit means a request rate cap refuses the scenario.
var ErrRateLimit = errors.New("over the synthetic request rate cap")

// rateSlack absorbs the rounding of fractional rates (60/45 per minute...)
// so that a sum that is exactly the cap is not refused.
const rateSlack = 1e-9

func (s *Service) clusterCap() float64 {
	if s.Cfg.MaxRequestsPerMinutePerCluster > 0 {
		return float64(s.Cfg.MaxRequestsPerMinutePerCluster)
	}
	return DefaultMaxRequestsPerMinutePerCluster
}

func (s *Service) scenarioCap() float64 {
	if s.Cfg.MaxRequestsPerMinutePerScenario > 0 {
		return float64(s.Cfg.MaxRequestsPerMinutePerScenario)
	}
	return DefaultMaxRequestsPerMinutePerScenario
}

// planScenario is a scenario as the scheduler and the caps see it.
type planScenario struct {
	id        uuid.UUID
	createdAt time.Time
	enabled   bool
	interval  time.Duration
	target    Targeting
	sel       selectors
	selErr    error
	rpm       float64
}

// loadPlans reads the scenarios to plan, oldest first (the per-cluster cap
// is filled in that order): every enabled scenario, or the one scenario
// only, enabled or not. A plan's rate is spec.RequestsPerMinute of its
// stored steps; only what the rate depends on is read (not the step specs,
// which may hold 64 KiB bodies).
func loadPlans(ctx context.Context, q store.Querier, only *uuid.UUID) ([]planScenario, error) {
	where, args := `WHERE enabled`, []any{}
	if only != nil {
		where, args = `WHERE id = $1`, []any{*only}
	}
	rows, err := q.Query(ctx, `SELECT id, created_at, enabled, interval_seconds, step_retries, run_on, run_on_selector, exclude_selectors
		FROM scenarios `+where+` ORDER BY created_at, id`, args...)
	if err != nil {
		return nil, err
	}
	type row struct {
		plan planScenario
		sc   spec.Scenario
	}
	var list []*row
	byID := map[uuid.UUID]*row{}
	var ids []uuid.UUID
	for rows.Next() {
		r := &row{}
		if err := rows.Scan(&r.plan.id, &r.plan.createdAt, &r.plan.enabled, &r.sc.IntervalSeconds, &r.sc.StepRetries,
			&r.plan.target.RunOn, &r.plan.target.RunOnSelector, &r.plan.target.Exclude); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, r)
		byID[r.plan.id] = r
		ids = append(ids, r.plan.id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err = q.Query(ctx, `SELECT scenario_id, kind, kind = 'http' AND spec->'follow_redirects' = 'true'::jsonb, credential_id
		FROM scenario_steps WHERE scenario_id = ANY($1) ORDER BY scenario_id, position`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var st spec.Step
		var redirects bool
		if err := rows.Scan(&id, &st.Kind, &redirects, &st.CredentialID); err != nil {
			rows.Close()
			return nil, err
		}
		if st.Kind == spec.KindHTTP {
			st.HTTP = &spec.HTTPSpec{FollowRedirects: redirects}
		}
		if r := byID[id]; r != nil {
			r.sc.Steps = append(r.sc.Steps, st)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]planScenario, 0, len(list))
	for _, r := range list {
		r.plan.interval = time.Duration(r.sc.IntervalSeconds) * time.Second
		r.plan.rpm = spec.RequestsPerMinute(&r.sc)
		r.plan.sel, r.plan.selErr = r.plan.target.parse()
		out = append(out, r.plan)
	}
	return out, nil
}

// pair is a scenario on a cluster.
type pair struct{ scenario, cluster uuid.UUID }

// fill applies the caps of §6.3 to one cluster: a scenario over the
// per-scenario cap is blocked and takes none of the cluster's room; the
// others fill the per-cluster cap in plan order (oldest first), and one that
// does not fit in what is left is blocked (a newer, smaller one may still
// fit). It reports, for each plan that targets the cluster, whether it is
// blocked, and the rate all of them together ask for.
func (s *Service) fill(plans []planScenario, labels map[string]string) (blocked map[int]bool, demand float64) {
	clusterCap, scenarioCap := s.clusterCap(), s.scenarioCap()
	blocked = map[int]bool{}
	used := 0.0
	for i, p := range plans {
		if !p.enabled || !p.sel.targets(labels) {
			continue
		}
		switch {
		case p.rpm > scenarioCap+rateSlack:
			blocked[i] = true
			continue
		case used+p.rpm > clusterCap+rateSlack:
			blocked[i] = true
		default:
			used += p.rpm
			blocked[i] = false
		}
		demand += p.rpm
	}
	return blocked, demand
}

// allocate is fill on every cluster, whatever the state of its probe: a
// probe that is offline now comes back with the same load, and its pairs
// keep their planned runs. It returns the pairs that may run and the pairs
// blocked, in plan order per cluster.
func (s *Service) allocate(plans []planScenario, cs []ClusterInfo) (run, blocked []pair) {
	for _, c := range cs {
		b, _ := s.fill(plans, clusterLabels(c))
		for i, p := range plans {
			isBlocked, targeted := b[i]
			switch {
			case !targeted:
			case isBlocked:
				blocked = append(blocked, pair{p.id, c.ID})
			default:
				run = append(run, pair{p.id, c.ID})
			}
		}
	}
	return run, blocked
}

// CheckRate is the API's check of a scenario before it is saved (ruling
// P15): sc on the clusters it would run on, among every other enabled
// scenario in the scheduler's order (oldest first). exclude is the
// scenario's own id when it is edited: its stored version is not counted,
// and sc takes its place in the order; a new scenario comes last. It
// returns the clusters where the scheduler would block sc itself (allocate),
// by name, with the rate all the scenarios on that cluster ask for; an
// empty map when sc runs everywhere. A cluster that is over the cap because
// of newer scenarios is not reported: they are the ones blocked.
//
// A disabled scenario runs nowhere: pass no clusters, and the map is empty.
// A scenario over the per-scenario cap by itself is refused with
// ErrRateLimit whatever the clusters: the cap is a property of the
// scenario.
func (s *Service) CheckRate(ctx context.Context, q store.Querier, sc *spec.Scenario, clusters []uuid.UUID, exclude *uuid.UUID) (map[string]float64, error) {
	rpm := spec.RequestsPerMinute(sc)
	if limit := s.scenarioCap(); rpm > limit+rateSlack {
		return nil, fmt.Errorf("%w: the scenario makes up to %.1f requests per minute on each cluster, the cap is %.0f", ErrRateLimit, rpm, limit)
	}
	out := map[string]float64{}
	if len(clusters) == 0 {
		return out, nil
	}
	others, err := loadPlans(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	all, _ := authz.ParseScope(RunOnAll)
	// The clusters given are sc's targets: it targets each of them.
	self := planScenario{enabled: true, rpm: rpm, sel: selectors{include: &all}}
	stored := false
	if exclude != nil {
		self.id = *exclude
		err := q.QueryRow(ctx, `SELECT created_at FROM scenarios WHERE id = $1`, *exclude).Scan(&self.createdAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		stored = err == nil
	}
	plans := make([]planScenario, 0, len(others)+1)
	for _, p := range others {
		if exclude == nil || p.id != *exclude {
			plans = append(plans, p)
		}
	}
	// sc's place in the order: its stored one, else last.
	at := len(plans)
	if stored {
		at = slices.IndexFunc(plans, func(p planScenario) bool {
			return p.createdAt.After(self.createdAt) || p.createdAt.Equal(self.createdAt) && bytes.Compare(p.id[:], self.id[:]) > 0
		})
		if at < 0 {
			at = len(plans)
		}
	}
	plans = slices.Insert(plans, at, self)

	cs, err := LoadClusters(ctx, q)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]ClusterInfo, len(cs))
	for _, c := range cs {
		byID[c.ID] = c
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range clusters {
		c, ok := byID[id]
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		blocked, demand := s.fill(plans, clusterLabels(c))
		if blocked[at] {
			out[c.Name] = demand
		}
	}
	return out, nil
}

// markBlocked records the pairs blocked by a cap (blocked_reason
// rate_limit) and clears rate_limit from every other pair: a scenario that
// fits again, was disabled or no longer targets the cluster. Another
// reason that is set is left alone.
func markBlocked(ctx context.Context, q store.Querier, blocked []pair) error {
	scen := make([]uuid.UUID, len(blocked))
	clus := make([]uuid.UUID, len(blocked))
	for i, p := range blocked {
		scen[i], clus[i] = p.scenario, p.cluster
	}
	if len(blocked) > 0 {
		if _, err := q.Exec(ctx, `INSERT INTO synthetic_state (scenario_id, cluster_id, blocked_reason)
			SELECT u.s, u.c, $3 FROM unnest($1::uuid[], $2::uuid[]) AS u(s, c)
			JOIN scenarios s ON s.id = u.s JOIN clusters c ON c.id = u.c
			ON CONFLICT (scenario_id, cluster_id) DO UPDATE SET blocked_reason = EXCLUDED.blocked_reason
			WHERE synthetic_state.blocked_reason = ''`, scen, clus, BlockedRateLimit); err != nil {
			return fmt.Errorf("record rate-limited scenarios: %w", err)
		}
	}
	if _, err := q.Exec(ctx, `UPDATE synthetic_state SET blocked_reason = ''
		WHERE blocked_reason = $3 AND (scenario_id, cluster_id) NOT IN (SELECT * FROM unnest($1::uuid[], $2::uuid[]))`,
		scen, clus, BlockedRateLimit); err != nil {
		return fmt.Errorf("clear rate limits: %w", err)
	}
	return nil
}

// rateLimited lists the clusters on which the scheduler blocked the
// scenario for a cap.
func rateLimited(ctx context.Context, q store.Querier, scenarioID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := q.Query(ctx, `SELECT cluster_id FROM synthetic_state WHERE scenario_id = $1 AND blocked_reason = $2`, scenarioID, BlockedRateLimit)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}
