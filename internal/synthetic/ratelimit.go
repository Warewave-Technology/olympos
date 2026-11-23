package synthetic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
	id       uuid.UUID
	enabled  bool
	interval time.Duration
	sel      selectors
	selErr   error
	rpm      float64
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
	rows, err := q.Query(ctx, `SELECT id, enabled, interval_seconds, step_retries, run_on, run_on_selector, exclude_selectors
		FROM scenarios `+where+` ORDER BY created_at, id`, args...)
	if err != nil {
		return nil, err
	}
	type row struct {
		plan    planScenario
		sc      spec.Scenario
		targets Targeting
	}
	var list []*row
	byID := map[uuid.UUID]*row{}
	var ids []uuid.UUID
	for rows.Next() {
		r := &row{}
		if err := rows.Scan(&r.plan.id, &r.plan.enabled, &r.sc.IntervalSeconds, &r.sc.StepRetries,
			&r.targets.RunOn, &r.targets.RunOnSelector, &r.targets.Exclude); err != nil {
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
		r.plan.sel, r.plan.selErr = r.targets.parse()
		out = append(out, r.plan)
	}
	return out, nil
}

// pair is a scenario on a cluster.
type pair struct{ scenario, cluster uuid.UUID }

// allocate applies the caps to the included pairs (§6.3): a scenario over
// the per-scenario cap runs nowhere; on each cluster, the scenarios fill
// the per-cluster cap oldest first, and one that does not fit in what is
// left is blocked (a newer, smaller one may still fit). It returns the
// pairs to run and the pairs blocked, in plan order per cluster.
func (s *Service) allocate(plans []planScenario, cs []ClusterInfo) (run, blocked []pair) {
	clusterCap, scenarioCap := s.clusterCap(), s.scenarioCap()
	for _, c := range cs {
		if probeState(c.ProbeStatus) != TargetIncluded {
			continue
		}
		labels := clusterLabels(c)
		used := 0.0
		for _, p := range plans {
			if !p.enabled || !p.sel.targets(labels) {
				continue
			}
			pr := pair{p.id, c.ID}
			switch {
			case p.rpm > scenarioCap+rateSlack, used+p.rpm > clusterCap+rateSlack:
				blocked = append(blocked, pr)
			default:
				used += p.rpm
				run = append(run, pr)
			}
		}
	}
	return run, blocked
}

// CheckRate is the API's check of a scenario before it is saved: sc on the
// clusters it would run on, next to every other enabled scenario (exclude
// is the scenario's own id when it is edited, so that its stored version is
// not counted twice). It returns, for each cluster where the scenarios
// together would ask for more than the per-cluster cap, the cluster's name
// and that rate; an empty map when sc fits everywhere. A scenario over the
// per-scenario cap by itself is refused with ErrRateLimit.
//
// Other scenarios count on a cluster they target whatever the state of its
// probe: a probe that is offline now comes back with the same load.
func (s *Service) CheckRate(ctx context.Context, q store.Querier, sc *spec.Scenario, clusters []uuid.UUID, exclude *uuid.UUID) (map[string]float64, error) {
	rpm := spec.RequestsPerMinute(sc)
	if limit := s.scenarioCap(); rpm > limit+rateSlack {
		return nil, fmt.Errorf("%w: the scenario makes up to %.1f requests per minute on each cluster, the cap is %.0f", ErrRateLimit, rpm, limit)
	}
	out := map[string]float64{}
	if len(clusters) == 0 {
		return out, nil
	}
	plans, err := loadPlans(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	cs, err := LoadClusters(ctx, q)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]ClusterInfo, len(cs))
	for _, c := range cs {
		byID[c.ID] = c
	}
	clusterCap, scenarioCap := s.clusterCap(), s.scenarioCap()
	seen := map[uuid.UUID]bool{}
	for _, id := range clusters {
		c, ok := byID[id]
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		labels := clusterLabels(c)
		total := rpm
		for _, p := range plans {
			// A scenario over its own cap is not scheduled: it adds nothing.
			if exclude != nil && p.id == *exclude || p.rpm > scenarioCap+rateSlack || !p.sel.targets(labels) {
				continue
			}
			total += p.rpm
		}
		if total > clusterCap+rateSlack {
			out[c.Name] = total
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
