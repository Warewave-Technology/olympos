package synthetic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/schedule"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// SchedulerInterval is how often the leader plans runs.
const SchedulerInterval = 5 * time.Second

// Why RunNow or TestRun refuses.
var (
	ErrScenarioDisabled = errors.New("scenario is disabled")
	// ErrNotTarget: the cluster is unknown, or the scenario's targeting
	// leaves it out.
	ErrNotTarget = errors.New("cluster is not a target of the scenario")
	// ErrProbeNotOnline: no run is made for a cluster whose probe is not
	// online (§2.3).
	ErrProbeNotOnline = errors.New("probe is not online")
	// ErrInvalidScenario: the scenario of a test run does not validate.
	ErrInvalidScenario = errors.New("invalid scenario")
)

// SlotFor is the first run time of a scenario on a cluster after now. A
// pair keeps one phase within the interval: the offset, from the FNV-64a of
// both ids, falls in ±spec.Jitter of the interval around the multiples of
// the interval (counted from the zero time, as time.Truncate does). The
// same pair gets the same phase on every replica and after every restart,
// and different pairs spread over the window, so that clusters do not all
// run at the same second.
func SlotFor(scenarioID, clusterID uuid.UUID, interval time.Duration, now time.Time) time.Time {
	if interval <= 0 {
		return now
	}
	h := fnv.New64a()
	_, _ = h.Write(scenarioID[:])
	_, _ = h.Write(clusterID[:])
	half := time.Duration(float64(interval) * spec.Jitter)
	offset := time.Duration(h.Sum64()%uint64(2*half+1)) - half
	slot := now.Truncate(interval).Add(offset)
	for !slot.After(now) {
		slot = slot.Add(interval)
	}
	return slot
}

// RunScheduler is the leader loop of LockSyntheticScheduler: Tick every
// SchedulerInterval.
func (s *Service) RunScheduler(ctx context.Context) {
	schedule.RunLeader(ctx, s.DB, schedule.LockSyntheticScheduler, SchedulerInterval, s.Log.With("loop", "scheduler"), s.Tick)
}

// Tick plans runs: each enabled scenario, on each cluster it targets whose
// probe is online, gets a scheduled run at the pair's next slot (SlotFor)
// when it has no scheduled or running run (a manual one included). Test
// runs do not count. Only the next slot is planned: a slot missed while no
// scheduler ran, or while a run was in flight, is never made up for.
//
// The caps of §6.3 apply first (allocate); a blocked pair gets no run and
// synthetic_state.blocked_reason = 'rate_limit', cleared once it fits
// again.
//
// Two ticks at once cannot plan a pair twice: synthetic_runs_one_open
// allows one open scheduler run per pair, and the inserts are made in one
// order so that two ticks wait for each other rather than deadlock.
func (s *Service) Tick(ctx context.Context) error {
	now := s.now()
	plans, err := loadPlans(ctx, s.DB, nil)
	if err != nil {
		return fmt.Errorf("load scenarios: %w", err)
	}
	for _, p := range plans {
		if p.selErr != nil {
			s.Log.Warn("synthetic scenario targeting does not parse: it runs nowhere", "scenario_id", p.id, "err", p.selErr)
		}
	}
	cs, err := LoadClusters(ctx, s.DB)
	if err != nil {
		return fmt.Errorf("load clusters: %w", err)
	}
	open, err := openPairs(ctx, s.DB)
	if err != nil {
		return fmt.Errorf("load open runs: %w", err)
	}
	run, blocked := s.allocate(plans, cs)

	interval := make(map[uuid.UUID]time.Duration, len(plans))
	for _, p := range plans {
		interval[p.id] = p.interval
	}
	var due []pair
	for _, pr := range run {
		if !open[pr] {
			due = append(due, pr)
		}
	}
	slices.SortFunc(due, func(a, b pair) int {
		if c := bytes.Compare(a.scenario[:], b.scenario[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.cluster[:], b.cluster[:])
	})
	var errs []error
	if len(due) > 0 {
		scen := make([]uuid.UUID, len(due))
		clus := make([]uuid.UUID, len(due))
		slots := make([]time.Time, len(due))
		for i, pr := range due {
			scen[i], clus[i] = pr.scenario, pr.cluster
			slots[i] = SlotFor(pr.scenario, pr.cluster, interval[pr.scenario], now)
		}
		// The joins drop a pair whose scenario was disabled or deleted, or
		// whose probe went away, since it was read.
		tag, err := s.DB.Exec(ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for)
			SELECT u.s, u.c, u.t FROM unnest($1::uuid[], $2::uuid[], $3::timestamptz[]) WITH ORDINALITY AS u(s, c, t, n)
			JOIN scenarios s ON s.id = u.s AND s.enabled
			JOIN clusters c ON c.id = u.c AND c.probe_status = 'online'
			ORDER BY u.n
			ON CONFLICT DO NOTHING`, scen, clus, slots)
		if err != nil {
			errs = append(errs, fmt.Errorf("schedule runs: %w", err))
		} else if tag.RowsAffected() > 0 {
			s.Log.Debug("synthetic runs scheduled", "runs", tag.RowsAffected())
		}
	}
	if err := markBlocked(ctx, s.DB, blocked); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// openPairs lists the pairs with a scheduled or running run that is not a
// test run.
func openPairs(ctx context.Context, q store.Querier) (map[pair]bool, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT scenario_id, cluster_id FROM synthetic_runs
		WHERE status IN ('scheduled','running') AND NOT test AND scenario_id IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	out := map[pair]bool{}
	_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
		var p pair
		if err := r.Scan(&p.scenario, &p.cluster); err != nil {
			return struct{}{}, err
		}
		out[p] = true
		return struct{}{}, nil
	})
	return out, err
}

// RunNow runs a scenario at once, outside its schedule, on the given
// clusters, or on every cluster it runs on when clusterIDs is empty. A
// manual run counts toward alerting like a scheduled one (decision 4); it
// takes no slot, and the next scheduled run of the pair is planned once it
// ends. It returns the runs, in the order of the clusters.
//
// A pair has at most one open manual run: asking again while one waits
// gives back that run. Named clusters must be targets with an online probe
// that no cap blocks, or nothing is run (ErrNotTarget, ErrProbeNotOnline,
// ErrRateLimit); with no cluster named, those are left out. A disabled
// scenario is refused (ErrScenarioDisabled), as is one over the
// per-scenario cap (ErrRateLimit). by is the principal who asked
// (requested_by), uuid.Nil for none.
func (s *Service) RunNow(ctx context.Context, scenarioID uuid.UUID, clusterIDs []uuid.UUID, by uuid.UUID) ([]uuid.UUID, error) {
	now := s.now()
	var ids []uuid.UUID
	err := store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		ids = nil
		plans, err := loadPlans(ctx, tx, &scenarioID)
		if err != nil {
			return err
		}
		if len(plans) == 0 {
			return store.ErrNotFound
		}
		p := plans[0]
		if !p.enabled {
			return ErrScenarioDisabled
		}
		if limit := s.scenarioCap(); p.rpm > limit+rateSlack {
			return fmt.Errorf("%w: the scenario makes up to %.1f requests per minute on each cluster, the cap is %.0f", ErrRateLimit, p.rpm, limit)
		}
		cs, err := LoadClusters(ctx, tx)
		if err != nil {
			return err
		}
		limited, err := rateLimited(ctx, tx, scenarioID)
		if err != nil {
			return err
		}
		byID := map[uuid.UUID]ClusterInfo{}
		for _, c := range cs {
			byID[c.ID] = c
		}
		state := func(c ClusterInfo) string {
			if !p.sel.targets(clusterLabels(c)) {
				return TargetExcluded
			}
			return probeState(c.ProbeStatus)
		}
		var want []uuid.UUID
		if len(clusterIDs) == 0 {
			for _, c := range cs {
				if state(c) == TargetIncluded && !limited[c.ID] {
					want = append(want, c.ID)
				}
			}
		} else {
			seen := map[uuid.UUID]bool{}
			for _, id := range clusterIDs {
				if seen[id] {
					continue
				}
				seen[id] = true
				c, ok := byID[id]
				if !ok {
					return fmt.Errorf("%w: cluster %s", ErrNotTarget, id)
				}
				switch st := state(c); {
				case st == TargetExcluded:
					return fmt.Errorf("%w: %s", ErrNotTarget, c.Name)
				case st != TargetIncluded:
					return fmt.Errorf("%w: %s (%s)", ErrProbeNotOnline, c.Name, st)
				case limited[id]:
					return fmt.Errorf("%w: %s", ErrRateLimit, c.Name)
				}
				want = append(want, id)
			}
		}
		for _, cl := range want {
			id, err := manualRun(ctx, tx, scenarioID, cl, now, by)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	return ids, err
}

// manualRun adds an open manual run of the pair, or returns the one that is
// open already (synthetic_runs_one_manual).
func manualRun(ctx context.Context, tx pgx.Tx, scenarioID, clusterID uuid.UUID, now time.Time, by uuid.UUID) (uuid.UUID, error) {
	for range 3 {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, manual, requested_by)
			VALUES ($1, $2, $3, true, $4) ON CONFLICT DO NOTHING RETURNING id`, scenarioID, clusterID, now, principal(by)).Scan(&id)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, err
		}
		err = tx.QueryRow(ctx, `SELECT id FROM synthetic_runs WHERE scenario_id = $1 AND cluster_id = $2 AND manual
			AND status IN ('scheduled','running')`, scenarioID, clusterID).Scan(&id)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, err
		}
		// The open run ended in between: try again.
	}
	return uuid.Nil, fmt.Errorf("manual run of scenario %s on cluster %s: no run made", scenarioID, clusterID)
}

// TestRun runs sc once on a cluster, from the editor: a test run, which
// never alerts and takes no slot (decision 4). sc need not be saved; its
// JSON is the run's test_spec. When sc.ID names a saved scenario, the run
// is linked to it. The caller checks the hosts against the allowlist and
// the credentials' bounds (spec.ValidateTaint) first, as on save; the probe
// enforces the allowlist again.
func (s *Service) TestRun(ctx context.Context, sc spec.Scenario, clusterID, by uuid.UUID) (uuid.UUID, error) {
	if f := spec.Validate(&sc); len(f) > 0 {
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k+": "+f[k])
		}
		slices.Sort(keys)
		return uuid.Nil, fmt.Errorf("%w: %s", ErrInvalidScenario, strings.Join(keys, "; "))
	}
	body, err := json.Marshal(sc)
	if err != nil {
		return uuid.Nil, err
	}
	var saved *uuid.UUID
	if id, err := uuid.Parse(sc.ID); err == nil {
		saved = &id
	}
	var id uuid.UUID
	err = store.Tx(ctx, s.DB, func(tx pgx.Tx) error {
		var probe, name string
		if err := tx.QueryRow(ctx, `SELECT probe_status, name FROM clusters WHERE id = $1`, clusterID).Scan(&probe, &name); err != nil {
			return store.NotFound(err)
		}
		if probe != ProbeOnlineState {
			return fmt.Errorf("%w: %s (%s)", ErrProbeNotOnline, name, probeState(probe))
		}
		return tx.QueryRow(ctx, `INSERT INTO synthetic_runs (scenario_id, cluster_id, scheduled_for, test, test_spec, requested_by)
			VALUES ((SELECT id FROM scenarios WHERE id = $1), $2, $3, true, $4, $5) RETURNING id`,
			saved, clusterID, s.now(), body, principal(by)).Scan(&id)
	})
	return id, err
}

// principal is requested_by: NULL for uuid.Nil.
func principal(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
