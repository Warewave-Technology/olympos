package synthetic

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Targeting values (scenarios.run_on).
const (
	RunOnAll      = "all"
	RunOnSelector = "selector"
)

// Target states: where a scenario stands on a cluster (§4).
const (
	// TargetIncluded: the scenario runs there.
	TargetIncluded = "included"
	// TargetExcluded: the cluster is outside run_on, or an exclude selector
	// matches it. It wins over the probe's state.
	TargetExcluded = "excluded"
	// TargetProbeOffline: the cluster is a target but its probe is not
	// online (offline, or enrolled and not connected yet). No run is made.
	TargetProbeOffline = "probe_offline"
	// TargetProbeNotInstalled: the cluster is a target but has no probe
	// (never installed, or revoked). No run is made.
	TargetProbeNotInstalled = "probe_not_installed"
)

// ClusterInfo is what targeting knows of a cluster. Labels are the
// cluster's labels in Olympos; Resolve adds inventory.ClusterNameLabel from
// Name.
type ClusterInfo struct {
	ID          uuid.UUID
	Name        string
	Labels      map[string]string
	ProbeStatus string
}

// Targeting is where a scenario runs: run_on (all or selector), its
// selector, and the exclude selectors.
type Targeting struct {
	RunOn, RunOnSelector string
	Exclude              []string
}

// TargetCluster is a cluster with the scenario's state on it.
type TargetCluster struct {
	ClusterInfo
	State string
}

// selectors is a parsed Targeting. A nil include matches nothing.
type selectors struct {
	include *authz.Scope
	exclude []authz.Scope
}

// parse parses the selectors with the grammar of grant scopes
// (authz.ParseScope: Kubernetes label selectors over the cluster labels).
// An empty exclude entry is ignored.
func (t Targeting) parse() (selectors, error) {
	var out selectors
	switch t.RunOn {
	case RunOnAll:
		all, _ := authz.ParseScope("all")
		out.include = &all
	case RunOnSelector:
		if strings.TrimSpace(t.RunOnSelector) == "" {
			return out, errors.New("run_on_selector: required when run_on is selector")
		}
		sc, err := authz.ParseScope(t.RunOnSelector)
		if err != nil {
			return out, fmt.Errorf("run_on_selector: %w", err)
		}
		out.include = &sc
	default:
		return out, fmt.Errorf("run_on: must be %s or %s", RunOnAll, RunOnSelector)
	}
	for i, e := range t.Exclude {
		if strings.TrimSpace(e) == "" {
			continue
		}
		sc, err := authz.ParseScope(e)
		if err != nil {
			return selectors{}, fmt.Errorf("exclude_selectors.%d: %w", i, err)
		}
		out.exclude = append(out.exclude, sc)
	}
	return out, nil
}

// Validate checks the targeting's selectors (the API's check on save).
func (t Targeting) Validate() error {
	_, err := t.parse()
	return err
}

// targets reports whether a cluster with these labels is a target: inside
// run_on and matched by no exclude selector.
func (sel selectors) targets(labels map[string]string) bool {
	if sel.include == nil || !sel.include.Matches(labels) {
		return false
	}
	for _, e := range sel.exclude {
		if e.Matches(labels) {
			return false
		}
	}
	return true
}

// clusterLabels returns the labels with the reserved cluster label set
// from the name, so that olympos.io/cluster=<name> always selects it.
func clusterLabels(c ClusterInfo) map[string]string {
	out := make(map[string]string, len(c.Labels)+1)
	for k, v := range c.Labels {
		out[k] = v
	}
	out[inventory.ClusterNameLabel] = c.Name
	return out
}

// probeState is the target state of a target cluster from its probe.
func probeState(status string) string {
	switch status {
	case ProbeOnlineState:
		return TargetIncluded
	case ProbeOfflineState, ProbePending:
		return TargetProbeOffline
	}
	return TargetProbeNotInstalled
}

// Resolve gives each cluster, in the order given, the scenario's state on
// it. Excluded wins over the probe's state. Targeting that does not parse
// includes no cluster (fail closed): the API refuses it on save
// (Targeting.Validate).
func Resolve(t Targeting, cs []ClusterInfo) []TargetCluster {
	sel, err := t.parse()
	if err != nil {
		sel = selectors{}
	}
	out := make([]TargetCluster, 0, len(cs))
	for _, c := range cs {
		tc := TargetCluster{ClusterInfo: c, State: TargetExcluded}
		tc.Labels = clusterLabels(c)
		if sel.targets(tc.Labels) {
			tc.State = probeState(c.ProbeStatus)
		}
		out = append(out, tc)
	}
	return out
}

// LoadClusters reads every cluster as targeting sees it, by name.
func LoadClusters(ctx context.Context, q store.Querier) ([]ClusterInfo, error) {
	rows, err := q.Query(ctx, `SELECT id, name, labels, probe_status FROM clusters ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ClusterInfo, error) {
		var c ClusterInfo
		err := r.Scan(&c.ID, &c.Name, &c.Labels, &c.ProbeStatus)
		return c, err
	})
}
