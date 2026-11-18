package audit

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// LastRun is the latest run of one tool on a cluster.
type LastRun struct {
	Tool        string     `json:"tool"`
	RunID       uuid.UUID  `json:"run_id"`
	Status      string     `json:"status"`
	Score       *float64   `json:"score"`
	FinishedAt  *time.Time `json:"finished_at"`
	NewFindings int        `json:"new_findings"`
}

// SeverityCounts are open findings by severity.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ClusterSummary is one row of GET /audit/clusters.
type ClusterSummary struct {
	ClusterID    uuid.UUID      `json:"cluster_id"`
	ClusterName  string         `json:"cluster_name"`
	Provider     string         `json:"provider"`
	BenchEnabled bool           `json:"bench_enabled"`
	LastRuns     []LastRun      `json:"last_runs"`
	OpenFindings SeverityCounts `json:"open_findings"`
}

// ClusterSummaries returns one row per cluster in ids (also clusters without
// runs or findings), ordered by name: the latest run per tool (index
// audit_runs_cluster_tool) and open audit findings (kubescape, polaris,
// kube-bench) by severity. Three queries for any number of clusters.
func ClusterSummaries(ctx context.Context, q store.Querier, ids []uuid.UUID) ([]ClusterSummary, error) {
	out := []ClusterSummary{}
	idx := map[uuid.UUID]int{}
	rows, err := q.Query(ctx, `SELECT id, name, COALESCE(NULLIF(provider_override, ''), provider), bench_enabled
		FROM clusters WHERE id = ANY($1) ORDER BY name`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s ClusterSummary
		if err := rows.Scan(&s.ClusterID, &s.ClusterName, &s.Provider, &s.BenchEnabled); err != nil {
			rows.Close()
			return nil, err
		}
		s.LastRuns = []LastRun{}
		idx[s.ClusterID] = len(out)
		out = append(out, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT DISTINCT ON (cluster_id, tool) cluster_id, tool, id, status, score::float8, finished_at, new_findings
		FROM audit_runs WHERE cluster_id = ANY($1)
		ORDER BY cluster_id, tool, created_at DESC`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cid uuid.UUID
		var lr LastRun
		if err := rows.Scan(&cid, &lr.Tool, &lr.RunID, &lr.Status, &lr.Score, &lr.FinishedAt, &lr.NewFindings); err != nil {
			rows.Close()
			return nil, err
		}
		if i, ok := idx[cid]; ok {
			out[i].LastRuns = append(out[i].LastRuns, lr)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT cluster_id,
		  count(*) FILTER (WHERE severity = 'critical'), count(*) FILTER (WHERE severity = 'high'),
		  count(*) FILTER (WHERE severity = 'medium'), count(*) FILTER (WHERE severity = 'low')
		FROM findings WHERE status = 'open' AND source = ANY($2) AND cluster_id = ANY($1)
		GROUP BY cluster_id`, ids, []string{ToolKubescape, ToolPolaris, ToolKubeBench})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid uuid.UUID
		var c SeverityCounts
		if err := rows.Scan(&cid, &c.Critical, &c.High, &c.Medium, &c.Low); err != nil {
			return nil, err
		}
		if i, ok := idx[cid]; ok {
			out[i].OpenFindings = c
		}
	}
	return out, rows.Err()
}

func (a *API) listClusterSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	items, err := ClusterSummaries(ctx, a.DB, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}
