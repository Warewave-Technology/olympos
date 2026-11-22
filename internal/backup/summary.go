package backup

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// RunCounts are backup runs by outcome.
type RunCounts struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Missed    int `json:"missed"`
	// Partial: runs that wrote some of their copies and whose repairs did
	// not complete them (not counted as ok). Repair runs are not counted.
	Partial int `json:"partial"`
}

// ClusterSummary is one row of GET /backup/clusters.
type ClusterSummary struct {
	ClusterID     uuid.UUID  `json:"cluster_id"`
	ClusterName   string     `json:"cluster_name"`
	Targets       int        `json:"targets"`
	Candidates    int        `json:"candidates"`
	Jobs          int        `json:"jobs"`
	JobsEnabled   int        `json:"jobs_enabled"`
	Last24h       RunCounts  `json:"last_24h"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	Bytes30d      int64      `json:"bytes_30d"`
}

// clusterSummarySQL aggregates per cluster in one statement:
//   - targets: backup targets (olympos.io/backup set) that are not gone;
//     candidates: those without a (non-deleted) job;
//   - jobs / jobs_enabled: non-deleted jobs on the cluster's targets;
//   - last_24h: original runs (not repairs) by outcome, at their finish
//     (or scheduled) time; a partial run counts as ok once a repair of it
//     succeeded (it then has every copy), else on its own, not as ok;
//   - bytes_30d: bytes of successful runs finished in the last 30 days;
//   - last_success_at: the newest restorable run (succeeded or partial) per
//     job via backup_runs_job (job_id, created_at DESC), so old run history
//     is not scanned.
//
// Connection-test runs (trigger=test) are not backups and are excluded.
const clusterSummarySQL = `
	WITH c AS (SELECT id, name FROM clusters WHERE id = ANY($1)),
	t AS (
	  SELECT t.cluster_id, count(*) AS targets,
	         count(*) FILTER (WHERE NOT EXISTS (
	           SELECT 1 FROM backup_jobs j WHERE j.target_id = t.id AND j.deleted_at IS NULL)) AS candidates
	  FROM targets t WHERE t.cluster_id = ANY($1) AND t.engine <> '' AND t.status <> 'gone'
	  GROUP BY t.cluster_id),
	cj AS (
	  SELECT j.id, j.enabled, j.deleted_at, t.cluster_id
	  FROM backup_jobs j JOIN targets t ON t.id = j.target_id WHERE t.cluster_id = ANY($1)),
	j AS (
	  SELECT cluster_id, count(*) AS jobs, count(*) FILTER (WHERE enabled) AS enabled
	  FROM cj WHERE deleted_at IS NULL GROUP BY cluster_id),
	r AS (
	  SELECT cj.cluster_id,
	         count(*) FILTER (WHERE r.repair_of IS NULL AND (r.status = 'succeeded' OR r.status = 'partial' AND rep.ok)
	           AND r.finished_at > now() - interval '24 hours') AS ok,
	         count(*) FILTER (WHERE r.repair_of IS NULL AND r.status = 'failed' AND COALESCE(r.finished_at, r.created_at) > now() - interval '24 hours') AS failed,
	         count(*) FILTER (WHERE r.repair_of IS NULL AND r.status = 'missed' AND COALESCE(r.scheduled_for, r.created_at) > now() - interval '24 hours') AS missed,
	         count(*) FILTER (WHERE r.repair_of IS NULL AND r.status = 'partial' AND NOT rep.ok AND r.finished_at > now() - interval '24 hours') AS partial,
	         COALESCE(sum(r.bytes) FILTER (WHERE r.status = 'succeeded' AND r.finished_at > now() - interval '30 days'), 0) AS bytes
	  FROM cj JOIN backup_runs r ON r.job_id = cj.id
	  CROSS JOIN LATERAL (SELECT r.status = 'partial' AND EXISTS (
	    SELECT 1 FROM backup_runs x WHERE x.repair_of = r.id AND x.status = 'succeeded') AS ok) rep
	  WHERE r.trigger <> 'test' AND r.created_at > now() - interval '31 days'
	  GROUP BY cj.cluster_id),
	ls AS (
	  SELECT cj.cluster_id, max(l.finished_at) AS at
	  FROM cj CROSS JOIN LATERAL (
	    SELECT finished_at FROM backup_runs
	    WHERE job_id = cj.id AND status IN ('succeeded', 'partial') AND trigger <> 'test'
	    ORDER BY created_at DESC LIMIT 1) l
	  GROUP BY cj.cluster_id)
	SELECT c.id, c.name, COALESCE(t.targets, 0), COALESCE(t.candidates, 0), COALESCE(j.jobs, 0), COALESCE(j.enabled, 0),
	       COALESCE(r.ok, 0), COALESCE(r.failed, 0), COALESCE(r.missed, 0), COALESCE(r.partial, 0), ls.at, COALESCE(r.bytes, 0)
	FROM c
	LEFT JOIN t ON t.cluster_id = c.id
	LEFT JOIN j ON j.cluster_id = c.id
	LEFT JOIN r ON r.cluster_id = c.id
	LEFT JOIN ls ON ls.cluster_id = c.id
	ORDER BY c.name`

// ClusterSummaries returns one row per cluster in ids, including clusters
// without targets or jobs.
func ClusterSummaries(ctx context.Context, q store.Querier, ids []uuid.UUID) ([]ClusterSummary, error) {
	rows, err := q.Query(ctx, clusterSummarySQL, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClusterSummary{}
	for rows.Next() {
		var s ClusterSummary
		if err := rows.Scan(&s.ClusterID, &s.ClusterName, &s.Targets, &s.Candidates, &s.Jobs, &s.JobsEnabled,
			&s.Last24h.Succeeded, &s.Last24h.Failed, &s.Last24h.Missed, &s.Last24h.Partial, &s.LastSuccessAt, &s.Bytes30d); err != nil {
			return nil, err
		}
		out = append(out, s)
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
