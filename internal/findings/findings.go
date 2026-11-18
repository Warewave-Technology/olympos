// Package findings stores security/audit findings keyed by
// (source, cluster, control_id, resource_ref) (SPEC §12.2).
package findings

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/store"
)

// Sources.
const (
	SourceKubescape  = "kubescape"
	SourcePolaris    = "polaris"
	SourceKubeBench  = "kube-bench"
	SourceKyverno    = "kyverno"
	SourceNetpol     = "netpol"
	SourceTLS        = "tls"
	SourceVaultDrift = "vault-drift"
	SourceTransfer   = "transfer"
)

// Finding is one open or resolved finding.
type Finding struct {
	ID          uuid.UUID      `json:"id"`
	Source      string         `json:"source"`
	ClusterID   uuid.UUID      `json:"cluster_id"`
	ClusterName string         `json:"cluster_name,omitempty"`
	ControlID   string         `json:"control_id"`
	Severity    string         `json:"severity"`
	ResourceRef string         `json:"resource_ref"`
	Title       string         `json:"title"`
	Details     map[string]any `json:"details,omitempty"`
	Status      string         `json:"status"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	FirstRunID  *uuid.UUID     `json:"first_seen_run_id,omitempty"`
}

// Open records a finding as open. It returns true if the finding is new
// (was not already open).
func Open(ctx context.Context, q store.Querier, f Finding, runID *uuid.UUID) (bool, error) {
	if f.Details == nil {
		f.Details = map[string]any{}
	}
	d, _ := json.Marshal(f.Details)
	var inserted bool
	err := q.QueryRow(ctx, `
		INSERT INTO findings (source, cluster_id, control_id, severity, resource_ref, title, details, first_seen_run_id, last_seen_run_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (source, cluster_id, control_id, resource_ref) WHERE status = 'open'
		DO UPDATE SET severity = EXCLUDED.severity, title = EXCLUDED.title, details = EXCLUDED.details,
		              last_seen_run_id = EXCLUDED.last_seen_run_id, last_seen_at = now()
		RETURNING (xmax = 0)`,
		f.Source, f.ClusterID, f.ControlID, f.Severity, f.ResourceRef, f.Title, d, runID).Scan(&inserted)
	return inserted, err
}

// Resolve marks an open finding resolved. Returns true if one was open.
func Resolve(ctx context.Context, q store.Querier, source string, clusterID uuid.UUID, controlID, resourceRef string, runID *uuid.UUID) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(), resolved_run_id = $5
		WHERE status = 'open' AND source = $1 AND cluster_id = $2 AND control_id = $3 AND resource_ref = $4`,
		source, clusterID, controlID, resourceRef, runID)
	return tag.RowsAffected() > 0, err
}

// Key identifies a finding within one source+cluster.
type Key struct{ ControlID, ResourceRef string }

// Reconcile makes the open set for (source, cluster[, controlPrefix]) equal
// to current: new ones are opened, missing ones resolved. Returns the counts.
func Reconcile(ctx context.Context, q store.Querier, source string, clusterID uuid.UUID, current []Finding, runID *uuid.UUID) (newCount, resolvedCount int, err error) {
	seen := map[Key]bool{}
	for _, f := range current {
		f.Source, f.ClusterID = source, clusterID
		k := Key{f.ControlID, f.ResourceRef}
		if seen[k] {
			continue
		}
		seen[k] = true
		isNew, err := Open(ctx, q, f, runID)
		if err != nil {
			return 0, 0, err
		}
		if isNew {
			newCount++
		}
	}
	rows, err := q.Query(ctx, `SELECT control_id, resource_ref FROM findings WHERE status = 'open' AND source = $1 AND cluster_id = $2`, source, clusterID)
	if err != nil {
		return 0, 0, err
	}
	var stale []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ControlID, &k.ResourceRef); err != nil {
			rows.Close()
			return 0, 0, err
		}
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	rows.Close()
	for _, k := range stale {
		if ok, err := Resolve(ctx, q, source, clusterID, k.ControlID, k.ResourceRef, runID); err != nil {
			return 0, 0, err
		} else if ok {
			resolvedCount++
		}
	}
	return newCount, resolvedCount, nil
}

// Filter narrows List.
type Filter struct {
	Source     string
	Status     string
	ClusterIDs []uuid.UUID // scope; nil = all
	ClusterID  *uuid.UUID
	RunID      *uuid.UUID // findings first seen in this run
	Limit      int
}

// List returns findings, most severe and newest first.
func List(ctx context.Context, q store.Querier, f Filter) ([]Finding, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := q.Query(ctx, `
		SELECT f.id, f.source, f.cluster_id, c.name, f.control_id, f.severity, f.resource_ref, f.title, f.details,
		       f.status, f.first_seen_at, f.last_seen_at, f.resolved_at, f.first_seen_run_id
		FROM findings f JOIN clusters c ON c.id = f.cluster_id
		WHERE ($1 = '' OR f.source = $1) AND ($2 = '' OR f.status = $2)
		  AND ($3::uuid[] IS NULL OR f.cluster_id = ANY($3)) AND ($4::uuid IS NULL OR f.cluster_id = $4)
		  AND ($5::uuid IS NULL OR f.first_seen_run_id = $5)
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         f.first_seen_at DESC
		LIMIT $6`, f.Source, f.Status, f.ClusterIDs, f.ClusterID, f.RunID, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var x Finding
		var d []byte
		if err := rows.Scan(&x.ID, &x.Source, &x.ClusterID, &x.ClusterName, &x.ControlID, &x.Severity, &x.ResourceRef,
			&x.Title, &d, &x.Status, &x.FirstSeenAt, &x.LastSeenAt, &x.ResolvedAt, &x.FirstRunID); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(d, &x.Details)
		out = append(out, x)
	}
	return out, rows.Err()
}
