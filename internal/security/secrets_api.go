package security

import (
	"net/http"

	"github.com/Warewave-Technology/olympos/internal/httpx"
)

// listSecrets answers GET /security/secrets: per cluster whether the opt-in
// inventory runs, and the Secrets (names, key names, references) with their
// open k8s-secrets findings. Never a value: none is stored.
func (a *API) listSecrets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := a.scopedClusters(r)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	cl := []SecretInventoryCluster{}
	rows, err := a.DB.Query(ctx, `SELECT id, name, secrets_inventory FROM clusters WHERE id = ANY($1) ORDER BY name`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	for rows.Next() {
		var c SecretInventoryCluster
		if err := rows.Scan(&c.ClusterID, &c.ClusterName, &c.Enabled); err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		cl = append(cl, c)
	}
	rows.Close()
	items := []SecretRow{}
	rows, err = a.DB.Query(ctx, `SELECT s.cluster_id, c.name, s.namespace, s.name, s.type, s.keys, s.keys_unknown, s.referenced_by,
		s.managed_by, s.created_at, s.first_seen_at, s.last_referenced_at,
		COALESCE((SELECT array_agg(f.control_id ORDER BY f.control_id) FROM findings f WHERE f.source = 'k8s-secrets' AND f.status = 'open'
		  AND f.cluster_id = s.cluster_id AND f.resource_ref = s.namespace || '/' || s.name), '{}')
		FROM k8s_secrets s JOIN clusters c ON c.id = s.cluster_id
		WHERE s.cluster_id = ANY($1) ORDER BY c.name, s.namespace, s.name LIMIT 20000`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s SecretRow
		if err := rows.Scan(&s.ClusterID, &s.ClusterName, &s.Namespace, &s.Name, &s.Type, &s.Keys, &s.KeysUnknown, &s.ReferencedBy,
			&s.ManagedBy, &s.CreatedAt, &s.FirstSeenAt, &s.LastReferencedAt, &s.Findings); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		items = append(items, s)
	}
	if err := rows.Err(); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"clusters": cl, "items": items, "fix": SecretsFix})
}
