package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/findings"
	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/notify"
)

// UnusedAfter: a Secret no workload or ServiceAccount referenced for this
// long is secret.unused (F3).
const UnusedAfter = 7 * 24 * time.Hour

// SecretsFix is shown on the Kubernetes secrets tab.
const SecretsFix = "Olympos does not delete Secrets. Remove unused ones with your usual change process."

// ManagedBy names the controller that owns a Secret (” = lives only in the
// cluster), from owner references and well-known labels.
func ManagedBy(owners []*pb.ObjectOwner, labels map[string]string, typ string) string {
	for _, o := range owners {
		group, _, _ := strings.Cut(o.ApiVersion, "/")
		switch {
		case group == "external-secrets.io":
			return "External Secrets Operator"
		case group == "secrets.hashicorp.com":
			return "Vault Secrets Operator"
		case group == "bitnami.com" && o.Kind == "SealedSecret":
			return "Sealed Secrets"
		case group == "cert-manager.io":
			return "cert-manager"
		}
	}
	switch {
	case labels["reconcile.external-secrets.io/managed"] != "" || labels["app.kubernetes.io/managed-by"] == "external-secrets":
		return "External Secrets Operator"
	case labels["app.kubernetes.io/managed-by"] == "vault-secrets-operator" || labels["app.kubernetes.io/managed-by"] == "hashicorp-vso":
		return "Vault Secrets Operator"
	case labels["controller.cert-manager.io/fao"] != "":
		return "cert-manager"
	case typ == "helm.sh/release.v1":
		return "Helm"
	}
	return ""
}

// secretInventory stores a full report (mark-and-sweep) and reconciles the
// k8s-secrets findings. No value exists anywhere in the report.
func (in *Ingester) secretInventory(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, rep *pb.SecretInventoryReport) error {
	type key struct{ ns, name string }
	seen := map[key]bool{}
	for _, s := range rep.Secrets {
		ns, name := clean(s.Namespace, 253), clean(s.Name, 253)
		if MatchesAny(in.SystemNamespaces, ns) || seen[key{ns, name}] {
			continue
		}
		seen[key{ns, name}] = true
		keys := make([]string, 0, len(s.Keys))
		for _, k := range s.Keys {
			keys = append(keys, clean(k, 253))
		}
		refs := make([]string, 0, len(s.ReferencedBy))
		for _, r := range s.ReferencedBy {
			refs = append(refs, clean(r, 300))
		}
		labels, _ := json.Marshal(s.Labels)
		owners, _ := json.Marshal(s.Owners)
		var created *time.Time
		if s.CreatedUnix > 0 {
			t := time.Unix(s.CreatedUnix, 0).UTC()
			created = &t
		}
		managed := ManagedBy(s.Owners, s.Labels, s.Type)
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_secrets (cluster_id, namespace, name, type, keys, keys_unknown, labels, owners, managed_by,
				referenced_by, created_at, last_referenced_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, CASE WHEN cardinality($10::text[]) > 0 THEN now() END)
			ON CONFLICT (cluster_id, namespace, name) DO UPDATE SET type = EXCLUDED.type, keys = EXCLUDED.keys,
			  keys_unknown = EXCLUDED.keys_unknown, labels = EXCLUDED.labels, owners = EXCLUDED.owners, managed_by = EXCLUDED.managed_by,
			  referenced_by = EXCLUDED.referenced_by, created_at = EXCLUDED.created_at, last_seen_at = now(),
			  last_referenced_at = CASE WHEN cardinality(EXCLUDED.referenced_by) > 0 THEN now() ELSE k8s_secrets.last_referenced_at END`,
			clusterID, ns, name, clean(s.Type, 120), keys, s.KeysUnknown, labels, owners, managed, refs, created); err != nil {
			return err
		}
	}
	if !rep.Truncated {
		var nss, names []string
		for k := range seen {
			nss, names = append(nss, k.ns), append(names, k.name)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM k8s_secrets s WHERE s.cluster_id = $1
			AND NOT EXISTS (SELECT 1 FROM unnest($2::text[], $3::text[]) AS x(ns, name) WHERE x.ns = s.namespace AND x.name = s.name)`,
			clusterID, nss, names); err != nil {
			return err
		}
	}
	current, err := in.secretFindings(ctx, tx, clusterID)
	if err != nil {
		return err
	}
	newCount, _, err := findings.Reconcile(ctx, tx, findings.SourceK8sSecrets, clusterID, current, nil)
	if err != nil || newCount == 0 {
		return err
	}
	var cname string
	if err := tx.QueryRow(ctx, `SELECT name FROM clusters WHERE id = $1`, clusterID).Scan(&cname); err != nil {
		return err
	}
	byControl := map[string]int{}
	for _, f := range current {
		byControl[f.ControlID]++
	}
	return notify.Emit(ctx, tx, notify.Event{Type: notify.SecretFindings,
		Title: fmt.Sprintf("%d new Secret inventory findings on %s", newCount, cname),
		Link:  "/security?cluster=" + clusterID.String() + "&tab=secrets",
		Fields: map[string]string{"cluster": cname, "new": fmt.Sprint(newCount), "unused": fmt.Sprint(byControl["secret.unused"]),
			"legacy SA tokens": fmt.Sprint(byControl["secret.legacy_sa_token"]), "unmanaged": fmt.Sprint(byControl["secret.unmanaged"])},
		Payload: map[string]any{"cluster_id": clusterID.String(), "new": newCount}})
}

// secretFindings derives the k8s-secrets findings from the stored rows.
func (in *Ingester) secretFindings(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID) ([]findings.Finding, error) {
	rows, err := tx.Query(ctx, `SELECT namespace, name, type, managed_by, cardinality(referenced_by) > 0,
		COALESCE(last_referenced_at, created_at, first_seen_at) FROM k8s_secrets WHERE cluster_id = $1`, clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findings.Finding
	for rows.Next() {
		var ns, name, typ, managed string
		var referenced bool
		var since time.Time
		if err := rows.Scan(&ns, &name, &typ, &managed, &referenced, &since); err != nil {
			return nil, err
		}
		ref := ns + "/" + name
		base := map[string]any{"namespace": ns, "name": name, "type": typ, "fix": SecretsFix}
		switch {
		case typ == "kubernetes.io/service-account-token":
			out = append(out, findings.Finding{ControlID: "secret.legacy_sa_token", Severity: "medium", ResourceRef: ref,
				Title: "Long-lived service account token " + ref, Details: base})
			continue
		case typ == "helm.sh/release.v1":
			continue // Helm's own state, not used by pods by design
		}
		if !referenced && time.Since(since) > UnusedAfter {
			out = append(out, findings.Finding{ControlID: "secret.unused", Severity: "low", ResourceRef: ref,
				Title: "Secret " + ref + " is not used by any workload or service account", Details: base})
		}
		if managed == "" && in.ReportUnmanaged {
			out = append(out, findings.Finding{ControlID: "secret.unmanaged", Severity: "info", ResourceRef: ref,
				Title: "Secret " + ref + " lives only in the cluster (no secrets operator owns it)", Details: base})
		}
	}
	return out, rows.Err()
}

// SecretRow is one entry of GET /security/secrets (names and key names only).
type SecretRow struct {
	ClusterID        uuid.UUID  `json:"cluster_id"`
	ClusterName      string     `json:"cluster_name"`
	Namespace        string     `json:"namespace"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Keys             []string   `json:"keys"`
	KeysUnknown      bool       `json:"keys_unknown"`
	ReferencedBy     []string   `json:"referenced_by"`
	ManagedBy        string     `json:"managed_by"`
	CreatedAt        *time.Time `json:"created_at"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastReferencedAt *time.Time `json:"last_referenced_at"`
	Findings         []string   `json:"findings"`
}

// SecretInventoryCluster tells whether a cluster's agent runs the inventory.
type SecretInventoryCluster struct {
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	Enabled     bool      `json:"enabled"`
}
