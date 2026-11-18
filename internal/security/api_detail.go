package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sigs.k8s.io/yaml"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
)

// ---------------------------------------------------------------- cluster summary

// ClusterSummary is one row of GET /security/clusters.
type ClusterSummary struct {
	ClusterID                    uuid.UUID `json:"cluster_id"`
	ClusterName                  string    `json:"cluster_name"`
	Provider                     string    `json:"provider"`
	Status                       string    `json:"status"`
	Images                       int       `json:"images"`
	Workloads                    int       `json:"workloads"`
	Critical                     int       `json:"critical"`
	High                         int       `json:"high"`
	ImagesWithCritical           int       `json:"images_with_critical"`
	NotScanned                   int       `json:"not_scanned"`
	KyvernoInstalled             bool      `json:"kyverno_installed"`
	KyvernoPolicies              int       `json:"kyverno_policies"`
	KyvernoFailures              int       `json:"kyverno_failures"`
	Namespaces                   int       `json:"namespaces"`
	NamespacesWithoutDefaultDeny int       `json:"namespaces_without_default_deny"`
	// Open sensitive-data findings (F2): credential-like values in ConfigMaps.
	SensitiveData     int `json:"sensitive_data"`
	SensitiveDataHigh int `json:"sensitive_data_high"`
}

// clusterSummarySQL aggregates per cluster in one statement (one pass per
// table, no per-cluster queries). critical/high count distinct CVEs across
// the cluster's images; namespaces_without_default_deny skips excluded
// (system) namespaces, like the netpol.no_default_deny finding.
const clusterSummarySQL = `
	WITH c AS (
	  SELECT id, name, COALESCE(NULLIF(provider_override, ''), provider) AS provider, status
	  FROM clusters WHERE id = ANY($1)),
	cd AS (SELECT DISTINCT cluster_id, digest FROM image_usage WHERE cluster_id = ANY($1)),
	u AS (
	  SELECT cluster_id, count(DISTINCT digest) AS images,
	         count(DISTINCT (namespace, workload_kind, workload_name)) AS workloads
	  FROM image_usage WHERE cluster_id = ANY($1) GROUP BY cluster_id),
	iv AS (
	  SELECT cd.cluster_id,
	         count(DISTINCT v.cve_id) FILTER (WHERE v.severity = 'critical') AS critical,
	         count(DISTINCT v.cve_id) FILTER (WHERE v.severity = 'high') AS high
	  FROM cd JOIN image_vulns v ON v.digest = cd.digest
	  WHERE v.severity IN ('critical', 'high') GROUP BY cd.cluster_id),
	ist AS (
	  SELECT cd.cluster_id, count(*) FILTER (WHERE i.critical > 0) AS with_critical,
	         count(*) FILTER (WHERE i.scan_status <> 'scanned') AS not_scanned
	  FROM cd JOIN images i ON i.digest = cd.digest GROUP BY cd.cluster_id),
	np AS (
	  SELECT cluster_id, count(*) AS namespaces,
	         count(*) FILTER (WHERE NOT excluded AND NOT default_deny) AS without_deny
	  FROM network_policy_status WHERE cluster_id = ANY($1) GROUP BY cluster_id),
	sd AS (
	  SELECT cluster_id, count(*) AS n, count(*) FILTER (WHERE severity = 'high') AS high
	  FROM findings WHERE source = 'sensitive-data' AND status = 'open' AND cluster_id = ANY($1) GROUP BY cluster_id)
	SELECT c.id, c.name, c.provider, c.status,
	       COALESCE(u.images, 0), COALESCE(u.workloads, 0), COALESCE(iv.critical, 0), COALESCE(iv.high, 0),
	       COALESCE(ist.with_critical, 0), COALESCE(ist.not_scanned, 0),
	       COALESCE(k.installed, false), COALESCE(k.policy_count, 0), COALESCE(k.fail_count, 0),
	       COALESCE(np.namespaces, 0), COALESCE(np.without_deny, 0), COALESCE(sd.n, 0), COALESCE(sd.high, 0)
	FROM c
	LEFT JOIN u ON u.cluster_id = c.id
	LEFT JOIN iv ON iv.cluster_id = c.id
	LEFT JOIN ist ON ist.cluster_id = c.id
	LEFT JOIN kyverno_status k ON k.cluster_id = c.id
	LEFT JOIN np ON np.cluster_id = c.id
	LEFT JOIN sd ON sd.cluster_id = c.id
	ORDER BY c.name`

func (a *API) listClusterSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, clusterSummarySQL, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	items := []ClusterSummary{}
	for rows.Next() {
		var s ClusterSummary
		if err := rows.Scan(&s.ClusterID, &s.ClusterName, &s.Provider, &s.Status, &s.Images, &s.Workloads, &s.Critical, &s.High,
			&s.ImagesWithCritical, &s.NotScanned, &s.KyvernoInstalled, &s.KyvernoPolicies, &s.KyvernoFailures,
			&s.Namespaces, &s.NamespacesWithoutDefaultDeny, &s.SensitiveData, &s.SensitiveDataHigh); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		items = append(items, s)
	}
	if err := rows.Err(); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// readableCluster resolves ?cluster= (ID or name) to a cluster the caller can
// read. ok is false (answer 404) when it is missing, unknown or out of scope.
func (a *API) readableCluster(r *http.Request) (id uuid.UUID, name string, ok bool, err error) {
	want := strings.TrimSpace(r.URL.Query().Get("cluster"))
	if want == "" {
		return uuid.Nil, "", false, nil
	}
	var labels map[string]string
	err = a.DB.QueryRow(r.Context(), `SELECT id, name, labels FROM clusters WHERE id::text = $1 OR name = $1
		ORDER BY (id::text = $1) DESC LIMIT 1`, want).Scan(&id, &name, &labels)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, err
	}
	return id, name, httpx.Subject(r).Can(authz.PermRead, labels), nil
}

// renderYAML renders a Kubernetes-style object; keys are sorted, which puts
// apiVersion, kind, metadata, spec in their usual order.
func renderYAML(obj map[string]any) string {
	b, err := yaml.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---------------------------------------------------------------- kyverno policy

// KyvernoViolation is a non-passing result of a policy in the current reports.
type KyvernoViolation struct {
	Rule              string `json:"rule"`
	Result            string `json:"result"`
	Severity          string `json:"severity"`
	Message           string `json:"message"`
	ResourceKind      string `json:"resource_kind"`
	ResourceNamespace string `json:"resource_namespace"`
	ResourceName      string `json:"resource_name"`
}

// KyvernoPolicyDetail is GET /security/kyverno/policy.
type KyvernoPolicyDetail struct {
	KyvernoPolicy
	Spec json.RawMessage `json:"spec"`
	YAML string          `json:"yaml"`
	// SpecOmitted: the agent did not send the spec (larger than its cap).
	SpecOmitted bool               `json:"spec_omitted"`
	Violations  []KyvernoViolation `json:"violations"`
}

// maxViolations bounds the violations returned for one policy.
const maxViolations = 2000

func (a *API) getKyvernoPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, cname, ok, err := a.readableCluster(r)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	q := r.URL.Query()
	kind, ns, name := q.Get("kind"), q.Get("namespace"), q.Get("name")
	if !ok || !kyvernoKinds[kind] || name == "" {
		httpx.NotFound(w)
		return
	}
	d := KyvernoPolicyDetail{KyvernoPolicy: KyvernoPolicy{ClusterID: id, ClusterName: cname}, Violations: []KyvernoViolation{}}
	var apiVersion string
	var annotations map[string]string
	var spec []byte
	err = a.DB.QueryRow(ctx, `SELECT kind, namespace, name, mode, rules, fail_count, ready, api_version, annotations, spec, spec_omitted
		FROM kyverno_policies WHERE cluster_id = $1 AND kind = $2 AND namespace = $3 AND name = $4`, id, kind, ns, name).Scan(
		&d.Kind, &d.Namespace, &d.Name, &d.Mode, &d.RuleNames, &d.FailCount, &d.Ready, &apiVersion, &annotations, &spec, &d.SpecOmitted)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if d.RuleNames == nil {
		d.RuleNames = []string{}
	}
	d.Rules = len(d.RuleNames)
	if len(spec) > 0 {
		d.Spec = spec
		d.YAML = renderYAML(kyvernoObject(apiVersion, d.Kind, d.Namespace, d.Name, annotations, spec))
	} else {
		d.Spec = json.RawMessage("null")
	}
	rows, err := a.DB.Query(ctx, `SELECT rule, result, severity, message, resource_kind, resource_namespace, resource_name
		FROM kyverno_violations WHERE cluster_id = $1 AND kind = $2 AND namespace = $3 AND name = $4
		ORDER BY CASE result WHEN 'fail' THEN 0 WHEN 'error' THEN 1 ELSE 2 END, resource_namespace, resource_kind, resource_name, rule
		LIMIT $5`, id, kind, ns, name, maxViolations)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var v KyvernoViolation
		if err := rows.Scan(&v.Rule, &v.Result, &v.Severity, &v.Message, &v.ResourceKind, &v.ResourceNamespace, &v.ResourceName); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		d.Violations = append(d.Violations, v)
	}
	if err := rows.Err(); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

// kyvernoObject rebuilds the policy object for the YAML view.
func kyvernoObject(apiVersion, kind, ns, name string, annotations map[string]string, spec []byte) map[string]any {
	if apiVersion == "" {
		apiVersion = "policies.kyverno.io/v1"
		if kind == "ClusterPolicy" || kind == "Policy" {
			apiVersion = "kyverno.io/v1"
		}
	}
	meta := map[string]any{"name": name}
	if ns != "" {
		meta["namespace"] = ns
	}
	if len(annotations) > 0 {
		meta["annotations"] = annotations
	}
	obj := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": meta}
	if len(spec) > 0 {
		obj["spec"] = json.RawMessage(spec)
	}
	return obj
}

// ---------------------------------------------------------------- netpol namespace

// NetpolPolicy is a NetworkPolicy with its spec.
type NetpolPolicy struct {
	Name string          `json:"name"`
	Spec json.RawMessage `json:"spec"`
	YAML string          `json:"yaml"`
}

// NamespaceWorkload is a workload with its pod template labels.
type NamespaceWorkload struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Ports  []int32           `json:"ports"`
}

// NamespaceRef is another namespace of the cluster with its labels.
type NamespaceRef struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// NetpolNamespaceDetail is GET /security/netpol/namespace.
type NetpolNamespaceDetail struct {
	ClusterID       uuid.UUID           `json:"cluster_id"`
	ClusterName     string              `json:"cluster_name"`
	Namespace       string              `json:"namespace"`
	NamespaceLabels map[string]string   `json:"namespace_labels"`
	DefaultDeny     bool                `json:"default_deny"`
	Excluded        bool                `json:"excluded"`
	Policies        []NetpolPolicy      `json:"policies"`
	Workloads       []NamespaceWorkload `json:"workloads"`
	OtherNamespaces []NamespaceRef      `json:"other_namespaces"`
}

func (a *API) getNetpolNamespace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, cname, ok, err := a.readableCluster(r)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	ns := r.URL.Query().Get("namespace")
	if !ok || ns == "" {
		httpx.NotFound(w)
		return
	}
	d := NetpolNamespaceDetail{ClusterID: id, ClusterName: cname, Namespace: ns,
		Policies: []NetpolPolicy{}, Workloads: []NamespaceWorkload{}, OtherNamespaces: []NamespaceRef{}}
	err = a.DB.QueryRow(ctx, `SELECT labels, default_deny, excluded FROM network_policy_status WHERE cluster_id = $1 AND namespace = $2`,
		id, ns).Scan(&d.NamespaceLabels, &d.DefaultDeny, &d.Excluded)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if d.NamespaceLabels == nil {
		d.NamespaceLabels = map[string]string{}
	}
	if err := a.loadNetpolDetail(ctx, id, &d); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

func (a *API) loadNetpolDetail(ctx context.Context, id uuid.UUID, d *NetpolNamespaceDetail) error {
	rows, err := a.DB.Query(ctx, `SELECT name, spec FROM network_policies WHERE cluster_id = $1 AND namespace = $2 ORDER BY name`, id, d.Namespace)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p NetpolPolicy
		var spec []byte
		if err := rows.Scan(&p.Name, &spec); err != nil {
			rows.Close()
			return err
		}
		p.Spec = json.RawMessage("null")
		if len(spec) > 0 {
			p.Spec = spec
			p.YAML = renderYAML(map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
				"metadata": map[string]any{"name": p.Name, "namespace": d.Namespace}, "spec": json.RawMessage(spec)})
		}
		d.Policies = append(d.Policies, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = a.DB.Query(ctx, `SELECT kind, name, labels, ports FROM namespace_workloads WHERE cluster_id = $1 AND namespace = $2
		ORDER BY CASE kind WHEN 'Deployment' THEN 0 WHEN 'StatefulSet' THEN 1 ELSE 2 END, name`, id, d.Namespace)
	if err != nil {
		return err
	}
	for rows.Next() {
		var wl NamespaceWorkload
		if err := rows.Scan(&wl.Kind, &wl.Name, &wl.Labels, &wl.Ports); err != nil {
			rows.Close()
			return err
		}
		if wl.Labels == nil {
			wl.Labels = map[string]string{}
		}
		if wl.Ports == nil {
			wl.Ports = []int32{}
		}
		d.Workloads = append(d.Workloads, wl)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = a.DB.Query(ctx, `SELECT namespace, labels FROM network_policy_status WHERE cluster_id = $1 AND namespace <> $2
		ORDER BY namespace`, id, d.Namespace)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n NamespaceRef
		if err := rows.Scan(&n.Name, &n.Labels); err != nil {
			return err
		}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		d.OtherNamespaces = append(d.OtherNamespaces, n)
	}
	return rows.Err()
}
