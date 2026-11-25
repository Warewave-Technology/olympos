package inventory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/findings"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// EnrollTokenTTL is the bootstrap token lifetime (SPEC §2.2).
const EnrollTokenTTL = time.Hour

// API serves clusters, targets and the dashboard.
type API struct {
	DB         *store.DB
	Log        *slog.Logger
	Gateway    *gateway.Gateway
	CA         *pki.CA
	GatewayURL string
	AgentChart string
	// AgentSets are extra `--set k=v` lines for the install command, e.g. an
	// image mirror for air-gapped installs (OLYMPOS_AGENT_INSTALL_SETS).
	AgentSets []string
	Now       func() time.Time
	// OfflineAlertAfter is agents.offlineAlertAfter: an offline agent is a
	// Needs-attention item once it was last seen longer ago than this, like
	// the agent.offline message. Zero uses DefaultOfflineAlertAfter.
	OfflineAlertAfter time.Duration
	// SystemWarnings returns setup problems of the server itself (e.g. Key
	// Vault purge protection off) for the Needs-attention strip. Optional.
	SystemWarnings func() []AttentionItem
	// MoreAttention returns items of other modules for the Needs-attention
	// strip (e.g. synthetic credentials that cannot be resolved). It decides
	// by the subject what that subject may see. Optional.
	MoreAttention func(ctx context.Context, s *authz.Subject) ([]AttentionItem, error)
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Get("/dashboard", a.dashboard)
	r.Get("/clusters", a.listClusters)
	r.Post("/clusters", a.createCluster)
	r.Get("/clusters/{id}", a.getCluster)
	r.Patch("/clusters/{id}", a.patchCluster)
	r.Delete("/clusters/{id}", a.revokeCluster)
	r.Post("/clusters/{id}/token", a.newToken)
	r.Post("/clusters/{id}/probe-token", a.newProbeToken)
	r.Delete("/clusters/{id}/probe", a.revokeProbe)
	r.Get("/clusters/{id}/nodes", a.listNodes)
	r.Get("/targets", a.listTargets)
	r.Post("/targets/{id}/accept-tls-name", a.acceptTLSName)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Cluster is the API shape of a cluster.
type Cluster struct {
	ID               uuid.UUID         `json:"id"`
	Name             string            `json:"name"`
	Labels           map[string]string `json:"labels"`
	Provider         string            `json:"provider"`
	ProviderLabel    string            `json:"provider_label"`
	ProviderOverride string            `json:"provider_override"`
	Region           string            `json:"region"`
	APIVersion       string            `json:"api_version"`
	Status           string            `json:"status"`
	LastSeenAt       *time.Time        `json:"last_seen_at"`
	AgentVersion     string            `json:"agent_version"`
	BenchEnabled     bool              `json:"bench_enabled"`
	TransferMode     string            `json:"transfer_mode"`
	EgressRatePerGB  *float64          `json:"egress_rate_per_gb"`
	CertExpiresAt    *time.Time        `json:"cert_expires_at"`
	// The synthetic monitoring probe (docs/design/synthetic-monitoring.md
	// §2): not_installed, pending (enrolled, not connected yet), online,
	// offline or revoked.
	ProbeStatus     string     `json:"probe_status"`
	ProbeVersion    string     `json:"probe_version"`
	ProbeLastSeenAt *time.Time `json:"probe_last_seen_at"`
	Nodes           int        `json:"nodes"`
	NodesReady      int        `json:"nodes_ready"`
	CPUMilli        int64      `json:"cpu_milli"`
	MemBytes        int64      `json:"mem_bytes"`
	MinKubelet      string     `json:"min_kubelet"`
	VersionSkew     bool       `json:"version_skew"`
	EOL             bool       `json:"eol"`
	InventoryAt     *time.Time `json:"inventory_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

const clusterSelect = `
	SELECT c.id, c.name, c.labels, c.provider, c.provider_override, c.region, c.api_version, c.status, c.last_seen_at,
	       c.agent_version, c.bench_enabled, c.transfer_mode, c.egress_rate_per_gb::float8, c.cert_expires_at, c.inventory_at, c.created_at,
	       c.probe_status, c.probe_version, c.probe_last_seen_at,
	       count(n.name), count(n.name) FILTER (WHERE n.ready), COALESCE(sum(n.cpu_capacity),0), COALESCE(sum(n.mem_capacity),0),
	       COALESCE(array_agg(n.kubelet_version) FILTER (WHERE n.name IS NOT NULL), '{}')
	FROM clusters c LEFT JOIN nodes n ON n.cluster_id = c.id`

func (a *API) scanClusters(rows pgx.Rows) ([]Cluster, error) {
	defer rows.Close()
	var out []Cluster
	now := a.now()
	for rows.Next() {
		var c Cluster
		var kubelets []string
		if err := rows.Scan(&c.ID, &c.Name, &c.Labels, &c.Provider, &c.ProviderOverride, &c.Region, &c.APIVersion, &c.Status,
			&c.LastSeenAt, &c.AgentVersion, &c.BenchEnabled, &c.TransferMode, &c.EgressRatePerGB, &c.CertExpiresAt, &c.InventoryAt,
			&c.CreatedAt, &c.ProbeStatus, &c.ProbeVersion, &c.ProbeLastSeenAt, &c.Nodes, &c.NodesReady, &c.CPUMilli, &c.MemBytes, &kubelets); err != nil {
			return nil, err
		}
		if c.ProviderOverride != "" {
			c.Provider = c.ProviderOverride
		}
		if c.Provider == "" && c.Nodes > 0 {
			c.Provider = ProviderOnPrem
		}
		c.ProviderLabel = ProviderLabel[c.Provider]
		apiMinor := Minor(c.APIVersion)
		minK := 0
		for _, k := range kubelets {
			if m := Minor(k); m > 0 && (minK == 0 || m < minK) {
				minK = m
				c.MinKubelet = k
			}
		}
		c.VersionSkew = apiMinor > 0 && minK > 0 && minK < apiMinor
		c.EOL = IsEOL(apiMinor, now)
		if c.Labels == nil {
			c.Labels = map[string]string{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// visibleClusters returns clusters the subject can read.
func (a *API) visibleClusters(ctx context.Context, s *authz.Subject) ([]Cluster, error) {
	rows, err := a.DB.Query(ctx, clusterSelect+` GROUP BY c.id ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	all, err := a.scanClusters(rows)
	if err != nil {
		return nil, err
	}
	out := []Cluster{}
	for _, c := range all {
		if s.Can(authz.PermRead, c.Labels) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (a *API) listClusters(w http.ResponseWriter, r *http.Request) {
	cs, err := a.visibleClusters(r.Context(), httpx.Subject(r))
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": cs})
}

func (a *API) loadCluster(ctx context.Context, id uuid.UUID) (*Cluster, error) {
	rows, err := a.DB.Query(ctx, clusterSelect+` WHERE c.id = $1 GROUP BY c.id`, id)
	if err != nil {
		return nil, err
	}
	cs, err := a.scanClusters(rows)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, store.ErrNotFound
	}
	return &cs[0], nil
}

func (a *API) getCluster(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	c, err := a.loadCluster(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !httpx.Subject(r).Can(authz.PermRead, c.Labels)) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

var clusterNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ClusterNameLabel is the reserved, read-only label every cluster carries
// (olympos.io/cluster=<name>) so scopes can target exactly one cluster.
const ClusterNameLabel = "olympos.io/cluster"

// reservedLabel reports keys users cannot set (olympos.io/ prefix).
func reservedLabel(k string) bool { return strings.HasPrefix(k, "olympos.io/") }

// withClusterLabel returns user labels plus the reserved cluster label.
func withClusterLabel(name string, l map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range l {
		if !reservedLabel(k) {
			out[k] = v
		}
	}
	out[ClusterNameLabel] = name
	return out
}

// ValidateLabels checks Kubernetes-style label keys/values.
func ValidateLabels(l map[string]string) error {
	for k, v := range l {
		if k == ClusterNameLabel {
			continue // ignored on input, always set from the cluster name
		}
		if reservedLabel(k) {
			return fmt.Errorf("label keys under olympos.io/ are reserved (olympos.io/cluster is set automatically)")
		}
		if errs := validation.IsQualifiedName(k); len(errs) > 0 {
			return fmt.Errorf("label key %q: %s", k, strings.Join(errs, "; "))
		}
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			return fmt.Errorf("label value %q: %s", v, strings.Join(errs, "; "))
		}
	}
	return nil
}

type createClusterReq struct {
	Name         string            `json:"name"`
	Labels       map[string]string `json:"labels"`
	BenchEnabled bool              `json:"bench_enabled"`
}

// InstallResponse carries the one-time install command.
type InstallResponse struct {
	Cluster   *Cluster  `json:"cluster"`
	Command   string    `json:"command"`
	ExpiresAt time.Time `json:"expires_at"`
	// GitOps is the same install for Argo CD, Flux (#59).
	GitOps *GitOpsInstall `json:"gitops"`
}

func (a *API) createCluster(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	if !s.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	var req createClusterReq
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !clusterNameRe.MatchString(req.Name) {
		httpx.FieldErrors(w, "invalid cluster", map[string]string{"name": "Use lowercase letters, digits and dashes (max 63)."})
		return
	}
	if req.Labels == nil {
		req.Labels = map[string]string{}
	}
	if err := ValidateLabels(req.Labels); err != nil {
		httpx.FieldErrors(w, "invalid cluster", map[string]string{"labels": err.Error()})
		return
	}
	var id uuid.UUID
	var token string
	var exp time.Time
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		err := tx.QueryRow(r.Context(), `INSERT INTO clusters (name, labels, bench_enabled, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
			req.Name, withClusterLabel(req.Name, req.Labels), req.BenchEnabled, httpx.ActorID(r)).Scan(&id)
		if err != nil {
			return err
		}
		token, exp, err = a.issueToken(r.Context(), tx, id, []string{tokenRoleAgent, tokenRoleProbe})
		if err != nil {
			return err
		}
		return httpx.Record(r, tx, "cluster.created", "cluster", id.String(), &id, map[string]any{"name": req.Name, "labels": req.Labels, "bench_enabled": req.BenchEnabled})
	})
	if store.IsUniqueViolation(err) {
		httpx.FieldErrors(w, "invalid cluster", map[string]string{"name": "A cluster with this name already exists."})
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	c, err := a.loadCluster(r.Context(), id)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, InstallResponse{Cluster: c, Command: a.installCommand(c, token), ExpiresAt: exp, GitOps: a.gitopsInstall(c, token)})
}

// newToken issues a fresh bootstrap token (e.g. the first one expired, or
// a re-install after the identity Secret was lost). It enrolls the agent,
// and the probe too unless the cluster already has one (enrolled: pending,
// online or offline): then the command, which an admin may hand around,
// cannot enroll a second probe. A probe is replaced with Install probe.
func (a *API) newToken(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	c, err := a.loadCluster(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !s.Can(authz.PermRead, c.Labels)) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !s.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	if c.Status == "revoked" {
		httpx.Error(w, http.StatusConflict, "cluster is revoked; add it again as a new cluster")
		return
	}
	var token string
	var exp time.Time
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		var probeStatus string
		if err := tx.QueryRow(r.Context(), `SELECT probe_status FROM clusters WHERE id = $1 FOR UPDATE`, id).Scan(&probeStatus); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `UPDATE enroll_tokens SET expires_at = now() WHERE cluster_id = $1 AND `+unusedTokenSQL+` AND expires_at > now()`, id); err != nil {
			return err
		}
		roles := []string{tokenRoleAgent, tokenRoleProbe}
		switch probeStatus {
		case "pending", "online", "offline":
			roles = []string{tokenRoleAgent}
		}
		var err error
		if token, exp, err = a.issueToken(r.Context(), tx, id, roles); err != nil {
			return err
		}
		return httpx.Record(r, tx, "cluster.token_issued", "cluster", id.String(), &id, map[string]any{"roles": roles})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, InstallResponse{Cluster: c, Command: a.installCommand(c, token), ExpiresAt: exp, GitOps: a.gitopsInstall(c, token)})
}

// Roles a bootstrap token may enroll (enroll_tokens.roles).
const (
	tokenRoleAgent = "agent"
	tokenRoleProbe = "probe"
)

// unusedTokenSQL matches a token that can still enroll something: a role
// it lists and has not used yet. A token is unused only for the roles it
// has: a probe-only token never enrolls an agent, so its empty
// agent_used_at means nothing.
const unusedTokenSQL = `(('agent' = ANY(roles) AND agent_used_at IS NULL) OR ('probe' = ANY(roles) AND probe_used_at IS NULL))`

// issueToken stores a new bootstrap token of the cluster for roles and
// returns it with its expiry. Add cluster gives {agent, probe}: the agent
// enrolls the probe with the same token (decisions after review, 1);
// "Install probe" gives {probe}.
func (a *API) issueToken(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, roles []string) (string, time.Time, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	token := "olyb_" + base64.RawURLEncoding.EncodeToString(b)
	exp := a.now().Add(EnrollTokenTTL)
	_, err := tx.Exec(ctx, `INSERT INTO enroll_tokens (cluster_id, token_hash, expires_at, roles) VALUES ($1, $2, $3, $4)`,
		clusterID, gateway.HashToken(token), exp, roles)
	return token, exp, err
}

// withdrawProbeTokens ends what the cluster's live tokens may still do for
// a probe: a token that has not enrolled its agent yet keeps that and loses
// the probe role; any other token with an unused probe role expires. Only
// the newest probe token (or none, after a revoke) can enroll a probe.
func withdrawProbeTokens(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `UPDATE enroll_tokens SET roles = array_remove(roles, 'probe')
		WHERE cluster_id = $1 AND expires_at > now() AND 'probe' = ANY(roles) AND probe_used_at IS NULL
		  AND 'agent' = ANY(roles) AND agent_used_at IS NULL`, clusterID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE enroll_tokens SET expires_at = now()
		WHERE cluster_id = $1 AND expires_at > now() AND 'probe' = ANY(roles) AND probe_used_at IS NULL`, clusterID)
	return err
}

// newProbeToken is "Install probe" (Settings › Clusters & agents) for a
// cluster whose agent was installed without the probe: a probe-only token
// and the helm upgrade that hands it to the chart. Admin with scope all,
// like the agent's token.
func (a *API) newProbeToken(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	c, err := a.loadCluster(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !s.Can(authz.PermRead, c.Labels)) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !s.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	if c.Status == "revoked" {
		httpx.Error(w, http.StatusConflict, "cluster is revoked; add it again as a new cluster")
		return
	}
	// Ruling P24: a cluster still waiting for its first agent has its add
	// cluster token, which enrolls the probe too. A probe token would take
	// the probe role from it, and its helm upgrade needs a release that does
	// not exist yet.
	if c.Status == "pending" {
		httpx.Error(w, http.StatusConflict, "the agent has not enrolled yet; its install command already installs the probe")
		return
	}
	var token string
	var exp time.Time
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		if err := withdrawProbeTokens(r.Context(), tx, id); err != nil {
			return err
		}
		var err error
		if token, exp, err = a.issueToken(r.Context(), tx, id, []string{tokenRoleProbe}); err != nil {
			return err
		}
		return httpx.Record(r, tx, "cluster.probe_token_issued", "cluster", id.String(), &id, nil)
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, InstallResponse{Cluster: c, Command: a.probeInstallCommand(token), ExpiresAt: exp, GitOps: a.gitopsProbeInstall(token)})
}

// probeInstallCommand adds the probe to an installed agent release: the
// values it was installed with stay, the probe is enabled, and the chart
// puts the token into olympos-probe-identity for the agent to enroll the
// probe with. AgentSets (OLYMPOS_AGENT_INSTALL_SETS, e.g. an image mirror
// with probe.image.repository) are added as for a new cluster: a release
// installed before the probe has no probe values to reuse. The probe's own
// sets come last, so they win, and the token ends the command.
func (a *API) probeInstallCommand(token string) string {
	cmd := "helm upgrade olympos-agent " + a.chart() + " -n olympos-system --reuse-values"
	for _, kv := range a.AgentSets {
		cmd += " --set " + kv
	}
	return cmd + " --set probe.enabled=true --set probe.bootstrapToken=" + token
}

func (a *API) chart() string {
	if a.AgentChart != "" {
		return a.AgentChart
	}
	return "oci://ghcr.io/warewave-technology/charts/olympos-agent"
}

// revokeProbe revokes the cluster's probe alone (its certificates, and the
// tokens that could enroll a new one); the agent is untouched. "Install
// probe" enrolls a new one. Admin on the cluster, like revoking the
// cluster.
func (a *API) revokeProbe(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	allowed, visible, err := httpx.CanCluster(r.Context(), a.DB, s, id, authz.PermAdmin)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !visible {
		httpx.NotFound(w)
		return
	}
	if !allowed {
		httpx.Forbidden(w, "")
		return
	}
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		var status, probe string
		if err := tx.QueryRow(r.Context(), `SELECT status, probe_status FROM clusters WHERE id = $1 FOR UPDATE`, id).Scan(&status, &probe); err != nil {
			return store.NotFound(err)
		}
		if status == "revoked" {
			return errRevoked
		}
		// Nothing to revoke (ruling P17): no state changes.
		if probe == "not_installed" {
			return errNoProbe
		}
		if err := a.Gateway.RevokeProbe(r.Context(), tx, id); err != nil {
			return err
		}
		if err := withdrawProbeTokens(r.Context(), tx, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "cluster.probe_revoked", "cluster", id.String(), &id, map[string]any{"probe_status": probe})
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
		return
	case errors.Is(err, errRevoked):
		httpx.Error(w, http.StatusConflict, "cluster is revoked; its probe was revoked with it")
		return
	case errors.Is(err, errNoProbe):
		httpx.Error(w, http.StatusConflict, "no probe installed")
		return
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
		return
	}
	// RevokeProbe dropped the streams inside the transaction; a probe that
	// reconnected before the commit still saw the old state.
	a.Gateway.DisconnectProbe(id)
	w.WriteHeader(http.StatusNoContent)
}

var (
	errRevoked = errors.New("cluster revoked")
	errNoProbe = errors.New("no probe installed")
)

// caBase64 is the serverCA value: the base64 of the internal CA's PEM.
func (a *API) caBase64() string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.CA.Cert.Raw}))
}

func (a *API) installCommand(c *Cluster, token string) string {
	ca := a.caBase64()
	lines := []string{
		"helm upgrade --install olympos-agent " + a.chart(),
		"--namespace olympos-system --create-namespace",
		"--set server=" + a.GatewayURL,
		"--set clusterName=" + c.Name,
		"--set bootstrapToken=" + token,
		"--set serverCA=" + ca,
	}
	if c.BenchEnabled {
		lines = append(lines, "--set bench.enabled=true")
	}
	for _, kv := range a.AgentSets {
		lines = append(lines, "--set "+kv)
	}
	return strings.Join(lines, " \\\n  ")
}

type patchClusterReq struct {
	Labels           *map[string]string `json:"labels"`
	ProviderOverride *string            `json:"provider_override"`
	TransferMode     *string            `json:"transfer_mode"`
	EgressRatePerGB  *float64           `json:"egress_rate_per_gb"`
	ClearEgressRate  bool               `json:"clear_egress_rate"`
}

func (a *API) patchCluster(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	allowed, visible, err := httpx.CanCluster(r.Context(), a.DB, s, id, authz.PermAdmin)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !visible {
		httpx.NotFound(w)
		return
	}
	// Relabelling can move a cluster out of scoped grants: require admin on all.
	if !allowed || !s.CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return
	}
	var req patchClusterReq
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Labels != nil {
		if err := ValidateLabels(*req.Labels); err != nil {
			httpx.FieldErrors(w, "invalid cluster", map[string]string{"labels": err.Error()})
			return
		}
	}
	if req.ProviderOverride != nil && *req.ProviderOverride != "" && ProviderLabel[*req.ProviderOverride] == "" {
		httpx.FieldErrors(w, "invalid cluster", map[string]string{"provider_override": "Unknown provider."})
		return
	}
	if req.TransferMode != nil && *req.TransferMode != "e2e-tls" && *req.TransferMode != "compressed" {
		httpx.FieldErrors(w, "invalid cluster", map[string]string{"transfer_mode": "Use e2e-tls or compressed."})
		return
	}
	if req.EgressRatePerGB != nil && *req.EgressRatePerGB < 0 {
		httpx.FieldErrors(w, "invalid cluster", map[string]string{"egress_rate_per_gb": "Must be zero or more."})
		return
	}
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		details := map[string]any{}
		if req.Labels != nil {
			// The reserved label is re-added; users cannot change or remove it.
			if _, err := tx.Exec(r.Context(), `UPDATE clusters SET labels = $2::jsonb || jsonb_build_object('olympos.io/cluster', name) WHERE id = $1`,
				id, withClusterLabel("", *req.Labels)); err != nil {
				return err
			}
			details["labels"] = *req.Labels
		}
		if req.ProviderOverride != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE clusters SET provider_override = $2 WHERE id = $1`, id, *req.ProviderOverride); err != nil {
				return err
			}
			details["provider_override"] = *req.ProviderOverride
		}
		if req.EgressRatePerGB != nil || req.ClearEgressRate {
			if _, err := tx.Exec(r.Context(), `UPDATE clusters SET egress_rate_per_gb = $2 WHERE id = $1`, id, req.EgressRatePerGB); err != nil {
				return err
			}
			details["egress_rate_per_gb"] = req.EgressRatePerGB
		}
		if req.TransferMode != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE clusters SET transfer_mode = $2 WHERE id = $1`, id, *req.TransferMode); err != nil {
				return err
			}
			if err := SyncTransferFinding(r.Context(), tx, id, *req.TransferMode); err != nil {
				return err
			}
			details["transfer_mode"] = *req.TransferMode
		}
		return httpx.Record(r, tx, "cluster.updated", "cluster", id.String(), &id, details)
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	c, err := a.loadCluster(r.Context(), id)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

// SyncTransferFinding opens or resolves the transfer.compressed_mode finding.
// "compressed" mode always produces a visible finding (SPEC §18).
func SyncTransferFinding(ctx context.Context, q store.Querier, clusterID uuid.UUID, mode string) error {
	if mode == "compressed" {
		_, err := findings.Open(ctx, q, findings.Finding{
			Source: findings.SourceTransfer, ClusterID: clusterID, ControlID: "transfer.compressed_mode",
			Severity: "medium", ResourceRef: "cluster",
			Title:   "Compressed transfer mode: backup traffic is plaintext inside the cluster and visible to the agent",
			Details: map[string]any{"mode": mode},
		}, nil)
		return err
	}
	_, err := findings.Resolve(ctx, q, findings.SourceTransfer, clusterID, "transfer.compressed_mode", "cluster", nil)
	return err
}

func (a *API) revokeCluster(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	allowed, visible, err := httpx.CanCluster(r.Context(), a.DB, s, id, authz.PermAdmin)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !visible {
		httpx.NotFound(w)
		return
	}
	if !allowed {
		httpx.Forbidden(w, "")
		return
	}
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		if err := a.Gateway.Revoke(r.Context(), tx, id); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `UPDATE enroll_tokens SET expires_at = now() WHERE cluster_id = $1 AND `+unusedTokenSQL, id); err != nil {
			return err
		}
		return httpx.Record(r, tx, "cluster.revoked", "cluster", id.String(), &id, nil)
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.Gateway.Disconnect(id)
	w.WriteHeader(http.StatusNoContent)
}

// Node is the API shape of a node.
type Node struct {
	Name           string    `json:"name"`
	ProviderID     string    `json:"provider_id"`
	KubeletVersion string    `json:"kubelet_version"`
	Region         string    `json:"region"`
	Zone           string    `json:"zone"`
	InstanceType   string    `json:"instance_type"`
	CPUMilli       int64     `json:"cpu_milli"`
	MemBytes       int64     `json:"mem_bytes"`
	Roles          []string  `json:"roles"`
	Ready          bool      `json:"ready"`
	SeenAt         time.Time `json:"seen_at"`
}

func (a *API) listNodes(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	_, visible, err := httpx.CanCluster(r.Context(), a.DB, httpx.Subject(r), id, authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !visible {
		httpx.NotFound(w)
		return
	}
	rows, err := a.DB.Query(r.Context(), `SELECT name, provider_id, kubelet_version, region, zone, instance_type, cpu_capacity, mem_capacity, roles, ready, seen_at
		FROM nodes WHERE cluster_id = $1 ORDER BY name`, id)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.Name, &n.ProviderID, &n.KubeletVersion, &n.Region, &n.Zone, &n.InstanceType, &n.CPUMilli, &n.MemBytes, &n.Roles, &n.Ready, &n.SeenAt); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		out = append(out, n)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

// Target is the API shape of a discovered target.
type Target struct {
	ID            string    `json:"id"`
	ClusterID     uuid.UUID `json:"cluster_id"`
	ClusterName   string    `json:"cluster_name"`
	Namespace     string    `json:"namespace"`
	Service       string    `json:"service"`
	Port          int       `json:"port"`
	PortName      string    `json:"port_name"`
	Engine        string    `json:"engine"`
	VaultProvider string    `json:"vault_provider"`
	TLSServerName string    `json:"tls_server_name"`
	// TLSServerNamePending is a changed olympos.io/tls-server-name waiting
	// for an admin; TLSServerName stays the name that is verified.
	TLSServerNamePending   *string    `json:"tls_server_name_pending"`
	TLSServerNameChangedAt *time.Time `json:"tls_server_name_changed_at"`
	DetectedVersion        string     `json:"detected_version"`
	TLSOK                  *bool      `json:"tls_ok"`
	Status                 string     `json:"status"`
	FirstSeenAt            time.Time  `json:"first_seen_at"`
	LastSeenAt             time.Time  `json:"last_seen_at"`
}

// ListTargets returns targets visible to s, optionally filtered.
func ListTargets(ctx context.Context, q store.Querier, s *authz.Subject, status, engine string, tlsPending bool) ([]Target, error) {
	rows, err := q.Query(ctx, `SELECT t.id, t.cluster_id, c.name, c.labels, t.namespace, t.service, t.port, t.port_name, t.engine,
		t.vault_provider, t.tls_server_name, t.tls_server_name_pending, t.tls_server_name_changed_at, t.detected_version, t.tls_ok,
		t.status, t.first_seen_at, t.last_seen_at
		FROM targets t JOIN clusters c ON c.id = t.cluster_id
		WHERE ($1 = '' OR t.status = $1) AND ($2 = '' OR t.engine = $2) AND (NOT $3 OR t.tls_server_name_pending IS NOT NULL)
		  AND c.status <> 'revoked'
		ORDER BY c.name, t.namespace, t.service`, status, engine, tlsPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		var t Target
		var labels map[string]string
		if err := rows.Scan(&t.ID, &t.ClusterID, &t.ClusterName, &labels, &t.Namespace, &t.Service, &t.Port, &t.PortName, &t.Engine,
			&t.VaultProvider, &t.TLSServerName, &t.TLSServerNamePending, &t.TLSServerNameChangedAt, &t.DetectedVersion, &t.TLSOK,
			&t.Status, &t.FirstSeenAt, &t.LastSeenAt); err != nil {
			return nil, err
		}
		if s.Can(authz.PermRead, labels) {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

func (a *API) listTargets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ts, err := ListTargets(r.Context(), a.DB, httpx.Subject(r), q.Get("status"), q.Get("engine"), q.Get("tls_pending") == "1")
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": ts})
}

// acceptTLSName makes a changed olympos.io/tls-server-name the verified
// name (security review #1). Admin on the target's cluster; the name a
// cluster user wrote is never trusted without this.
func (a *API) acceptTLSName(w http.ResponseWriter, r *http.Request) {
	s := httpx.Subject(r)
	id := chi.URLParam(r, "id")
	var clusterID uuid.UUID
	var pending *string
	var pinned string
	err := a.DB.QueryRow(r.Context(), `SELECT cluster_id, tls_server_name, tls_server_name_pending FROM targets WHERE id = $1`, id).
		Scan(&clusterID, &pinned, &pending)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	allowed, visible, err := httpx.CanCluster(r.Context(), a.DB, s, clusterID, authz.PermAdmin)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if !visible {
		httpx.NotFound(w)
		return
	}
	if !allowed {
		httpx.Forbidden(w, "")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := httpx.Decode(r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	// The caller names what they accept: a second change in between is not
	// accepted by a stale click.
	if pending == nil || *pending != req.Name {
		httpx.Error(w, http.StatusConflict, "the TLS name changed again; reload and review it")
		return
	}
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE targets SET tls_server_name = tls_server_name_pending, tls_server_name_pending = NULL,
			tls_server_name_changed_at = NULL WHERE id = $1 AND tls_server_name_pending = $2`, id, req.Name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errConflict
		}
		return httpx.Record(r, tx, "target.tls_name_accepted", "target", id, &clusterID, map[string]any{"from": pinned, "to": req.Name})
	})
	if errors.Is(err, errConflict) {
		httpx.Error(w, http.StatusConflict, "the TLS name changed again; reload and review it")
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errConflict = errors.New("conflict")

// ---------------------------------------------------------------- dashboard

// AttentionItem is one entry of the Needs-attention strip.
type AttentionItem struct {
	Kind     string `json:"kind"`     // agent_offline | backup_failed | backup_missed | backup_partial | target_tls_changed | self_backup_failed | self_backup_partial | self_backup_unset | kek_purgeable | kek_recovery_unknown | synthetic_credential_broken | critical_cves | approvals | eol (docs/findings-and-events.md)
	Severity string `json:"severity"` // crit | warn
	Label    string `json:"label"`
	Detail   string `json:"detail"`
	Link     string `json:"link"`
}

// Dashboard is GET /api/v1/dashboard.
type Dashboard struct {
	Attention []AttentionItem `json:"attention"`
	Totals    struct {
		Clusters      int    `json:"clusters"`
		AgentsOnline  int    `json:"agents_online"`
		Nodes         int    `json:"nodes"`
		CPUMilli      int64  `json:"cpu_milli"`
		MemBytes      int64  `json:"mem_bytes"`
		Versions      int    `json:"versions"`
		VersionMin    string `json:"version_min"`
		VersionMax    string `json:"version_max"`
		SkewClusters  int    `json:"skew_clusters"`
		OfflineAgents int    `json:"offline_agents"`
		OfflineDetail string `json:"offline_detail"`
	} `json:"totals"`
	VersionMatrix []VersionRow  `json:"version_matrix"`
	Providers     []ProviderRow `json:"providers"`
	Clusters      []Cluster     `json:"clusters"`
	RefreshedAt   *time.Time    `json:"refreshed_at"`
}

// VersionRow counts clusters per API minor.
type VersionRow struct {
	Minor    string `json:"minor"`
	Clusters int    `json:"clusters"`
	EOL      bool   `json:"eol"`
}

// ProviderRow counts clusters per provider.
type ProviderRow struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Clusters int    `json:"clusters"`
	Nodes    int    `json:"nodes"`
}

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := httpx.Subject(r)
	cs, err := a.visibleClusters(ctx, s)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	d := Dashboard{Clusters: cs, Attention: []AttentionItem{}, VersionMatrix: []VersionRow{}, Providers: []ProviderRow{}}
	now := a.now()
	minors := map[int]int{}
	provs := map[string]*ProviderRow{}
	ids := make([]uuid.UUID, 0, len(cs))
	var eolClusters []string
	var eolMinor = map[int]bool{}
	for _, c := range cs {
		if c.Status == "revoked" {
			continue
		}
		ids = append(ids, c.ID)
		d.Totals.Clusters++
		if c.Status == "online" {
			d.Totals.AgentsOnline++
		}
		d.Totals.Nodes += c.Nodes
		d.Totals.CPUMilli += c.CPUMilli
		d.Totals.MemBytes += c.MemBytes
		if c.VersionSkew {
			d.Totals.SkewClusters++
		}
		if m := Minor(c.APIVersion); m > 0 {
			minors[m]++
			if c.EOL {
				eolClusters = append(eolClusters, c.Name)
				eolMinor[m] = true
			}
		}
		if c.Provider != "" {
			p := provs[c.Provider]
			if p == nil {
				p = &ProviderRow{Provider: c.Provider, Label: ProviderLabel[c.Provider]}
				provs[c.Provider] = p
			}
			p.Clusters++
			p.Nodes += c.Nodes
		}
		if c.InventoryAt != nil && (d.RefreshedAt == nil || c.InventoryAt.After(*d.RefreshedAt)) {
			t := *c.InventoryAt
			d.RefreshedAt = &t
		}
		if c.Status == "offline" {
			d.Totals.OfflineAgents++
			ago := "unknown"
			if c.LastSeenAt != nil {
				ago = humanDuration(now.Sub(*c.LastSeenAt))
				if now.Sub(*c.LastSeenAt) > offlineAlertAfter(a.OfflineAlertAfter) {
					d.Attention = append(d.Attention, AttentionItem{Kind: "agent_offline", Severity: "crit", Label: "Agent offline",
						Detail: c.Name + " · " + ago, Link: "/settings/clusters?cluster=" + c.ID.String()})
				}
			}
			if d.Totals.OfflineDetail == "" {
				d.Totals.OfflineDetail = c.Name + " · " + ago + " ago"
			}
		}
	}
	keys := make([]int, 0, len(minors))
	for m := range minors {
		keys = append(keys, m)
	}
	sort.Ints(keys)
	for _, m := range keys {
		d.VersionMatrix = append(d.VersionMatrix, VersionRow{Minor: fmt.Sprintf("1.%d", m), Clusters: minors[m], EOL: IsEOL(m, now)})
	}
	d.Totals.Versions = len(keys)
	if len(keys) > 0 {
		d.Totals.VersionMin = fmt.Sprintf("1.%d", keys[0])
		d.Totals.VersionMax = fmt.Sprintf("1.%d", keys[len(keys)-1])
	}
	for _, p := range provs {
		d.Providers = append(d.Providers, *p)
	}
	sort.Slice(d.Providers, func(i, j int) bool { return d.Providers[i].Clusters > d.Providers[j].Clusters })

	att, err := a.attention(ctx, s, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	d.Attention = append(d.Attention, att...)
	if len(eolClusters) > 0 {
		vs := []string{}
		for _, m := range keys {
			if eolMinor[m] {
				vs = append(vs, fmt.Sprintf("v1.%d", m))
			}
		}
		d.Attention = append(d.Attention, AttentionItem{Kind: "eol", Severity: "warn", Label: "End of life",
			Detail: fmt.Sprintf("%d %s on %s", len(eolClusters), plural(len(eolClusters), "cluster", "clusters"), strings.Join(vs, ", ")), Link: "/?filter=eol"})
	}
	// Critical CVEs last (lowest urgency of the crit items is shown after the warns? no: crit first).
	sort.SliceStable(d.Attention, func(i, j int) bool { return d.Attention[i].Severity == "crit" && d.Attention[j].Severity != "crit" })
	httpx.JSON(w, http.StatusOK, d)
}

// notRepairAttemptSQL keeps a run r unless it is a repair that did not
// complete the missing copies: such a repair stands for its original
// (partial) run, which stays the run the attention items look at. A
// succeeded repair is the latest run and clears the partial one.
const notRepairAttemptSQL = `(r.repair_of IS NULL OR r.status = 'succeeded')`

// missingSQL names the destinations of run r (in destination_ids order)
// without a succeeded copy in r or in any repair of it, among those the job
// still writes to (as repairs do: a destination removed from the job is no
// longer missing). Evaluated for the one run each item looks at.
const missingSQL = `COALESCE((SELECT string_agg(d.name, ', ' ORDER BY u.ord)
	FROM unnest(r.destination_ids) WITH ORDINALITY u(id, ord) JOIN destinations d ON d.id = u.id
	WHERE NOT EXISTS (SELECT 1 FROM backup_run_copies c JOIN backup_runs x ON x.id = c.run_id
	  WHERE (x.id = r.id OR x.repair_of = r.id) AND c.destination_id = u.id AND c.status = 'succeeded')
	  AND u.id IN (SELECT COALESCE(cj.destination_id, cm.destination_id) FROM backup_jobs cj
	    LEFT JOIN destination_group_members cm ON cm.group_id = cj.destination_group_id WHERE cj.id = r.job_id)), '')`

func (a *API) attention(ctx context.Context, s *authz.Subject, clusterIDs []uuid.UUID) ([]AttentionItem, error) {
	var out []AttentionItem
	// Olympos itself (F17): its database must be backed up (olympos-self)
	// and its Key Vault must keep the KEK recoverable.
	if s.CanGlobal(authz.PermRead) {
		var configured bool
		var lastStatus, lastErr, missing string
		err := a.DB.QueryRow(ctx, `SELECT true, COALESCE(r.status, ''), COALESCE(r.error, ''),
			CASE WHEN r.status = 'partial' THEN `+missingSQL+` ELSE '' END
			FROM backup_jobs j LEFT JOIN LATERAL (SELECT r.id, r.job_id, r.destination_ids, r.status, r.error FROM backup_runs r
			  WHERE r.job_id = j.id AND r.status IN ('succeeded','failed','partial') AND `+notRepairAttemptSQL+`
			  AND r.created_at > now() - interval '48 hours' ORDER BY r.created_at DESC LIMIT 1) r ON true
			WHERE j.system = 'olympos-self'`).Scan(&configured, &lastStatus, &lastErr, &missing)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		switch {
		case !configured:
			out = append(out, AttentionItem{Kind: "self_backup_unset", Severity: "warn", Label: "Olympos backup",
				Detail: "choose where the Olympos database is backed up", Link: "/backups?self=1"})
		case lastStatus == "failed":
			out = append(out, AttentionItem{Kind: "self_backup_failed", Severity: "crit", Label: "Olympos backup failed",
				Detail: shortErr(lastErr), Link: "/backups?self=1"})
		case lastStatus == "partial" && missing != "":
			out = append(out, AttentionItem{Kind: "self_backup_partial", Severity: "warn", Label: "Olympos backup incomplete",
				Detail: "missing " + missing, Link: "/backups?self=1"})
		}
		if a.SystemWarnings != nil {
			out = append(out, a.SystemWarnings()...)
		}
	}
	// Latest run per job in the last 48 h that failed, was missed or is
	// partial (and not completed by a repair since).
	rows, err := a.DB.Query(ctx, `
		SELECT r.job_id, r.service, r.status, r.error, CASE WHEN r.status = 'partial' THEN `+missingSQL+` ELSE '' END
		FROM (SELECT DISTINCT ON (j.id) r.id, r.job_id, r.destination_ids, t.service, r.status, r.error
		  FROM backup_runs r JOIN backup_jobs j ON j.id = r.job_id JOIN targets t ON t.id = j.target_id
		  WHERE t.cluster_id = ANY($1) AND j.deleted_at IS NULL AND r.trigger <> 'test' AND r.created_at > now() - interval '48 hours'
		    AND r.status IN ('succeeded','failed','missed','partial') AND `+notRepairAttemptSQL+`
		    AND NOT (r.status = 'failed' AND r.error LIKE 'agent_disconnected: retrying%')
		  ORDER BY j.id, r.created_at DESC) r`, clusterIDs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var jobID uuid.UUID
		var svc, st, errMsg, missing string
		if err := rows.Scan(&jobID, &svc, &st, &errMsg, &missing); err != nil {
			rows.Close()
			return nil, err
		}
		switch {
		case st == "partial" && missing != "": // nothing missing the job still writes to: no item
			out = append(out, AttentionItem{Kind: "backup_partial", Severity: "warn", Label: "Backup incomplete",
				Detail: svc + " · missing " + missing, Link: "/backups?job=" + jobID.String()})
		case st == "failed":
			out = append(out, AttentionItem{Kind: "backup_failed", Severity: "crit", Label: "Backup failed",
				Detail: svc + " · " + shortErr(errMsg), Link: "/backups?job=" + jobID.String()})
		case st == "missed":
			out = append(out, AttentionItem{Kind: "backup_missed", Severity: "crit", Label: "Backup missed",
				Detail: svc, Link: "/backups?job=" + jobID.String()})
		}
	}
	rows.Close()

	// A changed TLS name waits for an admin (security review #1).
	rows, err = a.DB.Query(ctx, `SELECT t.namespace, t.service, t.tls_server_name, t.tls_server_name_pending FROM targets t
		WHERE t.cluster_id = ANY($1) AND t.tls_server_name_pending IS NOT NULL AND t.status <> 'gone' ORDER BY t.namespace, t.service`, clusterIDs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ns, svc, pinned, pending string
		if err := rows.Scan(&ns, &svc, &pinned, &pending); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, AttentionItem{Kind: "target_tls_changed", Severity: "crit", Label: "TLS name changed",
			Detail: fmt.Sprintf("%s/%s asks for %s; still verifying %s", ns, svc, orDefault(pending, "the default name"), orDefault(pinned, svc+"."+ns+".svc")),
			Link:   "/backups?tls=1"})
	}
	rows.Close()

	// Pending approvals the current user can act on (not their own).
	if s.CanAny(authz.PermVaultApprove) {
		rows, err := a.DB.Query(ctx, `SELECT cr.expires_at, c.labels FROM change_requests cr
			JOIN vaults v ON v.id = cr.vault_id JOIN targets t ON t.id = v.target_id JOIN clusters c ON c.id = t.cluster_id
			WHERE cr.status = 'pending' AND cr.expires_at > now() AND cr.maker_principal_id <> $1`, s.Principal.ID)
		if err != nil {
			return nil, err
		}
		n := 0
		var oldest time.Time
		for rows.Next() {
			var exp time.Time
			var labels map[string]string
			if err := rows.Scan(&exp, &labels); err != nil {
				rows.Close()
				return nil, err
			}
			if s.Can(authz.PermVaultApprove, labels) {
				n++
				if oldest.IsZero() || exp.Before(oldest) {
					oldest = exp
				}
			}
		}
		rows.Close()
		if n > 0 {
			out = append(out, AttentionItem{Kind: "approvals", Severity: "warn", Label: fmt.Sprintf("%d %s", n, plural(n, "approval", "approvals")),
				Detail: "waiting for you · oldest " + humanDuration(time.Until(oldest)) + " left", Link: "/approvals"})
		}
	}

	// New critical CVEs (first seen in the last 24 h) in running images in scope.
	var cves, imgs int
	err = a.DB.QueryRow(ctx, `SELECT count(DISTINCT v.cve_id), count(DISTINCT v.digest) FROM image_vulns v
		WHERE lower(v.severity) = 'critical' AND v.first_seen_at > now() - interval '24 hours'
		  AND EXISTS (SELECT 1 FROM image_usage u WHERE u.digest = v.digest AND u.cluster_id = ANY($1))`, clusterIDs).Scan(&cves, &imgs)
	if err != nil {
		return nil, err
	}
	if cves > 0 {
		out = append(out, AttentionItem{Kind: "critical_cves", Severity: "crit", Label: "Critical CVEs",
			Detail: fmt.Sprintf("%d new in %d %s", cves, imgs, plural(imgs, "image", "images")), Link: "/security"})
	}
	if a.MoreAttention != nil {
		// Another module's items are extra: its failure does not take the
		// dashboard down.
		if more, err := a.MoreAttention(ctx, s); err != nil {
			if a.Log != nil {
				a.Log.Warn("dashboard: more attention items", "err", err)
			}
		} else {
			out = append(out, more...)
		}
	}
	return out, nil
}

func shortErr(s string) string {
	if s == "" {
		return "see run details"
	}
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:57] + "…"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d d", int(d.Hours()/24))
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
