package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/approvals"
	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /vaults.
type API struct {
	Svc *Service
	Log *slog.Logger
	// RequireTLS rejects root tokens sent over plain HTTP (production).
	RequireTLS bool
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Get("/vaults", a.list)
	r.Get("/vaults/search", a.search)
	r.Get("/vaults/{id}", a.get)
	r.Post("/vaults/{id}/inspect", a.inspect)
	r.Post("/vaults/{id}/configure", a.configure)
	r.Post("/vaults/{id}/refresh", a.refresh)
	r.Get("/vaults/{id}/tree", a.tree)
	r.Get("/vaults/{id}/secrets/*", a.secret)
}

// View is the API shape of a vault (no role_id, no secret_id reference).
type View struct {
	ID                uuid.UUID         `json:"id"`
	Target            inventory.Target  `json:"target"`
	ClusterLabels     map[string]string `json:"cluster_labels"`
	Provider          string            `json:"provider"`
	Version           string            `json:"version"`
	Status            string            `json:"status"`
	KVMounts          []KVMount         `json:"kv_mounts"`
	ConfiguredByName  string            `json:"configured_by_name"`
	ConfiguredAt      *time.Time        `json:"configured_at"`
	SecretIDRotatedAt *time.Time        `json:"secret_id_rotated_at"`
	LastIndexAt       *time.Time        `json:"last_index_at"`
	Secrets           int               `json:"secrets"`
	Drift             int               `json:"drift"`
	LastError         string            `json:"last_error"`
	TLSServerName     string            `json:"tls_server_name"`
	TransferMode      string            `json:"transfer_mode"`
	CABundleSet       bool              `json:"ca_bundle_set"`
}

func (a *API) view(ctx context.Context, q store.Querier, r *row) (View, error) {
	v := View{ID: r.ID, Provider: r.Provider, Version: r.Version, Status: r.Status, KVMounts: r.Mounts,
		ConfiguredByName: r.ConfiguredByName, ConfiguredAt: r.ConfiguredAt, SecretIDRotatedAt: r.RotatedAt,
		LastIndexAt: r.LastIndexAt, LastError: r.LastError, TLSServerName: r.serverName(), TransferMode: r.TransferMode,
		CABundleSet: strings.TrimSpace(r.CABundle) != "", ClusterLabels: r.Labels,
		Target: inventory.Target{ID: r.TargetID, ClusterID: r.ClusterID, ClusterName: r.ClusterName, Namespace: r.Namespace,
			Service: r.Service, Port: r.Port, PortName: r.PortName, Engine: r.Engine, VaultProvider: r.Provider,
			TLSServerName: r.TLSServerName, DetectedVersion: r.DetectedVersion, TLSOK: r.TLSOK, Status: r.TargetStatus,
			FirstSeenAt: r.FirstSeenAt, LastSeenAt: r.LastSeenAt}}
	if v.KVMounts == nil {
		v.KVMounts = []KVMount{}
	}
	if v.ClusterLabels == nil {
		v.ClusterLabels = map[string]string{}
	}
	err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM vault_secret_index WHERE vault_id = $1),
		(SELECT count(*) FROM findings WHERE source = 'vault-drift' AND status = 'open' AND cluster_id = $2 AND control_id = $3)`,
		r.ID, r.ClusterID, DriftControlID(r.ID)).Scan(&v.Secrets, &v.Drift)
	return v, err
}

// visible loads the vault and checks read scope (404 outside scope).
func (a *API) visible(w http.ResponseWriter, r *http.Request) (*row, bool) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	vr, err := loadRow(r.Context(), a.Svc.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return nil, false
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return nil, false
	}
	if !httpx.Subject(r).Can(authz.PermRead, vr.Labels) {
		httpx.NotFound(w)
		return nil, false
	}
	return vr, true
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub := httpx.Subject(r)
	rows, err := a.Svc.DB.Query(ctx, rowSelect+` WHERE c.status <> 'revoked' ORDER BY c.name, t.namespace, t.service`)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var rs []*row
	for rows.Next() {
		vr, err := scanRow(rows)
		if err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if sub.Can(authz.PermRead, vr.Labels) {
			rs = append(rs, vr)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	out := []View{}
	for _, vr := range rs {
		v, err := a.view(ctx, a.Svc.DB, vr)
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		out = append(out, v)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	vr, ok := a.visible(w, r)
	if !ok {
		return
	}
	v, err := a.view(r.Context(), a.Svc.DB, vr)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// token decodes a JSON string into bytes so it can be zeroed after use.
type token []byte

func (t *token) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("root_token must be a string")
	}
	*t = []byte(s)
	return nil
}

func (a *API) secureTransport(r *http.Request) bool {
	if !a.RequireTLS {
		return true
	}
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *API) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ue *UserError
	switch {
	case errors.As(err, &ue):
		if len(ue.Fields) > 0 {
			httpx.FieldErrors(w, ue.Msg, ue.Fields)
			return
		}
		httpx.Error(w, ue.Code, ue.Msg)
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	default:
		httpx.Internal(w, r, a.Log, err)
	}
}

// adminVault: visible + admin on the vault's cluster.
func (a *API) adminVault(w http.ResponseWriter, r *http.Request) (*row, bool) {
	vr, ok := a.visible(w, r)
	if !ok {
		return nil, false
	}
	if !httpx.Subject(r).Can(authz.PermAdmin, vr.Labels) {
		httpx.Forbidden(w, "configuring a vault requires the admin role")
		return nil, false
	}
	if !a.secureTransport(r) {
		httpx.Error(w, http.StatusBadRequest, "the root token must be sent over TLS")
		return nil, false
	}
	return vr, true
}

type inspectInput struct {
	RootToken token   `json:"root_token"`
	CABundle  *string `json:"ca_bundle"`
}

func (a *API) inspect(w http.ResponseWriter, r *http.Request) {
	var in inspectInput
	defer func() { secrets.Zero(in.RootToken) }()
	vr, ok := a.adminVault(w, r)
	if !ok {
		return
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(in.RootToken) == 0 {
		httpx.FieldErrors(w, "root token required", map[string]string{"root_token": "required"})
		return
	}
	res, err := a.Svc.Inspect(r.Context(), vr.ID, in.RootToken, in.CABundle)
	if err != nil {
		a.writeErr(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

type configureInput struct {
	RootToken token    `json:"root_token"`
	Mounts    []string `json:"mounts"`
	CABundle  *string  `json:"ca_bundle"`
}

func (a *API) configure(w http.ResponseWriter, r *http.Request) {
	var in configureInput
	defer func() { secrets.Zero(in.RootToken) }()
	vr, ok := a.adminVault(w, r)
	if !ok {
		return
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(in.RootToken) == 0 {
		httpx.FieldErrors(w, "root token required", map[string]string{"root_token": "required"})
		return
	}
	sub := httpx.Subject(r)
	err := a.Svc.Configure(r.Context(), vr.ID, ConfigureInput{RootToken: in.RootToken, Mounts: in.Mounts, CABundle: in.CABundle, Actor: sub.Principal.ID})
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			// Record the failed attempt (no token, safe message only).
			_ = httpx.Record(r, a.Svc.DB, "vault.configure_failed", "vault", vr.ID.String(), &vr.ClusterID, map[string]any{"error": ue.Msg})
		}
		a.writeErr(w, r, err)
		return
	}
	a.Log.Info("vault configured", "vault_id", vr.ID, "cluster_id", vr.ClusterID)
	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := a.Svc.Refresh(ctx, id); err != nil {
			a.Log.Error("vault index refresh after configure", "vault_id", id, "err", err)
		}
	}(vr.ID)
	nr, err := loadRow(r.Context(), a.Svc.DB, vr.ID)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	v, err := a.view(r.Context(), a.Svc.DB, nr)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	vr, ok := a.visible(w, r)
	if !ok {
		return
	}
	sub := httpx.Subject(r)
	if !(sub.Can(authz.PermOperate, vr.Labels) || sub.Can(authz.PermVaultMake, vr.Labels) || sub.Can(authz.PermVaultApprove, vr.Labels)) {
		httpx.Forbidden(w, "")
		return
	}
	if vr.Status != "configured" {
		httpx.Error(w, http.StatusConflict, "this vault is not configured")
		return
	}
	_ = httpx.Record(r, a.Svc.DB, "vault.refresh", "vault", vr.ID.String(), &vr.ClusterID, nil)
	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := a.Svc.Refresh(ctx, id); err != nil {
			a.Log.Error("vault index refresh", "vault_id", id, "err", err)
		}
	}(vr.ID)
	httpx.JSON(w, http.StatusAccepted, map[string]any{"status": "started"})
}

// SecretSummary is one indexed secret path.
type SecretSummary struct {
	Mount          string     `json:"mount"`
	Path           string     `json:"path"`
	Keys           int        `json:"keys"`
	CurrentVersion int        `json:"current_version"`
	UpdatedTime    *time.Time `json:"updated_time"`
	Managed        bool       `json:"managed"`
}

func (a *API) tree(w http.ResponseWriter, r *http.Request) {
	vr, ok := a.visible(w, r)
	if !ok {
		return
	}
	mount := ""
	if m := r.URL.Query().Get("mount"); m != "" {
		mount = approvals.NormalizeMount(m)
	}
	rows, err := a.Svc.DB.Query(r.Context(), `SELECT mount, path, cardinality(keys), current_version, updated_time, managed
		FROM vault_secret_index WHERE vault_id = $1 AND ($2 = '' OR mount = $2) ORDER BY mount, path`, vr.ID, mount)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	out := []SecretSummary{}
	for rows.Next() {
		var s SecretSummary
		if err := rows.Scan(&s.Mount, &s.Path, &s.Keys, &s.CurrentVersion, &s.UpdatedTime, &s.Managed); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

// SecretVersion is one version with provenance.
type SecretVersion struct {
	Version      int    `json:"version"`
	CreatedTime  string `json:"created_time"`
	DeletionTime string `json:"deletion_time"`
	Destroyed    bool   `json:"destroyed"`
	ByOlympos    bool   `json:"by_olympos"`
}

// SecretDetail is keys and versions of one secret. Values never.
type SecretDetail struct {
	Mount                 string          `json:"mount"`
	Path                  string          `json:"path"`
	Keys                  []string        `json:"keys"`
	CurrentVersion        int             `json:"current_version"`
	UpdatedTime           *time.Time      `json:"updated_time"`
	Managed               bool            `json:"managed"`
	Versions              []SecretVersion `json:"versions"`
	PendingChangeRequests int             `json:"pending_change_requests"`
}

func (a *API) secret(w http.ResponseWriter, r *http.Request) {
	vr, ok := a.visible(w, r)
	if !ok {
		return
	}
	mount := approvals.NormalizeMount(r.URL.Query().Get("mount"))
	path, okp := approvals.NormalizePath(chi.URLParam(r, "*"))
	if mount == "" || !okp {
		httpx.NotFound(w)
		return
	}
	ctx := r.Context()
	d := SecretDetail{Mount: mount, Path: path}
	var vb []byte
	err := a.Svc.DB.QueryRow(ctx, `SELECT keys, current_version, updated_time, managed, versions FROM vault_secret_index
		WHERE vault_id = $1 AND mount = $2 AND path = $3`, vr.ID, mount, path).Scan(&d.Keys, &d.CurrentVersion, &d.UpdatedTime, &d.Managed, &vb)
	if err != nil {
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			httpx.NotFound(w)
			return
		}
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var vs []VersionInfo
	_ = json.Unmarshal(vb, &vs)
	byOlympos := map[int]bool{}
	rows, err := a.Svc.DB.Query(ctx, `SELECT version FROM vault_managed_versions WHERE vault_id = $1 AND mount = $2 AND path = $3`, vr.ID, mount, path)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err == nil {
			byOlympos[v] = true
		}
	}
	rows.Close()
	d.Versions = []SecretVersion{}
	for _, v := range vs {
		d.Versions = append(d.Versions, SecretVersion{Version: v.Version, CreatedTime: v.CreatedTime, DeletionTime: v.DeletionTime,
			Destroyed: v.Destroyed, ByOlympos: byOlympos[v.Version]})
	}
	if d.Keys == nil {
		d.Keys = []string{}
	}
	if err := a.Svc.DB.QueryRow(ctx, `SELECT count(DISTINCT cr.id) FROM change_requests cr JOIN change_items ci ON ci.cr_id = cr.id
		WHERE cr.vault_id = $1 AND cr.status = 'pending' AND ci.mount = $2 AND ci.path = $3`, vr.ID, mount, path).Scan(&d.PendingChangeRequests); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

// SearchHit is one result of GET /vaults/search.
type SearchHit struct {
	Match       string    `json:"match"` // vault | path
	VaultID     uuid.UUID `json:"vault_id"`
	VaultName   string    `json:"vault_name"`
	Provider    string    `json:"provider"`
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	Namespace   string    `json:"namespace"`
	Mount       string    `json:"mount,omitempty"`
	Path        string    `json:"path,omitempty"`
	Keys        int       `json:"keys"`
}

// search finds vaults (name, cluster, namespace, provider, cluster labels)
// and indexed secret paths across every vault the caller can read.
func (a *API) search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len([]rune(q)) < 2 {
		httpx.FieldErrors(w, "invalid search", map[string]string{"q": "Type at least 2 characters."})
		return
	}
	lq := strings.ToLower(q)
	sub := httpx.Subject(r)
	rows, err := a.Svc.DB.Query(ctx, rowSelect+` WHERE c.status <> 'revoked' ORDER BY c.name, t.namespace, t.service`)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	byID := map[uuid.UUID]*row{}
	var ids []uuid.UUID
	out := []SearchHit{}
	for rows.Next() {
		vr, err := scanRow(rows)
		if err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if !sub.Can(authz.PermRead, vr.Labels) {
			continue
		}
		byID[vr.ID], ids = vr, append(ids, vr.ID)
		hay := []string{vr.Service, vr.ClusterName, vr.Namespace, vr.Provider, vr.Namespace + "/" + vr.Service}
		for k, v := range vr.Labels {
			hay = append(hay, k+"="+v, v)
		}
		for _, h := range hay {
			if strings.Contains(strings.ToLower(h), lq) {
				out = append(out, SearchHit{Match: "vault", VaultID: vr.ID, VaultName: vr.Service, Provider: vr.Provider,
					ClusterID: vr.ClusterID, ClusterName: vr.ClusterName, Namespace: vr.Namespace})
				break
			}
		}
	}
	rows.Close()
	if len(ids) > 0 && len(out) < 50 {
		prow, err := a.Svc.DB.Query(ctx, `SELECT vault_id, mount, path, cardinality(keys) FROM vault_secret_index
			WHERE vault_id = ANY($1) AND (mount || path) ILIKE '%' || $2 || '%'
			ORDER BY mount, path LIMIT $3`, ids, likeEscape(q), 50-len(out))
		if err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		for prow.Next() {
			var h SearchHit
			if err := prow.Scan(&h.VaultID, &h.Mount, &h.Path, &h.Keys); err != nil {
				prow.Close()
				httpx.Internal(w, r, a.Log, err)
				return
			}
			vr := byID[h.VaultID]
			h.Match, h.VaultName, h.Provider, h.ClusterID, h.ClusterName, h.Namespace = "path", vr.Service, vr.Provider, vr.ClusterID, vr.ClusterName, vr.Namespace
			out = append(out, h)
		}
		prow.Close()
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
