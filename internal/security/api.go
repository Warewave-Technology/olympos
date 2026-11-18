package security

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /images, /security/* and /registries.
type API struct {
	DB       *store.DB
	Log      *slog.Logger
	Envelope *secrets.Envelope
	// Scanner is poked after manual scans and registry changes (optional).
	Scanner *Scanner
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Get("/images", a.listImages)
	r.Post("/images/scan", a.scanAll)
	r.Get("/images/{digest}", a.getImage)
	r.Post("/images/{digest}/scan", a.scanImage)
	r.Get("/security/kyverno", a.listKyverno)
	r.Get("/security/netpol", a.listNetpol)
	r.Get("/registries", a.listRegistries)
	r.Post("/registries", a.createRegistry)
	r.Post("/registries/test", a.testRegistry)
	r.Patch("/registries/{id}", a.patchRegistry)
	r.Delete("/registries/{id}", a.deleteRegistry)
}

func (a *API) poke() {
	if a.Scanner != nil {
		a.Scanner.Poke()
	}
}

// scopedClusters returns the readable clusters, narrowed by ?cluster= (ID or
// name). An unknown or invisible cluster yields an empty set.
func (a *API) scopedClusters(r *http.Request) ([]uuid.UUID, error) {
	vis, err := httpx.ScopedClusters(r.Context(), a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		return nil, err
	}
	want := strings.TrimSpace(r.URL.Query().Get("cluster"))
	if want == "" {
		return vis, nil
	}
	var id uuid.UUID
	if err := a.DB.QueryRow(r.Context(), `SELECT id FROM clusters WHERE id::text = $1 OR name = $1 LIMIT 1`, want).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []uuid.UUID{}, nil
		}
		return nil, err
	}
	for _, v := range vis {
		if v == id {
			return []uuid.UUID{id}, nil
		}
	}
	return []uuid.UUID{}, nil
}

// ---------------------------------------------------------------- images

// Image is the API shape of an image (by digest).
type Image struct {
	Digest        string     `json:"digest"`
	Repo          string     `json:"repo"`
	Tags          []string   `json:"tags"`
	Clusters      int        `json:"clusters"`
	Workloads     int        `json:"workloads"`
	Critical      int        `json:"critical"`
	High          int        `json:"high"`
	Medium        int        `json:"medium"`
	Low           int        `json:"low"`
	Fixable       int        `json:"fixable"`
	ScanStatus    string     `json:"scan_status"`
	LastScannedAt *time.Time `json:"last_scanned_at"`
	Registry      string     `json:"registry"`
}

// Usage is where an image runs.
type Usage struct {
	ClusterID    uuid.UUID `json:"cluster_id"`
	ClusterName  string    `json:"cluster_name"`
	Namespace    string    `json:"namespace"`
	WorkloadKind string    `json:"workload_kind"`
	WorkloadName string    `json:"workload_name"`
	Container    string    `json:"container"`
	Image        string    `json:"image"`
}

// ImageDetail adds usage and vulnerabilities.
type ImageDetail struct {
	Image
	Usage     []Usage `json:"usage"`
	Vulns     []Vuln  `json:"vulns"`
	ScanError string  `json:"scan_error"`
}

const imageSelect = `
	SELECT i.digest, i.repo, i.tags, i.critical, i.high, i.medium, i.low, i.scan_status, i.last_scanned_at,
	       count(DISTINCT u.cluster_id),
	       count(DISTINCT (u.cluster_id, u.namespace, u.workload_kind, u.workload_name)),
	       (SELECT count(DISTINCT v.cve_id) FROM image_vulns v
	         WHERE v.digest = i.digest AND v.severity IN ('critical','high') AND v.fixed_in <> '')
	FROM images i JOIN image_usage u ON u.digest = i.digest
	WHERE u.cluster_id = ANY($1)`

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (a *API) registryLabel(regs []RegistryRef, repo string) string {
	if m := MatchRegistry(regs, repo); m != nil {
		return m.HostPattern
	}
	if IsPublicHost(HostOf(repo)) {
		return "public"
	}
	return ""
}

func (a *API) scanImages(rows pgx.Rows, regs []RegistryRef) ([]Image, error) {
	defer rows.Close()
	out := []Image{}
	for rows.Next() {
		var im Image
		if err := rows.Scan(&im.Digest, &im.Repo, &im.Tags, &im.Critical, &im.High, &im.Medium, &im.Low, &im.ScanStatus,
			&im.LastScannedAt, &im.Clusters, &im.Workloads, &im.Fixable); err != nil {
			return nil, err
		}
		if im.Tags == nil {
			im.Tags = []string{}
		}
		im.Registry = a.registryLabel(regs, im.Repo)
		out = append(out, im)
	}
	return out, rows.Err()
}

func (a *API) listImages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := a.scopedClusters(r)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	q := r.URL.Query()
	sev, status, text := q.Get("severity"), q.Get("status"), strings.TrimSpace(q.Get("q"))
	if sev != "" && sev != "critical" && sev != "high" {
		httpx.FieldErrors(w, "invalid filter", map[string]string{"severity": "Use critical or high."})
		return
	}
	regs, err := registryRefs(ctx, a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, imageSelect+`
		  AND ($2 = '' OR i.scan_status = $2)
		  AND ($3 = '' OR ($3 = 'critical' AND i.critical > 0) OR ($3 = 'high' AND i.critical + i.high > 0))
		  AND ($4 = '' OR i.repo ILIKE '%' || $4 || '%' OR i.digest LIKE $4 || '%'
		       OR array_to_string(i.tags, ' ') ILIKE '%' || $4 || '%')
		GROUP BY i.digest
		ORDER BY i.critical DESC, i.high DESC, i.repo, i.digest
		LIMIT 2000`, ids, status, sev, likeEscape(text))
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	items, err := a.scanImages(rows, regs)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func digestParam(r *http.Request) (string, bool) {
	d, err := url.PathUnescape(chi.URLParam(r, "digest"))
	if err != nil {
		return "", false
	}
	d = strings.ToLower(d)
	return d, DigestRe.MatchString(d)
}

func (a *API) getImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	digest, ok := digestParam(r)
	if !ok {
		httpx.NotFound(w)
		return
	}
	ids, err := httpx.ScopedClusters(ctx, a.DB, httpx.Subject(r), authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	regs, err := registryRefs(ctx, a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, imageSelect+` AND i.digest = $2 GROUP BY i.digest`, ids, digest)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	items, err := a.scanImages(rows, regs)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	if len(items) == 0 {
		httpx.NotFound(w) // unknown, or not running in any cluster the caller can read
		return
	}
	d := ImageDetail{Image: items[0], Usage: []Usage{}, Vulns: []Vuln{}}
	if err := a.DB.QueryRow(ctx, `SELECT scan_error FROM images WHERE digest = $1`, digest).Scan(&d.ScanError); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	urows, err := a.DB.Query(ctx, `
		SELECT u.cluster_id, c.name, u.namespace, u.workload_kind, u.workload_name, u.container, u.image
		FROM image_usage u JOIN clusters c ON c.id = u.cluster_id
		WHERE u.digest = $1 AND u.cluster_id = ANY($2)
		ORDER BY c.name, u.namespace, u.workload_kind, u.workload_name, u.container`, digest, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	for urows.Next() {
		var u Usage
		if err := urows.Scan(&u.ClusterID, &u.ClusterName, &u.Namespace, &u.WorkloadKind, &u.WorkloadName, &u.Container, &u.Image); err != nil {
			urows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		d.Usage = append(d.Usage, u)
	}
	urows.Close()
	vrows, err := a.DB.Query(ctx, `
		SELECT cve_id, severity, package, installed, fixed_in, title FROM image_vulns WHERE digest = $1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cve_id, package`, digest)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	for vrows.Next() {
		var v Vuln
		if err := vrows.Scan(&v.CVEID, &v.Severity, &v.Package, &v.Installed, &v.FixedIn, &v.Title); err != nil {
			vrows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		d.Vulns = append(d.Vulns, v)
	}
	vrows.Close()
	httpx.JSON(w, http.StatusOK, d)
}

func (a *API) scanImage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := httpx.Subject(r)
	digest, ok := digestParam(r)
	if !ok {
		httpx.NotFound(w)
		return
	}
	rows, err := a.DB.Query(ctx, `SELECT DISTINCT c.id, c.labels FROM image_usage u JOIN clusters c ON c.id = u.cluster_id WHERE u.digest = $1`, digest)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	visible, allowed := false, false
	for rows.Next() {
		var id uuid.UUID
		var labels map[string]string
		if err := rows.Scan(&id, &labels); err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		visible = visible || s.Can(authz.PermRead, labels)
		allowed = allowed || s.Can(authz.PermOperate, labels)
	}
	rows.Close()
	if !visible {
		httpx.NotFound(w)
		return
	}
	if !allowed {
		httpx.Forbidden(w, "")
		return
	}
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE images SET scan_status = 'pending', scan_error = ''
			WHERE digest = $1 AND scan_status <> 'scanning'`, digest); err != nil {
			return err
		}
		return httpx.Record(r, tx, "image.scan_requested", "image", digest, nil, nil)
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.poke()
	httpx.JSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// ---------------------------------------------------------------- kyverno / netpol

// KyvernoPolicy is the API shape of a policy.
type KyvernoPolicy struct {
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	Mode        string    `json:"mode"`
	Rules       int       `json:"rules"`
	RuleNames   []string  `json:"rule_names"`
	FailCount   int       `json:"fail_count"`
	Ready       bool      `json:"ready"`
}

// KyvernoCluster is Kyverno's install state on a cluster.
type KyvernoCluster struct {
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	Installed   bool      `json:"installed"`
	Policies    int       `json:"policies"`
	FailCount   int       `json:"fail_count"`
	ReportedAt  time.Time `json:"reported_at"`
}

func (a *API) listKyverno(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ids, err := a.scopedClusters(r)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, `
		SELECT p.cluster_id, c.name, p.namespace, p.name, p.mode, p.rules, p.fail_count, p.ready
		FROM kyverno_policies p JOIN clusters c ON c.id = p.cluster_id
		WHERE p.cluster_id = ANY($1)
		ORDER BY p.fail_count DESC, c.name, p.namespace, p.name`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	items := []KyvernoPolicy{}
	for rows.Next() {
		var p KyvernoPolicy
		if err := rows.Scan(&p.ClusterID, &p.ClusterName, &p.Namespace, &p.Name, &p.Mode, &p.RuleNames, &p.FailCount, &p.Ready); err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if p.RuleNames == nil {
			p.RuleNames = []string{}
		}
		p.Rules = len(p.RuleNames)
		items = append(items, p)
	}
	rows.Close()
	crows, err := a.DB.Query(ctx, `
		SELECT s.cluster_id, c.name, s.installed, s.policy_count, s.fail_count, s.reported_at
		FROM kyverno_status s JOIN clusters c ON c.id = s.cluster_id
		WHERE s.cluster_id = ANY($1) ORDER BY c.name`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	clusters := []KyvernoCluster{}
	for crows.Next() {
		var c KyvernoCluster
		if err := crows.Scan(&c.ClusterID, &c.ClusterName, &c.Installed, &c.Policies, &c.FailCount, &c.ReportedAt); err != nil {
			crows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		clusters = append(clusters, c)
	}
	crows.Close()
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "clusters": clusters})
}

// NetpolNamespace is the API shape of a namespace's NetworkPolicy status.
type NetpolNamespace struct {
	ClusterID   uuid.UUID `json:"cluster_id"`
	ClusterName string    `json:"cluster_name"`
	Namespace   string    `json:"namespace"`
	PolicyCount int       `json:"policy_count"`
	DefaultDeny bool      `json:"default_deny"`
	Excluded    bool      `json:"excluded"`
}

func (a *API) listNetpol(w http.ResponseWriter, r *http.Request) {
	ids, err := a.scopedClusters(r)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(r.Context(), `
		SELECT n.cluster_id, c.name, n.namespace, n.policy_count, n.default_deny, n.excluded
		FROM network_policy_status n JOIN clusters c ON c.id = n.cluster_id
		WHERE n.cluster_id = ANY($1)
		ORDER BY n.excluded, n.default_deny, c.name, n.namespace`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	defer rows.Close()
	items := []NetpolNamespace{}
	for rows.Next() {
		var n NetpolNamespace
		if err := rows.Scan(&n.ClusterID, &n.ClusterName, &n.Namespace, &n.PolicyCount, &n.DefaultDeny, &n.Excluded); err != nil {
			httpx.Internal(w, r, a.Log, err)
			return
		}
		items = append(items, n)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// ---------------------------------------------------------------- registries

// UnmatchedRegistry groups images that could not be pulled for lack of a
// credential, by registry host.
type UnmatchedRegistry struct {
	Host        string `json:"host"`
	Images      int    `json:"images"`
	ExampleRepo string `json:"example_repo"`
}

func (a *API) listRegistries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := httpx.Subject(r)
	if !s.CanAny(authz.PermRead) {
		httpx.Forbidden(w, "")
		return
	}
	regs, err := ListRegistries(ctx, a.DB)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	// Counts and unmatched hosts only consider images running in clusters
	// the caller can read.
	ids, err := httpx.ScopedClusters(ctx, a.DB, s, authz.PermRead)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rows, err := a.DB.Query(ctx, `SELECT i.digest, i.repo, i.scan_status FROM images i
		WHERE EXISTS (SELECT 1 FROM image_usage u WHERE u.digest = i.digest AND u.cluster_id = ANY($1))`, ids)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	refs := make([]RegistryRef, len(regs))
	idx := map[uuid.UUID]int{}
	for i, g := range regs {
		refs[i] = g.Ref()
		idx[g.ID] = i
	}
	unmatched := map[string]*UnmatchedRegistry{}
	for rows.Next() {
		var digest, repo, status string
		if err := rows.Scan(&digest, &repo, &status); err != nil {
			rows.Close()
			httpx.Internal(w, r, a.Log, err)
			return
		}
		if m := MatchRegistry(refs, repo); m != nil {
			regs[idx[m.ID]].Images++
		}
		if status == "missing_credential" {
			h := HostOf(repo)
			u := unmatched[h]
			if u == nil {
				u = &UnmatchedRegistry{Host: h, ExampleRepo: repo}
				unmatched[h] = u
			}
			u.Images++
			if repo < u.ExampleRepo {
				u.ExampleRepo = repo
			}
		}
	}
	rows.Close()
	um := make([]UnmatchedRegistry, 0, len(unmatched))
	for _, u := range unmatched {
		um = append(um, *u)
	}
	sort.Slice(um, func(i, j int) bool {
		if um[i].Images != um[j].Images {
			return um[i].Images > um[j].Images
		}
		return um[i].Host < um[j].Host
	})
	httpx.JSON(w, http.StatusOK, map[string]any{"items": regs, "unmatched": um})
}

type registryInput struct {
	HostPattern *string       `json:"host_pattern"`
	Username    *string       `json:"username"`
	Password    *SecretSource `json:"password"`
}

var patternRe = regexp.MustCompile(`^[a-z0-9*?]([a-z0-9.*?:_/-]*[a-z0-9*?])?$`)

// ValidatePattern checks a host pattern. Wildcards in the host must leave at
// least two literal labels ("*.azurecr.io" is fine, "*" or "*.io" is not):
// a match sends the credential to that registry, and image strings come from
// workloads in managed clusters.
func ValidatePattern(p string) (string, string) {
	n := normalizePattern(p)
	if n == "" {
		return "", "Required."
	}
	if len(n) > 255 || !patternRe.MatchString(n) {
		return "", "Use a registry host, optionally with a path, e.g. acr.contoso.io or ghcr.io/contoso/*."
	}
	host := HostOf(n)
	if strings.ContainsAny(host, "*?") {
		lit := host[strings.LastIndexAny(host, "*?")+1:]
		lit = strings.TrimPrefix(lit, ".")
		if strings.Count(lit, ".") < 1 {
			return "", "A wildcard host must end in a registry domain, e.g. *.azurecr.io."
		}
	}
	return n, ""
}

func validateSecret(src *SecretSource, allowNone bool) string {
	switch src.Source {
	case "keyvault_ref":
		if _, err := secrets.ParseRef(src.Ref); err != nil {
			return err.Error()
		}
		if src.Value != "" {
			return "Give either a Key Vault reference or a value, not both."
		}
	case "stored":
		if src.Value == "" {
			return "Required."
		}
		if len(src.Value) > 8192 {
			return "Too long."
		}
		if src.Ref != "" {
			return "Give either a Key Vault reference or a value, not both."
		}
	case "none":
		if !allowNone {
			return "Use keyvault_ref or stored."
		}
	default:
		return "Use keyvault_ref or stored."
	}
	return ""
}

func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !httpx.Subject(r).CanGlobal(authz.PermAdmin) {
		httpx.Forbidden(w, "")
		return false
	}
	return true
}

func (a *API) createRegistry(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	ctx := r.Context()
	var in registryInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	defer zeroInput(&in)
	fields := map[string]string{}
	pattern := ""
	if in.HostPattern == nil {
		fields["host_pattern"] = "Required."
	} else if p, msg := ValidatePattern(*in.HostPattern); msg != "" {
		fields["host_pattern"] = msg
	} else {
		pattern = p
	}
	username := ""
	if in.Username != nil {
		username = strings.TrimSpace(*in.Username)
	}
	if in.Password != nil && in.Password.Source == "none" {
		in.Password = nil
	}
	if in.Password != nil {
		if msg := validateSecret(in.Password, false); msg != "" {
			fields["password"] = msg
		}
		if username == "" {
			fields["username"] = "Required with a password."
		}
	} else if username != "" {
		fields["password"] = "Required with a username."
	}
	if len(username) > 256 {
		fields["username"] = "Too long."
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid registry", fields)
		return
	}
	var id uuid.UUID
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		var credID *uuid.UUID
		src := ""
		if in.Password != nil {
			cid, err := createCredential(ctx, tx, a.Envelope, username, *in.Password)
			if err != nil {
				return err
			}
			credID, src = &cid, in.Password.Source
		}
		if err := tx.QueryRow(ctx, `INSERT INTO registries (host_pattern, credential_id) VALUES ($1, $2) RETURNING id`,
			pattern, credID).Scan(&id); err != nil {
			return err
		}
		if err := RequeueUnscanned(ctx, tx); err != nil {
			return err
		}
		return httpx.Record(r, tx, "registry.created", "registry", id.String(), nil,
			map[string]any{"host_pattern": pattern, "credential_source": src})
	})
	if store.IsUniqueViolation(err) {
		httpx.FieldErrors(w, "invalid registry", map[string]string{"host_pattern": "A registry with this host pattern already exists."})
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.poke()
	reg, err := GetRegistry(ctx, a.DB, id)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, reg)
}

func zeroInput(in *registryInput) {
	if in.Password != nil {
		// Strings are immutable; dropping the reference is the best we can do.
		in.Password.Value = ""
	}
}

func (a *API) patchRegistry(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	ctx := r.Context()
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	cur, err := GetRegistry(ctx, a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var in registryInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	defer zeroInput(&in)
	fields := map[string]string{}
	pattern := cur.HostPattern
	if in.HostPattern != nil {
		if p, msg := ValidatePattern(*in.HostPattern); msg != "" {
			fields["host_pattern"] = msg
		} else {
			pattern = p
		}
	}
	username := cur.Username
	if in.Username != nil {
		username = strings.TrimSpace(*in.Username)
		if len(username) > 256 {
			fields["username"] = "Too long."
		}
	}
	if in.Password != nil {
		if msg := validateSecret(in.Password, true); msg != "" {
			fields["password"] = msg
		} else if in.Password.Source != "none" && username == "" {
			fields["username"] = "Required with a password."
		}
	} else if in.Username != nil && cur.CredentialID == nil && username != "" {
		fields["password"] = "Required with a username."
	} else if in.Username != nil && cur.CredentialID != nil && username == "" {
		fields["username"] = "Required while a password is set. Remove the password with source none."
	}
	if len(fields) > 0 {
		httpx.FieldErrors(w, "invalid registry", fields)
		return
	}
	err = store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		details := map[string]any{}
		if pattern != cur.HostPattern {
			if _, err := tx.Exec(ctx, `UPDATE registries SET host_pattern = $2 WHERE id = $1`, id, pattern); err != nil {
				return err
			}
			details["host_pattern"] = pattern
		}
		switch {
		case in.Password != nil:
			var newID *uuid.UUID
			if in.Password.Source != "none" {
				cid, err := createCredential(ctx, tx, a.Envelope, username, *in.Password)
				if err != nil {
					return err
				}
				newID = &cid
			}
			if _, err := tx.Exec(ctx, `UPDATE registries SET credential_id = $2 WHERE id = $1`, id, newID); err != nil {
				return err
			}
			if cur.CredentialID != nil {
				if _, err := tx.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, *cur.CredentialID); err != nil {
					return err
				}
			}
			details["credential_source"] = in.Password.Source
		case in.Username != nil && cur.CredentialID != nil && username != cur.Username:
			if _, err := tx.Exec(ctx, `UPDATE credentials SET username = $2 WHERE id = $1`, *cur.CredentialID, username); err != nil {
				return err
			}
			details["username_changed"] = true
		}
		if err := RequeueUnscanned(ctx, tx); err != nil {
			return err
		}
		return httpx.Record(r, tx, "registry.updated", "registry", id.String(), nil, details)
	})
	if store.IsUniqueViolation(err) {
		httpx.FieldErrors(w, "invalid registry", map[string]string{"host_pattern": "A registry with this host pattern already exists."})
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	a.poke()
	reg, err := GetRegistry(ctx, a.DB, id)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, reg)
}

func (a *API) deleteRegistry(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	ctx := r.Context()
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	err := store.Tx(ctx, a.DB, func(tx pgx.Tx) error {
		var pattern string
		var credID *uuid.UUID
		if err := tx.QueryRow(ctx, `DELETE FROM registries WHERE id = $1 RETURNING host_pattern, credential_id`, id).Scan(&pattern, &credID); err != nil {
			return store.NotFound(err)
		}
		if credID != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, *credID); err != nil {
				return err
			}
		}
		return httpx.Record(r, tx, "registry.deleted", "registry", id.String(), nil, map[string]any{"host_pattern": pattern})
	})
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
