package destinations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Warewave-Technology/olympos/internal/authz"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/httpx"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// API serves /destinations. Reads: any role. Writes and tests: admin with
// scope "all" (destinations are global objects).
type API struct {
	DB   *store.DB
	Log  *slog.Logger
	KV   secrets.KeyVault
	Env  *secrets.Envelope
	Cred azcore.TokenCredential
	Now  func() time.Time
	// Storage: NFS root, S3 CA bundle and part size (config backup.*).
	Storage blob.StorageOptions
	// ProbeTimeout per storage operation of the destination test (0 = 30s).
	ProbeTimeout time.Duration
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) prober() *Prober {
	return &Prober{Cred: a.Cred, Now: a.Now, Storage: a.Storage, Timeout: a.ProbeTimeout}
}

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Route("/destinations", func(r chi.Router) {
		r.Use(httpx.RequireAny(authz.PermRead))
		r.Get("/", a.list)
		r.Post("/", a.create)
		r.Post("/test", a.testUnsaved)
		r.Get("/mounts", a.mounts)
		r.Get("/{id}", a.get)
		r.Patch("/{id}", a.patch)
		r.Delete("/{id}", a.delete)
		r.Post("/{id}/test", a.testSaved)
	})
	a.routesGroups(r)
}

// SecretSourceInput is a Key Vault reference or a value to store.
type SecretSourceInput struct {
	Source string `json:"source"` // keyvault_ref | stored
	Ref    string `json:"ref"`
	Value  string `json:"value"`
}

// Input is the create/patch body (patch: absent fields keep their value).
type Input struct {
	Name             *string `json:"name"`
	Kind             *string `json:"kind"`
	Prefix           *string `json:"prefix"`
	EndpointOverride *string `json:"endpoint_override"`
	Auth             *string `json:"auth"`
	// azure_blob
	Account   *string            `json:"account"`
	Container *string            `json:"container"`
	SAS       *SecretSourceInput `json:"sas"`
	// s3
	Bucket      *string            `json:"bucket"`
	Region      *string            `json:"region"`
	PathStyle   *bool              `json:"path_style"`
	AccessKeyID *string            `json:"access_key_id"`
	SecretKey   *SecretSourceInput `json:"secret_key"`
	// nfs
	Path *string `json:"path"`
}

// View is the API shape of a destination. It never contains the SAS or the
// S3 secret key.
type View struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Kind             string     `json:"kind"`
	Prefix           string     `json:"prefix"`
	EndpointOverride string     `json:"endpoint_override"`
	Auth             string     `json:"auth"`
	Account          string     `json:"account"`
	Container        string     `json:"container"`
	SASSource        string     `json:"sas_source"`
	SASRef           string     `json:"sas_ref"`
	SASExpiresAt     *time.Time `json:"sas_expires_at"`
	SASPermissions   string     `json:"sas_permissions"`
	Bucket           string     `json:"bucket"`
	Region           string     `json:"region"`
	PathStyle        bool       `json:"path_style"`
	AccessKeyID      string     `json:"access_key_id"`
	SecretKeySource  string     `json:"secret_key_source"`
	SecretKeyRef     string     `json:"secret_key_ref"`
	Path             string     `json:"path"`
	LastTestAt       *time.Time `json:"last_test_at"`
	LastTestOK       *bool      `json:"last_test_ok"`
	LastTest         *Report    `json:"last_test"`
	Jobs             int        `json:"jobs"`
	Groups           int        `json:"groups"`
	CreatedAt        time.Time  `json:"created_at"`
	// Warnings are returned by create/patch/test when the saved destination
	// needs attention (e.g. the credential can delete). Never silent.
	Warnings []string `json:"warnings,omitempty"`
}

// TestFailed is the 422 body when create/patch is refused by the test.
type TestFailed struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Test   *Report           `json:"test,omitempty"`
}

const viewSelect = `SELECT d.id, d.name, d.kind, d.prefix, d.endpoint_override, d.auth, d.account, d.container,
	COALESCE(c.kind, ''), COALESCE(c.keyvault_name, ''), COALESCE(c.secret_name, ''), d.sas_expires_at, d.sas_permissions,
	d.bucket, d.region, d.path_style, d.access_key_id,
	COALESCE(k.kind, ''), COALESCE(k.keyvault_name, ''), COALESCE(k.secret_name, ''), d.path,
	d.last_test_at, d.last_test_ok, d.last_test_report, d.created_at,
	(SELECT count(*) FROM backup_jobs j WHERE j.destination_id = d.id),
	(SELECT count(*) FROM destination_group_members m WHERE m.destination_id = d.id)
	FROM destinations d LEFT JOIN credentials c ON c.id = d.sas_credential_id LEFT JOIN credentials k ON k.id = d.secret_credential_id`

func scanViews(rows pgx.Rows) ([]View, error) {
	defer rows.Close()
	out := []View{}
	for rows.Next() {
		var v View
		var kvName, secName, kKV, kSec string
		var report []byte
		if err := rows.Scan(&v.ID, &v.Name, &v.Kind, &v.Prefix, &v.EndpointOverride, &v.Auth, &v.Account, &v.Container,
			&v.SASSource, &kvName, &secName, &v.SASExpiresAt, &v.SASPermissions,
			&v.Bucket, &v.Region, &v.PathStyle, &v.AccessKeyID,
			&v.SecretKeySource, &kKV, &kSec, &v.Path,
			&v.LastTestAt, &v.LastTestOK, &report, &v.CreatedAt, &v.Jobs, &v.Groups); err != nil {
			return nil, err
		}
		if v.SASSource == "keyvault_ref" {
			v.SASRef = secrets.Ref{Vault: kvName, Secret: secName}.String()
		}
		if v.SecretKeySource == "keyvault_ref" {
			v.SecretKeyRef = secrets.Ref{Vault: kKV, Secret: kSec}.String()
		}
		if len(report) > 0 && string(report) != "null" {
			var rep Report
			if json.Unmarshal(report, &rep) == nil {
				v.LastTest = &rep
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func loadView(ctx context.Context, q store.Querier, id uuid.UUID) (View, error) {
	rows, err := q.Query(ctx, viewSelect+` WHERE d.id = $1`, id)
	if err != nil {
		return View{}, err
	}
	vs, err := scanViews(rows)
	if err != nil {
		return View{}, err
	}
	if len(vs) == 0 {
		return View{}, store.ErrNotFound
	}
	return vs[0], nil
}

// nameTaken answers 409 when another destination has the name (checked
// before the probe so a typo does not write probe blobs).
func (a *API) nameTaken(w http.ResponseWriter, r *http.Request, name string, self uuid.UUID) bool {
	var taken bool
	if err := a.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM destinations WHERE name = $1 AND id <> $2)`, name, self).Scan(&taken); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return true
	}
	if taken {
		httpx.JSON(w, http.StatusConflict, httpx.ErrorBody{Error: "a destination with this name already exists", Fields: map[string]string{"name": "already exists"}})
	}
	return taken
}

func canAdmin(r *http.Request) bool { return httpx.Subject(r).CanGlobal(authz.PermAdmin) }

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(r.Context(), viewSelect+` ORDER BY d.name`)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	vs, err := scanViews(rows)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": vs})
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	v, err := loadView(r.Context(), a.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// mounts lists the volumes below the NFS root (GET /destinations/mounts).
func (a *API) mounts(w http.ResponseWriter, r *http.Request) {
	ms, err := blob.ListMounts(a.Storage.NFSRoot)
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": ms})
}

// ---------------------------------------------------------------- validation

var (
	accountRe     = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	prefixRe      = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
	bucketRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)
	regionRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,31}$`)
	accessKeyIDRe = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
)

func validContainer(s string) bool {
	if len(s) < 3 || len(s) > 63 || strings.Contains(s, "--") || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// spec is a normalized, validated destination (plus new secret sources).
type spec struct {
	Name, Kind, Prefix, EndpointOverride, Auth string
	Account, Container                         string
	Bucket, Region, AccessKeyID                string
	PathStyle                                  bool
	Path                                       string
	SAS                                        *SecretSourceInput
	SecretKey                                  *SecretSourceInput
}

func defaultAuth(kind string) string {
	switch kind {
	case blob.KindS3:
		return blob.AuthAccessKey
	case blob.KindNFS:
		return blob.AuthNone
	}
	return blob.AuthManagedIdentity
}

func validateSecretSource(f map[string]string, field string, in *SecretSourceInput) {
	switch in.Source {
	case "keyvault_ref":
		// Destination endpoints are global-admin only (canAdmin); Olympos'
		// own secrets are still refused (security review #2).
		if _, err := secrets.CheckUserRef(strings.TrimSpace(in.Ref), secrets.RefUse{GlobalAdmin: true}); err != nil {
			f[field+".ref"] = err.Error()
		}
		if in.Value != "" {
			f[field+".value"] = "do not send a value with a Key Vault reference"
		}
	case "stored":
		if strings.TrimSpace(in.Value) == "" {
			f[field+".value"] = "required"
		}
	default:
		f[field+".source"] = "keyvault_ref or stored"
	}
}

func hasSecret(in *SecretSourceInput) bool {
	return in != nil && (in.Value != "" || in.Ref != "" || in.Source != "")
}

// validate normalizes s and returns field errors. nfsRoot is where mounts
// live (NFS paths are resolved against the filesystem).
func (s *spec) validate(nfsRoot string) map[string]string {
	f := map[string]string{}
	s.Name = strings.TrimSpace(s.Name)
	s.Prefix = strings.Trim(strings.TrimSpace(s.Prefix), "/")
	s.EndpointOverride = strings.TrimRight(strings.TrimSpace(s.EndpointOverride), "/")
	s.Account = strings.TrimSpace(s.Account)
	s.Container = strings.TrimSpace(s.Container)
	s.Bucket = strings.TrimSpace(s.Bucket)
	s.Region = strings.TrimSpace(s.Region)
	s.AccessKeyID = strings.TrimSpace(s.AccessKeyID)
	s.Path = strings.TrimSpace(s.Path)
	if s.Name == "" {
		f["name"] = "required"
	} else if len(s.Name) > 80 {
		f["name"] = "at most 80 characters"
	}
	if s.Prefix != "" {
		if len(s.Prefix) > 256 {
			f["prefix"] = "at most 256 characters"
		}
		for _, seg := range strings.Split(s.Prefix, "/") {
			if seg == "" || seg == "." || seg == ".." || !prefixRe.MatchString(seg) || seg == blob.ProbeDir {
				f["prefix"] = "path segments of letters, digits, '.', '_' and '-'"
				break
			}
		}
	}
	if s.Auth == "" {
		s.Auth = defaultAuth(s.Kind)
	}
	notFor := func(field string, set bool) {
		if set {
			f[field] = "not used with kind " + s.Kind
		}
	}
	switch s.Kind {
	case blob.KindAzureBlob:
		notFor("bucket", s.Bucket != "")
		notFor("region", s.Region != "")
		notFor("path_style", s.PathStyle)
		notFor("access_key_id", s.AccessKeyID != "")
		notFor("secret_key", hasSecret(s.SecretKey))
		notFor("path", s.Path != "")
		s.validateAzure(f)
	case blob.KindS3:
		notFor("account", s.Account != "")
		notFor("container", s.Container != "")
		notFor("sas", hasSecret(s.SAS))
		notFor("path", s.Path != "")
		s.validateS3(f)
	case blob.KindNFS:
		notFor("account", s.Account != "")
		notFor("container", s.Container != "")
		notFor("sas", hasSecret(s.SAS))
		notFor("bucket", s.Bucket != "")
		notFor("region", s.Region != "")
		notFor("path_style", s.PathStyle)
		notFor("access_key_id", s.AccessKeyID != "")
		notFor("secret_key", hasSecret(s.SecretKey))
		notFor("endpoint_override", s.EndpointOverride != "")
		if s.Auth != blob.AuthNone {
			f["auth"] = "none (the server writes as its own user)"
		}
		if s.Path == "" {
			f["path"] = "required"
		} else if _, _, _, err := blob.ResolveFSPath(nfsRoot, s.Path); err != nil {
			f["path"] = err.Error()
		} else {
			s.Path = filepath.Clean(s.Path)
		}
	default:
		f["kind"] = "azure_blob, s3 or nfs"
	}
	return f
}

func (s *spec) validateAzure(f map[string]string) {
	if !accountRe.MatchString(s.Account) {
		f["account"] = "3–24 lowercase letters and digits"
	}
	if !validContainer(s.Container) {
		f["container"] = "3–63 lowercase letters, digits and single hyphens"
	}
	if s.EndpointOverride != "" {
		u, err := url.Parse(s.EndpointOverride)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			f["endpoint_override"] = "absolute http(s) URL without credentials or query, e.g. https://acct.blob.core.usgovcloudapi.net"
		}
	}
	switch s.Auth {
	case blob.AuthManagedIdentity:
		if s.SAS != nil && (s.SAS.Value != "" || s.SAS.Ref != "") {
			f["sas"] = "only used with auth sas_token"
		}
		s.SAS = nil
	case blob.AuthSAS:
		if s.SAS != nil {
			validateSecretSource(f, "sas", s.SAS)
		}
	default:
		f["auth"] = "managed_identity or sas_token"
	}
}

func (s *spec) validateS3(f map[string]string) {
	if !bucketRe.MatchString(s.Bucket) || strings.Contains(s.Bucket, "..") {
		f["bucket"] = "3–63 lowercase letters, digits, '.' and '-'"
	}
	if s.Region == "" {
		s.Region = blob.DefaultS3Region
	} else if !regionRe.MatchString(s.Region) {
		f["region"] = "e.g. eu-central-1"
	}
	if s.EndpointOverride != "" {
		u, err := url.Parse(s.EndpointOverride)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" ||
			u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			f["endpoint_override"] = "http(s)://host[:port] without path, credentials or query, e.g. https://minio.example.internal:9000"
		}
	}
	if s.Auth != blob.AuthAccessKey {
		f["auth"] = "access_key"
	}
	if !accessKeyIDRe.MatchString(s.AccessKeyID) {
		f["access_key_id"] = "required (printable characters, no spaces)"
	}
	if s.SecretKey != nil {
		validateSecretSource(f, "secret_key", s.SecretKey)
	}
}

// resolveSecret returns the plaintext of a new secret source.
func (a *API) resolveSecret(ctx context.Context, field string, in *SecretSourceInput) (string, map[string]string) {
	norm := strings.TrimSpace
	if field == "sas" {
		norm = blob.NormalizeSAS
	}
	switch in.Source {
	case "stored":
		return norm(in.Value), nil
	case "keyvault_ref":
		b, err := secrets.ResolveUserRef(ctx, a.KV, strings.TrimSpace(in.Ref))
		if err != nil {
			if errors.Is(err, secrets.ErrSecretNotFound) {
				return "", map[string]string{field + ".ref": "secret not found in Key Vault"}
			}
			a.Log.Warn("resolve destination key vault reference", "field", field, "ref", strings.TrimSpace(in.Ref), "err", err)
			return "", map[string]string{field + ".ref": "could not read the secret from Key Vault"}
		}
		v := norm(string(b))
		secrets.Zero(b)
		return v, nil
	}
	return "", map[string]string{field + ".source": "keyvault_ref or stored"}
}

// newSecret returns the field name and source of the secret s carries (the
// SAS or the S3 secret key), if any.
func (s spec) newSecret() (string, *SecretSourceInput) {
	switch {
	case s.Kind == blob.KindAzureBlob && s.SAS != nil:
		return "sas", s.SAS
	case s.Kind == blob.KindS3 && s.SecretKey != nil:
		return "secret_key", s.SecretKey
	}
	return "", nil
}

// test runs the destination test for s with the plaintext secret (SAS or
// S3 secret key).
func (a *API) test(ctx context.Context, s spec, secret string) Report {
	p := a.prober()
	switch s.Kind {
	case blob.KindS3:
		return p.TestS3(ctx, blob.S3Target{Name: s.Name, Bucket: s.Bucket, Region: s.Region, Prefix: s.Prefix,
			EndpointOverride: s.EndpointOverride, PathStyle: s.PathStyle, AccessKeyID: s.AccessKeyID, SecretKey: secret})
	case blob.KindNFS:
		return p.TestFS(ctx, blob.FSTarget{Name: s.Name, Path: s.Path, Prefix: s.Prefix})
	}
	return p.Test(ctx, blob.Target{Name: s.Name, Account: s.Account, Container: s.Container, Prefix: s.Prefix, Auth: s.Auth,
		EndpointOverride: s.EndpointOverride, SAS: secret})
}

// warnings lists what the admin must see after a save.
func warnings(kind string, rep Report, now time.Time) []string {
	var out []string
	if rep.CanDelete {
		switch kind {
		case blob.KindS3:
			out = append(out, "The credential can delete objects. Olympos never deletes backups (retention is bucket lifecycle rules); "+
				"remove s3:DeleteObject and s3:DeleteObjectVersion from its policy (and use Object Lock) so a compromised server cannot delete either.")
		case blob.KindNFS:
			out = append(out, "Olympos can delete files on this export: a filesystem cannot refuse deletes to the server's own user. "+
				"Olympos never deletes backups; protect them with storage snapshots / WORM (e.g. SnapLock) and do retention on the storage.")
		default:
			out = append(out, "The credential can delete blobs. Olympos never deletes backups (retention is Blob lifecycle rules); "+
				"remove the delete permission (SAS without d/x/y, or a custom role without blobs/delete) so a compromised server cannot delete either.")
		}
	}
	if rep.SAS != nil {
		if rep.SAS.Scope == ScopeAccount {
			out = append(out, "This is an account SAS: it needs shared key access on the storage account and reaches every container. Prefer a container-scoped SAS or Managed Identity.")
		}
		for _, x := range rep.SAS.Extra {
			if x == "l" {
				out = append(out, "The SAS grants list (l), which the server does not need.")
			}
		}
		if rep.SAS.ExpiresAt != nil && rep.SAS.ExpiresAt.Sub(now) < 14*24*time.Hour {
			out = append(out, "The SAS expires on "+rep.SAS.ExpiresAt.Format("2006-01-02")+"; plan its rotation.")
		}
	}
	if st := rep.step(StepDeleteRefused); st != nil && !st.OK && !rep.CanDelete {
		out = append(out, "Could not verify that delete is refused: "+st.Detail)
	}
	return out
}

// details is the activity-log shape of a destination (never secrets).
func (s spec) details() map[string]any {
	d := map[string]any{"name": s.Name, "kind": s.Kind, "prefix": s.Prefix, "auth": s.Auth}
	switch s.Kind {
	case blob.KindAzureBlob:
		d["account"], d["container"], d["endpoint_override"] = s.Account, s.Container, s.EndpointOverride
		d["sas_source"] = sourceOf(s.SAS)
	case blob.KindS3:
		d["bucket"], d["region"], d["endpoint_override"], d["path_style"] = s.Bucket, s.Region, s.EndpointOverride, s.PathStyle
		d["access_key_id"], d["secret_key_source"] = s.AccessKeyID, sourceOf(s.SecretKey)
	case blob.KindNFS:
		d["path"] = s.Path
	}
	return d
}

func sourceOf(in *SecretSourceInput) string {
	if in == nil {
		return ""
	}
	return in.Source
}

func specFromInput(in Input) spec {
	s := spec{Name: deref(in.Name), Kind: deref(in.Kind), Prefix: deref(in.Prefix), EndpointOverride: deref(in.EndpointOverride),
		Auth: deref(in.Auth), Account: deref(in.Account), Container: deref(in.Container), SAS: in.SAS,
		Bucket: deref(in.Bucket), Region: deref(in.Region), AccessKeyID: deref(in.AccessKeyID), SecretKey: in.SecretKey, Path: deref(in.Path)}
	if in.PathStyle != nil {
		s.PathStyle = *in.PathStyle
	}
	if s.Kind == "" {
		s.Kind = blob.KindAzureBlob
	}
	return s
}

// requireSecret adds a field error when the kind needs a secret and none is
// given (or kept).
func (s spec) requireSecret(f map[string]string, have bool) {
	if have {
		return
	}
	switch {
	case s.Kind == blob.KindAzureBlob && s.Auth == blob.AuthSAS && s.SAS == nil:
		f["sas"] = "required for auth sas_token"
	case s.Kind == blob.KindS3 && s.SecretKey == nil:
		f["secret_key"] = "required for kind s3"
	}
}

// ---------------------------------------------------------------- create

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	var in Input
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s := specFromInput(in)
	f := s.validate(a.Storage.NFSRoot)
	s.requireSecret(f, false)
	if len(f) > 0 {
		httpx.FieldErrors(w, "invalid destination", f)
		return
	}
	if a.nameTaken(w, r, s.Name, uuid.Nil) {
		return
	}
	var secret string
	field, src := s.newSecret()
	if src != nil {
		var fe map[string]string
		if secret, fe = a.resolveSecret(r.Context(), field, src); fe != nil {
			httpx.FieldErrors(w, "invalid destination", fe)
			return
		}
	}
	rep := a.test(r.Context(), s, secret)
	if !rep.OK {
		httpx.JSON(w, http.StatusUnprocessableEntity, TestFailed{Error: "destination test failed: " + rep.Error, Test: &rep})
		return
	}
	var out View
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		credID, err := a.insertCredential(r.Context(), tx, src, secret)
		if err != nil {
			return err
		}
		var sasCred, secretCred *uuid.UUID
		if s.Kind == blob.KindS3 {
			secretCred = credID
		} else {
			sasCred = credID
		}
		repJSON, _ := json.Marshal(rep)
		var id uuid.UUID
		if err := tx.QueryRow(r.Context(), `INSERT INTO destinations (name, kind, account, container, prefix, auth, sas_credential_id,
			sas_expires_at, sas_permissions, endpoint_override, bucket, region, path_style, access_key_id, secret_credential_id, path,
			last_test_at, last_test_ok, last_test_report)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,now(),$17,$18) RETURNING id`,
			s.Name, s.Kind, s.Account, s.Container, s.Prefix, s.Auth, sasCred, sasExpiry(rep), sasPerms(rep), s.EndpointOverride,
			s.Bucket, s.Region, s.PathStyle, s.AccessKeyID, secretCred, s.Path, rep.OK, repJSON).Scan(&id); err != nil {
			return err
		}
		det := s.details()
		det["can_delete"] = rep.CanDelete
		if err := httpx.Record(r, tx, "destination.created", "destination", id.String(), nil, det); err != nil {
			return err
		}
		out, err = loadView(r.Context(), tx, id)
		return err
	})
	secret = ""
	if store.IsUniqueViolation(err) {
		httpx.JSON(w, http.StatusConflict, httpx.ErrorBody{Error: "a destination with this name already exists", Fields: map[string]string{"name": "already exists"}})
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	out.Warnings = warnings(s.Kind, rep, a.now())
	if rep.CanDelete {
		a.Log.Warn("destination saved with a credential that can delete backups", "destination", out.ID.String(), "name", out.Name, "kind", s.Kind)
	}
	httpx.JSON(w, http.StatusCreated, out)
}

// insertCredential stores a new secret credential row (SAS or S3 secret
// key) and returns its ID (nil when there is none). Stored values are sealed
// with AAD credentials:<id>.
func (a *API) insertCredential(ctx context.Context, tx pgx.Tx, in *SecretSourceInput, value string) (*uuid.UUID, error) {
	if in == nil {
		return nil, nil
	}
	id := uuid.New()
	switch in.Source {
	case "stored":
		b := []byte(value)
		sealed, err := a.Env.Seal(ctx, b, []byte("credentials:"+id.String()))
		secrets.Zero(b)
		if err != nil {
			return nil, fmt.Errorf("seal secret: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, kind, ciphertext, wrapped_dek, kek_version) VALUES ($1, 'stored', $2, $3, $4)`,
			id, sealed.Ciphertext, sealed.WrappedDEK, sealed.KEKVersion); err != nil {
			return nil, err
		}
	case "keyvault_ref":
		ref, err := secrets.ParseRef(strings.TrimSpace(in.Ref))
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, kind, keyvault_name, secret_name) VALUES ($1, 'keyvault_ref', $2, $3)`,
			id, ref.Vault, ref.Secret); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown secret source %q", in.Source)
	}
	return &id, nil
}

func sasExpiry(rep Report) *time.Time {
	if rep.SAS == nil {
		return nil
	}
	return rep.SAS.ExpiresAt
}

func sasPerms(rep Report) string {
	if rep.SAS == nil {
		return ""
	}
	return rep.SAS.Permissions
}

// ---------------------------------------------------------------- patch

type row struct {
	spec
	sasCred, secretCred *uuid.UUID
}

// credID is the credential the row's kind uses (SAS or S3 secret key).
func (r row) credID() *uuid.UUID {
	if r.Kind == blob.KindS3 {
		return r.secretCred
	}
	return r.sasCred
}

func loadRow(ctx context.Context, q store.Querier, id uuid.UUID, lock bool) (row, error) {
	var r row
	sql := `SELECT name, kind, account, container, prefix, auth, endpoint_override, sas_credential_id,
		bucket, region, path_style, access_key_id, secret_credential_id, path FROM destinations WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, id).Scan(&r.Name, &r.Kind, &r.Account, &r.Container, &r.Prefix, &r.Auth, &r.EndpointOverride, &r.sasCred,
		&r.Bucket, &r.Region, &r.PathStyle, &r.AccessKeyID, &r.secretCred, &r.Path)
	return r, store.NotFound(err)
}

func (a *API) patch(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in Input
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	cur, err := loadRow(r.Context(), a.DB, id, false)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	s := cur.spec
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	set(&s.Name, in.Name)
	set(&s.Prefix, in.Prefix)
	set(&s.EndpointOverride, in.EndpointOverride)
	set(&s.Auth, in.Auth)
	set(&s.Account, in.Account)
	set(&s.Container, in.Container)
	set(&s.Bucket, in.Bucket)
	set(&s.Region, in.Region)
	set(&s.AccessKeyID, in.AccessKeyID)
	set(&s.Path, in.Path)
	if in.PathStyle != nil {
		s.PathStyle = *in.PathStyle
	}
	s.SAS, s.SecretKey = in.SAS, in.SecretKey
	f := s.validate(a.Storage.NFSRoot)
	if in.Kind != nil && *in.Kind != cur.Kind {
		f["kind"] = "cannot be changed; create a new destination"
	}
	field, src := s.newSecret()
	// The current credential is kept when the kind still needs one and no
	// new one is given.
	needsCred := (s.Kind == blob.KindAzureBlob && s.Auth == blob.AuthSAS) || s.Kind == blob.KindS3
	keepCred := needsCred && src == nil && cur.credID() != nil
	s.requireSecret(f, keepCred)
	if len(f) > 0 {
		httpx.FieldErrors(w, "invalid destination", f)
		return
	}
	if a.nameTaken(w, r, s.Name, id) {
		return
	}
	var secret string
	switch {
	case src != nil:
		var fe map[string]string
		if secret, fe = a.resolveSecret(r.Context(), field, src); fe != nil {
			httpx.FieldErrors(w, "invalid destination", fe)
			return
		}
	case keepCred:
		what, fld := "SAS", "sas"
		if s.Kind == blob.KindS3 {
			what, fld = "S3 secret key", "secret_key"
		}
		b, err := blob.LoadSecret(r.Context(), a.DB, a.KV, a.Env, *cur.credID(), what)
		if err != nil {
			a.Log.Warn("load destination secret", "destination", id.String(), "err", err)
			httpx.FieldErrors(w, "the stored "+what+" could not be loaded; provide a new one", map[string]string{fld: "could not be loaded"})
			return
		}
		if fld == "sas" {
			secret = blob.NormalizeSAS(string(b))
		} else {
			secret = strings.TrimSpace(string(b))
		}
		secrets.Zero(b)
	}
	rep := a.test(r.Context(), s, secret)
	if !rep.OK {
		httpx.JSON(w, http.StatusUnprocessableEntity, TestFailed{Error: "destination test failed: " + rep.Error, Test: &rep})
		return
	}
	var out View
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		locked, err := loadRow(r.Context(), tx, id, true)
		if err != nil {
			return err
		}
		// Edits must keep the group invariant: no two members of a group
		// write to the same location. Without a location change nothing can
		// have become a duplicate.
		if lf := locationField(locked.spec, s); lf != "" {
			msg, err := groupLocationConflict(r.Context(), tx, groupDestOf(id, s))
			if err != nil {
				return err
			}
			if msg != "" {
				return errFields{lf: msg}
			}
		}
		credID := locked.credID()
		var oldCred *uuid.UUID
		switch {
		case !needsCred:
			oldCred, credID = locked.credID(), nil
		case src != nil:
			oldCred = locked.credID()
			if credID, err = a.insertCredential(r.Context(), tx, src, secret); err != nil {
				return err
			}
		}
		var sasCred, secretCred *uuid.UUID
		if s.Kind == blob.KindS3 {
			secretCred = credID
		} else {
			sasCred = credID
		}
		repJSON, _ := json.Marshal(rep)
		if _, err := tx.Exec(r.Context(), `UPDATE destinations SET name=$2, account=$3, container=$4, prefix=$5, auth=$6, sas_credential_id=$7,
			sas_expires_at=$8, sas_permissions=$9, endpoint_override=$10, bucket=$11, region=$12, path_style=$13, access_key_id=$14,
			secret_credential_id=$15, path=$16, last_test_at=now(), last_test_ok=$17, last_test_report=$18, updated_at=now() WHERE id=$1`,
			id, s.Name, s.Account, s.Container, s.Prefix, s.Auth, sasCred, sasExpiry(rep), sasPerms(rep), s.EndpointOverride,
			s.Bucket, s.Region, s.PathStyle, s.AccessKeyID, secretCred, s.Path, rep.OK, repJSON); err != nil {
			return err
		}
		if oldCred != nil {
			// The replaced secret must not linger (sealed or reference).
			if _, err := tx.Exec(r.Context(), `DELETE FROM credentials WHERE id = $1`, *oldCred); err != nil {
				return err
			}
		}
		changes := map[string]any{}
		diff := func(k, from, to string) {
			if from != to {
				changes[k] = map[string]string{"from": from, "to": to}
			}
		}
		diff("name", locked.Name, s.Name)
		diff("prefix", locked.Prefix, s.Prefix)
		diff("auth", locked.Auth, s.Auth)
		diff("endpoint_override", locked.EndpointOverride, s.EndpointOverride)
		diff("account", locked.Account, s.Account)
		diff("container", locked.Container, s.Container)
		diff("bucket", locked.Bucket, s.Bucket)
		diff("region", locked.Region, s.Region)
		diff("access_key_id", locked.AccessKeyID, s.AccessKeyID)
		diff("path", locked.Path, s.Path)
		if locked.PathStyle != s.PathStyle {
			changes["path_style"] = map[string]bool{"from": locked.PathStyle, "to": s.PathStyle}
		}
		if src != nil {
			changes[field] = "replaced (" + src.Source + ")"
		}
		changes["can_delete"] = rep.CanDelete
		if err := httpx.Record(r, tx, "destination.updated", "destination", id.String(), nil, changes); err != nil {
			return err
		}
		out, err = loadView(r.Context(), tx, id)
		return err
	})
	secret = ""
	var fe errFields
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.As(err, &fe):
		httpx.FieldErrors(w, "invalid destination", fe)
	case store.IsUniqueViolation(err):
		httpx.JSON(w, http.StatusConflict, httpx.ErrorBody{Error: "a destination with this name already exists", Fields: map[string]string{"name": "already exists"}})
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		out.Warnings = warnings(s.Kind, rep, a.now())
		httpx.JSON(w, http.StatusOK, out)
	}
}

// ---------------------------------------------------------------- delete

func (a *API) delete(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	errInUse := errors.New("in use")
	errInGroup := errors.New("in a group")
	var jobs, groups int
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		cur, err := loadRow(r.Context(), tx, id, true)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM destination_group_members WHERE destination_id = $1`, id).Scan(&groups); err != nil {
			return err
		}
		if groups > 0 {
			return errInGroup
		}
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM backup_jobs WHERE destination_id = $1`, id).Scan(&jobs); err != nil {
			return err
		}
		if jobs > 0 {
			return errInUse
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM destinations WHERE id = $1`, id); err != nil {
			return err
		}
		for _, c := range []*uuid.UUID{cur.sasCred, cur.secretCred} {
			if c != nil {
				if _, err := tx.Exec(r.Context(), `DELETE FROM credentials WHERE id = $1`, *c); err != nil {
					return err
				}
			}
		}
		return httpx.Record(r, tx, "destination.deleted", "destination", id.String(), nil, cur.spec.details())
	})
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case errors.Is(err, errInGroup):
		httpx.Error(w, http.StatusConflict, fmt.Sprintf("destination is in %d destination group(s); remove it there first", groups))
	case errors.Is(err, errInUse):
		httpx.Error(w, http.StatusConflict, fmt.Sprintf("destination is used by %d backup job(s); move or delete them first", jobs))
	case errors.As(err, &pg) && pg.Code == "23503":
		httpx.Error(w, http.StatusConflict, "destination is used by backup jobs; move or delete them first")
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------- tests

func (a *API) testUnsaved(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	var in Input
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s := specFromInput(in)
	if strings.TrimSpace(s.Name) == "" {
		s.Name = "unsaved"
	}
	f := s.validate(a.Storage.NFSRoot)
	s.requireSecret(f, false)
	if len(f) > 0 {
		httpx.FieldErrors(w, "invalid destination", f)
		return
	}
	var secret string
	if field, src := s.newSecret(); src != nil {
		var fe map[string]string
		if secret, fe = a.resolveSecret(r.Context(), field, src); fe != nil {
			httpx.FieldErrors(w, "invalid destination", fe)
			return
		}
	}
	rep := a.test(r.Context(), s, secret)
	secret = ""
	det := s.details()
	delete(det, "name")
	det["ok"], det["can_delete"] = rep.OK, rep.CanDelete
	if err := httpx.Record(r, a.DB, "destination.tested", "destination", "", nil, det); err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}

func (a *API) testSaved(w http.ResponseWriter, r *http.Request) {
	if !canAdmin(r) {
		httpx.Forbidden(w, "")
		return
	}
	id, ok := httpx.UUIDParam(w, r, "id")
	if !ok {
		return
	}
	cur, err := loadRow(r.Context(), a.DB, id, false)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	rep := a.testRow(r.Context(), id, cur.Kind)
	repJSON, _ := json.Marshal(rep)
	err = store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		if rep.SAS != nil {
			if _, err := tx.Exec(r.Context(), `UPDATE destinations SET sas_expires_at = $2, sas_permissions = $3 WHERE id = $1`,
				id, rep.SAS.ExpiresAt, rep.SAS.Permissions); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(r.Context(), `UPDATE destinations SET last_test_at = now(), last_test_ok = $2, last_test_report = $3 WHERE id = $1`,
			id, rep.OK, repJSON); err != nil {
			return err
		}
		return httpx.Record(r, tx, "destination.tested", "destination", id.String(), nil, map[string]any{"ok": rep.OK, "can_delete": rep.CanDelete})
	})
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}

// testRow tests a saved destination with its stored credential.
func (a *API) testRow(ctx context.Context, id uuid.UUID, kind string) Report {
	loadErr := func(err error) Report {
		a.Log.Warn("load destination for test", "destination", id.String(), "err", err)
		return Report{Steps: []Step{}, Error: "could not load the destination credential: " + secrets.RedactString(err.Error())}
	}
	p := a.prober()
	switch kind {
	case blob.KindS3:
		t, err := blob.LoadS3Target(ctx, a.DB, a.KV, a.Env, id)
		if err != nil {
			return loadErr(err)
		}
		rep := p.TestS3(ctx, t)
		t.SecretKey = ""
		return rep
	case blob.KindNFS:
		t, err := blob.LoadFSTarget(ctx, a.DB, id)
		if err != nil {
			return Report{Steps: []Step{}, Error: err.Error()}
		}
		return p.TestFS(ctx, t)
	}
	t, err := blob.LoadTarget(ctx, a.DB, a.KV, a.Env, id)
	if err != nil {
		return loadErr(err)
	}
	rep := p.Test(ctx, t)
	t.SAS = ""
	return rep
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
