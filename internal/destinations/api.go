package destinations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) prober() *Prober { return &Prober{Cred: a.Cred, Now: a.Now} }

// Routes mounts the module under /api/v1.
func (a *API) Routes(r chi.Router) {
	r.Route("/destinations", func(r chi.Router) {
		r.Use(httpx.RequireAny(authz.PermRead))
		r.Get("/", a.list)
		r.Post("/", a.create)
		r.Post("/test", a.testUnsaved)
		r.Get("/{id}", a.get)
		r.Patch("/{id}", a.patch)
		r.Delete("/{id}", a.delete)
		r.Post("/{id}/test", a.testSaved)
	})
}

// SecretSourceInput is a Key Vault reference or a value to store.
type SecretSourceInput struct {
	Source string `json:"source"` // keyvault_ref | stored
	Ref    string `json:"ref"`
	Value  string `json:"value"`
}

// Input is the create/patch body (patch: absent fields keep their value).
type Input struct {
	Name             *string            `json:"name"`
	Account          *string            `json:"account"`
	Container        *string            `json:"container"`
	Prefix           *string            `json:"prefix"`
	Auth             *string            `json:"auth"`
	SAS              *SecretSourceInput `json:"sas"`
	EndpointOverride *string            `json:"endpoint_override"`
}

// View is the API shape of a destination. It never contains the SAS value.
type View struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Kind             string     `json:"kind"`
	Account          string     `json:"account"`
	Container        string     `json:"container"`
	Prefix           string     `json:"prefix"`
	Auth             string     `json:"auth"`
	SASSource        string     `json:"sas_source"`
	SASRef           string     `json:"sas_ref"`
	SASExpiresAt     *time.Time `json:"sas_expires_at"`
	SASPermissions   string     `json:"sas_permissions"`
	EndpointOverride string     `json:"endpoint_override"`
	LastTestAt       *time.Time `json:"last_test_at"`
	LastTestOK       *bool      `json:"last_test_ok"`
	LastTest         *Report    `json:"last_test"`
	Jobs             int        `json:"jobs"`
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

const viewSelect = `SELECT d.id, d.name, d.kind, d.account, d.container, d.prefix, d.auth,
	COALESCE(c.kind, ''), COALESCE(c.keyvault_name, ''), COALESCE(c.secret_name, ''),
	d.sas_expires_at, d.sas_permissions, d.endpoint_override, d.last_test_at, d.last_test_ok, d.last_test_report, d.created_at,
	(SELECT count(*) FROM backup_jobs j WHERE j.destination_id = d.id)
	FROM destinations d LEFT JOIN credentials c ON c.id = d.sas_credential_id`

func scanViews(rows pgx.Rows) ([]View, error) {
	defer rows.Close()
	out := []View{}
	for rows.Next() {
		var v View
		var kvName, secName string
		var report []byte
		if err := rows.Scan(&v.ID, &v.Name, &v.Kind, &v.Account, &v.Container, &v.Prefix, &v.Auth, &v.SASSource, &kvName, &secName,
			&v.SASExpiresAt, &v.SASPermissions, &v.EndpointOverride, &v.LastTestAt, &v.LastTestOK, &report, &v.CreatedAt, &v.Jobs); err != nil {
			return nil, err
		}
		if v.SASSource == "keyvault_ref" {
			v.SASRef = secrets.Ref{Vault: kvName, Secret: secName}.String()
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

// ---------------------------------------------------------------- validation

var (
	accountRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	prefixRe  = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
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

// spec is a normalized, validated destination (plus SAS source).
type spec struct {
	Name, Account, Container, Prefix, Auth, EndpointOverride string
	SAS                                                      *SecretSourceInput
}

func (s *spec) validate() map[string]string {
	f := map[string]string{}
	s.Name = strings.TrimSpace(s.Name)
	s.Account = strings.TrimSpace(s.Account)
	s.Container = strings.TrimSpace(s.Container)
	s.Prefix = strings.Trim(strings.TrimSpace(s.Prefix), "/")
	s.EndpointOverride = strings.TrimRight(strings.TrimSpace(s.EndpointOverride), "/")
	if s.Name == "" {
		f["name"] = "required"
	} else if len(s.Name) > 80 {
		f["name"] = "at most 80 characters"
	}
	if !accountRe.MatchString(s.Account) {
		f["account"] = "3–24 lowercase letters and digits"
	}
	if !validContainer(s.Container) {
		f["container"] = "3–63 lowercase letters, digits and single hyphens"
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
			switch s.SAS.Source {
			case "keyvault_ref":
				if _, err := secrets.ParseRef(strings.TrimSpace(s.SAS.Ref)); err != nil {
					f["sas.ref"] = err.Error()
				}
				if s.SAS.Value != "" {
					f["sas.value"] = "do not send a value with a Key Vault reference"
				}
			case "stored":
				if strings.TrimSpace(s.SAS.Value) == "" {
					f["sas.value"] = "required"
				}
			default:
				f["sas.source"] = "keyvault_ref or stored"
			}
		}
	default:
		f["auth"] = "managed_identity or sas_token"
	}
	return f
}

// resolveSAS returns the plaintext SAS for a new source.
func (a *API) resolveSAS(ctx context.Context, in *SecretSourceInput) (string, map[string]string) {
	switch in.Source {
	case "stored":
		return blob.NormalizeSAS(in.Value), nil
	case "keyvault_ref":
		b, err := secrets.Resolve(ctx, a.KV, strings.TrimSpace(in.Ref))
		if err != nil {
			if errors.Is(err, secrets.ErrSecretNotFound) {
				return "", map[string]string{"sas.ref": "secret not found in Key Vault"}
			}
			a.Log.Warn("resolve SAS key vault reference", "ref", strings.TrimSpace(in.Ref), "err", err)
			return "", map[string]string{"sas.ref": "could not read the secret from Key Vault"}
		}
		v := blob.NormalizeSAS(string(b))
		secrets.Zero(b)
		return v, nil
	}
	return "", map[string]string{"sas.source": "keyvault_ref or stored"}
}

func (s spec) target(sas string) blob.Target {
	return blob.Target{Name: s.Name, Account: s.Account, Container: s.Container, Prefix: s.Prefix, Auth: s.Auth,
		EndpointOverride: s.EndpointOverride, SAS: sas}
}

// warnings lists what the admin must see after a save.
func warnings(rep Report, now time.Time) []string {
	var out []string
	if rep.CanDelete {
		out = append(out, "The credential can delete blobs. Olympos never deletes backups (retention is Blob lifecycle rules); "+
			"remove the delete permission (SAS without d/x/y, or a custom role without blobs/delete) so a compromised server cannot delete either.")
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
	s := spec{Name: deref(in.Name), Account: deref(in.Account), Container: deref(in.Container), Prefix: deref(in.Prefix),
		Auth: deref(in.Auth), EndpointOverride: deref(in.EndpointOverride), SAS: in.SAS}
	if s.Auth == "" {
		s.Auth = blob.AuthManagedIdentity
	}
	f := s.validate()
	if s.Auth == blob.AuthSAS && s.SAS == nil {
		f["sas"] = "required for auth sas_token"
	}
	if len(f) > 0 {
		httpx.FieldErrors(w, "invalid destination", f)
		return
	}
	if a.nameTaken(w, r, s.Name, uuid.Nil) {
		return
	}
	var sas string
	if s.SAS != nil {
		var fe map[string]string
		if sas, fe = a.resolveSAS(r.Context(), s.SAS); fe != nil {
			httpx.FieldErrors(w, "invalid destination", fe)
			return
		}
	}
	rep := a.prober().Test(r.Context(), s.target(sas))
	if !rep.OK {
		httpx.JSON(w, http.StatusUnprocessableEntity, TestFailed{Error: "destination test failed: " + rep.Error, Test: &rep})
		return
	}
	var out View
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		credID, err := a.insertCredential(r.Context(), tx, s.SAS, sas)
		if err != nil {
			return err
		}
		repJSON, _ := json.Marshal(rep)
		var id uuid.UUID
		if err := tx.QueryRow(r.Context(), `INSERT INTO destinations (name, account, container, prefix, auth, sas_credential_id,
			sas_expires_at, sas_permissions, endpoint_override, last_test_at, last_test_ok, last_test_report)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10,$11) RETURNING id`,
			s.Name, s.Account, s.Container, s.Prefix, s.Auth, credID, sasExpiry(rep), sasPerms(rep), s.EndpointOverride, rep.OK, repJSON).Scan(&id); err != nil {
			return err
		}
		if err := httpx.Record(r, tx, "destination.created", "destination", id.String(), nil, map[string]any{
			"name": s.Name, "account": s.Account, "container": s.Container, "prefix": s.Prefix, "auth": s.Auth,
			"sas_source": sasSource(s.SAS), "endpoint_override": s.EndpointOverride, "can_delete": rep.CanDelete,
		}); err != nil {
			return err
		}
		out, err = loadView(r.Context(), tx, id)
		return err
	})
	if store.IsUniqueViolation(err) {
		httpx.JSON(w, http.StatusConflict, httpx.ErrorBody{Error: "a destination with this name already exists", Fields: map[string]string{"name": "already exists"}})
		return
	}
	if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	out.Warnings = warnings(rep, a.now())
	if rep.CanDelete {
		a.Log.Warn("destination saved with a credential that can delete blobs", "destination", out.ID.String(), "name", out.Name)
	}
	httpx.JSON(w, http.StatusCreated, out)
}

// insertCredential stores a new SAS credential row and returns its ID (nil
// for managed identity). Stored values are sealed with AAD credentials:<id>.
func (a *API) insertCredential(ctx context.Context, tx pgx.Tx, in *SecretSourceInput, sas string) (*uuid.UUID, error) {
	if in == nil {
		return nil, nil
	}
	id := uuid.New()
	switch in.Source {
	case "stored":
		b := []byte(sas)
		sealed, err := a.Env.Seal(ctx, b, []byte("credentials:"+id.String()))
		secrets.Zero(b)
		if err != nil {
			return nil, fmt.Errorf("seal SAS: %w", err)
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
		return nil, fmt.Errorf("unknown SAS source %q", in.Source)
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

func sasSource(in *SecretSourceInput) string {
	if in == nil {
		return ""
	}
	return in.Source
}

// ---------------------------------------------------------------- patch

type row struct {
	spec
	credID *uuid.UUID
}

func loadRow(ctx context.Context, q store.Querier, id uuid.UUID, lock bool) (row, error) {
	var r row
	sql := `SELECT name, account, container, prefix, auth, endpoint_override, sas_credential_id FROM destinations WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, id).Scan(&r.Name, &r.Account, &r.Container, &r.Prefix, &r.Auth, &r.EndpointOverride, &r.credID)
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
	set(&s.Account, in.Account)
	set(&s.Container, in.Container)
	set(&s.Prefix, in.Prefix)
	set(&s.Auth, in.Auth)
	set(&s.EndpointOverride, in.EndpointOverride)
	s.SAS = in.SAS
	f := s.validate()
	keepCred := s.Auth == blob.AuthSAS && s.SAS == nil && cur.credID != nil
	if s.Auth == blob.AuthSAS && s.SAS == nil && cur.credID == nil {
		f["sas"] = "required for auth sas_token"
	}
	if len(f) > 0 {
		httpx.FieldErrors(w, "invalid destination", f)
		return
	}
	if a.nameTaken(w, r, s.Name, id) {
		return
	}
	var sas string
	switch {
	case s.SAS != nil:
		var fe map[string]string
		if sas, fe = a.resolveSAS(r.Context(), s.SAS); fe != nil {
			httpx.FieldErrors(w, "invalid destination", fe)
			return
		}
	case keepCred:
		b, err := blob.LoadSAS(r.Context(), a.DB, a.KV, a.Env, *cur.credID)
		if err != nil {
			a.Log.Warn("load destination SAS", "destination", id.String(), "err", err)
			httpx.FieldErrors(w, "the stored SAS could not be loaded; provide a new one", map[string]string{"sas": "could not be loaded"})
			return
		}
		sas = blob.NormalizeSAS(string(b))
		secrets.Zero(b)
	}
	rep := a.prober().Test(r.Context(), s.target(sas))
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
		credID := locked.credID
		var oldCred *uuid.UUID
		switch {
		case s.Auth == blob.AuthManagedIdentity:
			oldCred, credID = locked.credID, nil
		case s.SAS != nil:
			oldCred = locked.credID
			if credID, err = a.insertCredential(r.Context(), tx, s.SAS, sas); err != nil {
				return err
			}
		}
		repJSON, _ := json.Marshal(rep)
		if _, err := tx.Exec(r.Context(), `UPDATE destinations SET name=$2, account=$3, container=$4, prefix=$5, auth=$6, sas_credential_id=$7,
			sas_expires_at=$8, sas_permissions=$9, endpoint_override=$10, last_test_at=now(), last_test_ok=$11, last_test_report=$12 WHERE id=$1`,
			id, s.Name, s.Account, s.Container, s.Prefix, s.Auth, credID, sasExpiry(rep), sasPerms(rep), s.EndpointOverride, rep.OK, repJSON); err != nil {
			return err
		}
		if oldCred != nil {
			// The replaced SAS must not linger (sealed or reference).
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
		diff("account", locked.Account, s.Account)
		diff("container", locked.Container, s.Container)
		diff("prefix", locked.Prefix, s.Prefix)
		diff("auth", locked.Auth, s.Auth)
		diff("endpoint_override", locked.EndpointOverride, s.EndpointOverride)
		if s.SAS != nil {
			changes["sas"] = "replaced (" + s.SAS.Source + ")"
		}
		changes["can_delete"] = rep.CanDelete
		if err := httpx.Record(r, tx, "destination.updated", "destination", id.String(), nil, changes); err != nil {
			return err
		}
		out, err = loadView(r.Context(), tx, id)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
	case store.IsUniqueViolation(err):
		httpx.JSON(w, http.StatusConflict, httpx.ErrorBody{Error: "a destination with this name already exists", Fields: map[string]string{"name": "already exists"}})
	case err != nil:
		httpx.Internal(w, r, a.Log, err)
	default:
		out.Warnings = warnings(rep, a.now())
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
	var jobs int
	err := store.Tx(r.Context(), a.DB, func(tx pgx.Tx) error {
		cur, err := loadRow(r.Context(), tx, id, true)
		if err != nil {
			return err
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
		if cur.credID != nil {
			if _, err := tx.Exec(r.Context(), `DELETE FROM credentials WHERE id = $1`, *cur.credID); err != nil {
				return err
			}
		}
		return httpx.Record(r, tx, "destination.deleted", "destination", id.String(), nil,
			map[string]any{"name": cur.Name, "account": cur.Account, "container": cur.Container, "auth": cur.Auth})
	})
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.NotFound(w)
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
	s := spec{Name: deref(in.Name), Account: deref(in.Account), Container: deref(in.Container), Prefix: deref(in.Prefix),
		Auth: deref(in.Auth), EndpointOverride: deref(in.EndpointOverride), SAS: in.SAS}
	if s.Auth == "" {
		s.Auth = blob.AuthManagedIdentity
	}
	if s.Name == "" {
		s.Name = "unsaved"
	}
	f := s.validate()
	if s.Auth == blob.AuthSAS && s.SAS == nil {
		f["sas"] = "required for auth sas_token"
	}
	if len(f) > 0 {
		httpx.FieldErrors(w, "invalid destination", f)
		return
	}
	var sas string
	if s.SAS != nil {
		var fe map[string]string
		if sas, fe = a.resolveSAS(r.Context(), s.SAS); fe != nil {
			httpx.FieldErrors(w, "invalid destination", fe)
			return
		}
	}
	rep := a.prober().Test(r.Context(), s.target(sas))
	sas = ""
	if err := httpx.Record(r, a.DB, "destination.tested", "destination", "", nil, map[string]any{
		"account": s.Account, "container": s.Container, "prefix": s.Prefix, "auth": s.Auth, "ok": rep.OK, "can_delete": rep.CanDelete,
	}); err != nil {
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
	if _, err := loadRow(r.Context(), a.DB, id, false); errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w)
		return
	} else if err != nil {
		httpx.Internal(w, r, a.Log, err)
		return
	}
	var rep Report
	t, err := blob.LoadTarget(r.Context(), a.DB, a.KV, a.Env, id)
	switch {
	case err != nil:
		a.Log.Warn("load destination for test", "destination", id.String(), "err", err)
		rep = Report{Steps: []Step{}, Error: "could not load the destination credential: " + secrets.RedactString(err.Error())}
	default:
		rep = a.prober().Test(r.Context(), t)
		t.SAS = ""
	}
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
