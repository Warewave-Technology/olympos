package security

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Registry is a registry row joined with its credential metadata. It never
// carries a secret value.
type Registry struct {
	ID               uuid.UUID  `json:"id"`
	HostPattern      string     `json:"host_pattern"`
	Username         string     `json:"username"`
	CredentialSource string     `json:"credential_source"` // "" (anonymous) | keyvault_ref | stored
	CredentialRef    string     `json:"credential_ref"`    // kv://... for keyvault_ref only
	Images           int        `json:"images"`
	CreatedAt        time.Time  `json:"created_at"`
	CredentialID     *uuid.UUID `json:"-"`
}

// Ref returns the matching view of the registry.
func (r Registry) Ref() RegistryRef {
	return RegistryRef{ID: r.ID, HostPattern: r.HostPattern, CredentialID: r.CredentialID}
}

// ListRegistries returns every registry ordered by pattern.
func ListRegistries(ctx context.Context, q store.Querier) ([]Registry, error) {
	rows, err := q.Query(ctx, `
		SELECT r.id, r.host_pattern, r.created_at, r.credential_id, COALESCE(c.kind, ''), COALESCE(c.username, ''),
		       COALESCE(c.keyvault_name, ''), COALESCE(c.secret_name, '')
		FROM registries r LEFT JOIN credentials c ON c.id = r.credential_id
		ORDER BY r.host_pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Registry{}
	for rows.Next() {
		var r Registry
		var vault, secret string
		if err := rows.Scan(&r.ID, &r.HostPattern, &r.CreatedAt, &r.CredentialID, &r.CredentialSource, &r.Username, &vault, &secret); err != nil {
			return nil, err
		}
		if r.CredentialSource == "keyvault_ref" {
			r.CredentialRef = secrets.Ref{Vault: vault, Secret: secret}.String()
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRegistry loads one registry.
func GetRegistry(ctx context.Context, q store.Querier, id uuid.UUID) (Registry, error) {
	regs, err := ListRegistries(ctx, q)
	if err != nil {
		return Registry{}, err
	}
	for _, r := range regs {
		if r.ID == id {
			return r, nil
		}
	}
	return Registry{}, store.ErrNotFound
}

func registryRefs(ctx context.Context, q store.Querier) ([]RegistryRef, error) {
	rows, err := q.Query(ctx, `SELECT id, host_pattern, credential_id FROM registries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegistryRef
	for rows.Next() {
		var r RegistryRef
		if err := rows.Scan(&r.ID, &r.HostPattern, &r.CredentialID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CredentialAAD binds a stored credential's ciphertext to its row.
func CredentialAAD(id uuid.UUID) []byte { return []byte("credentials:" + id.String()) }

// SecretSource is the write-only password input of a registry.
type SecretSource struct {
	Source string `json:"source"` // keyvault_ref | stored | none (PATCH: remove the credential)
	Ref    string `json:"ref,omitempty"`
	Value  string `json:"value,omitempty"`
}

// createCredential stores a registry password: a kv:// reference (resolved at
// use) or a value sealed with a fresh DEK and AAD "credentials:<id>".
func createCredential(ctx context.Context, q store.Querier, env *secrets.Envelope, username string, src SecretSource) (uuid.UUID, error) {
	id := uuid.New()
	switch src.Source {
	case "keyvault_ref":
		ref, err := secrets.ParseRef(src.Ref)
		if err != nil {
			return uuid.Nil, err
		}
		_, err = q.Exec(ctx, `INSERT INTO credentials (id, kind, keyvault_name, secret_name, username) VALUES ($1, 'keyvault_ref', $2, $3, $4)`,
			id, ref.Vault, ref.Secret, username)
		return id, err
	case "stored":
		val := []byte(src.Value)
		defer secrets.Zero(val)
		sealed, err := env.Seal(ctx, val, CredentialAAD(id))
		if err != nil {
			return uuid.Nil, err
		}
		_, err = q.Exec(ctx, `INSERT INTO credentials (id, kind, ciphertext, wrapped_dek, kek_version, username) VALUES ($1, 'stored', $2, $3, $4, $5)`,
			id, sealed.Ciphertext, sealed.WrappedDEK, sealed.KEKVersion, username)
		return id, err
	}
	return uuid.Nil, fmt.Errorf("unknown credential source %q", src.Source)
}

// Auth is a resolved registry credential, passed to trivy via its
// environment only. Call Zero when done.
type Auth struct {
	Username string
	Password []byte
}

// Zero wipes the password bytes.
func (a *Auth) Zero() {
	if a != nil {
		secrets.Zero(a.Password)
	}
}

// ErrNoCredential is returned when a credential row is missing.
var ErrNoCredential = errors.New("registry credential not found")

// ResolveCredential decrypts a stored credential or resolves its Key Vault
// reference, at use time.
func ResolveCredential(ctx context.Context, q store.Querier, env *secrets.Envelope, kv secrets.KeyVault, id uuid.UUID) (*Auth, error) {
	var kind, vault, secret, kekVer, user string
	var ct, wdek []byte
	err := q.QueryRow(ctx, `SELECT kind, keyvault_name, secret_name, ciphertext, wrapped_dek, kek_version, username FROM credentials WHERE id = $1`, id).
		Scan(&kind, &vault, &secret, &ct, &wdek, &kekVer, &user)
	if err != nil {
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil, ErrNoCredential
		}
		return nil, err
	}
	var pw []byte
	switch kind {
	case "stored":
		pw, err = env.Open(ctx, secrets.Sealed{Ciphertext: ct, WrappedDEK: wdek, KEKVersion: kekVer}, CredentialAAD(id))
	case "keyvault_ref":
		pw, err = kv.GetSecret(ctx, vault, secret)
	default:
		err = fmt.Errorf("unknown credential kind %q", kind)
	}
	secrets.Zero(ct)
	if err != nil {
		return nil, err
	}
	return &Auth{Username: user, Password: trimNewline(pw)}, nil
}

// trimNewline drops a trailing newline (common in Key Vault values set from
// files) without copying.
func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b[len(b)-1] = 0
		b = b[:len(b)-1]
	}
	return b
}

// RequeueUnscanned marks images that could not be scanned for another try
// (after registries change).
func RequeueUnscanned(ctx context.Context, q store.Querier) error {
	_, err := q.Exec(ctx, `UPDATE images SET scan_status = 'pending', scan_error = ''
		WHERE scan_status IN ('missing_credential','failed')`)
	return err
}
