package backup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Credential sources (API: CredentialInput.source).
const (
	SourceKeyVault = "keyvault_ref"
	SourceStored   = "stored"
)

// CredentialInput is the API shape of a job credential. Password is
// write-only and never returned or logged.
type CredentialInput struct {
	Source   string `json:"source"`
	Ref      string `json:"ref,omitempty"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

// Validate returns per-field errors (keys prefixed with prefix). use says
// who enters a Key Vault reference and for which cluster (security review
// #2: a reference is resolved with Olympos' identity).
func (c *CredentialInput) Validate(prefix string, use secrets.RefUse) map[string]string {
	f := map[string]string{}
	if c.Source == "" {
		c.Source = SourceKeyVault
	}
	if strings.TrimSpace(c.Username) == "" {
		f[prefix+"username"] = "required"
	}
	switch c.Source {
	case SourceKeyVault:
		if _, err := secrets.CheckUserRef(c.Ref, use); err != nil {
			f[prefix+"ref"] = err.Error()
		}
		if c.Password != "" {
			f[prefix+"password"] = "not allowed with a Key Vault reference"
		}
	case SourceStored:
		if c.Password == "" {
			f[prefix+"password"] = "required"
		}
	default:
		f[prefix+"source"] = "must be keyvault_ref or stored"
	}
	return f
}

// CredentialView is the API shape returned for a job (never the secret).
type CredentialView struct {
	ID       uuid.UUID `json:"id"`
	Source   string    `json:"source"`
	Ref      string    `json:"ref,omitempty"`
	Username string    `json:"username"`
}

// credentialAAD binds a stored ciphertext to its row (SPEC §9).
func credentialAAD(id uuid.UUID) []byte { return []byte("credentials:" + id.String()) }

// Credentials stores and resolves job credentials.
type Credentials struct {
	KV       secrets.KeyVault
	Envelope *secrets.Envelope
}

// Insert creates a credentials row. Key Vault references store only the
// vault and secret names; stored passwords are envelope-encrypted.
func (cs *Credentials) Insert(ctx context.Context, q store.Querier, in CredentialInput) (uuid.UUID, error) {
	id := uuid.New()
	switch in.Source {
	case SourceKeyVault:
		ref, err := secrets.ParseRef(in.Ref)
		if err != nil {
			return uuid.Nil, err
		}
		_, err = q.Exec(ctx, `INSERT INTO credentials (id, kind, keyvault_name, secret_name, username) VALUES ($1, 'keyvault_ref', $2, $3, $4)`,
			id, ref.Vault, ref.Secret, in.Username)
		return id, err
	case SourceStored:
		pw := []byte(in.Password)
		defer secrets.Zero(pw)
		sealed, err := cs.Envelope.Seal(ctx, pw, credentialAAD(id))
		if err != nil {
			return uuid.Nil, fmt.Errorf("seal credential: %w", err)
		}
		_, err = q.Exec(ctx, `INSERT INTO credentials (id, kind, ciphertext, wrapped_dek, kek_version, username) VALUES ($1, 'stored', $2, $3, $4, $5)`,
			id, sealed.Ciphertext, sealed.WrappedDEK, sealed.KEKVersion, in.Username)
		return id, err
	}
	return uuid.Nil, fmt.Errorf("unknown credential source %q", in.Source)
}

// View loads the public part of a credential.
func (cs *Credentials) View(ctx context.Context, q store.Querier, id uuid.UUID) (*CredentialView, error) {
	var kind, vault, name, user string
	err := q.QueryRow(ctx, `SELECT kind, keyvault_name, secret_name, username FROM credentials WHERE id = $1`, id).Scan(&kind, &vault, &name, &user)
	if err != nil {
		return nil, store.NotFound(err)
	}
	v := &CredentialView{ID: id, Source: kind, Username: user}
	if kind == SourceKeyVault {
		v.Ref = secrets.Ref{Vault: vault, Secret: name}.String()
	}
	return v, nil
}

// Resolve returns the login for a credentials row. The caller MUST
// secrets.Zero the returned Secret after use.
func (cs *Credentials) Resolve(ctx context.Context, q store.Querier, id uuid.UUID) (Credential, error) {
	var kind, vault, name, user, kekVer string
	var ct, dek []byte
	err := q.QueryRow(ctx, `SELECT kind, keyvault_name, secret_name, username, ciphertext, wrapped_dek, kek_version FROM credentials WHERE id = $1`, id).
		Scan(&kind, &vault, &name, &user, &ct, &dek, &kekVer)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, errors.New("credential not found")
	}
	if err != nil {
		return Credential{}, err
	}
	switch kind {
	case SourceKeyVault:
		b, err := secrets.ResolveUserRef(ctx, cs.KV, secrets.Ref{Vault: vault, Secret: name}.String())
		if err != nil {
			return Credential{}, fmt.Errorf("resolve key vault reference %s: %w", secrets.Ref{Vault: vault, Secret: name}, err)
		}
		return Credential{Username: user, Secret: trimNewline(b)}, nil
	case SourceStored:
		b, err := cs.Envelope.Open(ctx, secrets.Sealed{Ciphertext: ct, WrappedDEK: dek, KEKVersion: kekVer}, credentialAAD(id))
		if err != nil {
			return Credential{}, fmt.Errorf("open stored credential: %w", err)
		}
		return Credential{Username: user, Secret: b}, nil
	}
	return Credential{}, fmt.Errorf("unknown credential kind %q", kind)
}

// FromInput resolves an unsaved credential (connection test). The caller
// MUST secrets.Zero the returned Secret.
func (cs *Credentials) FromInput(ctx context.Context, in CredentialInput) (Credential, error) {
	switch in.Source {
	case SourceKeyVault:
		b, err := secrets.ResolveUserRef(ctx, cs.KV, in.Ref)
		if err != nil {
			return Credential{}, fmt.Errorf("resolve key vault reference: %w", err)
		}
		return Credential{Username: in.Username, Secret: trimNewline(b)}, nil
	case SourceStored:
		return Credential{Username: in.Username, Secret: []byte(in.Password)}, nil
	}
	return Credential{}, fmt.Errorf("unknown credential source %q", in.Source)
}

// trimNewline drops a trailing newline that Key Vault secrets set from files
// often carry, in place.
func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b[len(b)-1] = 0
		b = b[:len(b)-1]
	}
	return b
}

// Delete removes a credentials row (when its job is deleted or the
// credential replaced).
func (cs *Credentials) Delete(ctx context.Context, q store.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, id)
	return err
}

// secretTracker hands out credentials and zeroes every secret afterwards;
// it also scrubs those secrets from error text before they are stored.
type secretTracker struct {
	secrets [][]byte
}

func (t *secretTracker) track(c Credential) Credential {
	t.secrets = append(t.secrets, c.Secret)
	return c
}

// scrub removes known secret values and common secret shapes from s.
func (t *secretTracker) scrub(s string) string {
	for _, b := range t.secrets {
		if len(b) >= 4 {
			s = strings.ReplaceAll(s, string(b), secrets.Redacted)
		}
	}
	s = secrets.RedactString(s)
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return s
}

func (t *secretTracker) zero() {
	for _, b := range t.secrets {
		secrets.Zero(b)
	}
	t.secrets = nil
}
