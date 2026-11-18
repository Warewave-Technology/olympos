// Package secrets implements Olympos's secret handling (SPEC §9):
// envelope encryption with a Key Vault KEK, kv:// references resolved at use
// time, HMAC fingerprints and log redaction.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// KeyVault is the subset of Azure Key Vault Olympos uses. The Azure
// implementation uses Managed Identity; the local implementation exists for
// development and e2e tests only.
type KeyVault interface {
	// WrapKey wraps a DEK with the configured KEK and returns the KEK version used.
	WrapKey(ctx context.Context, dek []byte) (wrapped []byte, kekVersion string, err error)
	// UnwrapKey reverses WrapKey.
	UnwrapKey(ctx context.Context, wrapped []byte, kekVersion string) ([]byte, error)
	// GetSecret reads a secret value. vault is the Key Vault name.
	GetSecret(ctx context.Context, vault, name string) ([]byte, error)
	// SetSecret writes a new version of a secret.
	SetSecret(ctx context.Context, vault, name string, value []byte) error
}

// ErrSecretNotFound is returned when a Key Vault secret does not exist.
var ErrSecretNotFound = errors.New("key vault secret not found")

// Ref is a parsed kv://<vault>/<secret> reference.
type Ref struct {
	Vault  string
	Secret string
}

func (r Ref) String() string { return "kv://" + r.Vault + "/" + r.Secret }

// ParseRef parses kv://<vault>/<secret>.
func ParseRef(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, "kv://")
	if !ok {
		return Ref{}, fmt.Errorf("key vault reference must start with kv://")
	}
	vault, name, ok := strings.Cut(rest, "/")
	if !ok || vault == "" || name == "" || strings.Contains(name, "/") {
		return Ref{}, fmt.Errorf("key vault reference must be kv://<vault>/<secret>")
	}
	if !validKVName(vault) || !validKVName(name) {
		return Ref{}, fmt.Errorf("invalid key vault or secret name in %q", s)
	}
	return Ref{Vault: vault, Secret: name}, nil
}

func validKVName(s string) bool {
	if len(s) == 0 || len(s) > 127 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// Resolve fetches the value behind a reference. The caller owns the returned
// slice and should Zero it when done.
func Resolve(ctx context.Context, kv KeyVault, ref string) ([]byte, error) {
	r, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	return kv.GetSecret(ctx, r.Vault, r.Secret)
}

// Zero overwrites b. Best effort: Go may have copied the data elsewhere.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
