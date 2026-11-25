// Package secrets implements Olympos's secret handling (SPEC §9):
// envelope encryption with a Key Vault KEK, kv:// references resolved at use
// time, HMAC fingerprints and log redaction.
package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
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
	// Sign signs a SHA-256 digest with the newest version of the EC P-256
	// key keyName (ES256, raw r||s, 64 bytes). keyID is <name>/<version>:
	// what Verify needs to find the same version again.
	Sign(ctx context.Context, keyName string, digest []byte) (sig []byte, keyID string, err error)
	// Verify checks sig over digest with the key version keyID names. Every
	// enabled version in the vault verifies, not only the newest: a version
	// stays enabled while a backup it signed is within retention. A bad
	// signature is ErrSignatureInvalid; an unknown key or version is
	// ErrKeyNotFound; a disabled version is ErrKeyDisabled.
	//
	// Verify checks the signature against the key version keyID names; it
	// does not decide which key is trusted. Callers MUST check that keyID's
	// name is the key they trust (for manifests, keyVault.manifestKeyName)
	// before calling it: a key ID read from storage can name any key in the
	// vault. KeyIDName returns the name; compare it case-insensitively, as
	// Key Vault key names are.
	Verify(ctx context.Context, keyID string, digest, sig []byte) error
}

// ErrSecretNotFound is returned when a Key Vault secret does not exist.
var ErrSecretNotFound = errors.New("key vault secret not found")

// ErrSecretForbidden is returned when the vault refuses Olympos access to a
// secret (HTTP 401 or 403, or an unreadable local file).
var ErrSecretForbidden = errors.New("key vault secret access denied")

// ErrSignatureInvalid is returned when a signature does not verify.
var ErrSignatureInvalid = errors.New("signature does not verify")

// ErrKeyNotFound is returned when a Key Vault key, or the version a key ID
// names, does not exist.
var ErrKeyNotFound = errors.New("key vault key not found")

// ErrKeyDisabled is returned when the key version a key ID names is
// disabled in the vault: what it signed no longer verifies.
var ErrKeyDisabled = errors.New("key vault key version disabled")

// KeyIDName returns the key name in a key ID (<name>/<version>), for the
// caller to pin before Verify.
func KeyIDName(keyID string) (string, error) {
	name, _, err := parseKeyID(keyID)
	return name, err
}

// parseKeyID splits a key ID, <name>/<version>, as Sign returns it.
func parseKeyID(keyID string) (name, version string, err error) {
	name, version, ok := strings.Cut(keyID, "/")
	if !ok || !validKVName(name) || !validKVName(version) {
		return "", "", fmt.Errorf("invalid key id %q", keyID)
	}
	return name, version, nil
}

// checkDigest: Sign and Verify take a SHA-256 digest, not the message.
func checkDigest(digest []byte) error {
	if len(digest) != sha256.Size {
		return fmt.Errorf("digest must be SHA-256 (%d bytes), got %d bytes", sha256.Size, len(digest))
	}
	return nil
}

// rawES256 encodes an ES256 signature as Key Vault does: r||s, 32 bytes each.
func rawES256(r, s *big.Int) []byte {
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

// verifyES256 checks a raw r||s signature with a P-256 public key.
func verifyES256(pub *ecdsa.PublicKey, digest, sig []byte) error {
	if len(sig) != 64 {
		return ErrSignatureInvalid
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return ErrSignatureInvalid
	}
	return nil
}

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
