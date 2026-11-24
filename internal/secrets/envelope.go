package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrDecrypt means the DEK unwrapped but the stored value does not open: the
// ciphertext or its binding is damaged. A KEK failure is not ErrDecrypt.
var ErrDecrypt = errors.New("stored secret cannot be decrypted")

// Sealed is an envelope-encrypted value as stored in the database.
type Sealed struct {
	Ciphertext []byte // nonce || AES-256-GCM(ciphertext+tag)
	WrappedDEK []byte
	KEKVersion string
}

// Envelope seals values with a fresh 256-bit DEK per record, wrapped by the
// Key Vault KEK.
type Envelope struct {
	KV KeyVault
}

// Seal encrypts plaintext. aad binds the ciphertext to its context (e.g.
// "credential:<uuid>") so rows cannot be swapped.
func (e *Envelope) Seal(ctx context.Context, plaintext, aad []byte) (Sealed, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Sealed{}, err
	}
	defer Zero(dek)
	ct, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, ver, err := e.KV.WrapKey(ctx, dek)
	if err != nil {
		return Sealed{}, fmt.Errorf("wrap dek: %w", err)
	}
	return Sealed{Ciphertext: ct, WrappedDEK: wrapped, KEKVersion: ver}, nil
}

// Open decrypts a sealed value. The caller should Zero the result.
func (e *Envelope) Open(ctx context.Context, s Sealed, aad []byte) ([]byte, error) {
	if len(s.Ciphertext) == 0 || len(s.WrappedDEK) == 0 {
		return nil, errors.New("sealed value is empty")
	}
	dek, err := e.KV.UnwrapKey(ctx, s.WrappedDEK, s.KEKVersion)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	defer Zero(dek)
	b, err := gcmOpen(dek, s.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return b, nil
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}
