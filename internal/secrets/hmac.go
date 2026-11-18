package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Fingerprinter computes HMAC-SHA256 fingerprints of secret values so a
// checker can compare values without seeing them. Never a plain hash.
type Fingerprinter struct {
	key []byte
}

// NewFingerprinter takes ownership of key (loaded from Key Vault).
func NewFingerprinter(key []byte) (*Fingerprinter, error) {
	if len(key) < 32 {
		return nil, errors.New("hmac key must be at least 32 bytes")
	}
	return &Fingerprinter{key: key}, nil
}

// Fingerprint returns the display form hm:xxxx·xxxx·xxxx (first 12 hex chars).
func (f *Fingerprinter) Fingerprint(value []byte) string {
	m := hmac.New(sha256.New, f.key)
	m.Write(value)
	h := hex.EncodeToString(m.Sum(nil))[:12]
	return "hm:" + h[0:4] + "·" + h[4:8] + "·" + h[8:12]
}
