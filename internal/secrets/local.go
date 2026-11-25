//go:build dev

package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// LocalKeyVault is a development stand-in for Azure Key Vault. The KEK and
// secrets live on disk under Dir. It MUST NOT be used in production: only
// development builds (-tags dev) contain it, and they need devMode (F6).
//
// Layout: <Dir>/kek (32 random bytes), <Dir>/secrets/<vault>/<name>, and
// signing keys at <Dir>/keys/<name>/<version>.pem (PKCS#8 EC P-256; versions
// 1, 2, ...). Sign uses the highest version and creates version 1 when there
// is none; a rotation is a new, higher file, and old versions stay for Verify.
type LocalKeyVault struct {
	Dir string

	once sync.Once
	kek  []byte
	err  error
}

const localKEKVersion = "local-v1"

func (l *LocalKeyVault) loadKEK() ([]byte, error) {
	l.once.Do(func() {
		p := filepath.Join(l.Dir, "kek")
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			b = make([]byte, 32)
			if _, err = rand.Read(b); err != nil {
				l.err = err
				return
			}
			if err = os.MkdirAll(l.Dir, 0o700); err == nil {
				err = os.WriteFile(p, b, 0o600)
			}
		}
		if err != nil {
			l.err = err
			return
		}
		if len(b) != 32 {
			l.err = fmt.Errorf("local kek must be 32 bytes, got %d", len(b))
			return
		}
		l.kek = b
	})
	return l.kek, l.err
}

func (l *LocalKeyVault) WrapKey(_ context.Context, dek []byte) ([]byte, string, error) {
	kek, err := l.loadKEK()
	if err != nil {
		return nil, "", err
	}
	w, err := gcmSeal(kek, dek, []byte("olympos-dek"))
	return w, localKEKVersion, err
}

func (l *LocalKeyVault) UnwrapKey(_ context.Context, wrapped []byte, ver string) ([]byte, error) {
	if ver != localKEKVersion {
		return nil, fmt.Errorf("unknown kek version %q", ver)
	}
	kek, err := l.loadKEK()
	if err != nil {
		return nil, err
	}
	return gcmOpen(kek, wrapped, []byte("olympos-dek"))
}

func (l *LocalKeyVault) secretPath(vault, name string) (string, error) {
	if !validKVName(vault) || !validKVName(name) {
		return "", fmt.Errorf("invalid key vault reference")
	}
	return filepath.Join(l.Dir, "secrets", vault, name), nil
}

func (l *LocalKeyVault) GetSecret(_ context.Context, vault, name string) ([]byte, error) {
	p, err := l.secretPath(vault, name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrSecretNotFound
	}
	if errors.Is(err, os.ErrPermission) {
		return nil, ErrSecretForbidden
	}
	return b, err
}

func (l *LocalKeyVault) SetSecret(_ context.Context, vault, name string, value []byte) error {
	p, err := l.secretPath(vault, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, value, 0o600)
}

func (l *LocalKeyVault) Sign(_ context.Context, keyName string, digest []byte) ([]byte, string, error) {
	if err := checkDigest(digest); err != nil {
		return nil, "", err
	}
	if !validKVName(keyName) {
		return nil, "", fmt.Errorf("invalid key name %q", keyName)
	}
	dir := filepath.Join(l.Dir, "keys", keyName)
	ver, err := latestKeyVersion(dir)
	if err != nil {
		return nil, "", err
	}
	if ver == "" {
		if err := createSigningKey(dir, "1"); err != nil {
			return nil, "", err
		}
		ver = "1"
	}
	key, err := readSigningKey(filepath.Join(dir, ver+".pem"))
	if err != nil {
		return nil, "", err
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, "", err
	}
	return rawES256(r, s), keyName + "/" + ver, nil
}

func (l *LocalKeyVault) Verify(_ context.Context, keyID string, digest, sig []byte) error {
	if err := checkDigest(digest); err != nil {
		return err
	}
	name, ver, err := parseKeyID(keyID)
	if err != nil {
		return err
	}
	if n, err := strconv.Atoi(ver); err != nil || n < 1 || strconv.Itoa(n) != ver {
		return fmt.Errorf("invalid key id %q", keyID)
	}
	key, err := readSigningKey(filepath.Join(l.Dir, "keys", name, ver+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("key %s: %w", keyID, ErrKeyNotFound)
	}
	if err != nil {
		return err
	}
	return verifyES256(&key.PublicKey, digest, sig)
}

// latestKeyVersion returns the highest version in dir, "" when there is none.
func latestKeyVersion(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	latest := 0
	for _, e := range entries {
		v, ok := strings.CutSuffix(e.Name(), ".pem")
		if n, err := strconv.Atoi(v); ok && err == nil && n > latest && strconv.Itoa(n) == v {
			latest = n
		}
	}
	if latest == 0 {
		return "", nil
	}
	return strconv.Itoa(latest), nil
}

// createSigningKey writes a new key as <dir>/<ver>.pem. The file appears
// complete or not at all (a hard link from a temporary file), and a key
// another process created first wins.
func createSigningKey(dir, ver string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".new-*") // mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), filepath.Join(dir, ver+".pem")); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func readSigningKey(p string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM private key", p)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: not an EC P-256 key", p)
	}
	return ek, nil
}
