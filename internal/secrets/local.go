package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LocalKeyVault is a development stand-in for Azure Key Vault. The KEK and
// secrets live on disk under Dir. It MUST NOT be used in production; the
// server refuses to start with it unless devMode is set.
//
// Layout: <Dir>/kek (32 random bytes), <Dir>/secrets/<vault>/<name>.
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
