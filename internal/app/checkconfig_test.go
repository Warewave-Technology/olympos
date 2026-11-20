package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/config"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// fakeKV is a Key Vault whose secret lookup and key wrapping can fail.
type fakeKV struct {
	secrets  map[string][]byte
	wrapErr  error
	recovery *bool
}

func (f *fakeKV) WrapKey(_ context.Context, dek []byte) ([]byte, string, error) {
	if f.wrapErr != nil {
		return nil, "", f.wrapErr
	}
	return append([]byte("w:"), dek...), "v1", nil
}

func (f *fakeKV) UnwrapKey(_ context.Context, wrapped []byte, _ string) ([]byte, error) {
	return wrapped[2:], nil
}

func (f *fakeKV) GetSecret(_ context.Context, vault, name string) ([]byte, error) {
	if v, ok := f.secrets[vault+"/"+name]; ok {
		return v, nil
	}
	return nil, secrets.ErrSecretNotFound
}

func (f *fakeKV) SetSecret(_ context.Context, vault, name string, value []byte) error {
	f.secrets[vault+"/"+name] = value
	return nil
}

func (f *fakeKV) KEKRecoverable(context.Context) (bool, string, error) {
	if f.recovery == nil {
		return true, "Recoverable", nil
	}
	return *f.recovery, "Recoverable+Purgeable", nil
}

// check-config -db used to print "config ok" for a Key Vault the server could
// not use, and the server then exited at start ("load hmac key").
func TestCheckKeyVault(t *testing.T) {
	cfg := &config.Server{}
	cfg.KeyVault.Name, cfg.KeyVault.HMACSecretName, cfg.KeyVault.KEKName = "kv", "olympos-hmac", "olympos-kek"
	ctx := context.Background()
	withHMAC := func() map[string][]byte {
		return map[string][]byte{"kv/olympos-hmac": []byte("0123456789abcdef0123456789abcdef")}
	}

	if err := checkKeyVault(ctx, &Deps{Cfg: cfg, KV: &fakeKV{secrets: withHMAC()}}); err != nil {
		t.Fatalf("usable vault: %v", err)
	}
	purgeable := false
	if err := checkKeyVault(ctx, &Deps{Cfg: cfg, KV: &fakeKV{secrets: withHMAC(), recovery: &purgeable}}); err != nil {
		t.Fatalf("purge protection off must only warn: %v", err)
	}
	err := checkKeyVault(ctx, &Deps{Cfg: cfg, KV: &fakeKV{secrets: map[string][]byte{}}})
	if err == nil || !strings.Contains(err.Error(), "HMAC secret kv/olympos-hmac") {
		t.Fatalf("missing HMAC secret: %v", err)
	}
	err = checkKeyVault(ctx, &Deps{Cfg: cfg, KV: &fakeKV{secrets: withHMAC(), wrapErr: errors.New("403 Forbidden")}})
	if err == nil || !strings.Contains(err.Error(), "KEK kv/olympos-kek") || !strings.Contains(err.Error(), "Key Vault Crypto User") {
		t.Fatalf("KEK not usable: %v", err)
	}
	dev := *cfg
	dev.DevMode = true
	if err := checkKeyVault(ctx, &Deps{Cfg: &dev, KV: &fakeKV{secrets: map[string][]byte{}}}); err != nil {
		t.Fatalf("dev mode creates the HMAC secret at start: %v", err)
	}
}

func TestCheckDatabasePgcrypto(t *testing.T) {
	db := testutil.DB(t) // PostgreSQL with contrib: pgcrypto is available
	if err := checkDatabase(context.Background(), db); err != nil {
		t.Fatal(err)
	}
}
