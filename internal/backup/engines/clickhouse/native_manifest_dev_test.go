//go:build dev

package clickhouse

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// TestNativeManifestLocalKeyVault: the manifest signs and verifies with the
// dev Key Vault, and a version that never signed it does not verify it.
func TestNativeManifestLocalKeyVault(t *testing.T) {
	ctx := context.Background()
	kv := &secrets.LocalKeyVault{Dir: t.TempDir()}
	raw := signedJSON(t, kv, testManifestKey, testNativeManifest())
	got, err := VerifySigned(ctx, kv, testManifestKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Canonical(), testNativeManifest().Canonical()) {
		t.Fatal("verified manifest differs")
	}
	bad := bytes.Replace(raw, []byte(`"key_id":"`+testManifestKey+`/1"`), []byte(`"key_id":"`+testManifestKey+`/2"`), 1)
	if _, err := VerifySigned(ctx, kv, testManifestKey, bad); !errors.Is(err, secrets.ErrKeyNotFound) {
		t.Fatalf("unknown key version: %v", err)
	}
}
