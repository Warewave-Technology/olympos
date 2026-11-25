//go:build dev

package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLocalSignVerify(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kv := &LocalKeyVault{Dir: dir}
	d := sha256.Sum256([]byte(`{"format":"olympos.clickhouse.native/v1"}`))
	digest := d[:]

	sig, keyID, err := kv.Sign(ctx, testKeyName, digest)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != testKeyName+"/1" || len(sig) != 64 {
		t.Fatalf("sign: keyID %q, %d bytes", keyID, len(sig))
	}
	// The key is created on first use, and the signature is plain ES256.
	p := filepath.Join(dir, "keys", testKeyName, "1.pem")
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	pub := readPEMKey(t, p).PublicKey
	if !ecdsa.Verify(&pub, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("not an ES256 r||s signature by the key file")
	}
	if err := kv.Verify(ctx, keyID, digest, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	flip := func(b []byte, i int) []byte { c := append([]byte(nil), b...); c[i] ^= 1; return c }
	if err := kv.Verify(ctx, keyID, flip(digest, 31), sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("flipped digest: %v", err)
	}
	if err := kv.Verify(ctx, keyID, digest, flip(sig, 0)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("flipped signature: %v", err)
	}
	if err := kv.Verify(ctx, keyID, digest, append(sig, 0)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("long signature: %v", err)
	}
	for _, unknown := range []string{testKeyName + "/2", "other-key/1"} {
		if err := kv.Verify(ctx, unknown, digest, sig); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("%s: %v", unknown, err)
		}
	}
	for _, bad := range []string{"", testKeyName, testKeyName + "/", "a/b/c", "../x/1", testKeyName + "/../1", testKeyName + "/x"} {
		if err := kv.Verify(ctx, bad, digest, sig); err == nil || errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("keyID %q: %v", bad, err)
		}
	}
	if _, _, err := kv.Sign(ctx, "../x", digest); err == nil {
		t.Error("an invalid key name must be refused")
	}
	if _, _, err := kv.Sign(ctx, testKeyName, digest[:20]); err == nil {
		t.Error("a digest that is not SHA-256 must be refused")
	}

	// The key persists: another instance on the same directory signs with it.
	sig2, keyID2, err := (&LocalKeyVault{Dir: dir}).Sign(ctx, testKeyName, digest)
	if err != nil || keyID2 != keyID {
		t.Fatalf("second instance: %q %v", keyID2, err)
	}
	if err := kv.Verify(ctx, keyID2, digest, sig2); err != nil {
		t.Fatal(err)
	}

	// After a rotation (a new version on disk), Sign uses the newest version
	// and what the old one signed still verifies (design §5, key versions).
	writePEMKey(t, filepath.Join(dir, "keys", testKeyName, "2.pem"), newKey(t))
	writePEMKey(t, filepath.Join(dir, "keys", testKeyName, "10.pem"), newKey(t))
	sig10, keyID10, err := kv.Sign(ctx, testKeyName, digest)
	if err != nil || keyID10 != testKeyName+"/10" {
		t.Fatalf("after rotation: %q %v", keyID10, err)
	}
	if err := kv.Verify(ctx, keyID10, digest, sig10); err != nil {
		t.Fatal(err)
	}
	if err := kv.Verify(ctx, keyID, digest, sig); err != nil {
		t.Fatalf("version 1 after rotation: %v", err)
	}
	if err := kv.Verify(ctx, testKeyName+"/2", digest, sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("version 1 signature checked with version 2: %v", err)
	}
}

// Concurrent first use creates one key, not one per caller.
func TestLocalSignConcurrentFirstUse(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d := sha256.Sum256([]byte("m"))
	type res struct {
		sig []byte
		id  string
		err error
	}
	out := make([]res, 8)
	var wg sync.WaitGroup
	for i := range out {
		wg.Go(func() {
			// Separate instances, as separate processes would be.
			s, id, err := (&LocalKeyVault{Dir: dir}).Sign(ctx, testKeyName, d[:])
			out[i] = res{s, id, err}
		})
	}
	wg.Wait()
	kv := &LocalKeyVault{Dir: dir}
	for _, r := range out {
		if r.err != nil || r.id != testKeyName+"/1" {
			t.Fatalf("%q %v", r.id, r.err)
		}
		if err := kv.Verify(ctx, r.id, d[:], r.sig); err != nil {
			t.Fatal(err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "keys", testKeyName, "*")); len(m) != 1 {
		t.Fatalf("files: %v", m)
	}
}

func readPEMKey(t *testing.T, p string) *ecdsa.PrivateKey {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PrivateKey)
}

func writePEMKey(t *testing.T, p string, k *ecdsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
