package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

const (
	testKeyName = "olympos-manifest"
	testOldVer  = "0123456789abcdef0123456789abcdef"
	testCurVer  = "fedcba9876543210fedcba9876543210"
	testOffVer  = "00112233445566778899aabbccddeeff"
)

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "t", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeKeyServer speaks the Key Vault keys REST that Sign and Verify use:
// POST /keys/<name>/<version>/sign and GET /keys/<name>/<version>, after the
// challenge (401 with WWW-Authenticate) the azkeys client expects first.
type fakeKeyServer struct {
	url  string
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey // by version
	off  map[string]bool              // disabled versions
	gets map[string]int
	alg  string
}

func (f *fakeKeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// The client drops an empty version: /keys/<name>/sign signs with the
	// current one.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	sign := r.Method == http.MethodPost && parts[len(parts)-1] == "sign"
	if sign {
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "keys" || !sign && (r.Method != http.MethodGet || len(parts) != 3) {
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		return
	}
	name, ver := parts[1], testCurVer
	if len(parts) == 3 {
		ver = parts[2]
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.keys[ver]
	if !strings.EqualFold(name, testKeyName) || !ok { // names are case-insensitive
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"KeyNotFound","message":"A key with (name/id) was not found"}}`))
		return
	}
	kid := f.url + "/keys/" + testKeyName + "/" + ver // the vault's spelling
	w.Header().Set("Content-Type", "application/json")
	if sign {
		var req struct{ Alg, Value string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.alg = req.Alg
		digest, err := base64.RawURLEncoding.DecodeString(req.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sig, err := es256(key, digest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"kid": kid, "value": base64.RawURLEncoding.EncodeToString(sig)})
		return
	}
	f.gets[ver]++
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enc := base64.RawURLEncoding.EncodeToString
	_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{
		"kid": kid, "kty": "EC", "crv": "P-256", "key_ops": []string{"sign", "verify"},
		"x": enc(pub[1:33]), "y": enc(pub[33:]),
	}, "attributes": map[string]any{"enabled": !f.off[ver]}})
}

// change edits the vault's keys, as an operator would.
func (f *fakeKeyServer) change(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// fetched returns how often GetKey fetched each version, and the last sign alg.
func (f *fakeKeyServer) fetched() (map[string]int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.gets), f.alg
}

// es256 signs digest the way Key Vault returns ES256: r||s, 32 bytes each.
func es256(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func rawSign(t *testing.T, key *ecdsa.PrivateKey, digest []byte) []byte {
	sig, err := es256(key, digest)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAzureSignVerify(t *testing.T) {
	ctx := context.Background()
	f := &fakeKeyServer{gets: map[string]int{}, off: map[string]bool{testOffVer: true}, keys: map[string]*ecdsa.PrivateKey{
		testOldVer: newKey(t), testCurVer: newKey(t), testOffVer: newKey(t),
	}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	f.url = srv.URL
	c, err := azkeys.NewClient(srv.URL, fakeCred{}, &azkeys.ClientOptions{
		ClientOptions:                        azcore.ClientOptions{Transport: srv.Client(), Retry: azpolicy.RetryOptions{MaxRetries: -1}},
		DisableChallengeResourceVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	kv := &AzureKeyVault{keys: c, now: func() time.Time { return clock }}
	d := sha256.Sum256([]byte(`{"format":"olympos.clickhouse.native/v1"}`))
	digest := d[:]

	sig, keyID, err := kv.Sign(ctx, testKeyName, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, alg := f.fetched(); keyID != testKeyName+"/"+testCurVer || len(sig) != 64 || alg != "ES256" {
		t.Fatalf("sign: keyID %q, %d bytes, alg %q", keyID, len(sig), alg)
	}
	for range 2 {
		if err := kv.Verify(ctx, keyID, digest, sig); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
	if gets, _ := f.fetched(); gets[testCurVer] != 1 {
		t.Fatalf("the public key is fetched once per version, got %v", gets)
	}

	flip := func(b []byte, i int) []byte { c := append([]byte(nil), b...); c[i] ^= 1; return c }
	if err := kv.Verify(ctx, keyID, flip(digest, 0), sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("flipped digest: %v", err)
	}
	if err := kv.Verify(ctx, keyID, digest, flip(sig, 40)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("flipped signature: %v", err)
	}
	if err := kv.Verify(ctx, keyID, digest, sig[:63]); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("short signature: %v", err)
	}

	// An older version still verifies what it signed, and only that.
	old := testKeyName + "/" + testOldVer
	if err := kv.Verify(ctx, old, digest, rawSign(t, f.keys[testOldVer], digest)); err != nil {
		t.Fatalf("old version: %v", err)
	}
	if err := kv.Verify(ctx, old, digest, sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("current signature checked with the old version: %v", err)
	}
	if gets, _ := f.fetched(); gets[testOldVer] != 1 {
		t.Fatalf("verify fetches the version in keyID, got %v", gets)
	}

	// A disabled version is refused on the first fetch.
	off := testKeyName + "/" + testOffVer
	if err := kv.Verify(ctx, off, digest, rawSign(t, f.keys[testOffVer], digest)); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("disabled version: %v", err)
	}

	// A cached version disabled in the vault still verifies until the cache
	// entry expires (1 hour), and is refused after it.
	f.change(func() { f.off[testCurVer] = true })
	clock = clock.Add(59 * time.Minute)
	if err := kv.Verify(ctx, keyID, digest, sig); err != nil {
		t.Fatalf("disabled, cached: %v", err)
	}
	clock = clock.Add(2 * time.Minute)
	if err := kv.Verify(ctx, keyID, digest, sig); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("disabled, after the cache entry expired: %v", err)
	}
	f.change(func() { f.off[testCurVer] = false })
	if err := kv.Verify(ctx, keyID, digest, sig); err != nil {
		t.Fatalf("enabled again: %v", err)
	}
	if gets, _ := f.fetched(); gets[testCurVer] != 3 {
		t.Fatalf("fetches of the current version: %v", gets)
	}
	// A version deleted from the vault is refused once its entry expires.
	f.change(func() { delete(f.keys, testOldVer) })
	clock = clock.Add(61 * time.Minute)
	if err := kv.Verify(ctx, old, digest, rawSign(t, newKey(t), digest)); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("deleted version: %v", err)
	}

	if err := kv.Verify(ctx, testKeyName+"/00000000000000000000000000000000", digest, sig); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown version: %v", err)
	}
	// Key Vault key names are case-insensitive: the key ID has the vault's
	// spelling of the name.
	sigUpper, idUpper, err := kv.Sign(ctx, "Olympos-Manifest", digest)
	if err != nil || idUpper != keyID {
		t.Fatalf("sign with another case: %q %v", idUpper, err)
	}
	if err := kv.Verify(ctx, idUpper, digest, sigUpper); err != nil {
		t.Fatal(err)
	}
	if _, _, err := kv.Sign(ctx, "no-such-key", digest); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	for _, bad := range []string{"", testKeyName, testKeyName + "/", "/" + testCurVer, "a/b/c", "../x/" + testCurVer} {
		if err := kv.Verify(ctx, bad, digest, sig); err == nil || errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("keyID %q: %v", bad, err)
		}
	}
	if _, _, err := kv.Sign(ctx, testKeyName, digest[:20]); err == nil {
		t.Error("a digest that is not SHA-256 must be refused")
	}
}

// TestAzurePublicKeyCacheCaseInsensitive: Key Vault key names are
// case-insensitive, so key IDs that differ only in the name's case are one
// cache entry: one GetKey, and one expiry for both.
func TestAzurePublicKeyCacheCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	f := &fakeKeyServer{gets: map[string]int{}, off: map[string]bool{}, keys: map[string]*ecdsa.PrivateKey{testCurVer: newKey(t)}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	f.url = srv.URL
	c, err := azkeys.NewClient(srv.URL, fakeCred{}, &azkeys.ClientOptions{
		ClientOptions:                        azcore.ClientOptions{Transport: srv.Client(), Retry: azpolicy.RetryOptions{MaxRetries: -1}},
		DisableChallengeResourceVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	kv := &AzureKeyVault{keys: c}
	d := sha256.Sum256([]byte("manifest"))
	sig := rawSign(t, f.keys[testCurVer], d[:])
	for _, name := range []string{testKeyName, "OLYMPOS-MANIFEST", "Olympos-Manifest"} {
		if err := kv.Verify(ctx, name+"/"+testCurVer, d[:], sig); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if gets, _ := f.fetched(); gets[testCurVer] != 1 {
		t.Fatalf("case variants of one key ID fetched the key %d times, want 1", gets[testCurVer])
	}
	kv.mu.Lock()
	n := len(kv.pub)
	kv.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d cache entries for one key version, want 1", n)
	}
}

// A malformed key ID in a response is refused, not a panic (azkeys.ID.Name).
func TestKIDParts(t *testing.T) {
	for kid, want := range map[string][2]string{
		"https://v.vault.azure.net/keys/k/" + testCurVer: {"k", testCurVer},
		"https://v.vault.azure.net/keys/k":               {"k", ""},
		"https://v.vault.azure.net/":                     {"", ""},
		"https://v.vault.azure.net/secrets/k/1":          {"", ""},
		"::":                                             {"", ""},
	} {
		id := azkeys.ID(kid)
		if n, v := kidParts(&id); n != want[0] || v != want[1] {
			t.Errorf("%q: %q %q", kid, n, v)
		}
	}
	if n, v := kidParts(nil); n != "" || v != "" {
		t.Errorf("nil: %q %q", n, v)
	}
}

func TestKeyIDName(t *testing.T) {
	if n, err := KeyIDName(testKeyName + "/" + testCurVer); err != nil || n != testKeyName {
		t.Fatalf("%q %v", n, err)
	}
	for _, bad := range []string{"", testKeyName, testKeyName + "/", "/" + testCurVer, "a/b/c", "../x/1"} {
		if n, err := KeyIDName(bad); err == nil {
			t.Errorf("%q: %q", bad, n)
		}
	}
}
