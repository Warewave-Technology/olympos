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
	if name != testKeyName || !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"KeyNotFound","message":"A key with (name/id) was not found"}}`))
		return
	}
	kid := f.url + "/keys/" + name + "/" + ver
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
	}})
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
	f := &fakeKeyServer{gets: map[string]int{}, keys: map[string]*ecdsa.PrivateKey{
		testOldVer: newKey(t), testCurVer: newKey(t),
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
	kv := &AzureKeyVault{keys: c}
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

	if err := kv.Verify(ctx, testKeyName+"/00000000000000000000000000000000", digest, sig); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown version: %v", err)
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
