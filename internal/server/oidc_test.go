package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	tenantA  = "11111111-1111-1111-1111-111111111111"
	tenantB  = "22222222-2222-2222-2222-222222222222"
	clientID = "33333333-3333-3333-3333-333333333333"
)

// mockIdP serves OIDC discovery and JWKS for tenant A.
type mockIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m := &mockIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+tenantA+"/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 m.srv.URL + "/" + tenantA + "/v2.0",
			"authorization_endpoint": m.srv.URL + "/authorize",
			"token_endpoint":         m.srv.URL + "/token",
			"jwks_uri":               m.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIdP) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: m.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseClaims(m *mockIdP) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": m.srv.URL + "/" + tenantA + "/v2.0", "tid": tenantA, "aud": clientID, "oid": "44444444-4444-4444-4444-444444444444",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "nonce": "n1",
		"name": "Ada", "preferred_username": "ada@contoso.com",
	}
}

func TestVerifyIDToken(t *testing.T) {
	m := newMockIdP(t)
	o := &OIDC{TenantID: tenantA, ClientID: clientID, AuthorityHost: m.srv.URL}
	ctx := context.Background()

	if c, err := o.VerifyIDToken(ctx, m.token(t, baseClaims(m)), "n1"); err != nil || c.ObjectID == "" {
		t.Fatalf("valid token rejected: %v", err)
	}

	cases := map[string]func(c map[string]any){
		"foreign tid":     func(c map[string]any) { c["tid"] = tenantB },
		"foreign iss":     func(c map[string]any) { c["iss"] = m.srv.URL + "/" + tenantB + "/v2.0" },
		"common iss":      func(c map[string]any) { c["iss"] = m.srv.URL + "/common/v2.0" },
		"wrong audience":  func(c map[string]any) { c["aud"] = "other-app" },
		"expired":         func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"not yet valid":   func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
		"nonce mismatch":  func(c map[string]any) { c["nonce"] = "other" },
		"missing oid":     func(c map[string]any) { delete(c, "oid") },
	}
	for name, mut := range cases {
		c := baseClaims(m)
		mut(c)
		if _, err := o.VerifyIDToken(ctx, m.token(t, c), "n1"); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
	c := baseClaims(m)
	c["tid"] = tenantB
	if _, err := o.VerifyIDToken(ctx, m.token(t, c), "n1"); !errors.Is(err, ErrForeignTenant) {
		t.Errorf("foreign tenant must return ErrForeignTenant, got %v", err)
	}
}

func TestSafeReturnTo(t *testing.T) {
	for in, want := range map[string]string{"/vaults": "/vaults", "//evil.com": "/", "https://evil.com": "/", "/\\evil": "/", "": "/"} {
		if got := safeReturnTo(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}
