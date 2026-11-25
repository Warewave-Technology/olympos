package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKeyVault talks to Azure Key Vault with the server's Managed Identity.
type AzureKeyVault struct {
	Cred azcore.TokenCredential
	// KEKVault and KEKName identify the key used to wrap DEKs.
	KEKVault string
	KEKName  string
	// DNSSuffix defaults to vault.azure.net (override for sovereign clouds).
	DNSSuffix string

	mu      sync.Mutex
	secrets map[string]*azsecrets.Client
	keys    *azkeys.Client
	// pub caches signing keys' public halves by key ID (<name>/<version>)
	// for pubKeyTTL.
	pub map[string]cachedPub
	now func() time.Time // time.Now; tests set it
}

// pubKeyTTL bounds how long a version disabled or deleted in the vault
// still verifies here: Verify fetches the public key again after it.
const pubKeyTTL = time.Hour

type cachedPub struct {
	key     *ecdsa.PublicKey
	fetched time.Time
}

func (a *AzureKeyVault) url(vault string) string {
	suffix := a.DNSSuffix
	if suffix == "" {
		suffix = "vault.azure.net"
	}
	return "https://" + vault + "." + suffix + "/"
}

func (a *AzureKeyVault) keyClient() (*azkeys.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys == nil {
		c, err := azkeys.NewClient(a.url(a.KEKVault), a.Cred, nil)
		if err != nil {
			return nil, err
		}
		a.keys = c
	}
	return a.keys, nil
}

func (a *AzureKeyVault) secretClient(vault string) (*azsecrets.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.secrets == nil {
		a.secrets = map[string]*azsecrets.Client{}
	}
	if c, ok := a.secrets[vault]; ok {
		return c, nil
	}
	c, err := azsecrets.NewClient(a.url(vault), a.Cred, nil)
	if err != nil {
		return nil, err
	}
	a.secrets[vault] = c
	return c, nil
}

func (a *AzureKeyVault) WrapKey(ctx context.Context, dek []byte) ([]byte, string, error) {
	c, err := a.keyClient()
	if err != nil {
		return nil, "", err
	}
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := c.WrapKey(ctx, a.KEKName, "", azkeys.KeyOperationParameters{Algorithm: &alg, Value: dek}, nil)
	if err != nil {
		return nil, "", err
	}
	ver := ""
	if resp.KID != nil {
		ver = resp.KID.Version()
	}
	return resp.Result, ver, nil
}

func (a *AzureKeyVault) UnwrapKey(ctx context.Context, wrapped []byte, ver string) ([]byte, error) {
	c, err := a.keyClient()
	if err != nil {
		return nil, err
	}
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := c.UnwrapKey(ctx, a.KEKName, ver, azkeys.KeyOperationParameters{Algorithm: &alg, Value: wrapped}, nil)
	if err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func (a *AzureKeyVault) GetSecret(ctx context.Context, vault, name string) ([]byte, error) {
	c, err := a.secretClient(vault)
	if err != nil {
		return nil, err
	}
	resp, err := c.GetSecret(ctx, name, "", nil)
	if err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == 404 {
			return nil, ErrSecretNotFound
		}
		if errors.As(err, &re) && (re.StatusCode == 401 || re.StatusCode == 403) {
			return nil, fmt.Errorf("get secret %s/%s: %s: %w", vault, name, statusOnly(err), ErrSecretForbidden)
		}
		return nil, fmt.Errorf("get secret %s/%s: %s", vault, name, statusOnly(err))
	}
	if resp.Value == nil {
		return nil, ErrSecretNotFound
	}
	return []byte(*resp.Value), nil
}

func (a *AzureKeyVault) SetSecret(ctx context.Context, vault, name string, value []byte) error {
	c, err := a.secretClient(vault)
	if err != nil {
		return err
	}
	_, err = c.SetSecret(ctx, name, azsecrets.SetSecretParameters{Value: to.Ptr(string(value))}, nil)
	if err != nil {
		return fmt.Errorf("set secret %s/%s: %s", vault, name, statusOnly(err))
	}
	return nil
}

// Sign signs digest with the newest version of keyName, a key in the KEK's
// vault (keys/sign; the Managed Identity needs the sign permission).
func (a *AzureKeyVault) Sign(ctx context.Context, keyName string, digest []byte) ([]byte, string, error) {
	if err := checkDigest(digest); err != nil {
		return nil, "", err
	}
	if !validKVName(keyName) {
		return nil, "", fmt.Errorf("invalid key name %q", keyName)
	}
	c, err := a.keyClient()
	if err != nil {
		return nil, "", err
	}
	alg := azkeys.SignatureAlgorithmES256
	resp, err := c.Sign(ctx, keyName, "", azkeys.SignParameters{Algorithm: &alg, Value: digest}, nil)
	if err != nil {
		return nil, "", keyError("sign with key "+keyName, err)
	}
	// Key Vault key names are case-insensitive; the key ID keeps the vault's
	// spelling.
	name, ver := kidParts(resp.KID)
	if !strings.EqualFold(name, keyName) || !validKVName(name) || !validKVName(ver) {
		return nil, "", fmt.Errorf("sign with key %s: the response names no version of the key", keyName)
	}
	if len(resp.Result) != 64 {
		return nil, "", fmt.Errorf("sign with key %s: %d-byte signature, want 64 (ES256)", keyName, len(resp.Result))
	}
	return resp.Result, name + "/" + ver, nil
}

// Verify checks sig locally with the public key of the version keyID names.
// The public key is fetched (keys/get) and cached for pubKeyTTL. A version
// disabled in the vault is ErrKeyDisabled, a deleted one ErrKeyNotFound: at
// once if it was not cached, otherwise when its cache entry expires.
func (a *AzureKeyVault) Verify(ctx context.Context, keyID string, digest, sig []byte) error {
	if err := checkDigest(digest); err != nil {
		return err
	}
	pub, err := a.publicKey(ctx, keyID)
	if err != nil {
		return err
	}
	return verifyES256(pub, digest, sig)
}

func (a *AzureKeyVault) publicKey(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	name, ver, err := parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	a.mu.Lock()
	e, ok := a.pub[keyID]
	if ok && now().Sub(e.fetched) >= pubKeyTTL {
		delete(a.pub, keyID)
		ok = false
	}
	a.mu.Unlock()
	if ok {
		return e.key, nil
	}
	c, err := a.keyClient()
	if err != nil {
		return nil, err
	}
	resp, err := c.GetKey(ctx, name, ver, nil)
	if err != nil {
		return nil, keyError("get key "+keyID, err)
	}
	k := resp.Key
	if k == nil {
		return nil, fmt.Errorf("get key %s: the response has no key", keyID)
	}
	if n, v := kidParts(k.KID); !strings.EqualFold(n, name) || v != ver {
		return nil, fmt.Errorf("get key %s: the response is for another key", keyID)
	}
	if resp.Attributes != nil && resp.Attributes.Enabled != nil && !*resp.Attributes.Enabled {
		return nil, fmt.Errorf("key %s: %w", keyID, ErrKeyDisabled)
	}
	if k.Kty == nil || (*k.Kty != azkeys.KeyTypeEC && *k.Kty != azkeys.KeyTypeECHSM) ||
		k.Crv == nil || *k.Crv != azkeys.CurveNameP256 || len(k.X) != 32 || len(k.Y) != 32 {
		return nil, fmt.Errorf("get key %s: not an EC P-256 key", keyID)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, k.X...), k.Y...))
	if err != nil {
		return nil, fmt.Errorf("get key %s: %w", keyID, err)
	}
	a.mu.Lock()
	if a.pub == nil {
		a.pub = map[string]cachedPub{}
	}
	a.pub[keyID] = cachedPub{key: pub, fetched: now()}
	a.mu.Unlock()
	return pub, nil
}

// kidParts returns a key ID's name and version, "" for what it lacks.
// azkeys.ID.Name panics on an ID without a name.
func kidParts(id *azkeys.ID) (name, version string) {
	if id == nil {
		return "", ""
	}
	u, err := url.Parse(string(*id))
	if err != nil {
		return "", ""
	}
	p := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(p) < 2 || p[0] != "keys" {
		return "", ""
	}
	if len(p) > 2 {
		version = p[2]
	}
	return p[1], version
}

// keyError maps a keys API error: 404 is ErrKeyNotFound, the rest keep only
// the status (statusOnly).
func keyError(what string, err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) && re.StatusCode == 404 {
		return fmt.Errorf("%s: %w", what, ErrKeyNotFound)
	}
	return fmt.Errorf("%s: %s", what, statusOnly(err))
}

// statusOnly keeps Azure errors from echoing request bodies into logs.
func statusOnly(err error) string {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return fmt.Sprintf("%d %s", re.StatusCode, re.ErrorCode)
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	return s
}

// RecoveryChecker is implemented by key vaults that can tell whether the KEK
// survives a deletion (F17: a database dump is useless without the KEK).
type RecoveryChecker interface {
	// KEKRecoverable reports whether the KEK is protected from purge
	// (soft delete + purge protection) and the raw recovery level.
	KEKRecoverable(ctx context.Context) (bool, string, error)
}

// KEKRecoverable reads the KEK's recoveryLevel (data plane, keys/get): any
// level containing "Purgeable" means purge protection is off.
func (a *AzureKeyVault) KEKRecoverable(ctx context.Context) (bool, string, error) {
	c, err := a.keyClient()
	if err != nil {
		return false, "", err
	}
	resp, err := c.GetKey(ctx, a.KEKName, "", nil)
	if err != nil {
		return false, "", errors.New("read KEK attributes: " + statusOnly(err))
	}
	if resp.Attributes == nil || resp.Attributes.RecoveryLevel == nil {
		return false, "", errors.New("the KEK has no recovery level")
	}
	level := string(*resp.Attributes.RecoveryLevel)
	return RecoverableLevel(level), level, nil
}

// RecoverableLevel: soft delete with purge protection (no "Purgeable").
func RecoverableLevel(level string) bool {
	if strings.Contains(level, "Purgeable") {
		return false
	}
	return strings.HasPrefix(level, "Recoverable") || strings.HasPrefix(level, "CustomizedRecoverable")
}
