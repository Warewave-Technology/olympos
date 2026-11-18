package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

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
