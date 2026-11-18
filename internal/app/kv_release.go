//go:build !dev

package app

import (
	"errors"

	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// localKeyVault: release builds do not contain the local Key Vault (F6).
func localKeyVault(string) (secrets.KeyVault, error) {
	return nil, errors.New("keyVault.provider=local is not available in release builds")
}
