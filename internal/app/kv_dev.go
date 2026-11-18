//go:build dev

package app

import "github.com/Warewave-Technology/olympos/internal/secrets"

func localKeyVault(dir string) (secrets.KeyVault, error) {
	return &secrets.LocalKeyVault{Dir: dir}, nil
}
