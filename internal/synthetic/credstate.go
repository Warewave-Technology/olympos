package synthetic

import (
	"errors"

	"github.com/Warewave-Technology/olympos/internal/secrets"
)

// Why a credential cannot be resolved (resolve_cause). All but unavailable
// are permanent: retrying will not help until someone changes the credential
// or the vault.
const (
	CauseNotFound    = "not_found"
	CauseForbidden   = "forbidden"
	CauseDecrypt     = "decrypt"
	CauseEmpty       = "empty"
	CauseExpired     = "expired"
	CauseUnavailable = "unavailable"
)

// resolveCause classifies an error from runCredentials. Anything not known
// to be permanent is transient, the KEK failing to unwrap included: that
// breaks every stored credential at once and is reported by the KEK watch.
func resolveCause(err error) (cause string, permanent bool) {
	switch {
	case errors.Is(err, secrets.ErrSecretNotFound):
		return CauseNotFound, true
	case errors.Is(err, secrets.ErrSecretForbidden),
		errors.Is(err, secrets.ErrRefReserved),
		errors.Is(err, secrets.ErrRefNotAllowed):
		return CauseForbidden, true
	case errors.Is(err, secrets.ErrDecrypt):
		return CauseDecrypt, true
	case errors.Is(err, errCredentialEmpty):
		return CauseEmpty, true
	case errors.Is(err, errCredentialExpired):
		return CauseExpired, true
	}
	return CauseUnavailable, false
}
