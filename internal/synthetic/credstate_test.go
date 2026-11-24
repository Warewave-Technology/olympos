package synthetic

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Warewave-Technology/olympos/internal/secrets"
)

func TestResolveCause(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("resolve credential c: %w", fmt.Errorf("resolve key vault reference kv://v/s: %w", err))
	}
	for _, c := range []struct {
		name      string
		err       error
		cause     string
		permanent bool
	}{
		{"not found", wrap(secrets.ErrSecretNotFound), CauseNotFound, true},
		{"forbidden", wrap(secrets.ErrSecretForbidden), CauseForbidden, true},
		{"reserved", wrap(secrets.ErrRefReserved), CauseForbidden, true},
		{"not allowed", wrap(secrets.ErrRefNotAllowed), CauseForbidden, true},
		{"decrypt", wrap(secrets.ErrDecrypt), CauseDecrypt, true},
		{"expired", fmt.Errorf("%w: credential c", errCredentialExpired), CauseExpired, true},
		{"empty", fmt.Errorf("%w: credential c is empty", errCredentialEmpty), CauseEmpty, true},
		{"5xx", errors.New("get secret v/s: 503 ServiceUnavailable"), CauseUnavailable, false},
		{"kek unwrap", fmt.Errorf("unwrap dek: %w", errors.New("x")), CauseUnavailable, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cause, permanent := resolveCause(c.err)
			if cause != c.cause || permanent != c.permanent {
				t.Fatalf("got %q, %v; want %q, %v", cause, permanent, c.cause, c.permanent)
			}
		})
	}
}

func TestCredentialReasonEmpty(t *testing.T) {
	status, reason := credentialReason(fmt.Errorf("%w: credential c is empty", errCredentialEmpty))
	if status != StatusError || reason != ReasonCredentialError {
		t.Fatalf("got %s/%s", status, reason)
	}
}
