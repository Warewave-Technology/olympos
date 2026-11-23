package spec

import (
	"fmt"
	"io"
	"log/slog"
)

// redacted is what a Secret or a RunCredential's secret fields print as.
const redacted = "[redacted]"

// Secret holds sensitive bytes so that they cannot be printed, logged or
// encoded by mistake. Every printing, logging and JSON method writes
// "[redacted]".
//
// Methods are not enough: fmt cannot call them through an unexported
// field, and then prints by reflection, even through a pointer (a bad verb
// such as %s on a *T prints the T). So the bytes sit behind a function,
// which fmt, slog and encoding/json never call and print, at most, as an
// address.
//
// A nil *Secret is empty. Bytes and Zero are the only ways to the content.
type Secret struct{ ref func() *[]byte }

// NewSecret takes ownership of b: the caller must not use or keep b after
// the call, so that Zero reaches the only copy. It returns nil for an
// empty b.
func NewSecret(b []byte) *Secret {
	if len(b) == 0 {
		return nil
	}
	return &Secret{ref: func() *[]byte { return &b }}
}

// Bytes returns the secret's bytes, not a copy; nil for a nil or zeroed
// secret. Do not keep the slice past Zero.
func (s *Secret) Bytes() []byte {
	if s == nil || s.ref == nil {
		return nil
	}
	return *s.ref()
}

// Len returns the number of bytes.
func (s *Secret) Len() int { return len(s.Bytes()) }

// Zero overwrites the bytes with zeros and drops them.
func (s *Secret) Zero() {
	if s == nil || s.ref == nil {
		return
	}
	b := s.ref()
	clear(*b)
	*b = nil
}

// String returns "[redacted]".
func (s *Secret) String() string { return redacted }

// GoString returns "[redacted]".
func (s *Secret) GoString() string { return redacted }

// Format writes "[redacted]" for every verb.
func (s *Secret) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue returns "[redacted]".
func (s *Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON returns "[redacted]" as a JSON string.
func (s *Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText returns "[redacted]".
func (s *Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
