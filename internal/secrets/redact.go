package secrets

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// Redacted is the placeholder written instead of a sensitive value.
const Redacted = "[REDACTED]"

var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "sas", "sig", "authorization",
	"cookie", "credential", "dsn", "private", "apikey", "api_key", "value", "csr",
}

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)([?&]sig=)[^&\s"]+`),                                     // SAS signature
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*`),                       // bearer tokens
	regexp.MustCompile(`\b(hvs|hvb|hvr|s|b|r)\.[A-Za-z0-9]{20,}`),                    // Vault tokens
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
	regexp.MustCompile(`(://[^:/\s]+:)[^@\s]+(@)`),                                   // user:pass@ in URLs/DSNs
	regexp.MustCompile(`(?i)(password=)[^\s&]+`),                                     // key=value DSNs
	regexp.MustCompile(`xox[abpr]-[A-Za-z0-9-]+`),                                    // Slack tokens
}

// RedactString masks known secret shapes inside free text.
func RedactString(s string) string {
	for _, re := range sensitivePatterns {
		switch re.NumSubexp() {
		case 0:
			s = re.ReplaceAllString(s, Redacted)
		case 1:
			s = re.ReplaceAllString(s, "${1}"+Redacted)
		default:
			s = re.ReplaceAllString(s, "${1}"+Redacted+"${2}")
		}
	}
	return s
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// RedactingHandler wraps a slog.Handler: attributes with sensitive names are
// replaced, and string values / messages are scrubbed for secret shapes.
type RedactingHandler struct {
	inner slog.Handler
}

func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, RedactString(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(out)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	// Resolve first: a LogValuer may produce a group (security review #11).
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		out := make([]any, len(g))
		for i, ga := range g {
			out[i] = redactAttr(ga)
		}
		return slog.Group(a.Key, out...)
	}
	v := a.Value
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, RedactString(v.String()))
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, RedactString(err.Error()))
		}
		return slog.String(a.Key, RedactString(v.String()))
	}
	return a
}
