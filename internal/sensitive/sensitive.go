// Package sensitive finds and redacts credentials in text: the gitleaks
// rules (embedded in the build) plus Olympos' key-name heuristics.
//
// The agent uses the Detector to report where sensitive data sits in
// ConfigMaps (F2) without reporting the value. olympos-probe uses the
// Redactor to remove credentials from response excerpts and assertion
// values before anything leaves the cluster
// (docs/design/synthetic-monitoring.md §6.2).
package sensitive

import (
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/detect"
	gllog "github.com/zricethezav/gitleaks/v8/logging"
)

// MaxValue is how many bytes of one value Find and the Redactor scan with
// the gitleaks rules. The rest is not scanned.
const MaxValue = 1 << 20

// minKeyNameValue: shorter values are flags, not credentials.
const minKeyNameValue = 4

// genericRule is gitleaks' catch-all rule; a specific rule wins over it.
const genericRule = "generic-api-key"

// keyWords are key-name heuristics: a key whose normalized name contains one
// of them and has a non-placeholder value is a medium-confidence finding.
var keyWords = []struct{ word, desc string }{
	{"privatekey", "Key name suggests a private key"},
	{"connectionstring", "Key name suggests a connection string with credentials"},
	{"password", "Key name suggests a password"},
	{"passwd", "Key name suggests a password"},
	{"pwd", "Key name suggests a password"},
	{"secret", "Key name suggests a secret"},
	{"token", "Key name suggests a token"},
	{"apikey", "Key name suggests an API key"},
	{"accesskey", "Key name suggests an access key"},
	{"credential", "Key name suggests credentials"},
	{"dsn", "Key name suggests a database DSN"},
}

// redactWords are the extra words SensitiveName looks for in HTTP header
// and JSON field names, on top of keyWords.
var redactWords = []string{"auth", "cookie", "session", "jwt", "bearer", "signature"}

// placeholder values are not credentials (templating, references, empty).
var placeholder = regexp.MustCompile(`^(\$\{[^}]*\}|\{\{.*\}\}|<[^>]*>|%[A-Za-z_]+%|changeme|change-me|xxx+|\*+|true|false|none|null|nil|n/a)$`)

// Detector runs the gitleaks default rules. It is safe for concurrent use;
// scans are serialized.
type Detector struct {
	mu  sync.Mutex
	det *detect.Detector
}

// NewDetector loads the gitleaks default rules. It is slow (the rules are
// compiled); make one and share it.
func NewDetector() (*Detector, error) {
	// gitleaks logs to stderr by default; it must not log fragments.
	gllog.Logger = zerolog.Nop()
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	return &Detector{det: d}, nil
}

// Find reports the most specific gitleaks rule that matches value, with
// key as context ("key=value"; keyword rules such as generic-api-key need
// it). Only the first MaxValue bytes of value are scanned. It never returns
// the value or part of it.
func (d *Detector) Find(key, value string) (ruleID, desc string, ok bool) {
	if len(value) > MaxValue {
		value = value[:MaxValue]
	}
	d.mu.Lock()
	fs := d.det.DetectString(key + "=" + value)
	d.mu.Unlock()
	for _, f := range fs {
		if !ok || ruleID == genericRule && f.RuleID != genericRule {
			ruleID, desc, ok = f.RuleID, f.Description, true
		}
	}
	return ruleID, desc, ok
}

// secrets returns the secrets the gitleaks rules find in text (at most
// MaxValue bytes of it), longest first, once each.
func (d *Detector) secrets(text string) []string {
	if len(text) > MaxValue {
		text = text[:MaxValue]
	}
	d.mu.Lock()
	fs := d.det.DetectString(text)
	d.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		s := f.Secret
		if s == "" {
			s = f.Match
		}
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// Longest first, so that a secret that contains another is replaced
	// whole.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && len(out[j]) > len(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// LengthBucket reports a value's length as the next power of two (8, 16,
// 32, ... 4096+): enough to tell a PIN from a key, without the exact size
// (security review #11).
func LengthBucket(n int) int64 {
	b := int64(8)
	for b < int64(n) && b < 4096 {
		b *= 2
	}
	return b
}

// referenceSuffixes mark keys that name or point to a secret rather than
// hold one (secretName, tokenPath, passwordFile, credentialsRef, ...).
var referenceSuffixes = []string{"name", "ref", "path", "file", "id", "enabled", "length", "ttl", "url", "endpoint", "mount", "key"}

// normalizeKey lowers the key and drops separators.
func normalizeKey(key string) string {
	k := strings.ToLower(key)
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(k)
}

// KeyNameMatch normalizes the key (lower case, no separators) and returns
// the first heuristic word it contains, with its description. Keys that
// name or point to a secret (secretName, tokenPath, ...) match nothing.
// This is the agent's F2 heuristic, tuned against false positives.
func KeyNameMatch(key string) (word, desc string) {
	k := normalizeKey(key)
	for _, suf := range referenceSuffixes {
		if strings.HasSuffix(k, suf) && !strings.HasSuffix(k, "apikey") && !strings.HasSuffix(k, "privatekey") && !strings.HasSuffix(k, "accesskey") {
			return "", ""
		}
	}
	for _, w := range keyWords {
		if strings.Contains(k, w.word) {
			return w.word, w.desc
		}
	}
	return "", ""
}

// Meaningful reports whether v looks like a real value: at least four
// characters and not a placeholder such as "${X}", "changeme" or "true".
func Meaningful(v string) bool {
	v = strings.TrimSpace(v)
	return len(v) >= minKeyNameValue && !placeholder.MatchString(strings.ToLower(v))
}

// SensitiveName reports whether a header or JSON field name suggests that
// its value is a credential, for redaction. It is broader than
// KeyNameMatch: it has no exception for reference names ("secret_key",
// "tokenPath" are sensitive here) and also matches auth, cookie, session,
// jwt, bearer and signature. A redaction that hides too much costs a less
// useful excerpt; one that hides too little leaks a secret.
func SensitiveName(name string) bool {
	k := normalizeKey(name)
	if k == "" {
		return false
	}
	for _, w := range keyWords {
		if strings.Contains(k, w.word) {
			return true
		}
	}
	for _, w := range redactWords {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}
