package agent

// Sensitive data in ConfigMaps (F2). The agent scans ConfigMap values with
// the gitleaks rules (embedded in the build) plus key-name heuristics and
// reports only where a match is and which rule matched: never the value, a
// prefix/suffix of it or a hash. Values never leave the cluster and never
// enter the informer cache (the transform scans and strips them).

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/detect"
	gllog "github.com/zricethezav/gitleaks/v8/logging"
	corev1 "k8s.io/api/core/v1"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

// SensitiveRulesVersion versions the rule set shipped in this agent build:
// the gitleaks default rules plus Olympos' key-name heuristics.
const SensitiveRulesVersion = "gitleaks-v8.30.1+olympos-keys-1"

// Confidence of a sensitive-data match.
const (
	ConfidenceHigh   = "high"   // matched a credential pattern
	ConfidenceMedium = "medium" // key name only
)

const (
	maxSensitiveValue = 1 << 20 // bytes scanned per value
	minKeyNameValue   = 4       // shorter values are flags, not credentials
)

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

// placeholder values are not credentials (templating, references, empty).
var placeholder = regexp.MustCompile(`^(\$\{[^}]*\}|\{\{.*\}\}|<[^>]*>|%[A-Za-z_]+%|changeme|change-me|xxx+|\*+|true|false|none|null|nil|n/a)$`)

type sensitiveScanner struct {
	mu  sync.Mutex
	det *detect.Detector
}

func newSensitiveScanner() (*sensitiveScanner, error) {
	// gitleaks logs to stderr by default; it must not log fragments.
	gllog.Logger = zerolog.Nop()
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	d.Redact = 100
	return &sensitiveScanner{det: d}, nil
}

// scan returns one item per key with a match (the most specific rule).
func (s *sensitiveScanner) scan(cm *corev1.ConfigMap) []*pb.SensitiveDataItem {
	var out []*pb.SensitiveDataItem
	check := func(key, value string) {
		if it := s.scanValue(key, value); it != nil {
			it.Namespace, it.ConfigMap = cm.Namespace, cm.Name
			out = append(out, it)
		}
	}
	for k, v := range cm.Data {
		check(k, v)
	}
	for k, v := range cm.BinaryData {
		if utf8.Valid(v) {
			check(k, string(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (s *sensitiveScanner) scanValue(key, value string) *pb.SensitiveDataItem {
	n := int64(len(value))
	if len(value) > maxSensitiveValue {
		value = value[:maxSensitiveValue]
	}
	// The key name gives keyword rules (generic-api-key) their context.
	s.mu.Lock()
	fs := s.det.DetectString(key + "=" + value)
	s.mu.Unlock()
	var best *pb.SensitiveDataItem
	for _, f := range fs {
		if best == nil || best.RuleId == genericRule && f.RuleID != genericRule {
			best = &pb.SensitiveDataItem{Key: key, RuleId: f.RuleID, RuleDescription: f.Description, Confidence: ConfidenceHigh, ValueLength: n}
		}
	}
	if best != nil {
		return best
	}
	if w, desc := keyNameMatch(key); w != "" && meaningful(value) {
		return &pb.SensitiveDataItem{Key: key, RuleId: "key-name:" + w, RuleDescription: desc, Confidence: ConfidenceMedium, ValueLength: n}
	}
	return nil
}

// referenceSuffixes mark keys that name or point to a secret rather than
// hold one (secretName, tokenPath, passwordFile, credentialsRef, ...).
var referenceSuffixes = []string{"name", "ref", "path", "file", "id", "enabled", "length", "ttl", "url", "endpoint", "mount", "key"}

// keyNameMatch normalizes the key (lower case, no separators) and returns
// the first heuristic word it contains.
func keyNameMatch(key string) (string, string) {
	k := strings.ToLower(key)
	k = strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(k)
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

func meaningful(v string) bool {
	v = strings.TrimSpace(v)
	return len(v) >= minKeyNameValue && !placeholder.MatchString(strings.ToLower(v))
}
