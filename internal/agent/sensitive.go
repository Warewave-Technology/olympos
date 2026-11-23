package agent

// Sensitive data in ConfigMaps (F2). The agent scans ConfigMap values with
// the gitleaks rules (embedded in the build) plus key-name heuristics and
// reports only where a match is and which rule matched: never the value, a
// prefix/suffix of it or a hash. Values never leave the cluster and never
// enter the informer cache (the transform scans and strips them).
//
// The detector and the heuristics live in internal/sensitive, which
// olympos-probe shares for redaction.

import (
	"sort"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
)

// SensitiveRulesVersion versions the rule set shipped in this agent build:
// the gitleaks default rules plus Olympos' key-name heuristics.
const SensitiveRulesVersion = "gitleaks-v8.30.1+olympos-keys-1"

// Confidence of a sensitive-data match.
const (
	ConfidenceHigh   = "high"   // matched a credential pattern
	ConfidenceMedium = "medium" // key name only
)

// maxSensitiveValue is how many bytes of a value are scanned.
const maxSensitiveValue = sensitive.MaxValue

// The key-name heuristics (internal/sensitive).
var (
	lengthBucket = sensitive.LengthBucket
	keyNameMatch = sensitive.KeyNameMatch
	meaningful   = sensitive.Meaningful
)

type sensitiveScanner struct {
	det *sensitive.Detector
}

func newSensitiveScanner() (*sensitiveScanner, error) {
	d, err := sensitive.NewDetector()
	if err != nil {
		return nil, err
	}
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
	n := lengthBucket(len(value))
	if len(value) > maxSensitiveValue {
		value = value[:maxSensitiveValue]
	}
	// The key name gives keyword rules (generic-api-key) their context.
	if id, desc, ok := s.det.Find(key, value); ok {
		return &pb.SensitiveDataItem{Key: key, RuleId: id, RuleDescription: desc, Confidence: ConfidenceHigh, ValueLength: n}
	}
	if w, desc := keyNameMatch(key); w != "" && meaningful(value) {
		return &pb.SensitiveDataItem{Key: key, RuleId: "key-name:" + w, RuleDescription: desc, Confidence: ConfidenceMedium, ValueLength: n}
	}
	return nil
}
