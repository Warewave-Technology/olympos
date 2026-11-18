// Package inventory ingests agent inventory and discovery, tracks cluster
// liveness, and computes the fleet dashboard (SPEC §5, §6).
package inventory

import (
	"strconv"
	"strings"
	"time"
)

// Providers.
const (
	ProviderAzure  = "azure"
	ProviderAWS    = "aws"
	ProviderGCP    = "gcp"
	ProviderOracle = "oracle"
	ProviderHuawei = "huawei"
	ProviderOnPrem = "onprem"
)

// ProviderLabel is the display name.
var ProviderLabel = map[string]string{
	ProviderAzure: "Azure", ProviderAWS: "AWS", ProviderGCP: "GCP",
	ProviderOracle: "Oracle Cloud", ProviderHuawei: "Huawei Cloud", ProviderOnPrem: "On-prem",
}

// DetectProvider maps a node providerID prefix to a provider.
func DetectProvider(providerID string) string {
	switch {
	case strings.HasPrefix(providerID, "azure://"):
		return ProviderAzure
	case strings.HasPrefix(providerID, "aws://"):
		return ProviderAWS
	case strings.HasPrefix(providerID, "gce://"):
		return ProviderGCP
	case strings.HasPrefix(providerID, "oci://"):
		return ProviderOracle
	case strings.HasPrefix(providerID, "huaweicloud://"):
		return ProviderHuawei
	}
	return ProviderOnPrem
}

// ManagedControlPlane reports whether the provider runs the control plane
// (kube-bench control plane checks are N/A).
func ManagedControlPlane(provider string) bool {
	switch provider {
	case ProviderAzure, ProviderAWS, ProviderGCP, ProviderOracle, ProviderHuawei:
		return true
	}
	return false
}

// EOL is the upstream Kubernetes end-of-life date per minor version.
// Source: kubernetes.io/releases (patch support end). Update with each release.
var EOL = map[int]time.Time{
	25: date(2023, 10, 28), 26: date(2024, 2, 28), 27: date(2024, 6, 28), 28: date(2024, 10, 28),
	29: date(2025, 2, 28), 30: date(2025, 6, 28), 31: date(2025, 10, 28), 32: date(2026, 2, 28),
	33: date(2026, 6, 28), 34: date(2026, 10, 27), 35: date(2027, 2, 28), 36: date(2027, 6, 28),
	37: date(2027, 10, 28),
}

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// Minor parses "v1.31.4-gke.100" → 31. Returns 0 if unparsable.
func Minor(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || parts[0] != "1" {
		return 0
	}
	digits := parts[1]
	for i, c := range digits {
		if c < '0' || c > '9' {
			digits = digits[:i]
			break
		}
	}
	n, _ := strconv.Atoi(digits)
	return n
}

// IsEOL reports whether a minor version is past upstream EOL at now.
// Versions older than the table are EOL; newer ones are not.
func IsEOL(minor int, now time.Time) bool {
	if minor == 0 {
		return false
	}
	if d, ok := EOL[minor]; ok {
		return now.After(d)
	}
	oldest := 1 << 30
	for m := range EOL {
		oldest = min(oldest, m)
	}
	return minor < oldest
}
