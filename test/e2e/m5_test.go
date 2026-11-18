//go:build e2e

package e2e

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestM5Security checks image inventory + trivy scan, NetworkPolicy
// default-deny findings and Kyverno policy reports from the real agent.
func TestM5Security(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")

	t.Run("images", func(t *testing.T) {
		var digest string
		eventually(t, 3*time.Minute, "postgres image inventoried", func() (bool, string) {
			var is struct {
				Items []struct {
					Digest     string `json:"digest"`
					Repo       string `json:"repo"`
					ScanStatus string `json:"scan_status"`
				} `json:"items"`
			}
			admin.must("GET", "/images?cluster="+labClusterID+"&q=postgres", nil, &is, 200)
			for _, i := range is.Items {
				if strings.HasSuffix(i.Repo, "postgres") && strings.HasPrefix(i.Digest, "sha256:") {
					digest = i.Digest
					return true, ""
				}
			}
			return false, fmt.Sprintf("%+v", is.Items)
		})
		var d struct {
			ScanStatus string `json:"scan_status"`
			ScanError  string `json:"scan_error"`
			Usage      []struct {
				Namespace    string `json:"namespace"`
				WorkloadKind string `json:"workload_kind"`
				WorkloadName string `json:"workload_name"`
			} `json:"usage"`
			Vulns []map[string]any `json:"vulns"`
		}
		admin.must("POST", "/images/"+url.PathEscape(digest)+"/scan", nil, nil, 202)
		time.Sleep(2 * time.Second)
		eventually(t, 15*time.Minute, "postgres image scanned by trivy", func() (bool, string) {
			admin.must("GET", "/images/"+url.PathEscape(digest), nil, &d, 200)
			return d.ScanStatus == "scanned" || (d.ScanStatus == "failed" && !strings.Contains(d.ScanError, "15:12")), d.ScanStatus + " " + d.ScanError
		})
		if d.ScanStatus != "scanned" {
			t.Fatalf("scan failed: %s", d.ScanError)
		}
		owned := false
		for _, u := range d.Usage {
			if u.Namespace == "lab" && u.WorkloadKind == "StatefulSet" && u.WorkloadName == "orders-pg" {
				owned = true
			}
		}
		if !owned {
			t.Errorf("owner resolution: %+v", d.Usage)
		}
	})

	t.Run("netpol", func(t *testing.T) {
		eventually(t, 2*time.Minute, "lab namespace without default deny", func() (bool, string) {
			var ns struct {
				Items []struct {
					Namespace   string `json:"namespace"`
					DefaultDeny bool   `json:"default_deny"`
					Excluded    bool   `json:"excluded"`
				} `json:"items"`
			}
			admin.must("GET", "/security/netpol?cluster="+labClusterID, nil, &ns, 200)
			for _, n := range ns.Items {
				if n.Namespace == "kube-system" && !n.Excluded {
					t.Fatal("kube-system must be excluded")
				}
				if n.Namespace == "lab" {
					return !n.DefaultDeny, ""
				}
			}
			return false, "lab missing"
		})
		var fs struct{ Items []map[string]any }
		admin.must("GET", "/findings?source=netpol&status=open&cluster="+labClusterID, nil, &fs, 200)
		found := false
		for _, f := range fs.Items {
			if strings.Contains(fmt.Sprint(f["resource_ref"]), "lab") {
				found = true
			}
		}
		if !found {
			t.Fatalf("netpol.no_default_deny for lab missing: %v", fs.Items)
		}
		// Adding a default-deny ingress policy resolves the finding.
		run(t, "kubectl", "apply", "-f", "test/e2e/manifests/lab-default-deny.yaml")
		defer run(t, "kubectl", "delete", "-f", "test/e2e/manifests/lab-default-deny.yaml")
		eventually(t, 15*time.Minute, "netpol finding resolved", func() (bool, string) {
			var fs struct{ Items []map[string]any }
			admin.must("GET", "/findings?source=netpol&status=open&cluster="+labClusterID, nil, &fs, 200)
			for _, f := range fs.Items {
				if strings.HasSuffix(fmt.Sprint(f["resource_ref"]), "lab") {
					return false, fmt.Sprint(f["resource_ref"])
				}
			}
			return true, ""
		})
	})

	t.Run("kyverno", func(t *testing.T) {
		// Kyverno 1.20 runs only CEL policies; the lab applies a ValidatingPolicy
		// always and the legacy ClusterPolicy only with Kyverno <= 1.19.
		legacy := strings.TrimSpace(run(t, "kubectl", "get", "clusterpolicies.kyverno.io", "-o", "name", "--ignore-not-found")) != ""
		// Existing pods are only evaluated by background scans; touch one so
		// admission reports are produced quickly.
		run(t, "kubectl", "-n", "lab", "annotate", "pod", "orders-pg-0", "olympos.io/e2e-touch="+fmt.Sprint(time.Now().Unix()), "--overwrite")
		eventually(t, 5*time.Minute, "kyverno policies reported with failures", func() (bool, string) {
			var ps struct {
				Items []struct {
					Kind      string `json:"kind"`
					Name      string `json:"name"`
					Mode      string `json:"mode"`
					FailCount int    `json:"fail_count"`
				} `json:"items"`
			}
			admin.must("GET", "/security/kyverno?cluster="+labClusterID, nil, &ps, 200)
			vpol, cpol := false, !legacy
			for _, p := range ps.Items {
				if p.Kind == "ValidatingPolicy" && p.Name == "require-app-label" && p.Mode == "Audit" && p.FailCount > 0 {
					vpol = true
				}
				if p.Kind == "ClusterPolicy" && p.Name == "require-team-label" && p.FailCount > 0 {
					cpol = true
				}
			}
			return vpol && cpol, fmt.Sprintf("%+v", ps.Items)
		})
	})
}
