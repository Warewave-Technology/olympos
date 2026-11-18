//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	sdAWS = "AKIAQ3VZ7RMXK2JWDTPL"
	sdPW  = "CANARY-sd-Pw-7f3a91"
	sdPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM2BxeLmKgcXQCANARYsdPemBody4t0H8x2vQ\n-----END RSA PRIVATE KEY-----\n"
)

// TestM5SensitiveData (F2): a ConfigMap with an AWS key, a private key and a
// DB_PASSWORD gives three findings; removing the keys resolves them; the
// values appear nowhere in the server's database or logs.
func TestM5SensitiveData(t *testing.T) {
	if labClusterID == "" {
		t.Skip("needs TestM1EnrollInventoryDiscovery")
	}
	admin := login(t, devAdminOID, "Lab Admin")
	applyStdin(t, fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata: {name: e2e-leaky-config, namespace: lab}
data:
  AWS_ACCESS_KEY_ID: %s
  DB_PASSWORD: %s
  DB_HOST: orders-pg.lab.svc
  tls.key: |
%s`, sdAWS, sdPW, indent(sdPEM, "    ")))
	t.Cleanup(func() { _, _ = runOK(t, "kubectl", "-n", "lab", "delete", "configmap", "e2e-leaky-config", "--ignore-not-found") })

	type finding struct {
		ResourceRef string         `json:"resource_ref"`
		Severity    string         `json:"severity"`
		Status      string         `json:"status"`
		Details     map[string]any `json:"details"`
	}
	list := func(status string) []finding {
		var fs struct{ Items []finding }
		admin.must("GET", "/findings?source=sensitive-data&status="+status+"&cluster="+labClusterID+"&limit=1000", nil, &fs, 200)
		var out []finding
		for _, f := range fs.Items {
			if strings.HasPrefix(f.ResourceRef, "lab/e2e-leaky-config:") {
				out = append(out, f)
			}
		}
		return out
	}
	eventually(t, 2*time.Minute, "three sensitive-data findings", func() (bool, string) {
		fs := list("open")
		return len(fs) == 3, fmt.Sprintf("%+v", fs)
	})
	for _, f := range list("open") {
		if f.Details["fix"] == nil || f.Details["value_length"] == nil {
			t.Errorf("finding without fix/length: %+v", f)
		}
		if strings.HasSuffix(f.ResourceRef, ":AWS_ACCESS_KEY_ID") && f.Severity != "high" {
			t.Errorf("AWS key must be high: %+v", f)
		}
	}

	// Remove the keys: resolved.
	applyStdin(t, `apiVersion: v1
kind: ConfigMap
metadata: {name: e2e-leaky-config, namespace: lab}
data:
  DB_HOST: orders-pg.lab.svc
`)
	eventually(t, 2*time.Minute, "sensitive-data findings resolved", func() (bool, string) {
		return len(list("open")) == 0 && len(list("resolved")) >= 3, fmt.Sprintf("open %d", len(list("open")))
	})

	// Canary: no value in the database (full dump) or the server logs.
	dump := run(t, "kubectl", "-n", "olympos", "exec", "statefulset/olympos-postgresql", "--", "pg_dump", "-U", "olympos", "--data-only", "olympos")
	logs := run(t, "kubectl", "-n", "olympos", "logs", "deploy/olympos", "--tail=-1")
	agent := run(t, "kubectl", "-n", "olympos-system", "logs", "deploy/olympos-agent", "--tail=-1")
	for _, c := range []string{sdAWS, sdPW, "CANARYsdPemBody", "MIIEpAIBAAKCAQEA3Tz2"} {
		for where, text := range map[string]string{"database": dump, "server logs": logs, "agent logs": agent} {
			if strings.Contains(text, c) {
				t.Errorf("value %q found in %s", c, where)
			}
		}
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}
