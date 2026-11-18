package security

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

func TestParseReference(t *testing.T) {
	cases := []struct{ in, host, repo, tag string }{
		{"nginx", "docker.io", "docker.io/library/nginx", "latest"},
		{"nginx:1.25", "docker.io", "docker.io/library/nginx", "1.25"},
		{"bitnami/redis:7.2.4", "docker.io", "docker.io/bitnami/redis", "7.2.4"},
		{"docker.io/library/nginx:1.25", "docker.io", "docker.io/library/nginx", "1.25"},
		{"index.docker.io/library/nginx", "docker.io", "docker.io/library/nginx", "latest"},
		{"acr.contoso.io/erp/payments-api:2.14.1", "acr.contoso.io", "acr.contoso.io/erp/payments-api", "2.14.1"},
		{"registry.local:5000/team/app", "registry.local:5000", "registry.local:5000/team/app", "latest"},
		{"localhost/app:dev", "localhost", "localhost/app", "dev"},
		{"ghcr.io/org/app@sha256:" + "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", "ghcr.io", "ghcr.io/org/app", ""},
		{"quay.io/x/y:1.0@sha256:abc", "quay.io", "quay.io/x/y", "1.0"},
	}
	for _, c := range cases {
		h, r, tag := ParseReference(c.in)
		if h != c.host || r != c.repo || tag != c.tag {
			t.Errorf("ParseReference(%q) = %q %q %q, want %q %q %q", c.in, h, r, tag, c.host, c.repo, c.tag)
		}
	}
}

func TestValidRepo(t *testing.T) {
	for _, ok := range []string{"docker.io/library/nginx", "registry.local:5000/a/b", "acr.contoso.io/erp/payments-api", "ghcr.io/a_b/c__d"} {
		if !ValidRepo(ok) {
			t.Errorf("ValidRepo(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "-oconfig/x", "docker.io", "docker.io/--help", "a b/c", "docker.io/x;rm"} {
		if ValidRepo(bad) {
			t.Errorf("ValidRepo(%q) = true", bad)
		}
	}
}

func TestRegistryMatching(t *testing.T) {
	cred := uuid.New()
	regs := []RegistryRef{
		{ID: uuid.New(), HostPattern: "*.azurecr.io"},
		{ID: uuid.New(), HostPattern: "prod.azurecr.io", CredentialID: &cred},
		{ID: uuid.New(), HostPattern: "ghcr.io"},
		{ID: uuid.New(), HostPattern: "ghcr.io/contoso/*"},
		{ID: uuid.New(), HostPattern: "quay.io/legacy"},
		{ID: uuid.New(), HostPattern: "index.docker.io/acme/*"},
	}
	cases := []struct{ repo, want string }{
		{"prod.azurecr.io/erp/api", "prod.azurecr.io"},
		{"dev.azurecr.io/erp/api", "*.azurecr.io"},
		{"ghcr.io/contoso/ingest-worker", "ghcr.io/contoso/*"},
		{"ghcr.io/other/tool", "ghcr.io"},
		{"quay.io/legacy/report-gen", "quay.io/legacy"},
		{"quay.io/legacyx/report-gen", ""},
		{"quay.io/other/x", ""},
		{"docker.io/acme/api", "index.docker.io/acme/*"},
		{"docker.io/library/nginx", ""},
		{"azurecr.io.evil.com/x", ""},
	}
	for _, c := range cases {
		m := MatchRegistry(regs, c.repo)
		got := ""
		if m != nil {
			got = m.HostPattern
		}
		if got != c.want {
			t.Errorf("MatchRegistry(%q) = %q, want %q", c.repo, got, c.want)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	for _, ok := range []string{"acr.contoso.io", "*.azurecr.io", "ghcr.io/contoso/*", "registry.local:5000", "HTTPS://Quay.io/legacy/"} {
		if _, msg := ValidatePattern(ok); msg != "" {
			t.Errorf("ValidatePattern(%q) = %q", ok, msg)
		}
	}
	for _, bad := range []string{"", "*", "*.io", "*/foo", "a b", "acr.contoso.io;x", "-x"} {
		if _, msg := ValidatePattern(bad); msg == "" {
			t.Errorf("ValidatePattern(%q) accepted", bad)
		}
	}
	if n, _ := ValidatePattern("HTTPS://Quay.io/legacy/"); n != "quay.io/legacy" {
		t.Errorf("normalized = %q", n)
	}
}

func TestIsDefaultDeny(t *testing.T) {
	cases := []struct {
		name string
		p    *pb.NetworkPolicy
		want bool
	}{
		{"ingress deny", &pb.NetworkPolicy{SelectsAllPods: true, PolicyTypes: []string{"Ingress"}}, true},
		{"ingress+egress deny", &pb.NetworkPolicy{SelectsAllPods: true, PolicyTypes: []string{"Egress", "Ingress"}}, true},
		{"ingress deny, egress allow rules", &pb.NetworkPolicy{SelectsAllPods: true, PolicyTypes: []string{"Egress", "Ingress"}, EgressRules: 2}, true},
		{"ingress with rules", &pb.NetworkPolicy{SelectsAllPods: true, PolicyTypes: []string{"Ingress"}, IngressRules: 1}, false},
		{"egress only", &pb.NetworkPolicy{SelectsAllPods: true, PolicyTypes: []string{"Egress"}}, false},
		{"selector", &pb.NetworkPolicy{SelectsAllPods: false, PolicyTypes: []string{"Ingress"}}, false},
	}
	for _, c := range cases {
		if got := IsDefaultDeny(c.p); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseTrivyFixture(t *testing.T) {
	f, err := os.Open("testdata/trivy-report.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vulns, err := ParseTrivy(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 7 {
		t.Fatalf("got %d vulns: %+v", len(vulns), vulns)
	}
	if vulns[0].Severity != "critical" || vulns[0].CVEID != "CVE-2024-45337" || vulns[0].FixedIn != "0.31.0" {
		t.Errorf("first = %+v", vulns[0])
	}
	sev := map[string]int{}
	for _, v := range vulns {
		sev[v.Severity]++
	}
	if sev["critical"] != 2 || sev["high"] != 2 || sev["medium"] != 1 || sev["low"] != 1 || sev["unknown"] != 1 {
		t.Errorf("severities = %v", sev)
	}
	if _, err := ParseTrivy(strings.NewReader(`{"SchemaVersion": 9}`)); err == nil {
		t.Error("expected schema error")
	}
}

func TestIsAuthError(t *testing.T) {
	yes := []string{
		`FATAL	Fatal error	image scan error: unable to find the specified image "harbor.local/x@sha256:..": GET https://harbor.local/v2/x/manifests/sha256:..: UNAUTHORIZED: authentication required`,
		`remote error: GET https://index.docker.io/v2/acme/private/manifests/x: unexpected status code 401 Unauthorized`,
		`denied: requested access to the resource is denied`,
	}
	for _, s := range yes {
		if !IsAuthError(s) {
			t.Errorf("not auth: %q", s)
		}
	}
	for _, s := range []string{`MANIFEST_UNKNOWN: manifest unknown`, `dial tcp: lookup harbor.local: no such host`} {
		if IsAuthError(s) {
			t.Errorf("auth: %q", s)
		}
	}
}
