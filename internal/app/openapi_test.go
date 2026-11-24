//go:build dev

package app

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/Warewave-Technology/olympos/internal/testutil"
)

// TestOpenAPIListsEveryRoute: every /api/v1 route of the production module
// wiring is in docs/openapi.yaml with its method, and every operation there
// is a route. Parameter names are not compared ({id} and {digest} are both
// one path segment; a chi wildcard is the last one).
func TestOpenAPIListsEveryRoute(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("docs/openapi.yaml: %v", err)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	norm := func(p string) string {
		p = param.ReplaceAllString(p, "{}")
		if strings.HasSuffix(p, "/*") {
			p = strings.TrimSuffix(p, "*") + "{}"
		}
		// A sub-router's root ("/destinations/") is the path itself.
		if len(p) > 1 {
			p = strings.TrimSuffix(p, "/")
		}
		return p
	}
	documented := map[string]bool{}
	for p, ops := range doc.Paths {
		for m := range ops {
			switch m {
			case "get", "post", "put", "patch", "delete":
				documented[strings.ToUpper(m)+" "+norm(p)] = true
			}
		}
	}

	h := wiredHandler(t, testutil.DB(t))
	routed := map[string]bool{}
	if err := chi.Walk(h.(chi.Routes), func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(pattern, "/api/v1/") {
			routed[method+" "+norm(strings.TrimPrefix(pattern, "/api/v1"))] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var missing, stale []string
	for r := range routed {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	for d := range documented {
		if !routed[d] {
			stale = append(stale, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("routes missing from docs/openapi.yaml:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("docs/openapi.yaml operations with no route:\n  %s", strings.Join(stale, "\n  "))
	}
}
