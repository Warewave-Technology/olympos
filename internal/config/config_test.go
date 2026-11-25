package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSyntheticDefaults(t *testing.T) {
	c := &Server{}
	c.defaults()
	want := Synthetic{
		RunRetention: 720 * time.Hour, AggregateRetention: 9600 * time.Hour, ExcerptRetention: 168 * time.Hour,
		MaxRequestsPerMinutePerCluster: 600, MaxRequestsPerMinutePerScenario: 120, ProbeOfflineAlertAfter: 5 * time.Minute,
	}
	if c.Synthetic != want {
		t.Fatalf("defaults %+v, want %+v", c.Synthetic, want)
	}
}

func TestSyntheticYAML(t *testing.T) {
	c := &Server{}
	if err := yaml.Unmarshal([]byte("synthetic:\n  probeOfflineAlertAfter: 10m\n  maxRequestsPerMinutePerCluster: 900\n"), c); err != nil {
		t.Fatal(err)
	}
	c.defaults()
	if c.Synthetic.ProbeOfflineAlertAfter != 10*time.Minute || c.Synthetic.MaxRequestsPerMinutePerCluster != 900 ||
		c.Synthetic.MaxRequestsPerMinutePerScenario != 120 {
		t.Fatalf("parsed %+v", c.Synthetic)
	}
	neg := Synthetic{RunRetention: -time.Hour, MaxRequestsPerMinutePerScenario: -1}
	neg.defaults()
	if errs := neg.validate(); len(errs) != 2 {
		t.Fatalf("negative values: %v", errs)
	}
}

func TestIngestDefaults(t *testing.T) {
	c := &Server{}
	c.defaults()
	if c.Listen.Ingest != ":9444" || c.Ingest.MaxRuns != 4 || c.Ingest.MaxRunDuration != 6*time.Hour {
		t.Fatalf("ingest defaults: listen %q, %+v", c.Listen.Ingest, c.Ingest)
	}
	if c.KeyVault.ManifestKeyName != "olympos-manifest" {
		t.Fatalf("manifestKeyName %q", c.KeyVault.ManifestKeyName)
	}
	if c.Ingest.SpillDir != "" {
		t.Fatalf("spillDir defaults to the OS temp dir (empty), got %q", c.Ingest.SpillDir)
	}
}

func TestIngestYAML(t *testing.T) {
	c := &Server{}
	doc := "listen:\n  ingest: \":9555\"\ningest:\n  url: https://olympos-ingest.example:9555\n  maxRuns: 8\n  maxRunDuration: 12h\n  spillDir: /spill\n  tlsCertFile: /c.crt\n  tlsKeyFile: /c.key\n"
	if err := yaml.Unmarshal([]byte(doc), c); err != nil {
		t.Fatal(err)
	}
	c.defaults()
	want := Ingest{URL: "https://olympos-ingest.example:9555", TLSCertFile: "/c.crt", TLSKeyFile: "/c.key",
		MaxRuns: 8, MaxRunDuration: 12 * time.Hour, SpillDir: "/spill"}
	if c.Listen.Ingest != ":9555" || c.Ingest != want {
		t.Fatalf("got %q %+v", c.Listen.Ingest, c.Ingest)
	}
}

// validServer returns a Server that passes Validate (no dev mode, so the test
// runs in release builds too).
func validServer() *Server {
	c := &Server{PublicURL: "https://olympos.example", AgentGatewayURL: "gw.example:8443"}
	c.Entra.TenantID, c.Entra.ClientID, c.KeyVault.Name = "tenant", "client", "kv"
	c.defaults()
	return c
}

func TestIngestURLRequiredWhenListening(t *testing.T) {
	c := validServer()
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "ingest.url is required") {
		t.Fatalf("listener on without ingest.url: %v", err)
	}
	c.Ingest.URL = "https://olympos-ingest.example:9444"
	if err := c.Validate(); err != nil {
		t.Fatalf("with ingest.url: %v", err)
	}
	// An empty listener turns the endpoint off: no URL needed.
	c = validServer()
	c.Listen.Ingest = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("endpoint off: %v", err)
	}
}

func TestIngestValidation(t *testing.T) {
	for name, mod := range map[string]func(*Server){
		"cert without key": func(c *Server) { c.Ingest.TLSCertFile = "/c.crt" },
		"relative url":     func(c *Server) { c.Ingest.URL = "olympos-ingest.example" },
		"maxRuns":          func(c *Server) { c.Ingest.MaxRuns = -1 },
		"maxRunDuration":   func(c *Server) { c.Ingest.MaxRunDuration = -time.Hour },
	} {
		c := validServer()
		c.Ingest.URL = "https://olympos-ingest.example:9444"
		mod(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: want a validation error", name)
		}
	}
}

func TestIngestHost(t *testing.T) {
	for url, want := range map[string]string{
		"https://olympos-ingest.example:9444": "olympos-ingest.example",
		"https://olympos-ingest.example":      "olympos-ingest.example",
		"https://[fd00::1]:9444/":             "fd00::1",
		"https://10.0.0.5:9444":               "10.0.0.5",
	} {
		c := &Server{}
		c.Ingest.URL = url
		if got := c.IngestHost(); got != want {
			t.Errorf("%s: %q, want %q", url, got, want)
		}
	}
}

// An empty listen.ingest in the file turns the endpoint off; an absent one
// takes the default.
func TestIngestOffByEmptyListener(t *testing.T) {
	dir := t.TempDir()
	load := func(doc string) *Server {
		t.Helper()
		p := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		c, _ := Load(p) // validation errors (no publicURL...) are not the point
		return c
	}
	for doc, want := range map[string]string{
		"listen: {ingest: \"\"}\n":             "",
		"olympos:\n  listen: {ingest: \"\"}\n": "",
		"olympos:\n  listen: {http: \":1\"}\n": ":9444",
		"listen: {ingest: \":7000\"}\n":        ":7000",
		"olympos:\n  listen: {ingest: null}\n": ":9444",
		"publicURL: https://olympos.example\n": ":9444",
	} {
		if got := load(doc).Listen.Ingest; got != want {
			t.Errorf("%q: listen.ingest %q, want %q", doc, got, want)
		}
	}
}
