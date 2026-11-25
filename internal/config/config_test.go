package config

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Warewave-Technology/olympos/internal/devbuild"
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

// The endpoint is on only when ingest.url is set: without it there is no
// listener and no error; with it the URL must be valid.
func TestIngestOnlyWithURL(t *testing.T) {
	c := validServer()
	if c.IngestEnabled() || c.Validate() != nil {
		t.Fatalf("no ingest.url: the endpoint is off without an error: %v", c.Validate())
	}
	c.Ingest.URL = "https://olympos-ingest.example:9444"
	if !c.IngestEnabled() || !c.IngestTLS() {
		t.Fatal("ingest.url set: the endpoint is on, over TLS")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("with ingest.url: %v", err)
	}
	// Plain HTTP is for development only.
	c.Ingest.URL = "http://olympos-ingest.example:9444"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ingest.url must be https unless devMode is on") {
		t.Fatalf("http ingest.url without devMode: %v", err)
	}
	if !c.IngestEnabled() || c.IngestTLS() {
		t.Fatal("an http ingest.url is plain HTTP")
	}
	if devbuild.Enabled {
		c.DevMode = true
		if err := c.Validate(); err != nil {
			t.Fatalf("http ingest.url with devMode: %v", err)
		}
	}
}

func TestIngestValidation(t *testing.T) {
	const ok = "https://olympos-ingest.example:9444"
	for name, mod := range map[string]func(*Server){
		"cert without key":    func(c *Server) { c.Ingest.TLSCertFile = "/c.crt" },
		"no scheme":           func(c *Server) { c.Ingest.URL = "olympos-ingest.example:9444" },
		"other scheme":        func(c *Server) { c.Ingest.URL = "ftp://olympos-ingest.example" },
		"no host":             func(c *Server) { c.Ingest.URL = "https://" },
		"path":                func(c *Server) { c.Ingest.URL = ok + "/s3" },
		"query":               func(c *Server) { c.Ingest.URL = ok + "?a=b" },
		"empty listener":      func(c *Server) { c.Listen.Ingest = "" },
		"negative maxRuns":    func(c *Server) { c.Ingest.MaxRuns = -1 },
		"negative maxRunTime": func(c *Server) { c.Ingest.MaxRunDuration = -time.Hour },
	} {
		c := validServer()
		c.Ingest.URL = ok
		mod(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: want a validation error", name)
		}
	}
	if devbuild.Enabled {
		c := validServer()
		c.DevMode, c.Ingest.URL, c.Ingest.TLSCertFile, c.Ingest.TLSKeyFile = true, "http://h:9444", "/c", "/k"
		if err := c.Validate(); err == nil {
			t.Error("certificate files with an http ingest.url: want a validation error")
		}
	}
	// A trailing slash is fine, and with the endpoint off nothing else is checked.
	c := validServer()
	c.Ingest.URL = ok + "/"
	if err := c.Validate(); err != nil {
		t.Errorf("trailing slash: %v", err)
	}
	c = validServer()
	c.Listen.Ingest = ""
	if err := c.Validate(); err != nil {
		t.Errorf("endpoint off: an empty listen.ingest is not checked: %v", err)
	}
}

// Ingest sessions live in one server process, so the endpoint is refused
// with more than one replica.
func TestIngestNotWithMultiReplica(t *testing.T) {
	c := validServer()
	c.Experimental.MultiReplica = true
	if err := c.Validate(); err != nil {
		t.Fatalf("multiReplica without ingest.url: %v", err)
	}
	c.Ingest.URL = "https://olympos-ingest.example:9444"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ingest.url cannot be set while experimental.multiReplica is true") {
		t.Fatalf("multiReplica with ingest.url: %v", err)
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
