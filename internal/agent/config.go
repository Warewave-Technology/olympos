// Package agent is the in-cluster olympos-agent: discovery, inventory, a
// tunnel endpoint restricted to discovered targets, a read-only API proxy and
// the opt-in kube-bench runner. It holds no credentials other than its own
// client certificate and never listens on a non-localhost port.
package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Version is set at build time.
var Version = "dev"

// Config is read from the environment (rendered by the Helm chart).
type Config struct {
	Server           string // host:port of the agent gateway
	ServerCAFile     string // PEM of the Olympos internal CA (pinned)
	ServerName       string // TLS server name override
	Namespace        string // own namespace (identity Secret lives here)
	IdentitySecret   string
	ProviderOverride string
	BenchEnabled     bool
	BenchMaxParallel int
	BenchNamespace   string
	MaxTunnels       int
	HealthAddr       string
	// SensitiveData scans ConfigMaps for credentials (F2); Exclude are
	// namespace globs not scanned.
	SensitiveData        bool
	SensitiveDataExclude []string
	// SecretsInventory: opt-in, metadata-only Secret inventory (F3).
	SecretsInventory bool
}

// ConfigFromEnv reads OLYMPOS_* variables.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Server:           os.Getenv("OLYMPOS_SERVER"),
		ServerCAFile:     envOr("OLYMPOS_SERVER_CA_FILE", "/etc/olympos/ca.crt"),
		ServerName:       os.Getenv("OLYMPOS_SERVER_NAME"),
		Namespace:        envOr("POD_NAMESPACE", "olympos-system"),
		IdentitySecret:   envOr("OLYMPOS_IDENTITY_SECRET", "olympos-agent-identity"),
		ProviderOverride: os.Getenv("OLYMPOS_PROVIDER_OVERRIDE"),
		BenchEnabled:     os.Getenv("OLYMPOS_BENCH_ENABLED") == "true",
		BenchNamespace:   envOr("OLYMPOS_BENCH_NAMESPACE", "olympos-bench"),
		HealthAddr:       envOr("OLYMPOS_HEALTH_ADDR", "127.0.0.1:8081"),
		SensitiveData:    os.Getenv("OLYMPOS_SENSITIVE_DATA") != "false",
		SecretsInventory: os.Getenv("OLYMPOS_SECRETS_INVENTORY") == "true",
	}
	if v, ok := os.LookupEnv("OLYMPOS_SENSITIVE_DATA_EXCLUDE"); ok {
		c.SensitiveDataExclude = []string{}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.SensitiveDataExclude = append(c.SensitiveDataExclude, p)
			}
		}
	}
	var err error
	if c.BenchMaxParallel, err = envInt("OLYMPOS_BENCH_MAX_PARALLEL", 3); err != nil {
		return c, err
	}
	if c.MaxTunnels, err = envInt("OLYMPOS_MAX_TUNNELS", 16); err != nil {
		return c, err
	}
	if c.Server == "" {
		return c, fmt.Errorf("OLYMPOS_SERVER is required")
	}
	if c.ServerName == "" {
		c.ServerName = c.Server
		if i := strings.LastIndexByte(c.ServerName, ':'); i > 0 {
			c.ServerName = c.ServerName[:i]
		}
	}
	if !strings.HasPrefix(c.HealthAddr, "127.0.0.1:") && !strings.HasPrefix(c.HealthAddr, "localhost:") {
		return c, fmt.Errorf("OLYMPOS_HEALTH_ADDR must be localhost-only")
	}
	return c, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return d, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}
