package probe

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Version is set at build time.
var Version = "dev"

// Defaults of Config.
const (
	DefaultIdentityDir    = "/etc/olympos-probe"
	DefaultMaxConcurrency = 20
	DefaultHealthAddr     = "127.0.0.1:8082"
	// maxMaxConcurrency bounds OLYMPOS_PROBE_MAX_CONCURRENCY: each run holds
	// connections and buffers.
	maxMaxConcurrency = 1000
)

// Config is read from the environment (rendered by the Helm chart).
type Config struct {
	// Server is host:port of the Olympos gateway (ProbeGateway).
	Server string
	// ServerName is the TLS server name; the host of Server by default.
	ServerName string
	// IdentityDir holds the mounted olympos-probe-identity Secret: tls.crt,
	// tls.key and ca.crt.
	IdentityDir string
	// MaxConcurrency is how many runs this replica runs at once.
	MaxConcurrency int
	// HealthAddr serves /healthz and /readyz, on localhost only.
	HealthAddr string
	// APIServer is the Kubernetes API service address
	// (KUBERNETES_SERVICE_HOST), always denied to runs. Empty outside a
	// cluster.
	APIServer []netip.Addr
}

// ConfigFromEnv reads OLYMPOS_* variables and KUBERNETES_SERVICE_HOST.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Server:      os.Getenv("OLYMPOS_SERVER"),
		ServerName:  os.Getenv("OLYMPOS_SERVER_NAME"),
		IdentityDir: envOr("OLYMPOS_PROBE_IDENTITY_DIR", DefaultIdentityDir),
		HealthAddr:  envOr("OLYMPOS_HEALTH_ADDR", DefaultHealthAddr),
	}
	if c.Server == "" {
		return c, fmt.Errorf("OLYMPOS_SERVER is required")
	}
	if c.ServerName == "" {
		c.ServerName = c.Server
		if h, _, err := net.SplitHostPort(c.Server); err == nil {
			c.ServerName = h
		}
	}
	n, err := envInt("OLYMPOS_PROBE_MAX_CONCURRENCY", DefaultMaxConcurrency)
	if err != nil {
		return c, err
	}
	if n < 1 || n > maxMaxConcurrency {
		return c, fmt.Errorf("OLYMPOS_PROBE_MAX_CONCURRENCY must be between 1 and %d", maxMaxConcurrency)
	}
	c.MaxConcurrency = n
	if !localhostAddr(c.HealthAddr) {
		return c, fmt.Errorf("OLYMPOS_HEALTH_ADDR must be localhost-only (127.0.0.1:<port>, [::1]:<port> or localhost:<port>)")
	}
	// The address the API service has in this cluster: runs may never
	// reach it, whatever name points at it.
	if v := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return c, fmt.Errorf("KUBERNETES_SERVICE_HOST %q is not an IP address", v)
		}
		c.APIServer = []netip.Addr{a.Unmap()}
	}
	return c, nil
}

// localhostAddr reports whether addr is host:port on a loopback host.
func localhostAddr(addr string) bool {
	h, p, err := net.SplitHostPort(addr)
	if err != nil || p == "" {
		return false
	}
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
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
