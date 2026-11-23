// Command olympos-probe runs synthetic monitoring scenarios inside a managed
// cluster (docs/design/synthetic-monitoring.md). It only dials out, to the
// Olympos gateway, and never talks to the Kubernetes API: its identity is
// the Secret the agent keeps for it, mounted read-only.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Warewave-Technology/olympos/internal/probe"
	"github.com/Warewave-Technology/olympos/internal/sensitive"
)

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "health" {
			// Distroless has no shell: the liveness probe execs the
			// binary itself.
			os.Exit(health(healthAddr()))
		}
		fmt.Fprintln(os.Stderr, "usage: olympos-probe [health]")
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		fmt.Fprintln(os.Stderr, "olympos-probe:", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := probe.ConfigFromEnv()
	if err != nil {
		return err
	}
	resolver, err := probe.SystemResolver()
	if err != nil {
		return fmt.Errorf("resolver: %w", err)
	}
	det, err := sensitive.NewDetector()
	if err != nil {
		return fmt.Errorf("redaction rules: %w", err)
	}
	ident := probe.NewIdentity(cfg.IdentityDir, log)
	c := probe.NewClient(cfg, ident, resolver, &sensitive.Redactor{D: det}, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { _ = probe.ServeHealth(ctx, cfg.HealthAddr, c.Connected, log) }()
	log.Info("olympos probe starting", "version", probe.Version, "server", cfg.Server,
		"max_concurrency", cfg.MaxConcurrency, "identity_dir", cfg.IdentityDir)
	return c.Run(ctx)
}

func healthAddr() string {
	if v := os.Getenv("OLYMPOS_HEALTH_ADDR"); v != "" {
		return v
	}
	return probe.DefaultHealthAddr
}

// health checks the localhost health endpoint: 0 when it answers 200.
func health(addr string) int {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if a, err := netip.ParseAddr(h); h != "localhost" && (err != nil || !a.IsLoopback()) {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
