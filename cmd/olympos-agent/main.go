// Command olympos-agent runs inside a managed cluster. It only dials out.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/rest"

	"github.com/Warewave-Technology/olympos/internal/agent"
	"github.com/Warewave-Technology/olympos/internal/secrets"
)

func main() {
	// Distroless has no shell: probes exec the binary itself.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		os.Exit(health())
	}
	log := slog.New(secrets.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "olympos-agent:", err)
		os.Exit(1)
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "olympos-agent: in-cluster config:", err)
		os.Exit(1)
	}
	rc.UserAgent = "olympos-agent/" + agent.Version
	a, err := agent.New(cfg, log, rc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "olympos-agent:", err)
		os.Exit(1)
	}
	agent.Extend(a, cfg, rc)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("olympos agent starting", "version", agent.Version, "server", cfg.Server)
	if err := a.Run(ctx); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}

func health() int {
	addr := os.Getenv("OLYMPOS_HEALTH_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
