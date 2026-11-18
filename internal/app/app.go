// Package app wires the olympos-server process: config, Key Vault, DB, CA,
// gateway, API modules and background workers. Modules added in later
// milestones register themselves in modules.go.
package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-chi/chi/v5"

	"github.com/Warewave-Technology/olympos/internal/config"
	"github.com/Warewave-Technology/olympos/internal/gateway"
	"github.com/Warewave-Technology/olympos/internal/inventory"
	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/pki"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/server"
	"github.com/Warewave-Technology/olympos/internal/store"
	"github.com/Warewave-Technology/olympos/internal/targettls"
	"github.com/Warewave-Technology/olympos/web"
)

// Deps are shared by every module.
type Deps struct {
	Cfg       *config.Server
	Log       *slog.Logger
	DB        *store.DB
	KV        secrets.KeyVault
	Envelope  *secrets.Envelope
	HMAC      *secrets.Fingerprinter
	CA        *pki.CA
	Gateway   *gateway.Gateway
	Inventory *inventory.Service
	Cred      azcore.TokenCredential // nil in devMode without Azure
}

// Worker is a background loop started with the server.
type Worker func(ctx context.Context)

// Wiring is what a module contributes.
type Wiring struct {
	Modules []server.Module
	Workers []Worker
}

// moduleFactories are registered by modules.go (one per milestone module).
var moduleFactories []func(d *Deps) (Wiring, error)

// Register adds a module factory. Call from init() in modules.go.
func Register(f func(d *Deps) (Wiring, error)) { moduleFactories = append(moduleFactories, f) }

// NewLogger returns the JSON logger with the redaction layer.
func NewLogger(level slog.Level) *slog.Logger {
	return slog.New(secrets.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

// Run starts the server and blocks until SIGTERM.
func Run(cfgPath string) error {
	log := NewLogger(slog.LevelInfo)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.DevMode {
		log.Warn("DEV MODE ENABLED: local key vault, dev login and insecure cookies are allowed. Never use in production.")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	d := &Deps{Cfg: cfg, Log: log}
	if err := d.initKeyVault(); err != nil {
		return err
	}
	dsn := cfg.Database.DSN
	if cfg.Database.DSNRef != "" {
		b, err := secrets.Resolve(ctx, d.KV, cfg.Database.DSNRef)
		if err != nil {
			return fmt.Errorf("resolve database dsn: %w", err)
		}
		dsn = strings.TrimSpace(string(b))
		secrets.Zero(b)
	}
	d.DB, err = store.Open(ctx, dsn)
	dsn = ""
	if err != nil {
		return err
	}
	defer d.DB.Close()
	if err := store.Migrate(ctx, d.DB); err != nil {
		return err
	}
	if err := targettls.SetCABundleFile(cfg.TargetTLS.CABundleFile); err != nil {
		return err
	}
	d.Envelope = &secrets.Envelope{KV: d.KV}
	hk, err := d.KV.GetSecret(ctx, cfg.KeyVault.Name, cfg.KeyVault.HMACSecretName)
	if errors.Is(err, secrets.ErrSecretNotFound) && cfg.DevMode {
		hk = make([]byte, 32)
		_, _ = rand.Read(hk)
		err = d.KV.SetSecret(ctx, cfg.KeyVault.Name, cfg.KeyVault.HMACSecretName, hk)
	}
	if err != nil {
		return fmt.Errorf("load hmac key: %w", err)
	}
	if d.HMAC, err = secrets.NewFingerprinter(hk); err != nil {
		return err
	}
	if d.CA, err = pki.LoadOrCreate(ctx, d.DB, d.Envelope); err != nil {
		return fmt.Errorf("internal ca: %w", err)
	}

	d.Gateway = gateway.New(d.DB, d.CA, log.With("component", "gateway"))
	d.Inventory = &inventory.Service{DB: d.DB, Log: log.With("component", "inventory")}

	var wiring []Wiring
	for _, f := range moduleFactories {
		w, err := f(d)
		if err != nil {
			return err
		}
		wiring = append(wiring, w)
	}
	// Inventory hooks are installed after modules so they can append
	// OnTargetGone/OnTargetUpsert handlers.
	d.Inventory.Hooks(&d.Gateway.Hooks)

	srv := &server.Server{
		DB: d.DB, Log: log.With("component", "http"), TenantID: strings.ToLower(cfg.Entra.TenantID),
		BootstrapAdmins: cfg.BootstrapAdmins, DevMode: cfg.DevMode, InsecureCookies: cfg.DevMode && strings.HasPrefix(cfg.PublicURL, "http://"),
	}
	if srv.TenantID == "" && cfg.DevMode {
		srv.TenantID = "00000000-0000-0000-0000-000000000000"
	}
	if cfg.Entra.ClientID != "" {
		srv.OIDC = &server.OIDC{TenantID: srv.TenantID, ClientID: cfg.Entra.ClientID, ClientSecretRef: cfg.Entra.ClientSecretRef,
			AuthorityHost: cfg.Entra.AuthorityHost, RedirectURL: strings.TrimRight(cfg.PublicURL, "/") + "/auth/callback", KV: d.KV}
	}
	if d.Cred != nil && !cfg.DevMode {
		srv.Directory = &server.Graph{BaseURL: cfg.Entra.GraphURL, Cred: d.Cred}
	} else {
		srv.Directory = server.LocalDirectory{DB: d.DB}
	}
	sub, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return err
	}
	srv.SPA = sub
	srv.Modules = append(srv.Modules, &inventory.API{DB: d.DB, Log: log.With("component", "inventory"), Gateway: d.Gateway, CA: d.CA,
		GatewayURL: cfg.AgentGatewayURL, AgentChart: os.Getenv("OLYMPOS_AGENT_CHART")})
	for _, w := range wiring {
		srv.Modules = append(srv.Modules, w.Modules...)
	}
	srv.Ready = func(ctx context.Context) error { return d.DB.Ping(ctx) }

	// Gateway TLS.
	gwCert, err := d.gatewayCert()
	if err != nil {
		return err
	}
	gs := d.Gateway.GRPCServer(d.Gateway.TLSConfig(gwCert))
	gl, err := net.Listen("tcp", cfg.Listen.Gateway)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	start := func(f func(ctx context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	start(d.Inventory.RunOfflineMonitor)
	start(srv.CleanupSessions)
	start(func(ctx context.Context) { d.principalSync(ctx, srv.Directory) })
	start(d.metricsLoop)
	for _, w := range wiring {
		for _, wk := range w.Workers {
			start(wk)
		}
	}

	httpSrv := &http.Server{Addr: cfg.Listen.HTTP, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	opsSrv := &http.Server{Addr: cfg.Listen.Metrics, Handler: srv.OpsHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 3)
	go func() { errc <- gs.Serve(gl) }()
	go func() { errc <- httpSrv.ListenAndServe() }()
	go func() { errc <- opsSrv.ListenAndServe() }()
	log.Info("olympos server started", "http", cfg.Listen.HTTP, "gateway", cfg.Listen.Gateway, "metrics", cfg.Listen.Metrics)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listener failed", "err", err)
		}
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdown)
	_ = opsSrv.Shutdown(shutdown)
	gs.GracefulStop()
	wg.Wait()
	return nil
}

func (d *Deps) initKeyVault() error {
	cfg := d.Cfg
	switch cfg.KeyVault.Provider {
	case "local":
		d.KV = &secrets.LocalKeyVault{Dir: cfg.KeyVault.LocalDir}
		if cfg.KeyVault.Name == "" {
			cfg.KeyVault.Name = "local"
		}
		return nil
	case "azure":
		var err error
		if cfg.KeyVault.ManagedIdentityClientID != "" {
			d.Cred, err = azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
				ID: azidentity.ClientID(cfg.KeyVault.ManagedIdentityClientID)})
		} else {
			d.Cred, err = azidentity.NewDefaultAzureCredential(nil)
		}
		if err != nil {
			return fmt.Errorf("azure credential: %w", err)
		}
		d.KV = &secrets.AzureKeyVault{Cred: d.Cred, KEKVault: cfg.KeyVault.Name, KEKName: cfg.KeyVault.KEKName}
		return nil
	}
	return fmt.Errorf("unknown keyVault.provider %q", cfg.KeyVault.Provider)
}

func (d *Deps) gatewayCert() (tls.Certificate, error) {
	if d.Cfg.Gateway.TLSCertFile != "" {
		return tls.LoadX509KeyPair(d.Cfg.Gateway.TLSCertFile, d.Cfg.Gateway.TLSKeyFile)
	}
	hosts := append([]string{d.Cfg.GatewayHost()}, d.Cfg.Gateway.ExtraSANs...)
	der, key, err := d.CA.IssueServerCert(hosts, 90*24*time.Hour)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	d.Log.Info("issued gateway certificate from internal CA", "hosts", hosts)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func (d *Deps) principalSync(ctx context.Context, dir server.Directory) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute): // first run shortly after start
		}
		if err := server.SyncPrincipals(ctx, d.DB, dir, d.Log.With("component", "principal-sync")); err != nil && ctx.Err() == nil {
			d.Log.Error("principal sync", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Deps) metricsLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		var online, backlog int
		_ = d.DB.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE status = 'online'`).Scan(&online)
		_ = d.DB.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE delivered_at IS NULL`).Scan(&backlog)
		metrics.AgentsOnline.Set(float64(online))
		metrics.OutboxBacklog.Set(float64(backlog))
		metrics.Tunnels.Set(float64(d.Gateway.TunnelCount()))
		rows, err := d.DB.Query(ctx, `SELECT status, count(*) FROM change_requests GROUP BY status`)
		if err == nil {
			for rows.Next() {
				var st string
				var n int
				if rows.Scan(&st, &n) == nil {
					metrics.ChangeRequests.WithLabelValues(st).Set(float64(n))
				}
			}
			rows.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PublicLink builds an absolute link for notifications.
func (d *Deps) PublicLink(path string) string {
	u, err := url.Parse(d.Cfg.PublicURL)
	if err != nil {
		return path
	}
	return strings.TrimRight(u.String(), "/") + path
}

// Mount helper for modules that only need a routes func.
type RoutesFunc func(r chi.Router)

func (f RoutesFunc) Routes(r chi.Router) { f(r) }
