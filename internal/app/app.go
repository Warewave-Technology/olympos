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
	"os/exec"
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
	SelfDB    SelfDB
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

// SelfDB is the login of Olympos' own database, for the olympos-self backup.
type SelfDB struct {
	DSN, Password string
}

// openDatabase resolves the DSN (dsnRef via Key Vault) and the password
// file and connects, waiting up to wait for the database (bundled
// PostgreSQL, a host booting).
func (d *Deps) openDatabase(ctx context.Context, wait time.Duration) error {
	cfg := d.Cfg
	dsn := cfg.Database.DSN
	if cfg.Database.DSNRef != "" {
		b, err := secrets.Resolve(ctx, d.KV, cfg.Database.DSNRef)
		if err != nil {
			return fmt.Errorf("resolve database dsn: %w", err)
		}
		dsn = strings.TrimSpace(string(b))
		secrets.Zero(b)
	}
	var dbPassword string
	if cfg.Database.PasswordFile != "" {
		b, err := os.ReadFile(cfg.Database.PasswordFile)
		if err != nil {
			return fmt.Errorf("read database.passwordFile: %w", err)
		}
		dbPassword = strings.TrimSpace(string(b))
	}
	deadline := time.Now().Add(wait)
	var err error
	for pause := time.Second; ; pause = min(2*pause, 10*time.Second) {
		d.DB, err = store.OpenWithPassword(ctx, dsn, dbPassword)
		if err == nil || ctx.Err() != nil || time.Now().Add(pause).After(deadline) {
			break
		}
		d.Log.Warn("database not reachable yet, retrying", "err", err, "in", pause.String())
		time.Sleep(pause)
	}
	// The self-backup (olympos-self) dumps this database with the same login.
	d.SelfDB = SelfDB{DSN: dsn, Password: dbPassword}
	return err
}

// Migrate applies pending migrations and exits (olympos-server migrate).
// Downgrades are refused.
func Migrate(cfgPath string) error {
	log := NewLogger(slog.LevelInfo)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	d := &Deps{Cfg: cfg, Log: log}
	if err := d.initKeyVault(); err != nil {
		return err
	}
	if err := d.openDatabase(ctx, 30*time.Second); err != nil {
		return err
	}
	defer d.DB.Close()
	if err := store.Migrate(ctx, d.DB); err != nil {
		return err
	}
	v, err := store.SchemaVersion(ctx, d.DB)
	if err != nil {
		return err
	}
	fmt.Printf("database schema at version %d\n", v)
	return nil
}

// CheckConfig validates the configuration and the files it points to; with
// db it also connects to the database (olympos-server check-config).
func CheckConfig(cfgPath string, db bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	var problems []string
	for what, f := range map[string]string{"listen.tlsCertFile": cfg.Listen.TLSCertFile, "listen.tlsKeyFile": cfg.Listen.TLSKeyFile,
		"gateway.tlsCertFile": cfg.Gateway.TLSCertFile, "gateway.tlsKeyFile": cfg.Gateway.TLSKeyFile,
		"database.passwordFile": cfg.Database.PasswordFile, "targetTLS.caBundleFile": cfg.TargetTLS.CABundleFile} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", what, err))
		}
	}
	if cfg.Listen.TLSCertFile != "" && len(problems) == 0 {
		if _, err := tls.LoadX509KeyPair(cfg.Listen.TLSCertFile, cfg.Listen.TLSKeyFile); err != nil {
			problems = append(problems, "listen TLS key pair: "+err.Error())
		}
	}
	for what, bin := range map[string]string{"audit.kubescapeBin": cfg.Audit.KubescapeBin, "audit.polarisBin": cfg.Audit.PolarisBin, "security.trivyBin": cfg.Security.TrivyBin} {
		if _, err := exec.LookPath(bin); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s): %v", what, bin, err))
		}
	}
	if len(problems) > 0 {
		return errors.New("config problems:\n  - " + strings.Join(problems, "\n  - "))
	}
	if db {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d := &Deps{Cfg: cfg, Log: NewLogger(slog.LevelWarn)}
		if err := d.initKeyVault(); err != nil {
			return err
		}
		if err := d.openDatabase(ctx, 0); err != nil {
			return err
		}
		d.DB.Close()
	}
	fmt.Println("config ok")
	return nil
}

// Run starts the server and blocks until SIGTERM.
func Run(cfgPath string) error {
	started := time.Now()
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
	if err := d.openDatabase(ctx, 2*time.Minute-time.Since(started)); err != nil {
		return err
	}
	defer d.DB.Close()
	if err := store.Migrate(ctx, d.DB); err != nil {
		return err
	}
	if err := targettls.Configure(cfg.TargetTLS.CABundleFile, cfg.TargetTLS.SystemRoots); err != nil {
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
	d.Inventory = &inventory.Service{DB: d.DB, Log: log.With("component", "inventory"), Started: time.Now(),
		OfflineAlertAfter: cfg.Agents.OfflineAlertAfter, FlappingDisconnects: cfg.Agents.FlappingDisconnects, FlappingWindow: cfg.Agents.FlappingWindow}

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
	sysWarn := d.checkKEKRecovery(ctx)
	srv.Modules = append(srv.Modules, &inventory.API{DB: d.DB, Log: log.With("component", "inventory"), Gateway: d.Gateway, CA: d.CA,
		GatewayURL: cfg.AgentGatewayURL, AgentChart: os.Getenv("OLYMPOS_AGENT_CHART"), AgentSets: agentSets(),
		SystemWarnings: func() []inventory.AttentionItem { return sysWarn }})
	for _, w := range wiring {
		srv.Modules = append(srv.Modules, w.Modules...)
	}
	guard, err := newInstanceGuard(ctx, d.DB, log.With("component", "instances"), cfg.Experimental.MultiReplica)
	if err != nil {
		return fmt.Errorf("register server instance: %w", err)
	}
	srv.Ready = func(ctx context.Context) error {
		if err := d.DB.Ping(ctx); err != nil {
			return err
		}
		return guard.Ready()
	}

	// Gateway TLS. Certificates from files (gateway and UI) are reloaded on
	// SIGHUP; the internal-CA gateway certificate is issued at start.
	gwTLS, reloadGW, err := d.gatewayTLS()
	if err != nil {
		return err
	}
	gs := d.Gateway.GRPCServer(gwTLS)
	var uiCert *certFile
	if cfg.Listen.TLSCertFile != "" {
		if uiCert, err = loadCertFile(cfg.Listen.TLSCertFile, cfg.Listen.TLSKeyFile); err != nil {
			return err
		}
	}
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
			}
			for _, c := range []*certFile{reloadGW, uiCert} {
				if c == nil {
					continue
				}
				if err := c.reload(); err != nil {
					log.Error("SIGHUP: certificate not reloaded, keeping the current one", "err", err)
				} else {
					log.Info("SIGHUP: certificate reloaded", "file", c.certPath)
				}
			}
			log.Info("SIGHUP: other configuration changes need a restart")
		}
	}()
	gl, err := net.Listen("tcp", cfg.Listen.Gateway)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	start := func(f func(ctx context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	start(guard.run)
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
	if uiCert != nil {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: uiCert.get}
	}
	opsSrv := &http.Server{Addr: cfg.Listen.Metrics, Handler: srv.OpsHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 3)
	go func() { errc <- gs.Serve(gl) }()
	go func() {
		if uiCert != nil {
			errc <- httpSrv.ListenAndServeTLS("", "")
			return
		}
		errc <- httpSrv.ListenAndServe()
	}()
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

// checkKEKRecovery warns when the KEK could be purged (F17): the Olympos
// database dump is useless without it. Checked once at startup.
func (d *Deps) checkKEKRecovery(ctx context.Context) []inventory.AttentionItem {
	rc, ok := d.KV.(secrets.RecoveryChecker)
	if !ok {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	okRec, level, err := rc.KEKRecoverable(cctx)
	switch {
	case err != nil:
		d.Log.Warn("could not check Key Vault purge protection", "err", err)
		return []inventory.AttentionItem{{Kind: "kek_recovery_unknown", Severity: "warn", Label: "Key Vault",
			Detail: "could not check purge protection of the KEK (needs keys/get)", Link: "/settings"}}
	case !okRec:
		d.Log.Error("Key Vault purge protection is off: the KEK can be purged and every Olympos backup of its own database becomes useless",
			"recovery_level", level)
		return []inventory.AttentionItem{{Kind: "kek_purgeable", Severity: "crit", Label: "Key Vault",
			Detail: "purge protection is off (" + level + "): enable soft delete and purge protection", Link: "/settings"}}
	}
	return nil
}

func (d *Deps) initKeyVault() error {
	cfg := d.Cfg
	switch cfg.KeyVault.Provider {
	case "local":
		kv, err := localKeyVault(cfg.KeyVault.LocalDir)
		if err != nil {
			return err
		}
		d.KV = kv
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

// gatewayTLS is the gateway's TLS config; the returned certFile (nil for
// the internal-CA certificate) is reloaded on SIGHUP.
func (d *Deps) gatewayTLS() (*tls.Config, *certFile, error) {
	if d.Cfg.Gateway.TLSCertFile != "" {
		cf, err := loadCertFile(d.Cfg.Gateway.TLSCertFile, d.Cfg.Gateway.TLSKeyFile)
		if err != nil {
			return nil, nil, err
		}
		c := d.Gateway.TLSConfig(tls.Certificate{})
		c.Certificates, c.GetCertificate = nil, cf.get
		return c, cf, nil
	}
	// Internal CA: a 90-day certificate, re-issued when it has less than 30
	// days left (a systemd service can run longer than that).
	hosts := append([]string{d.Cfg.GatewayHost()}, d.Cfg.Gateway.ExtraSANs...)
	var mu sync.Mutex
	var cur *tls.Certificate
	issue := func() error {
		der, key, err := d.CA.IssueServerCert(hosts, 90*24*time.Hour)
		if err != nil {
			return err
		}
		leaf, _ := x509.ParseCertificate(der)
		cur = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
		d.Log.Info("issued gateway certificate from internal CA", "hosts", hosts, "not_after", leaf.NotAfter)
		return nil
	}
	if err := issue(); err != nil {
		return nil, nil, err
	}
	c := d.Gateway.TLSConfig(tls.Certificate{})
	c.Certificates = nil
	c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Until(cur.Leaf.NotAfter) < 30*24*time.Hour {
			if err := issue(); err != nil {
				d.Log.Error("renew gateway certificate", "err", err)
			}
		}
		return cur, nil
	}
	return c, nil, nil
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

// agentSets parses OLYMPOS_AGENT_INSTALL_SETS ("k=v,k2=v2") into extra
// --set lines for the generated agent install command.
func agentSets() []string {
	var out []string
	for _, kv := range strings.Split(os.Getenv("OLYMPOS_AGENT_INSTALL_SETS"), ",") {
		if kv = strings.TrimSpace(kv); strings.Contains(kv, "=") && !strings.ContainsAny(kv, " \t;|&$`'\"") {
			out = append(out, kv)
		}
	}
	return out
}
