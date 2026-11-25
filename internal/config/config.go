// Package config loads server configuration from a YAML file (Helm values
// render it) with OLYMPOS_* environment overrides for a few deploy-time keys.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Warewave-Technology/olympos/internal/devbuild"
)

// Server is the olympos-server configuration (SPEC §2.1).
type Server struct {
	PublicURL       string `yaml:"publicURL"`
	AgentGatewayURL string `yaml:"agentGatewayURL"`
	// DevMode enables the local Key Vault, the dev login and plain HTTP
	// cookies. Only development builds (-tags dev) accept it (F6).
	DevMode bool `yaml:"devMode"`

	// Experimental features. MultiReplica allows more than one server
	// instance on the same database (v0.1 supports one, F5).
	Experimental struct {
		MultiReplica bool `yaml:"multiReplica"`
	} `yaml:"experimental"`

	Listen struct {
		HTTP    string `yaml:"http"`    // user-facing, default :8080 (TLS terminated by ingress)
		Gateway string `yaml:"gateway"` // agent gateway, default :8443
		Metrics string `yaml:"metrics"` // /metrics, /healthz, /readyz; default :9090
		// Ingest is the address of the S3 endpoint of native ClickHouse
		// backups, default :9444. The endpoint is on only when ingest.url is
		// set.
		Ingest string `yaml:"ingest"`
		// TLSCertFile/TLSKeyFile serve the UI over HTTPS directly (systemd
		// install, no ingress). Reloaded on SIGHUP.
		TLSCertFile string `yaml:"tlsCertFile"`
		TLSKeyFile  string `yaml:"tlsKeyFile"`
	} `yaml:"listen"`

	Entra struct {
		TenantID        string `yaml:"tenantID"`
		ClientID        string `yaml:"clientID"`
		ClientSecretRef string `yaml:"clientSecretRef"`
		// AuthorityHost defaults to https://login.microsoftonline.com.
		AuthorityHost string `yaml:"authorityHost"`
		// GraphURL defaults to https://graph.microsoft.com.
		GraphURL string `yaml:"graphURL"`
	} `yaml:"entra"`

	BootstrapAdmins []string `yaml:"bootstrapAdmins"`

	KeyVault struct {
		Provider       string `yaml:"provider"` // azure (default) | local (dev only)
		Name           string `yaml:"name"`
		KEKName        string `yaml:"kekName"`
		HMACSecretName string `yaml:"hmacSecretName"`
		// ManifestKeyName is the Key Vault key that signs backup manifests,
		// default olympos-manifest.
		ManifestKeyName string `yaml:"manifestKeyName"`
		LocalDir        string `yaml:"localDir"`
		// ManagedIdentityClientID selects the user-assigned identity.
		ManagedIdentityClientID string `yaml:"managedIdentityClientID"`
		// References lets users other than global admins enter kv://
		// references: each rule allows a glob on <vault>/<secret> for
		// clusters matching a label selector (security review #2). Without
		// rules only global admins may enter references.
		References []RefRule `yaml:"references"`
	} `yaml:"keyVault"`

	// Database: Olympos' own PostgreSQL. Default: the local server on the
	// same host over the Unix socket with peer auth (systemd install, F17).
	// The Helm chart sets dsn + passwordFile for its bundled PostgreSQL;
	// dsnRef (Key Vault) is for external databases.
	Database struct {
		DSNRef string `yaml:"dsnRef"`
		DSN    string `yaml:"dsn"`
		// PasswordFile holds the password for DSN (not in the DSN itself).
		PasswordFile string `yaml:"passwordFile"`
	} `yaml:"database"`

	Gateway struct {
		// TLSCertFile/TLSKeyFile: optional externally issued server cert.
		// When empty the internal CA issues one for the agentGatewayURL host.
		TLSCertFile string   `yaml:"tlsCertFile"`
		TLSKeyFile  string   `yaml:"tlsKeyFile"`
		ExtraSANs   []string `yaml:"extraSANs"`
	} `yaml:"gateway"`

	// Ingest is the endpoint ClickHouse writes native backups to and reads
	// them from (listen.ingest). It is served over TLS: from the files, or
	// else a certificate of the internal CA for the host of URL.
	Ingest Ingest `yaml:"ingest"`

	// TargetTLS configures how the server verifies targets' TLS certificates
	// (end-to-end through the tunnel). CABundleFile holds the CAs that issue
	// target certificates (PEM). Public CAs are trusted only with
	// SystemRoots: a target's TLS name comes from a Service annotation.
	TargetTLS struct {
		CABundleFile string `yaml:"caBundleFile"`
		SystemRoots  bool   `yaml:"systemRoots"`
	} `yaml:"targetTLS"`

	Slack struct {
		BotTokenRef string `yaml:"botTokenRef"`
		APIURL      string `yaml:"apiURL"` // tests only
	} `yaml:"slack"`

	DeadMansSwitch struct {
		URL string `yaml:"url"`
	} `yaml:"deadMansSwitch"`

	Backup struct {
		GlobalConcurrency     int    `yaml:"globalConcurrency"`
		PerClusterConcurrency int    `yaml:"perClusterConcurrency"`
		PgDumpDir             string `yaml:"pgDumpDir"` // contains <major>/bin/pg_dump
		// ClickHouseClient is the clickhouse binary restores run as
		// `<bin> client` (default "clickhouse" on PATH). Missing: the server
		// still starts and ClickHouse restores fail with a clear message.
		ClickHouseClient string `yaml:"clickhouseClient"`
		// NFSRoot holds the volumes NFS destinations may write to: every
		// first-level subdirectory is one mount (Helm mounts nfsMounts[].name
		// at <nfsRoot>/<name>). Default /var/lib/olympos/nfs.
		NFSRoot string `yaml:"nfsRoot"`
		// StorageCABundleFile adds private CAs (PEM) to the system roots for
		// S3 endpoints (e.g. MinIO / Ceph behind an internal CA). It is not
		// the targetTLS bundle: storage and targets are trusted separately.
		StorageCABundleFile string `yaml:"storageCABundleFile"`
		// S3PartSizeMiB is the multipart part size for S3 uploads of unknown
		// length (memory per running upload; max object = 10000 parts).
		// Default 32 (≈ 312 GiB per backup object), 5–5120.
		S3PartSizeMiB int `yaml:"s3PartSizeMiB"`
	} `yaml:"backup"`

	ChangeRequests struct {
		TTL time.Duration `yaml:"ttl"`
	} `yaml:"changeRequests"`

	// Agents: alert debounce (F18).
	Agents struct {
		// OfflineAlertAfter: agent.offline fires after this long offline
		// (default 5m). One agent.online follows when it comes back.
		OfflineAlertAfter time.Duration `yaml:"offlineAlertAfter"`
		// FlappingDisconnects within FlappingWindow fire agent.flapping
		// (defaults 5 and 30m).
		FlappingDisconnects int           `yaml:"flappingDisconnects"`
		FlappingWindow      time.Duration `yaml:"flappingWindow"`
	} `yaml:"agents"`

	Audit struct {
		KubescapeBin string `yaml:"kubescapeBin"`
		// KubescapeArtifacts: frameworks/controls downloaded at build time
		// (default /usr/share/olympos/kubescape-artifacts; F14, air-gapped).
		KubescapeArtifacts string `yaml:"kubescapeArtifacts"`
		PolarisBin         string `yaml:"polarisBin"`
	} `yaml:"audit"`

	Security struct {
		TrivyBin         string   `yaml:"trivyBin"`
		TrivyCacheDir    string   `yaml:"trivyCacheDir"`
		TrivyDBRepo      string   `yaml:"trivyDBRepo"`
		SystemNamespaces []string `yaml:"systemNamespaces"`
		// SecretsInventory: findings of the opt-in Secret inventory (F3).
		// ReportUnmanaged (default true) raises secret.unmanaged (info) for
		// Secrets not owned by External Secrets / Vault Secrets Operator /
		// sealed-secrets / cert-manager.
		SecretsInventory struct {
			ReportUnmanaged *bool `yaml:"reportUnmanaged"`
		} `yaml:"secretsInventory"`
	} `yaml:"security"`

	Synthetic Synthetic `yaml:"synthetic"`
}

// Synthetic configures synthetic monitoring
// (docs/design/synthetic-monitoring.md). Zero values take the defaults.
type Synthetic struct {
	// RunRetention keeps runs and their step results (default 720h, 30
	// days), then only the hourly aggregates remain.
	RunRetention time.Duration `yaml:"runRetention"`
	// AggregateRetention keeps the hourly aggregates (default 9600h, 400
	// days).
	AggregateRetention time.Duration `yaml:"aggregateRetention"`
	// ExcerptRetention keeps response excerpts (default 168h, 7 days).
	ExcerptRetention time.Duration `yaml:"excerptRetention"`
	// MaxRequestsPerMinutePerCluster caps what all scenarios together may
	// make one cluster's probe send (default 600, §6.3).
	MaxRequestsPerMinutePerCluster int `yaml:"maxRequestsPerMinutePerCluster"`
	// MaxRequestsPerMinutePerScenario caps one scenario on one cluster
	// (default 120, decision 4).
	MaxRequestsPerMinutePerScenario int `yaml:"maxRequestsPerMinutePerScenario"`
	// ProbeOfflineAlertAfter: probe.offline fires after a probe has been
	// offline this long (default 5m). One probe.online follows when it
	// comes back.
	ProbeOfflineAlertAfter time.Duration `yaml:"probeOfflineAlertAfter"`
}

func (s *Synthetic) defaults() {
	dur := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	dur(&s.RunRetention, 720*time.Hour)
	dur(&s.AggregateRetention, 9600*time.Hour)
	dur(&s.ExcerptRetention, 168*time.Hour)
	dur(&s.ProbeOfflineAlertAfter, 5*time.Minute)
	if s.MaxRequestsPerMinutePerCluster == 0 {
		s.MaxRequestsPerMinutePerCluster = 600
	}
	if s.MaxRequestsPerMinutePerScenario == 0 {
		s.MaxRequestsPerMinutePerScenario = 120
	}
}

func (s *Synthetic) validate() []string {
	var errs []string
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"synthetic.runRetention", s.RunRetention}, {"synthetic.aggregateRetention", s.AggregateRetention},
		{"synthetic.excerptRetention", s.ExcerptRetention}, {"synthetic.probeOfflineAlertAfter", s.ProbeOfflineAlertAfter},
	} {
		if d.v < 0 {
			errs = append(errs, d.name+" must not be negative")
		}
	}
	if s.MaxRequestsPerMinutePerCluster < 0 {
		errs = append(errs, "synthetic.maxRequestsPerMinutePerCluster must not be negative")
	}
	if s.MaxRequestsPerMinutePerScenario < 0 {
		errs = append(errs, "synthetic.maxRequestsPerMinutePerScenario must not be negative")
	}
	return errs
}

// Load reads path (may be empty) and applies defaults and env overrides.
func Load(path string) (*Server, error) {
	c := &Server{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var wrapper struct {
			Olympos *Server `yaml:"olympos"`
		}
		if err := yaml.Unmarshal(b, &wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if wrapper.Olympos != nil {
			c = wrapper.Olympos
		} else if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	envOverride(&c.Database.DSN, "OLYMPOS_DATABASE_DSN")
	envOverride(&c.PublicURL, "OLYMPOS_PUBLIC_URL")
	envOverride(&c.Entra.ClientID, "OLYMPOS_ENTRA_CLIENT_ID")
	envOverride(&c.Entra.TenantID, "OLYMPOS_ENTRA_TENANT_ID")
	if os.Getenv("OLYMPOS_DEV_MODE") == "1" {
		c.DevMode = true
	}
	c.defaults()
	return c, c.Validate()
}

// Ingest configures the native-backup endpoint.
type Ingest struct {
	// URL is how ClickHouse reaches the endpoint (https://host:port). Set,
	// it turns the endpoint on (listener at listen.ingest) and names the
	// host of the internal-CA certificate; empty, there is no endpoint.
	URL string `yaml:"url"`
	// TLSCertFile/TLSKeyFile: optional externally issued server certificate,
	// reloaded on SIGHUP. When empty the internal CA issues one for the host
	// of URL.
	TLSCertFile string `yaml:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile"`
	// MaxRuns is how many native runs may hold an ingest session at once
	// (default 4).
	MaxRuns int `yaml:"maxRuns"`
	// MaxRunDuration ends a native run's session (default 6h).
	MaxRunDuration time.Duration `yaml:"maxRunDuration"`
	// MaxRunBytes is how many bytes one native run may write. 0 (default)
	// is automatic: the largest of twice the job's last full native run,
	// 1.5 times the size on disk of the run's databases, and 1 GiB.
	MaxRunBytes int64 `yaml:"maxRunBytes"`
	// SpillDir holds out-of-order upload parts until their turn, up to 1 GiB
	// per run. Default: the operating system's temporary directory.
	SpillDir string `yaml:"spillDir"`
}

// DefaultDSN: local PostgreSQL over the Unix socket, peer auth, database
// and role "olympos".
const DefaultDSN = "postgres:///olympos?host=/var/run/postgresql"

func envOverride(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func (c *Server) defaults() {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&c.Listen.HTTP, ":8080")
	def(&c.Listen.Gateway, ":8443")
	def(&c.Listen.Metrics, ":9090")
	def(&c.Listen.Ingest, ":9444")
	def(&c.Entra.AuthorityHost, "https://login.microsoftonline.com")
	def(&c.Entra.GraphURL, "https://graph.microsoft.com")
	def(&c.KeyVault.Provider, "azure")
	def(&c.KeyVault.KEKName, "olympos-kek")
	def(&c.KeyVault.HMACSecretName, "olympos-hmac")
	def(&c.KeyVault.ManifestKeyName, "olympos-manifest")
	def(&c.KeyVault.LocalDir, "/var/lib/olympos/localkv")
	if c.Database.DSNRef == "" {
		def(&c.Database.DSN, DefaultDSN)
	}
	def(&c.Backup.PgDumpDir, "/usr/lib/postgresql")
	def(&c.Backup.NFSRoot, "/var/lib/olympos/nfs")
	def(&c.Backup.ClickHouseClient, "clickhouse")
	if c.Backup.S3PartSizeMiB == 0 {
		c.Backup.S3PartSizeMiB = 32
	}
	def(&c.Audit.KubescapeBin, "kubescape")
	def(&c.Audit.KubescapeArtifacts, "/usr/share/olympos/kubescape-artifacts")
	def(&c.Audit.PolarisBin, "polaris")
	def(&c.Security.TrivyBin, "trivy")
	def(&c.Security.TrivyCacheDir, "/var/cache/trivy")
	if c.Backup.GlobalConcurrency == 0 {
		c.Backup.GlobalConcurrency = 4
	}
	if c.Backup.PerClusterConcurrency == 0 {
		c.Backup.PerClusterConcurrency = 2
	}
	if c.Ingest.MaxRuns == 0 {
		c.Ingest.MaxRuns = 4
	}
	if c.Ingest.MaxRunDuration == 0 {
		c.Ingest.MaxRunDuration = 6 * time.Hour
	}
	if c.ChangeRequests.TTL == 0 {
		c.ChangeRequests.TTL = 72 * time.Hour
	}
	if c.Security.SystemNamespaces == nil {
		c.Security.SystemNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", "olympos-system", "olympos-bench"}
	}
	c.Synthetic.defaults()
}

// Validate checks required settings.
func (c *Server) Validate() error {
	var errs []string
	if (c.Listen.TLSCertFile == "") != (c.Listen.TLSKeyFile == "") {
		errs = append(errs, "listen.tlsCertFile and listen.tlsKeyFile must be set together")
	}
	if (c.Gateway.TLSCertFile == "") != (c.Gateway.TLSKeyFile == "") {
		errs = append(errs, "gateway.tlsCertFile and gateway.tlsKeyFile must be set together")
	}
	if (c.Ingest.TLSCertFile == "") != (c.Ingest.TLSKeyFile == "") {
		errs = append(errs, "ingest.tlsCertFile and ingest.tlsKeyFile must be set together")
	}
	if c.Ingest.MaxRuns < 0 {
		errs = append(errs, "ingest.maxRuns must be positive")
	}
	if c.Ingest.MaxRunDuration < 0 {
		errs = append(errs, "ingest.maxRunDuration must be positive")
	}
	if c.Ingest.MaxRunBytes < 0 {
		errs = append(errs, "ingest.maxRunBytes must be 0 (automatic) or positive")
	}
	if c.IngestEnabled() {
		u, err := url.Parse(c.Ingest.URL)
		switch {
		case err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http"):
			errs = append(errs, "ingest.url must be an absolute https (or http) URL with a host")
		case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
			errs = append(errs, "ingest.url must be only scheme, host and port, with no path or query")
		case u.Scheme == "http" && !c.DevMode:
			errs = append(errs, "ingest.url must be https unless devMode is on")
		case u.Scheme == "http" && c.Ingest.TLSCertFile != "":
			errs = append(errs, "ingest.tlsCertFile needs an https ingest.url")
		}
		if c.Listen.Ingest == "" {
			errs = append(errs, "listen.ingest must not be empty while ingest.url is set")
		}
		if c.Experimental.MultiReplica {
			// A run's session, and its secret, live in the one process
			// that opened it.
			errs = append(errs, "ingest.url cannot be set while experimental.multiReplica is true: ingest sessions live in one server process")
		}
	}
	if c.DevMode && !devbuild.Enabled {
		errs = append(errs, "devMode is only available in development builds (go build -tags dev); release binaries have no dev login and no local key vault")
	}
	if c.PublicURL == "" {
		errs = append(errs, "publicURL is required")
	} else if u, err := url.Parse(c.PublicURL); err != nil || u.Host == "" {
		errs = append(errs, "publicURL must be an absolute URL")
	} else if u.Scheme != "https" && !c.DevMode {
		errs = append(errs, "publicURL must be https (set devMode for local http)")
	}
	if c.AgentGatewayURL == "" {
		errs = append(errs, "agentGatewayURL is required")
	}
	if c.Entra.TenantID == "" || c.Entra.ClientID == "" {
		if !c.DevMode {
			errs = append(errs, "entra.tenantID and entra.clientID are required")
		}
	}
	if c.KeyVault.Provider == "local" && !c.DevMode {
		errs = append(errs, "keyVault.provider=local is only allowed with devMode")
	}
	if c.KeyVault.Provider == "azure" && c.KeyVault.Name == "" {
		errs = append(errs, "keyVault.name is required")
	}
	if c.Backup.S3PartSizeMiB < 5 || c.Backup.S3PartSizeMiB > 5120 {
		errs = append(errs, "backup.s3PartSizeMiB must be between 5 and 5120")
	}
	if c.Database.DSN != "" && c.Database.DSNRef != "" {
		errs = append(errs, "set database.dsn or database.dsnRef, not both")
	}
	errs = append(errs, c.Synthetic.validate()...)
	if len(errs) > 0 {
		return errors.New("invalid config: " + strings.Join(errs, "; "))
	}
	return nil
}

// GatewayHost returns the host part of agentGatewayURL.
func (c *Server) GatewayHost() string {
	h := c.AgentGatewayURL
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}

// IngestEnabled reports whether the ingest endpoint of native ClickHouse
// backups is on: it is, when ingest.url is set.
func (c *Server) IngestEnabled() bool { return c.Ingest.URL != "" }

// IngestTLS reports whether the endpoint is served over HTTPS (an http
// ingest.url serves plain HTTP: lab use inside a trusted network).
func (c *Server) IngestTLS() bool { return !strings.HasPrefix(c.Ingest.URL, "http://") }

// IngestHost returns the host part of ingest.url, without port or brackets.
func (c *Server) IngestHost() string {
	u, err := url.Parse(c.Ingest.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// RefRule allows Key Vault references matching Ref (glob on
// <vault>/<secret>) for clusters matching Scope (label selector; "" = all).
type RefRule struct {
	Ref   string `yaml:"ref"`
	Scope string `yaml:"scope"`
}
