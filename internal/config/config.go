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
		LocalDir       string `yaml:"localDir"`
		// ManagedIdentityClientID selects the user-assigned identity.
		ManagedIdentityClientID string `yaml:"managedIdentityClientID"`
	} `yaml:"keyVault"`

	Database struct {
		DSNRef string `yaml:"dsnRef"`
		DSN    string `yaml:"dsn"` // dev only; prefer dsnRef
	} `yaml:"database"`

	Gateway struct {
		// TLSCertFile/TLSKeyFile: optional externally issued server cert.
		// When empty the internal CA issues one for the agentGatewayURL host.
		TLSCertFile string   `yaml:"tlsCertFile"`
		TLSKeyFile  string   `yaml:"tlsKeyFile"`
		ExtraSANs   []string `yaml:"extraSANs"`
	} `yaml:"gateway"`

	// TargetTLS configures how the server verifies targets' TLS certificates
	// (end-to-end through the tunnel). The system pool is always trusted;
	// CABundleFile adds private CAs (PEM).
	TargetTLS struct {
		CABundleFile string `yaml:"caBundleFile"`
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

	Audit struct {
		KubescapeBin string `yaml:"kubescapeBin"`
		PolarisBin   string `yaml:"polarisBin"`
	} `yaml:"audit"`

	Security struct {
		TrivyBin         string   `yaml:"trivyBin"`
		TrivyCacheDir    string   `yaml:"trivyCacheDir"`
		TrivyDBRepo      string   `yaml:"trivyDBRepo"`
		SystemNamespaces []string `yaml:"systemNamespaces"`
	} `yaml:"security"`
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
	def(&c.Entra.AuthorityHost, "https://login.microsoftonline.com")
	def(&c.Entra.GraphURL, "https://graph.microsoft.com")
	def(&c.KeyVault.Provider, "azure")
	def(&c.KeyVault.KEKName, "olympos-kek")
	def(&c.KeyVault.HMACSecretName, "olympos-hmac")
	def(&c.KeyVault.LocalDir, "/var/lib/olympos/localkv")
	def(&c.Backup.PgDumpDir, "/usr/lib/postgresql")
	def(&c.Backup.NFSRoot, "/var/lib/olympos/nfs")
	if c.Backup.S3PartSizeMiB == 0 {
		c.Backup.S3PartSizeMiB = 32
	}
	def(&c.Audit.KubescapeBin, "kubescape")
	def(&c.Audit.PolarisBin, "polaris")
	def(&c.Security.TrivyBin, "trivy")
	def(&c.Security.TrivyCacheDir, "/var/cache/trivy")
	if c.Backup.GlobalConcurrency == 0 {
		c.Backup.GlobalConcurrency = 4
	}
	if c.Backup.PerClusterConcurrency == 0 {
		c.Backup.PerClusterConcurrency = 2
	}
	if c.ChangeRequests.TTL == 0 {
		c.ChangeRequests.TTL = 72 * time.Hour
	}
	if c.Security.SystemNamespaces == nil {
		c.Security.SystemNamespaces = []string{"kube-system", "kube-public", "kube-node-lease", "olympos-system", "olympos-bench"}
	}
}

// Validate checks required settings.
func (c *Server) Validate() error {
	var errs []string
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
	if c.Database.DSN == "" && c.Database.DSNRef == "" {
		errs = append(errs, "database.dsnRef is required")
	}
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
