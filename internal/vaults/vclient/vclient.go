// Package vclient builds HashiCorp Vault / OpenBao API clients whose
// connections go through the agent tunnel (SPEC §7, §11).
//
// In transfer mode e2e-tls (default) the server speaks TLS end-to-end with the
// target: the certificate is verified against the system pool plus an
// optional CA bundle, with the server name <svc>.<ns>.svc unless overridden.
// InsecureSkipVerify is never used. In "compressed" mode the client speaks
// plain HTTP (the tunnel itself is mTLS + zstd).
package vclient

import (
	"github.com/Warewave-Technology/olympos/internal/targettls"

	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Options configure a client.
type Options struct {
	// Dial opens a new connection to the target (a tunnel in production).
	Dial func(ctx context.Context) (net.Conn, error)
	// TLS: speak TLS end-to-end (transfer mode e2e-tls).
	TLS bool
	// ServerName is verified in the certificate and sent as SNI / Host.
	ServerName string
	// CABundle is an optional PEM bundle added to the system roots.
	CABundle []byte
	// Timeout bounds each request (0: only the caller's context). Leave 0 for
	// streaming snapshots.
	Timeout time.Duration
}

// Client is a Vault API client bound to one target. Close releases idle
// tunnel connections.
type Client struct {
	*vaultapi.Client
	tr *http.Transport
}

// Close drops idle connections (tunnels).
func (c *Client) Close() { c.tr.CloseIdleConnections() }

// RootCAs returns the server-wide target CA bundle (targetTLS.caBundleFile,
// plus the system pool with targetTLS.systemRoots) and the per-vault PEM
// bundle. With none of them nothing verifies the vault: targettls.ErrNoRoots.
func RootCAs(bundle []byte) (*x509.CertPool, error) {
	perVault := len(strings.TrimSpace(string(bundle))) > 0
	if err := targettls.Usable(false, perVault); err != nil {
		return nil, err
	}
	pool := targettls.RootCAs().Clone()
	if perVault && !pool.AppendCertsFromPEM(bundle) {
		return nil, errors.New("CA bundle contains no PEM certificates")
	}
	return pool, nil
}

// New returns a client without a token. The VAULT_TOKEN / VAULT_NAMESPACE
// environment of the server process is ignored.
func New(o Options) (*Client, error) {
	if o.Dial == nil {
		return nil, errors.New("vclient: Dial is required")
	}
	if o.ServerName == "" {
		return nil, errors.New("vclient: ServerName is required")
	}
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return o.Dial(ctx) },
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 20 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	scheme := "http"
	if o.TLS {
		pool, err := RootCAs(o.CABundle)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName, RootCAs: pool}
		scheme = "https"
	}
	cfg := &vaultapi.Config{
		Address: scheme + "://" + o.ServerName,
		HttpClient: &http.Client{Transport: tr,
			// The Vault client handles 307 leader redirects itself.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		MaxRetries: 0, // writes are cas-protected, but never replay them silently
		Timeout:    o.Timeout,
	}
	c, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	c.ClearToken()
	c.ClearNamespace()
	return &Client{Client: c, tr: tr}, nil
}

// DefaultServerName is <service>.<namespace>.svc.
func DefaultServerName(service, namespace string) string { return service + "." + namespace + ".svc" }

// AppRoleLogin logs in with the Olympos AppRole and sets the token on c.
func AppRoleLogin(ctx context.Context, c *Client, roleID string, secretID []byte) error {
	sec, err := c.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]any{"role_id": roleID, "secret_id": string(secretID)})
	if err != nil {
		return fmt.Errorf("approle login: %w", Sanitize(err))
	}
	if sec == nil || sec.Auth == nil || sec.Auth.ClientToken == "" {
		return errors.New("approle login returned no token")
	}
	c.SetToken(sec.Auth.ClientToken)
	return nil
}

// RevokeSelf revokes the client's token (best effort) and clears it.
func RevokeSelf(c *Client) {
	if c.Token() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = c.Logical().WriteWithContext(ctx, "auth/token/revoke-self", nil)
	c.ClearToken()
}

// StatusCode returns the HTTP status of a Vault error, or 0.
func StatusCode(err error) int {
	var re *vaultapi.ResponseError
	if errors.As(err, &re) {
		return re.StatusCode
	}
	return 0
}

// ErrorText returns the Vault error messages of err (no URL, no request).
func ErrorText(err error) string {
	var re *vaultapi.ResponseError
	if errors.As(err, &re) {
		return strings.Join(re.Errors, "; ")
	}
	return ""
}

// Sanitize maps a Vault/transport error to one that carries no request
// details: status code and Vault's own error messages only.
func Sanitize(err error) error {
	if err == nil {
		return nil
	}
	var re *vaultapi.ResponseError
	if errors.As(err, &re) {
		msg := strings.Join(re.Errors, "; ")
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("vault returned HTTP %d: %s", re.StatusCode, msg)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timed out talking to vault")
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return fmt.Errorf("vault TLS certificate not trusted: %v", ce.Err)
	}
	var he x509.HostnameError
	if errors.As(err, &he) {
		return fmt.Errorf("vault TLS certificate does not match the server name: %v", he)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, http.ErrSchemeMismatch) || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		// No silent fallback to HTTP: the root token, AppRole tokens and
		// new secret values would cross the agent in clear.
		return errors.New("this vault serves plain HTTP, but Olympos requires TLS end-to-end for vaults " +
			"(otherwise the root token, AppRole tokens and secret values cross the agent in clear). " +
			"Enable TLS on the vault listener, or, accepting that risk, set this cluster's transfer mode to compressed in Settings › Clusters")
	}
	return errors.New("could not reach vault: " + firstLine(err.Error()))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	// Drop the "Get "https://...": " prefix of url.Error.
	if i := strings.LastIndex(s, "\": "); i >= 0 {
		s = s[i+3:]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Health is the unauthenticated seal status.
type Health struct {
	Version     string
	Sealed      bool
	Initialized bool
	StorageType string
}

// SealStatus reads sys/seal-status (no token needed).
func SealStatus(ctx context.Context, c *Client) (Health, error) {
	st, err := c.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return Health{}, Sanitize(err)
	}
	return Health{Version: st.Version, Sealed: st.Sealed, Initialized: st.Initialized, StorageType: st.StorageType}, nil
}

// CABundleFor, when set (by the vaults module), returns the configured CA
// bundle for a target. Used by the snapshot engine.
var CABundleFor func(ctx context.Context, targetID string) ([]byte, error)
