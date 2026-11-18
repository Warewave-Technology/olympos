package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DialFunc opens one read-only API proxy tunnel to the agent (plain HTTP
// inside the mTLS tunnel; the agent injects its own ServiceAccount token).
type DialFunc func(ctx context.Context) (net.Conn, error)

// maxProxyTunnels bounds how many tunnels one tool run holds open at once.
// Requests beyond that wait for a free keep-alive connection instead of
// failing on the agent's tunnel limit (shared with backups).
const maxProxyTunnels = 4

// APIProxy is a local listener on 127.0.0.1 that forwards kube-apiserver
// requests from a server-side tool (kubescape, polaris) through the agent's
// read-only API proxy (SPEC §7, §12.1). It also owns a temporary kubeconfig
// that points at the listener and carries no credentials.
//
// Defense in depth: non-GET requests are refused here too, before anything
// crosses the tunnel; the agent enforces the same rule (and rejects Secret
// paths) independently.
type APIProxy struct {
	// Kubeconfig is the path of the generated kubeconfig (0600, private dir).
	Kubeconfig string
	// URL is the listener's base URL (http://127.0.0.1:<port>).
	URL string

	dir    string
	ln     net.Listener
	srv    *http.Server
	tr     *http.Transport
	cancel context.CancelFunc
	once   sync.Once
	done   chan struct{}
}

// StartAPIProxy opens the listener and writes the kubeconfig. Close it when
// the tool has finished; Close removes the kubeconfig and its directory.
func StartAPIProxy(ctx context.Context, dial DialFunc, log *slog.Logger) (*APIProxy, error) {
	if log == nil {
		log = slog.Default()
	}
	dir, err := os.MkdirTemp("", "olympos-audit-")
	if err != nil {
		return nil, fmt.Errorf("api proxy temp dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("api proxy listener: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &APIProxy{dir: dir, ln: ln, cancel: cancel, done: make(chan struct{}),
		URL: "http://" + ln.Addr().String()}

	p.tr = &http.Transport{
		DialContext:           func(dctx context.Context, _, _ string) (net.Conn, error) { return dial(dctx) },
		MaxConnsPerHost:       maxProxyTunnels,
		MaxIdleConnsPerHost:   maxProxyTunnels,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ForceAttemptHTTP2:     false,
	}
	upstream := &url.URL{Scheme: "http", Host: "kubernetes.olympos-tunnel"}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = upstream.Host
			// Nothing credential-like ever leaves the server: the agent
			// injects its own token and strips these anyway.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Proxy-Authorization")
			for k := range r.Out.Header {
				if strings.HasPrefix(strings.ToLower(k), "impersonate-") {
					r.Out.Header.Del(k)
				}
			}
		},
		Transport:     p.tr,
		FlushInterval: -1, // stream watch responses
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warn("api proxy request failed", "method", r.Method, "path", r.URL.Path, "err", err)
			http.Error(w, "olympos api proxy: upstream unavailable", http.StatusBadGateway)
		},
	}
	p.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "olympos api proxy is read-only", http.StatusForbidden)
				return
			}
			rp.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		defer close(p.done)
		_ = p.srv.Serve(ln)
	}()

	p.Kubeconfig = filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(p.Kubeconfig, []byte(Kubeconfig(p.URL)), 0o600); err != nil {
		p.Close()
		return nil, fmt.Errorf("write kubeconfig: %w", err)
	}
	return p, nil
}

// Dir is the private temp directory (tools may write their output here).
func (p *APIProxy) Dir() string { return p.dir }

// Close stops the listener, drops tunnels and removes the temp directory.
func (p *APIProxy) Close() {
	p.once.Do(func() {
		p.cancel()
		_ = p.srv.Close()
		<-p.done
		p.tr.CloseIdleConnections()
		_ = os.RemoveAll(p.dir)
	})
}

// Kubeconfig renders a kubeconfig for server with no credentials at all
// (no token, no client certificate, no exec plugin).
func Kubeconfig(server string) string {
	return `apiVersion: v1
kind: Config
clusters:
- name: olympos
  cluster:
    server: ` + server + `
contexts:
- name: olympos
  context:
    cluster: olympos
    user: olympos
current-context: olympos
users:
- name: olympos
  user: {}
preferences: {}
`
}
