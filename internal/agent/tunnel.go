package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/rest"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
	"github.com/Warewave-Technology/olympos/internal/tunnel"
)

func (a *Agent) reject(id, reason string) {
	a.log.Warn("tunnel rejected", "tunnel_id", id, "reason", reason)
	_ = a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_TunnelRejected{TunnelRejected: &pb.TunnelRejected{TunnelId: id, Reason: reason}}})
}

func (a *Agent) acquireTunnel() bool {
	if int(a.tunnels.Add(1)) > a.cfg.MaxTunnels {
		a.tunnels.Add(-1)
		return false
	}
	return true
}

// openTunnel serves OpenTunnel: only targets this agent discovered itself
// are reachable. The server never supplies a host or port.
func (a *Agent) openTunnel(ctx context.Context, req *pb.OpenTunnel) {
	t, ok := a.disc.lookupTarget(req.TargetId)
	if !ok {
		a.reject(req.TunnelId, "unknown target")
		return
	}
	if !a.acquireTunnel() {
		a.reject(req.TunnelId, "too many tunnels")
		return
	}
	defer a.tunnels.Add(-1)
	addr, err := a.disc.resolve(t)
	if err != nil {
		a.reject(req.TunnelId, "target not resolvable: "+err.Error())
		return
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		a.reject(req.TunnelId, "connect failed")
		return
	}
	a.attach(ctx, req.TunnelId, tcp, req.Compressed)
}

func (a *Agent) attach(ctx context.Context, tunnelID string, local net.Conn, compressed bool) {
	defer local.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.sendMu.Lock()
	client := a.client
	a.sendMu.Unlock()
	stream, err := client.Tunnel(ctx)
	if err != nil {
		a.reject(tunnelID, "tunnel stream failed")
		return
	}
	if err := stream.Send(&pb.TunnelFrame{TunnelId: tunnelID}); err != nil {
		a.reject(tunnelID, "tunnel stream failed")
		return
	}
	_ = a.send(&pb.AgentMessage{Msg: &pb.AgentMessage_TunnelAccepted{TunnelAccepted: &pb.TunnelAccepted{TunnelId: tunnelID}}})
	err = tunnel.Bridge(local, stream, compressed, tunnel.Limits{}, nil, func() { _ = stream.CloseSend() })
	if err != nil && ctx.Err() == nil {
		a.log.Debug("tunnel closed", "tunnel_id", tunnelID, "err", err)
	}
}

// resolve maps a target to an address: the Service ClusterIP, or a ready
// endpoint for headless Services.
func (d *discovery) resolve(t *pb.Target) (string, error) {
	svc, err := d.svcs.Services(t.Namespace).Get(t.Service)
	if err != nil {
		return "", err
	}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
		return net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(t.Port))), nil
	}
	var sp *corev1.ServicePort
	for i := range svc.Spec.Ports {
		if svc.Spec.Ports[i].Port == t.Port {
			sp = &svc.Spec.Ports[i]
		}
	}
	if sp == nil {
		return "", errors.New("service port gone")
	}
	var slices []*discoveryv1.EndpointSlice
	for _, o := range d.eps.List() {
		if es, ok := o.(*discoveryv1.EndpointSlice); ok {
			slices = append(slices, es)
		}
	}
	return pickEndpoint(slices, t.Namespace, t.Service, sp.Name)
}

// endpointSliceController manages the slices of selector-based Services.
const endpointSliceController = "endpointslice-controller.k8s.io"

// pickEndpoint returns a ready endpoint of a headless Service. Only slices
// the EndpointSlice controller made from the Service's selector count, and
// only IP addresses that are not loopback, link-local (cloud metadata) or
// unspecified (security review #9): a user who can write EndpointSlices in
// the namespace must not steer the tunnel to a host name or outside the
// cluster.
func pickEndpoint(slices []*discoveryv1.EndpointSlice, namespace, service, portName string) (string, error) {
	sort.Slice(slices, func(i, j int) bool { return slices[i].Name < slices[j].Name })
	for _, es := range slices {
		if es.Namespace != namespace || es.Labels[discoveryv1.LabelServiceName] != service ||
			es.Labels[discoveryv1.LabelManagedBy] != endpointSliceController ||
			es.AddressType != discoveryv1.AddressTypeIPv4 && es.AddressType != discoveryv1.AddressTypeIPv6 {
			continue
		}
		port := int32(0)
		for _, p := range es.Ports {
			if p.Port != nil && (p.Name == nil && portName == "" || p.Name != nil && *p.Name == portName) {
				port = *p.Port
			}
		}
		if port == 0 {
			continue
		}
		for _, ep := range es.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				ip := net.ParseIP(a)
				if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
					continue
				}
				return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
			}
		}
	}
	return "", errors.New("no ready endpoints")
}

// ---------------------------------------------------------------- API proxy

// secretPath matches a "secrets" path segment anywhere: the core API
// (namespaced or not), the legacy /api/v1/watch/... prefix and any API
// group or aggregated API. Case-insensitive, after normalization. With the
// opt-in Secret inventory the agent's token can list/watch Secrets, so this
// filter is what keeps values out of the proxy.
var secretPath = regexp.MustCompile(`(?i)(^|/)secrets(/|$)`)

// forbiddenSub blocks subresources that execute or forward, even via GET.
var forbiddenSub = regexp.MustCompile(`(?i)/(exec|attach|portforward|proxy)(/|$)`)

// APIProxyHandler returns the read-only kube-apiserver proxy handler.
// Exported for tests.
func APIProxyHandler(upstream *url.URL, transport http.RoundTripper) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = upstream.Host
			// The agent's own ServiceAccount token is injected by transport.
			r.Out.Header.Del("Authorization")
			// Identity headers the API server could honour with other
			// authenticators (requestheader front proxy) never pass.
			for k := range r.Out.Header {
				if lk := strings.ToLower(k); strings.HasPrefix(lk, "impersonate-") || strings.HasPrefix(lk, "x-remote-") || strings.HasPrefix(lk, "x-forwarded-") {
					r.Out.Header.Del(k)
				}
			}
		},
		Transport: transport,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "olympos api proxy: read-only (GET only)", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-HTTP-Method-Override") != "" || r.Header.Get("X-HTTP-Method") != "" {
			http.Error(w, "olympos api proxy: method overrides are not allowed", http.StatusForbidden)
			return
		}
		if r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			http.Error(w, "olympos api proxy: upgrades are not allowed", http.StatusForbidden)
			return
		}
		p := path(r.URL)
		// Checked on the normalized path and once more decoded: the API
		// server decodes the path once, a proxy in between might again.
		if secretPath.MatchString(p) || secretPath.MatchString(twiceDecoded(p)) {
			http.Error(w, "olympos api proxy: secrets are not readable", http.StatusForbidden)
			return
		}
		if forbiddenSub.MatchString(p) {
			http.Error(w, "olympos api proxy: subresource not allowed", http.StatusForbidden)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// twiceDecoded decodes and normalizes an already normalized path once more.
func twiceDecoded(p string) string {
	if dp, err := url.PathUnescape(p); err == nil {
		return path(&url.URL{Path: dp, RawPath: dp})
	}
	return p
}

// path normalizes the request path so "//api/v1/../v1/secrets" tricks fail.
func path(u *url.URL) string {
	p := u.EscapedPath()
	if dp, err := url.PathUnescape(p); err == nil {
		p = dp
	}
	clean := "/" + strings.TrimLeft(p, "/")
	for strings.Contains(clean, "//") {
		clean = strings.ReplaceAll(clean, "//", "/")
	}
	parts := []string{}
	for _, seg := range strings.Split(clean, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, seg)
		}
	}
	return "/" + strings.Join(parts, "/")
}

var (
	proxyOnce    sync.Once
	proxyHandler http.Handler
	proxyErr     error
)

func (a *Agent) apiProxy() (http.Handler, error) {
	proxyOnce.Do(func() {
		u, err := url.Parse(a.rest.Host)
		if err != nil {
			proxyErr = err
			return
		}
		if u.Scheme == "" {
			u, _ = url.Parse("https://" + a.rest.Host)
		}
		rt, err := rest.TransportFor(a.rest)
		if err != nil {
			proxyErr = err
			return
		}
		proxyHandler = APIProxyHandler(u, rt)
	})
	return proxyHandler, proxyErr
}

func (a *Agent) openAPIProxy(ctx context.Context, req *pb.OpenAPIProxy) {
	h, err := a.apiProxy()
	if err != nil {
		a.reject(req.TunnelId, "api proxy unavailable")
		return
	}
	if !a.acquireTunnel() {
		a.reject(req.TunnelId, "too many tunnels")
		return
	}
	defer a.tunnels.Add(-1)
	srvSide, tunSide := net.Pipe()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second}
	l := &oneConnListener{c: srvSide, done: make(chan struct{})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()
	a.attach(ctx, req.TunnelId, tunSide, false)
}

// oneConnListener serves exactly one connection.
type oneConnListener struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, fmt.Errorf("listener closed")
}

func (l *oneConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "olympos-tunnel" }
