// Package probe is olympos-probe's run engine: it runs a scenario's steps
// (DNS, HTTP, TCP, TLS) from inside the cluster and reports a RunResult
// (docs/design/synthetic-monitoring.md §3, §6.1, §6.2).
//
// Every connection goes through Dialer, which enforces the host allowlist:
// the host must normalize and match the allowlist snapshot of the run; it
// is resolved once, as an absolute name, by a DNS-only resolver; every
// answer is checked against the always-denied addresses; and only the
// checked addresses are dialed, never the name, so a second resolution
// (DNS rebinding) cannot happen.
//
// Credentials are attached only to requests whose host matches the
// credential's bound hosts. Nothing leaves the probe before it is
// redacted: response excerpts and assertion values go through
// sensitive.Redactor and then have the run's credential values and
// extracted values scrubbed as literals.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Warewave-Technology/olympos/internal/synthetic/hostallow"
)

// Error codes. A failed run's RunResult.failure_reason starts with one of
// them, followed by ": " and a message.
const (
	// CodeHostNotAllowed: the host is not a valid name, is always denied
	// (IP literal, localhost, the Kubernetes API names) or does not match
	// the allowlist.
	CodeHostNotAllowed = "host_not_allowed"
	// CodeIPDenied: an answer for the name is an always-denied address.
	CodeIPDenied = "ip_denied"
	// CodeRedirectBlocked: a redirect went to a host that is not allowed,
	// to another scheme, or past the redirect limit.
	CodeRedirectBlocked = "redirect_blocked"
	// CodeDNSError: the name could not be resolved.
	CodeDNSError = "dns_error"
	// CodeConnectError: the connection failed, or the server's answer
	// could not be read.
	CodeConnectError = "connect_error"
	// CodeTLSError: the TLS handshake failed.
	CodeTLSError = "tls_error"
	// CodeTimeout: the run's deadline passed.
	CodeTimeout = "timeout"
	// CodeAssertionFailed: an assertion did not hold, or an extract found
	// no value.
	CodeAssertionFailed = "assertion_failed"
	// CodeInvalidRequest: the request is not valid once its variables are
	// substituted (a header value with CR, LF or NUL; a URL whose scheme,
	// host or port changed).
	CodeInvalidRequest = "invalid_request"
	// CodeCredentialError: the step's credential is missing or unusable,
	// or its OAuth2 token could not be fetched.
	CodeCredentialError = "credential_error"
)

// Error is a step failure with its code. Its message never holds a
// credential or an extracted value (the runner scrubs it again anyway).
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Resolver looks names up. *DNSResolver is the probe's; tests use fakes.
// host is always an absolute name (with a trailing dot).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer connects to allowlisted hosts only (§6.1).
type Dialer struct {
	// Allow is the allowlist snapshot of the run.
	Allow hostallow.List
	// Resolver resolves names. It must not use a search list or a hosts
	// file (DNSResolver does neither).
	Resolver Resolver
	// APIServer are the Kubernetes API service addresses, always denied.
	APIServer []netip.Addr
	// Net makes the TCP connection to a checked "ip:port". Nil means a
	// net.Dialer.
	Net func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Resolve checks host and returns its addresses: host must pass
// hostallow.Normalize and match the allowlist; the normalized name is then
// looked up once as an absolute name (name + "."), without a search list;
// and when any answer is an always-denied address (hostallow.DeniedIP),
// the whole name fails with ip_denied. The addresses returned are unmapped
// and have no zone.
func (d *Dialer) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	_, addrs, err := d.resolve(ctx, host)
	return addrs, err
}

// checkHost normalizes host and matches it against the allowlist.
func (d *Dialer) checkHost(host string) (string, error) {
	name, err := hostallow.Normalize(host)
	if err != nil {
		switch {
		case errors.Is(err, hostallow.ErrIPLiteral):
			return "", errorf(CodeHostNotAllowed, "IP addresses are not allowed: %q", host)
		case errors.Is(err, hostallow.ErrDeniedName):
			return "", errorf(CodeHostNotAllowed, "%q is always denied", host)
		default:
			return "", errorf(CodeHostNotAllowed, "%q is not a valid host name", host)
		}
	}
	if _, ok := d.Allow.Match(name); !ok {
		return "", errorf(CodeHostNotAllowed, "%s is not on the synthetic monitoring allowlist (version %d)", name, d.Allow.Version)
	}
	return name, nil
}

func (d *Dialer) resolve(ctx context.Context, host string) (string, []netip.Addr, error) {
	name, err := d.checkHost(host)
	if err != nil {
		return "", nil, err
	}
	if d.Resolver == nil {
		return "", nil, errorf(CodeDNSError, "no resolver")
	}
	addrs, err := d.Resolver.LookupNetIP(ctx, "ip", name+".")
	if err != nil {
		if code := ctxCode(ctx, err); code == CodeTimeout {
			return "", nil, errorf(CodeTimeout, "resolving %s", name)
		}
		return "", nil, errorf(CodeDNSError, "resolving %s: %s", name, dnsMessage(err))
	}
	if len(addrs) == 0 {
		return "", nil, errorf(CodeDNSError, "%s has no addresses", name)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if reason, denied := hostallow.DeniedIP(a, d.APIServer); denied {
			return "", nil, errorf(CodeIPDenied, "%s resolves to an address that is always denied (%s)", name, reason)
		}
		out = append(out, a.WithZone("").Unmap())
	}
	return name, out, nil
}

func dnsMessage(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsNotFound {
			return "no such host"
		}
		return de.Err
	}
	return err.Error()
}

// DialContext resolves addr's host with Resolve and connects to the first
// address that answers, by IP. The name is never passed to the network.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return newSession(d).dial(ctx, network, addr)
}

// session is the dialing state of one step attempt. Each name is resolved
// once per session and its checked addresses reused for every connection
// (redirect hops included), so the addresses cannot change between the
// check and the connection, or from one hop to the next.
type session struct {
	d *Dialer

	mu      sync.Mutex
	pins    map[string][]netip.Addr
	dns     time.Duration
	connect time.Duration
	remote  netip.Addr
	local   netip.Addr
}

func newSession(d *Dialer) *session {
	return &session{d: d, pins: map[string][]netip.Addr{}}
}

// resolve is Dialer.resolve with the session's pins.
func (s *session) resolve(ctx context.Context, host string) (string, []netip.Addr, error) {
	name, err := s.d.checkHost(host)
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	addrs, ok := s.pins[name]
	s.mu.Unlock()
	if ok {
		return name, addrs, nil
	}
	start := time.Now()
	name, addrs, err = s.d.resolve(ctx, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dns += time.Since(start)
	if err != nil {
		return "", nil, err
	}
	if pinned, ok := s.pins[name]; ok {
		// Another connection of the session resolved it meanwhile.
		return name, pinned, nil
	}
	s.pins[name] = addrs
	return name, addrs, nil
}

func (s *session) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errorf(CodeConnectError, "network %q is not supported", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errorf(CodeConnectError, "invalid address")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, errorf(CodeConnectError, "invalid port %q", portStr)
	}
	_, addrs, err := s.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dialNet := s.d.Net
	if dialNet == nil {
		var nd net.Dialer
		dialNet = nd.DialContext
	}
	var last error
	for _, ip := range addrs {
		if network == "tcp4" && !ip.Is4() || network == "tcp6" && !ip.Is6() {
			continue
		}
		// Checked again right before the connection: the pins are only
		// ever filled by resolve, but this is the line that must hold.
		if _, denied := hostallow.DeniedIP(ip, s.d.APIServer); denied {
			return nil, errorf(CodeIPDenied, "address is always denied")
		}
		start := time.Now()
		c, err := dialNet(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String())
		s.mu.Lock()
		s.connect += time.Since(start)
		if err == nil {
			s.remote = ip
			if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
				if a, ok := netip.AddrFromSlice(la.IP); ok {
					s.local = a.Unmap()
				}
			}
		}
		s.mu.Unlock()
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		return nil, errorf(CodeConnectError, "no %s address", network)
	}
	if ctxCode(ctx, last) == CodeTimeout {
		return nil, errorf(CodeTimeout, "connecting")
	}
	return nil, errorf(CodeConnectError, "%s", connectMessage(last))
}

// connectMessage is a dial error without the address it names.
func connectMessage(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		var se *os.SyscallError
		if errors.As(oe.Err, &se) {
			return se.Err.Error()
		}
		return oe.Err.Error()
	}
	return err.Error()
}

// ctxCode returns CodeTimeout when err comes from the deadline (of ctx or
// of a connection), and "" otherwise.
func ctxCode(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || ctx.Err() != nil {
		return CodeTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CodeTimeout
	}
	return ""
}

// timings returns the DNS and connect durations so far.
func (s *session) timings() (dns, connect time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dns, s.connect
}

// addrs returns the last remote address dialed and the local address.
func (s *session) addrs() (remote, local netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remote, s.local
}
