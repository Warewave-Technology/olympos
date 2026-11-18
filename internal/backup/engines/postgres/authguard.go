package postgres

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrPlaintextPassword is returned when a target without TLS, in transfer
// mode e2e-tls, asks for a password method that would expose the password
// on the wire (cleartext, MD5, ...). Only SCRAM-SHA-256 is accepted without
// TLS: the password never crosses the connection in that exchange.
var ErrPlaintextPassword = errors.New("postgresql: password not sent")

// authGuard wraps a connection to a target without TLS and checks the
// server's authentication request before the client can answer it. The
// check is on the read side: the client only writes its password after it
// has read the request, and a refused request is never delivered. After
// AuthenticationOk the guard is a plain pass-through.
type authGuard struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte // server bytes not yet parsed (startup phase)
	out  []byte // checked bytes not yet returned to the client
	done bool   // authentication finished: pass-through
	err  error
}

func guardAuth(c net.Conn) *authGuard { return &authGuard{Conn: c} }

// Err is the refusal, if any.
func (g *authGuard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

func (g *authGuard) CloseWrite() error {
	if cw, ok := g.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (g *authGuard) Read(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for {
		if g.err != nil {
			return 0, g.err
		}
		if len(g.out) > 0 {
			n := copy(p, g.out)
			g.out = g.out[n:]
			return n, nil
		}
		if g.done {
			if len(g.buf) > 0 {
				n := copy(p, g.buf)
				g.buf = g.buf[n:]
				return n, nil
			}
			return g.Conn.Read(p)
		}
		tmp := make([]byte, 4096)
		n, err := g.Conn.Read(tmp)
		g.buf = append(g.buf, tmp[:n]...)
		g.scan()
		if err != nil && len(g.out) == 0 && g.err == nil {
			return 0, err
		}
	}
}

// scan moves complete, allowed messages from buf to out. It stops at the
// first incomplete message, a refused one (err) or AuthenticationOk.
func (g *authGuard) scan() {
	for !g.done && g.err == nil {
		if len(g.buf) < 5 {
			return
		}
		typ := g.buf[0]
		size := int(binary.BigEndian.Uint32(g.buf[1:5]))
		if size < 4 || size > 1<<16 {
			g.refuse(fmt.Errorf("%w: unexpected startup message from the target", ErrPlaintextPassword))
			return
		}
		if len(g.buf) < 1+size {
			return
		}
		msg := g.buf[:1+size]
		body := msg[5:]
		switch typ {
		case 'R':
			if len(body) < 4 {
				g.refuse(fmt.Errorf("%w: malformed authentication request", ErrPlaintextPassword))
				return
			}
			switch code := binary.BigEndian.Uint32(body[:4]); code {
			case 0: // AuthenticationOk
				g.done = true
			case 10: // AuthenticationSASL: the mechanism list
				if !hasMechanism(body[4:], "SCRAM-SHA-256") {
					g.refuse(plaintextRefusal("SASL without SCRAM-SHA-256"))
					return
				}
			case 11, 12: // SASLContinue, SASLFinal
			default:
				g.refuse(plaintextRefusal(authName(code)))
				return
			}
		case 'E', 'v', 'N':
			// ErrorResponse, NegotiateProtocolVersion, NoticeResponse.
		default:
			g.refuse(fmt.Errorf("%w: unexpected message %q before authentication", ErrPlaintextPassword, typ))
			return
		}
		g.out = append(g.out, msg...)
		g.buf = g.buf[1+size:]
	}
}

func (g *authGuard) refuse(err error) {
	g.err = err
	g.buf, g.out = nil, nil
	_ = g.Conn.Close()
}

func hasMechanism(list []byte, want string) bool {
	for _, m := range bytes.Split(list, []byte{0}) {
		if string(m) == want {
			return true
		}
	}
	return false
}

func authName(code uint32) string {
	switch code {
	case 2:
		return "Kerberos V5"
	case 3:
		return "a cleartext password"
	case 5:
		return "an MD5 password"
	case 7, 8:
		return "GSSAPI"
	case 9:
		return "SSPI"
	}
	return fmt.Sprintf("authentication method %d", code)
}

func plaintextRefusal(method string) error {
	return fmt.Errorf("%w: this target has no TLS and asked for %s, which would expose the password on the network. "+
		"Without TLS Olympos only logs in with SCRAM-SHA-256. Enable TLS on the target "+
		"(or use scram-sha-256 in pg_hba.conf and reset the password), or set this cluster's transfer mode to compressed "+
		"in Settings › Clusters, which accepts plaintext inside the cluster", ErrPlaintextPassword, method)
}
