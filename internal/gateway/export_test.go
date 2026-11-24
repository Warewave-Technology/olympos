package gateway

import (
	"time"

	"github.com/Warewave-Technology/olympos/internal/pki"
)

// SetHelloTimeout shortens the hello bound (tests only).
func SetHelloTimeout(g *Gateway, d time.Duration) { g.helloTimeout = d }

// SetAttachHooks sets functions called after a stream authenticated but
// before its hello (awaitingHello), and after it was registered and its
// identity checked again (attached). Set them before any client connects.
func SetAttachHooks(g *Gateway, awaitingHello, attached func(pki.IdentityRole)) {
	g.testHooks.awaitingHello = awaitingHello
	g.testHooks.attached = attached
}
