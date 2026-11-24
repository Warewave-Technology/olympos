package probe

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/Warewave-Technology/olympos/internal/synthetic/spec"
)

// tcpStep connects to host:port through the Dialer and closes the
// connection. A refused or unreachable port is a result (connects =
// false) when the step asserts on connects, and an error otherwise; a
// host that is not allowed is always an error.
func (r *Runner) tcpStep(ctx context.Context, rs *runState, st *spec.Step) *outcome {
	sess := newSession(r.Dialer)
	start := time.Now()
	o := &outcome{}
	c, err := sess.dial(ctx, "tcp", net.JoinHostPort(st.TCP.Host, strconv.Itoa(st.TCP.Port)))
	rs.noteSession(sess, o, start)
	connects := err == nil
	if c != nil {
		_ = c.Close()
	}
	if err != nil {
		e := classify(ctx, err)
		if e.Code != CodeConnectError || !assertsOn(st, spec.SubjectConnects) {
			o.status, o.err = StatusError, e
			return o
		}
	}
	f := &facts{kind: spec.KindTCP, latencyMS: time.Since(start).Milliseconds(), connects: connects, redact: r.Redactor}
	o.assertions, o.actualCut = r.evaluate(st, f)
	o.finish()
	return o
}

// assertsOn reports whether the step has an assertion on subject.
func assertsOn(st *spec.Step, subject string) bool {
	for _, a := range st.Assertions {
		if a.Subject == subject {
			return true
		}
	}
	return false
}
