package agent

import (
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

const (
	// DefaultOutboxBytes bounds the result-bearing messages the agent keeps
	// for re-sending (F18).
	DefaultOutboxBytes = 16 << 20
	// outboxSettle: a message sent in a session that stayed up this long
	// afterwards reached the server (keepalive detects a dead link in 40 s).
	outboxSettle = 2 * time.Minute
)

// outbox keeps result-bearing messages (kube-bench status and result
// chunks) and re-sends them in order after the next Hello. A successful
// Send only means gRPC buffered the message, so sent messages are kept until
// the session that carried them has lived outboxSettle longer; the server
// drops duplicates by seq. State messages (inventory, reports) are not
// buffered: a fresh snapshot replaces them on reconnect. When full, the
// oldest messages are dropped with a warning; the server sees the gap in seq
// and fails that node instead of storing a partial result.
type outbox struct {
	max int
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	queue   []outboxEntry
	size    int
	session uint64 // current session number (0 = disconnected)
}

type outboxEntry struct {
	m       *pb.AgentMessage
	size    int
	session uint64 // session that sent it (0 = not sent yet)
	sentAt  time.Time
}

func newOutbox(max int, log *slog.Logger) *outbox {
	if max <= 0 {
		max = DefaultOutboxBytes
	}
	return &outbox{max: max, log: log, now: time.Now}
}

// deliver sends m (unless older messages still wait, to keep order) and
// keeps it for re-sending.
func (o *outbox) deliver(m *pb.AgentMessage, send func(*pb.AgentMessage) error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.prune()
	e := outboxEntry{m: m, size: proto.Size(m)}
	if o.session != 0 && o.pendingLocked() == 0 && send(m) == nil {
		e.session, e.sentAt = o.session, o.now()
	}
	o.queue = append(o.queue, e)
	o.size += e.size
	dropped := 0
	for o.size > o.max && len(o.queue) > 1 {
		o.size -= o.queue[0].size
		o.queue = o.queue[1:]
		dropped++
	}
	if dropped > 0 {
		o.log.Warn("outbox full: dropped the oldest buffered results", "dropped", dropped, "max_bytes", o.max)
	}
}

// connected starts session n and re-sends everything not settled, in order.
// It stops at the first error (the session is gone again).
func (o *outbox) connected(n uint64, send func(*pb.AgentMessage) error) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.session = n
	sent := 0
	for i := range o.queue {
		if send(o.queue[i].m) != nil {
			o.session = 0
			break
		}
		o.queue[i].session, o.queue[i].sentAt = n, o.now()
		sent++
	}
	return sent
}

// disconnected marks the end of session n.
func (o *outbox) disconnected(n uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.session == n {
		o.session = 0
	}
}

// prune drops messages that settled in the current session.
func (o *outbox) prune() {
	if o.session == 0 {
		return
	}
	cut := o.now().Add(-outboxSettle)
	keep := o.queue[:0]
	for _, e := range o.queue {
		if e.session == o.session && e.sentAt.Before(cut) {
			o.size -= e.size
			continue
		}
		keep = append(keep, e)
	}
	o.queue = keep
}

func (o *outbox) pendingLocked() int {
	n := 0
	for _, e := range o.queue {
		if e.session != o.session {
			n++
		}
	}
	return n
}

func (o *outbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.queue)
}
