package agent

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	pb "github.com/Warewave-Technology/olympos/internal/gen/olympos/v1"
)

func chunk(seq uint32, n int) *pb.AgentMessage {
	return &pb.AgentMessage{Msg: &pb.AgentMessage_BenchResult{BenchResult: &pb.BenchResultChunk{RunId: "r", NodeName: "n", Seq: seq, Data: make([]byte, n)}}}
}

type wire struct {
	up   bool
	got  []uint32
	fail error
}

func (w *wire) send(m *pb.AgentMessage) error {
	if !w.up {
		return errors.New("not connected")
	}
	w.got = append(w.got, m.GetBenchResult().GetSeq())
	return nil
}

// F18: results produced while disconnected are re-sent in order after the
// reconnect; results sent just before a disconnect are re-sent too (Send
// does not prove delivery); settled ones are dropped.
func TestOutboxResendsAfterReconnect(t *testing.T) {
	now := time.Now()
	o := newOutbox(1<<20, slog.New(slog.NewTextHandler(io.Discard, nil)))
	o.now = func() time.Time { return now }
	w := &wire{up: true}
	o.connected(1, w.send)
	o.deliver(chunk(1, 10), w.send) // sent, not settled
	w.up = false
	o.disconnected(1)
	o.deliver(chunk(2, 10), w.send) // buffered
	o.deliver(chunk(3, 10), w.send)
	if len(w.got) != 1 || o.len() != 3 {
		t.Fatalf("sent %v, queued %d", w.got, o.len())
	}
	w.up, w.got = true, nil
	if n := o.connected(2, w.send); n != 3 || len(w.got) != 3 || w.got[0] != 1 || w.got[2] != 3 {
		t.Fatalf("re-sent %d: %v", n, w.got)
	}
	// Settled after outboxSettle in the same session: dropped.
	now = now.Add(outboxSettle + time.Second)
	o.deliver(chunk(4, 10), w.send)
	if o.len() != 1 || w.got[len(w.got)-1] != 4 {
		t.Fatalf("after settle: queued %d, sent %v", o.len(), w.got)
	}
}

func TestOutboxBounded(t *testing.T) {
	o := newOutbox(1000, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := &wire{}
	for i := uint32(1); i <= 10; i++ {
		o.deliver(chunk(i, 300), w.send)
	}
	w.up = true
	o.connected(1, w.send)
	if len(w.got) == 0 || len(w.got) > 3 || w.got[len(w.got)-1] != 10 {
		t.Fatalf("kept the newest only: %v", w.got)
	}
}
