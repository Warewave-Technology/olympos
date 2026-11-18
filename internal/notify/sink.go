package notify

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Channel is a configured notification channel (notification_channels row).
type Channel struct {
	ID             uuid.UUID `json:"id"`
	Kind           string    `json:"kind"`
	Name           string    `json:"name"`
	SlackChannelID string    `json:"slack_channel_id"`
}

// Message is what a sink renders. It never carries secret values: payloads
// are written by Emit callers that MUST NOT include them, and sinks scrub
// known secret shapes again before sending.
type Message struct {
	// Key is the outbox idempotency key; sinks attach it to the delivered
	// message so receivers can de-duplicate at-least-once deliveries.
	Key       string
	EventType string
	Title     string
	// Link is absolute (publicURL + path) or empty.
	Link      string
	Fields    map[string]string
	CreatedAt time.Time
	Test      bool
}

// Sink delivers messages for one channel kind (slack today; Teams/email can
// be added by implementing Sink and registering it under the kind).
type Sink interface {
	Send(ctx context.Context, ch Channel, m Message) error
}

// ErrSinkNotConfigured means the sink cannot deliver at all yet (e.g. no
// Slack bot token). The dispatcher keeps such events pending without
// counting an attempt, so nothing is dropped.
var ErrSinkNotConfigured = errors.New("notification sink not configured")
