package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Warewave-Technology/olympos/internal/metrics"
	"github.com/Warewave-Technology/olympos/internal/secrets"
	"github.com/Warewave-Technology/olympos/internal/store"
)

// Dispatcher delivers outbox events (SPEC §14). Every server replica runs
// one: rows are claimed with SELECT … FOR UPDATE SKIP LOCKED inside a
// transaction that stays open while the batch is sent, so two replicas never
// work on the same event. Delivery is at-least-once: a crash between a send
// and the commit resends, and messages carry the idempotency key.
type Dispatcher struct {
	DB    *store.DB
	Sinks map[string]Sink // by channel kind
	// Link turns a payload link path into an absolute URL (Deps.PublicLink).
	Link func(path string) string
	Log  *slog.Logger

	Interval     time.Duration // poll interval, default 5s
	Batch        int           // events per transaction, default 20
	BaseBackoff  time.Duration // first retry delay, default 30s
	MaxBackoff   time.Duration // cap, default 1h
	SendTimeout  time.Duration // per send, default 20s
	PendingDelay time.Duration // recheck delay while a sink is not configured, default 1m
}

func (d *Dispatcher) defaults() {
	if d.Interval == 0 {
		d.Interval = 5 * time.Second
	}
	if d.Batch == 0 {
		d.Batch = 20
	}
	if d.BaseBackoff == 0 {
		d.BaseBackoff = 30 * time.Second
	}
	if d.MaxBackoff == 0 {
		d.MaxBackoff = time.Hour
	}
	if d.SendTimeout == 0 {
		d.SendTimeout = 20 * time.Second
	}
	if d.PendingDelay == 0 {
		d.PendingDelay = time.Minute
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
}

// Backoff returns the delay before retry number attempts (1-based):
// base·2^(attempts-1), capped at MaxBackoff.
func (d *Dispatcher) Backoff(attempts int) time.Duration {
	d.defaults()
	if attempts < 1 {
		attempts = 1
	}
	b := d.BaseBackoff
	for i := 1; i < attempts; i++ {
		b *= 2
		if b >= d.MaxBackoff {
			return d.MaxBackoff
		}
	}
	return min(b, d.MaxBackoff)
}

// Run polls until ctx is done.
func (d *Dispatcher) Run(ctx context.Context) {
	d.defaults()
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		for {
			n, err := d.DispatchOnce(ctx)
			if err != nil {
				if ctx.Err() == nil {
					d.Log.Error("notification dispatch", "err", err)
				}
				break
			}
			if n < d.Batch {
				break // drained
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type outboxRow struct {
	id        uuid.UUID
	eventType string
	payload   map[string]any
	channelID *uuid.UUID
	key       string
	attempts  int
	createdAt time.Time
	delivered []uuid.UUID
}

// DispatchOnce claims and processes up to Batch due events. It returns the
// number of events claimed.
func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	d.defaults()
	tx, err := d.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	rows, err := tx.Query(ctx, `SELECT id, event_type, payload, channel_id, idempotency_key, attempts, created_at, delivered_channels
		FROM outbox WHERE delivered_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at, created_at LIMIT $1 FOR UPDATE SKIP LOCKED`, d.Batch)
	if err != nil {
		return 0, err
	}
	var items []outboxRow
	for rows.Next() {
		var it outboxRow
		var raw []byte
		if err := rows.Scan(&it.id, &it.eventType, &raw, &it.channelID, &it.key, &it.attempts, &it.createdAt, &it.delivered); err != nil {
			rows.Close()
			return 0, err
		}
		_ = json.Unmarshal(raw, &it.payload)
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, it := range items {
		if err := d.process(ctx, tx, it); err != nil {
			return 0, err
		}
	}
	return len(items), tx.Commit(ctx)
}

func (d *Dispatcher) process(ctx context.Context, tx pgx.Tx, it outboxRow) error {
	channels, err := d.resolve(ctx, tx, it)
	if err != nil {
		return err
	}
	if len(channels) == 0 {
		metrics.NotificationDeliveries.WithLabelValues("no_route").Inc()
		d.Log.Debug("notification has no route", "event", it.eventType, "key", it.key)
		_, err := tx.Exec(ctx, `UPDATE outbox SET delivered_at = now(), outcome = 'no_route', last_error = '' WHERE id = $1`, it.id)
		return err
	}

	msg := d.message(it)
	delivered := append([]uuid.UUID{}, it.delivered...) // never nil: column is NOT NULL
	var errs []string
	allUnconfigured := true
	for _, ch := range channels {
		if slices.Contains(delivered, ch.ID) {
			continue
		}
		err := d.send(ctx, ch, msg)
		if err == nil {
			delivered = append(delivered, ch.ID)
			continue
		}
		if !errors.Is(err, ErrSinkNotConfigured) {
			allUnconfigured = false
		}
		errs = append(errs, fmt.Sprintf("%s: %s", ch.Name, err.Error()))
	}
	if len(errs) == 0 {
		metrics.NotificationDeliveries.WithLabelValues("delivered").Inc()
		_, err := tx.Exec(ctx, `UPDATE outbox SET delivered_at = now(), outcome = 'delivered', attempts = attempts + 1,
			delivered_channels = $2, last_error = '' WHERE id = $1`, it.id, delivered)
		return err
	}
	lastErr := sanitizeError(strings.Join(errs, "; "))
	if allUnconfigured {
		// Nothing can be delivered until the sink is configured: keep the
		// event pending without burning attempts or growing the backoff.
		metrics.NotificationDeliveries.WithLabelValues("pending_unconfigured").Inc()
		_, err := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at = now() + make_interval(secs => $2), delivered_channels = $3, last_error = $4
			WHERE id = $1`, it.id, d.PendingDelay.Seconds(), delivered, lastErr)
		return err
	}
	attempts := it.attempts + 1
	delay := d.Backoff(attempts)
	metrics.NotificationDeliveries.WithLabelValues("retry").Inc()
	d.Log.Warn("notification delivery failed; will retry", "event", it.eventType, "key", it.key, "attempts", attempts,
		"retry_in", delay.String(), "err", lastErr)
	_, err = tx.Exec(ctx, `UPDATE outbox SET attempts = $2, next_attempt_at = now() + make_interval(secs => $3), delivered_channels = $4,
		last_error = $5 WHERE id = $1`, it.id, attempts, delay.Seconds(), delivered, lastErr)
	return err
}

func (d *Dispatcher) send(ctx context.Context, ch Channel, m Message) error {
	sink := d.Sinks[ch.Kind]
	if sink == nil {
		return fmt.Errorf("no sink for channel kind %q: %w", ch.Kind, ErrSinkNotConfigured)
	}
	sctx, cancel := context.WithTimeout(ctx, d.SendTimeout)
	defer cancel()
	start := time.Now()
	err := sink.Send(sctx, ch, m)
	status := "ok"
	if err != nil {
		status = "error"
	}
	metrics.NotificationSendDuration.WithLabelValues(ch.Kind, status).Observe(time.Since(start).Seconds())
	return err
}

// resolve returns the channels an event goes to. An explicit channel on the
// event (job/schedule override) replaces routing. Opt-in events
// (backup.succeeded) are only delivered when the event type has at least one
// route, so a job's override channel does not turn them on by itself.
func (d *Dispatcher) resolve(ctx context.Context, q store.Querier, it outboxRow) ([]Channel, error) {
	routed, err := queryChannels(ctx, q, `SELECT c.id, c.kind, c.name, c.slack_channel_id
		FROM notification_routes r JOIN notification_channels c ON c.id = r.channel_id
		WHERE r.event_type = $1 ORDER BY c.name, c.id`, it.eventType)
	if err != nil {
		return nil, err
	}
	if IsOptIn(it.eventType) && len(routed) == 0 {
		return nil, nil
	}
	if it.channelID != nil {
		override, err := queryChannels(ctx, q, `SELECT id, kind, name, slack_channel_id FROM notification_channels WHERE id = $1`, *it.channelID)
		if err != nil {
			return nil, err
		}
		if len(override) > 0 {
			return override, nil
		}
		d.Log.Warn("notification override channel no longer exists; using routes", "event", it.eventType, "channel_id", it.channelID.String())
	}
	return routed, nil
}

func queryChannels(ctx context.Context, q store.Querier, sql string, args ...any) ([]Channel, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.Kind, &c.Name, &c.SlackChannelID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *Dispatcher) message(it outboxRow) Message {
	m := Message{Key: it.key, EventType: it.eventType, CreatedAt: it.createdAt, Fields: map[string]string{}}
	if s, ok := it.payload["title"].(string); ok {
		m.Title = s
	}
	if m.Title == "" {
		m.Title = it.eventType
	}
	if s, ok := it.payload["link"].(string); ok && s != "" {
		m.Link = s
		if d.Link != nil && strings.HasPrefix(s, "/") {
			m.Link = d.Link(s)
		}
	}
	if f, ok := it.payload["fields"].(map[string]any); ok {
		for k, v := range f {
			if s, ok := v.(string); ok {
				m.Fields[k] = s
			}
		}
	}
	return m
}

// sanitizeError scrubs secret shapes and truncates error text stored in
// outbox.last_error.
func sanitizeError(s string) string {
	s = secrets.RedactString(s)
	if len(s) > 1000 {
		s = s[:1000] + "…"
	}
	return s
}
