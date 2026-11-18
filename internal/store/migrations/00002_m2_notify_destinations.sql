-- M2: notification dispatcher bookkeeping.
-- +goose Up

-- outcome records how a delivered event ended: 'delivered' (sent to every
-- resolved channel) or 'no_route' (no channel configured; marked delivered so
-- the backlog does not grow). delivered_channels tracks per-channel progress
-- so a retry after a partial failure does not resend to channels that already
-- got the message.
ALTER TABLE outbox ADD COLUMN outcome text NOT NULL DEFAULT ''
  CHECK (outcome IN ('', 'delivered', 'no_route'));
ALTER TABLE outbox ADD COLUMN delivered_channels uuid[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE outbox DROP COLUMN delivered_channels;
ALTER TABLE outbox DROP COLUMN outcome;
