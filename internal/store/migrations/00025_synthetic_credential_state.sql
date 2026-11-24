-- +goose Up
-- Synthetic monitoring, one alert per credential that cannot be resolved
-- (docs/design/credential-alerts.md, issue #54): a credential that cannot be
-- resolved fails every scenario that uses it on every cluster, and one cause
-- should be one alert. The state below says whether the credential resolved at
-- its last use, so that dispatch can alert once per episode and say when it is
-- over.

-- ---------------------------------------------------------------- credentials

-- resolve_state is ok, broken (permanent: the secret is gone, or its reference
-- is wrong) or unavailable (transient: Key Vault did not answer). The other
-- columns describe the current episode and are NULL while the state is ok:
-- the cause, the first failure, and when synthetic.credential_broken went out
-- for it (the one-message mark). Credentials that exist now start as ok; the
-- next run decides.
ALTER TABLE synthetic_credentials
  ADD COLUMN resolve_state text NOT NULL DEFAULT 'ok'
    CHECK (resolve_state IN ('ok','broken','unavailable')),
  ADD COLUMN resolve_cause text,
  ADD COLUMN resolve_failing_since timestamptz,
  ADD COLUMN resolve_alerted_at timestamptz;

-- ---------------------------------------------------------------- routes

-- The two new events go wherever synthetic.credential_expiring goes, as
-- synthetic.allowlist_changed did in 00024: routes are explicit rows with no
-- default, and the dispatcher drops an event with no route. Whoever hears that
-- a credential expires soon wants to hear that one cannot be resolved, and
-- that it can again. The other synthetic events are left to the operator.
INSERT INTO notification_routes (event_type, channel_id)
  SELECT e.event_type, r.channel_id FROM notification_routes r
  CROSS JOIN (VALUES ('synthetic.credential_broken'), ('synthetic.credential_restored')) AS e(event_type)
  WHERE r.event_type = 'synthetic.credential_expiring'
  ON CONFLICT (event_type, channel_id) DO NOTHING;

-- +goose Down
-- The old schema knows neither event. Only those events' routes go: 00025
-- made no others. The state is derived (the next run sets it again), so
-- dropping it loses nothing.
DELETE FROM notification_routes WHERE event_type IN ('synthetic.credential_broken', 'synthetic.credential_restored');

ALTER TABLE synthetic_credentials
  DROP COLUMN resolve_alerted_at,
  DROP COLUMN resolve_failing_since,
  DROP COLUMN resolve_cause,
  DROP COLUMN resolve_state;
