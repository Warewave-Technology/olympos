-- +goose Up
-- Restore from the UI into a new target (docs/design/ui-restore.md). A restore
-- request goes through maker/checker approval like a Vault change request and
-- is then run by the backup worker. source_copy_run_id is the run that wrote
-- the chosen copy: the run itself or one of its repairs. The target's admin
-- login is a credentials row (stored or Key Vault reference) and a Vault token
-- is sealed in sealed_token/wrapped_dek; code deletes the credential row and
-- the trigger below clears the token in every terminal state.

CREATE TABLE restore_requests (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_run_id         uuid NOT NULL REFERENCES backup_runs(id),
  source_destination_id uuid NOT NULL REFERENCES destinations(id),
  source_copy_run_id    uuid NOT NULL REFERENCES backup_runs(id),
  engine                text NOT NULL,
  target_id             text NOT NULL REFERENCES targets(id),
  databases             text[] NOT NULL DEFAULT '{}',
  options               jsonb NOT NULL DEFAULT '{}',
  credential_id         uuid REFERENCES credentials(id) ON DELETE SET NULL,
  sealed_token          bytea,
  wrapped_dek           bytea,
  kek_version           text NOT NULL DEFAULT '',
  maker_principal_id    uuid NOT NULL REFERENCES principals(id),
  justification         text NOT NULL,
  break_glass           boolean NOT NULL DEFAULT false,
  status                text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','running','succeeded','failed','rejected','expired','cancelled')),
  expires_at            timestamptz NOT NULL,
  checker_principal_id  uuid REFERENCES principals(id),
  decided_at            timestamptz,
  decision_comment      text NOT NULL DEFAULT '',
  approved_expires_at   timestamptz,
  started_at            timestamptz,
  finished_at           timestamptz,
  progress              jsonb NOT NULL DEFAULT '{}',
  result                jsonb NOT NULL DEFAULT '{}',
  error                 text NOT NULL DEFAULT '',
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CHECK (checker_principal_id IS NULL OR checker_principal_id <> maker_principal_id)
);
CREATE TRIGGER restore_requests_touch BEFORE UPDATE ON restore_requests
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();
CREATE INDEX restore_requests_status ON restore_requests (status, created_at);
-- One restore at a time per target.
CREATE UNIQUE INDEX restore_requests_target_active ON restore_requests (target_id)
  WHERE status IN ('approved','running');

-- Defence in depth: whatever code does, a request in a terminal state holds no
-- sealed token. BEFORE, so the clearing is part of the same row write, and on
-- every write so that a terminal row cannot be given a token again.
-- +goose StatementBegin
CREATE FUNCTION olympos_restore_scrub() RETURNS trigger AS $$
BEGIN
  IF NEW.status IN ('succeeded','failed','rejected','expired','cancelled') THEN
    NEW.sealed_token := NULL;
    NEW.wrapped_dek := NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER restore_requests_scrub BEFORE INSERT OR UPDATE ON restore_requests
  FOR EACH ROW EXECUTE FUNCTION olympos_restore_scrub();

-- restore.failed and restore.break_glass (new events, not opt-in) go
-- wherever backup.failed goes today, as backup.partial did in 00022: routes
-- are explicit rows with no default, and the dispatcher drops an event with
-- no route. backup.failed is the channel an install watches for what went
-- wrong with its data; a break-glass restore is critical in the same way
-- (cr.opened is the approval queue, and an install without Vault change
-- requests has no route for it). The other restore events are left to the
-- operator.
INSERT INTO notification_routes (event_type, channel_id)
  SELECT e.event_type, r.channel_id FROM notification_routes r
  CROSS JOIN (VALUES ('restore.failed'), ('restore.break_glass')) AS e(event_type)
  WHERE r.event_type = 'backup.failed'
  ON CONFLICT (event_type, channel_id) DO NOTHING;

-- +goose Down
-- The old schema knows no restore events.
DELETE FROM notification_routes WHERE event_type LIKE 'restore.%';
DROP TRIGGER restore_requests_scrub ON restore_requests;
DROP FUNCTION olympos_restore_scrub();
DROP TABLE restore_requests;
