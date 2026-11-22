-- +goose Up
-- Destination groups: a backup job (or the self-backup) can write one dump to
-- several destinations (docs/design/destination-groups.md). A job targets
-- either one destination or one group. Every run records one result per
-- destination in backup_run_copies, and a run that wrote some but not all of
-- its copies ends 'partial'; repair runs complete the missing copies.

CREATE TABLE destination_groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER destination_groups_touch BEFORE UPDATE ON destination_groups
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- Member count (2 to 4) is enforced by the API. position orders the members
-- and picks the default restore copy.
CREATE TABLE destination_group_members (
  group_id       uuid NOT NULL REFERENCES destination_groups(id) ON DELETE CASCADE,
  destination_id uuid NOT NULL REFERENCES destinations(id),
  position       int NOT NULL,
  PRIMARY KEY (group_id, destination_id)
);
CREATE INDEX destination_group_members_destination ON destination_group_members (destination_id);

ALTER TABLE backup_jobs ALTER COLUMN destination_id DROP NOT NULL;
ALTER TABLE backup_jobs ADD COLUMN destination_group_id uuid REFERENCES destination_groups(id);
ALTER TABLE backup_jobs ADD CONSTRAINT backup_jobs_one_destination
  CHECK (num_nonnulls(destination_id, destination_group_id) = 1);

ALTER TABLE backup_runs DROP CONSTRAINT backup_runs_status_check;
ALTER TABLE backup_runs ADD CONSTRAINT backup_runs_status_check
  CHECK (status IN ('queued','running','succeeded','failed','missed','partial'));
-- repair_of always points at the original run, never at a previous repair.
ALTER TABLE backup_runs ADD COLUMN repair_of uuid REFERENCES backup_runs(id);
-- The destinations the run set out to write, fixed when it is queued
-- (repairs) or starts (all others).
ALTER TABLE backup_runs ADD COLUMN destination_ids uuid[];
-- A queued run is not claimed before not_before (NULL = now): repairs wait
-- 5 minutes, 30 minutes, then 2 hours after the run before them.
ALTER TABLE backup_runs ADD COLUMN not_before timestamptz;
CREATE INDEX backup_runs_repair_of ON backup_runs (repair_of) WHERE repair_of IS NOT NULL;

CREATE TABLE backup_run_copies (
  run_id         uuid NOT NULL REFERENCES backup_runs(id),
  destination_id uuid NOT NULL REFERENCES destinations(id),
  status         text NOT NULL CHECK (status IN ('succeeded','failed')),
  blob_path      text NOT NULL DEFAULT '',
  bytes          bigint NOT NULL DEFAULT 0,
  sha256         text NOT NULL DEFAULT '',
  tier           text NOT NULL DEFAULT '',
  error          text NOT NULL DEFAULT '',
  started_at     timestamptz,
  finished_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, destination_id)
);
CREATE INDEX backup_run_copies_destination ON backup_run_copies (destination_id, finished_at DESC);

-- Copies are written once, when the run finishes.
-- +goose StatementBegin
CREATE FUNCTION olympos_backup_run_copies_freeze() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'backup_run_copies rows are append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER olympos_backup_run_copies_freeze BEFORE UPDATE OR DELETE ON backup_run_copies
  FOR EACH ROW EXECUTE FUNCTION olympos_backup_run_copies_freeze();

-- backup.partial (new event) goes wherever backup.failed goes today: routes
-- are explicit rows with no default, so without this an install that routes
-- by event type would never hear of a partial run.
INSERT INTO notification_routes (event_type, channel_id)
  SELECT 'backup.partial', channel_id FROM notification_routes WHERE event_type = 'backup.failed'
  ON CONFLICT (event_type, channel_id) DO NOTHING;

-- +goose Down
-- Production never migrates down. Refuse rather than lose data that the old
-- schema cannot represent.
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM backup_runs WHERE status = 'partial') THEN
    RAISE EXCEPTION 'cannot migrate down: partial backup runs exist';
  END IF;
  IF EXISTS (SELECT 1 FROM backup_jobs WHERE destination_group_id IS NOT NULL) THEN
    RAISE EXCEPTION 'cannot migrate down: backup jobs target a destination group';
  END IF;
END
$$;
-- +goose StatementEnd
-- The old schema knows no backup.partial event.
DELETE FROM notification_routes WHERE event_type = 'backup.partial';
DROP TRIGGER olympos_backup_run_copies_freeze ON backup_run_copies;
DROP FUNCTION olympos_backup_run_copies_freeze();
DROP TABLE backup_run_copies;
DROP INDEX backup_runs_repair_of;
ALTER TABLE backup_runs DROP COLUMN not_before;
ALTER TABLE backup_runs DROP COLUMN destination_ids;
ALTER TABLE backup_runs DROP COLUMN repair_of;
ALTER TABLE backup_runs DROP CONSTRAINT backup_runs_status_check;
ALTER TABLE backup_runs ADD CONSTRAINT backup_runs_status_check
  CHECK (status IN ('queued','running','succeeded','failed','missed'));
ALTER TABLE backup_jobs DROP CONSTRAINT backup_jobs_one_destination;
ALTER TABLE backup_jobs DROP COLUMN destination_group_id;
ALTER TABLE backup_jobs ALTER COLUMN destination_id SET NOT NULL;
DROP TABLE destination_group_members;
DROP TABLE destination_groups;
