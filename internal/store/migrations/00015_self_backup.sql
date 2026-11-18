-- +goose Up
-- F17: built-in, non-deletable backup job of Olympos' own database
-- (system = 'olympos-self'). It has no target (not reached through an
-- agent); queries that join targets never see it. Runs use backup_runs,
-- so the manifest, tags and retention tiers are the same.
ALTER TABLE backup_jobs ALTER COLUMN target_id DROP NOT NULL;
ALTER TABLE backup_jobs ADD COLUMN system text NOT NULL DEFAULT '' CHECK (system IN ('', 'olympos-self'));
ALTER TABLE backup_jobs ADD CONSTRAINT backup_jobs_target_or_system CHECK ((system = '') = (target_id IS NOT NULL));
ALTER TABLE backup_jobs ADD CONSTRAINT backup_jobs_system_not_deleted CHECK (system = '' OR deleted_at IS NULL);
CREATE UNIQUE INDEX backup_jobs_system ON backup_jobs (system) WHERE system <> '';

-- +goose Down
DROP INDEX backup_jobs_system;
DELETE FROM backup_runs WHERE job_id IN (SELECT id FROM backup_jobs WHERE system <> '');
DELETE FROM backup_jobs WHERE system <> '';
ALTER TABLE backup_jobs DROP CONSTRAINT backup_jobs_system_not_deleted;
ALTER TABLE backup_jobs DROP CONSTRAINT backup_jobs_target_or_system;
ALTER TABLE backup_jobs DROP COLUMN system;
ALTER TABLE backup_jobs ALTER COLUMN target_id SET NOT NULL;
