-- +goose Up
-- M2 backups: soft delete for jobs (backup_runs reference jobs and are
-- append-only, so job rows are never hard-deleted) and lookup indexes.
ALTER TABLE backup_jobs ADD COLUMN deleted_at timestamptz;
CREATE INDEX backup_jobs_target ON backup_jobs (target_id) WHERE deleted_at IS NULL;
CREATE INDEX backup_runs_job ON backup_runs (job_id, created_at DESC);
CREATE INDEX backup_runs_running ON backup_runs (updated_at) WHERE status = 'running';

-- +goose Down
DROP INDEX IF EXISTS backup_runs_running;
DROP INDEX IF EXISTS backup_runs_job;
DROP INDEX IF EXISTS backup_jobs_target;
ALTER TABLE backup_jobs DROP COLUMN IF EXISTS deleted_at;
