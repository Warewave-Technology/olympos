-- +goose Up
-- F18: agent reconnect semantics.
-- Runs that fail because the agent disconnected are retried after the
-- reconnect while inside the job's window (attempt <= 3, retry_until), else
-- they end as 'missed'. A scheduled activation may now have several runs
-- (one per attempt).
ALTER TABLE backup_runs ADD COLUMN attempt int NOT NULL DEFAULT 1;
ALTER TABLE backup_runs ADD COLUMN retry_until timestamptz;
DROP INDEX backup_runs_sched;
CREATE UNIQUE INDEX backup_runs_sched ON backup_runs (job_id, scheduled_for, attempt) WHERE scheduled_for IS NOT NULL;

ALTER TABLE audit_runs ADD COLUMN attempt int NOT NULL DEFAULT 1;
ALTER TABLE audit_runs ADD COLUMN retry_until timestamptz;
ALTER TABLE audit_runs DROP CONSTRAINT audit_runs_status_check;
ALTER TABLE audit_runs ADD CONSTRAINT audit_runs_status_check CHECK (status IN ('queued','running','succeeded','failed','missed'));
DROP INDEX audit_runs_sched;
CREATE UNIQUE INDEX audit_runs_sched ON audit_runs (schedule_id, cluster_id, scheduled_for, attempt) WHERE scheduled_for IS NOT NULL;

-- Alert debounce: agent.offline only after a sustained outage, one
-- agent.online after an alert, agent.flapping on repeated disconnects.
ALTER TABLE clusters ADD COLUMN offline_since timestamptz;
ALTER TABLE clusters ADD COLUMN offline_alerted boolean NOT NULL DEFAULT false;
ALTER TABLE clusters ADD COLUMN flapping_alerted_at timestamptz;
CREATE TABLE agent_disconnects (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_disconnects_cluster ON agent_disconnects (cluster_id, at);

-- +goose Down
DROP TABLE agent_disconnects;
ALTER TABLE clusters DROP COLUMN flapping_alerted_at;
ALTER TABLE clusters DROP COLUMN offline_alerted;
ALTER TABLE clusters DROP COLUMN offline_since;
DELETE FROM audit_runs WHERE attempt > 1;
DROP INDEX audit_runs_sched;
CREATE UNIQUE INDEX audit_runs_sched ON audit_runs (schedule_id, cluster_id, scheduled_for) WHERE scheduled_for IS NOT NULL;
UPDATE audit_runs SET status = 'failed' WHERE status = 'missed';
ALTER TABLE audit_runs DROP CONSTRAINT audit_runs_status_check;
ALTER TABLE audit_runs ADD CONSTRAINT audit_runs_status_check CHECK (status IN ('queued','running','succeeded','failed'));
ALTER TABLE audit_runs DROP COLUMN retry_until;
ALTER TABLE audit_runs DROP COLUMN attempt;
DELETE FROM backup_runs WHERE attempt > 1;
DROP INDEX backup_runs_sched;
CREATE UNIQUE INDEX backup_runs_sched ON backup_runs (job_id, scheduled_for) WHERE scheduled_for IS NOT NULL;
ALTER TABLE backup_runs DROP COLUMN retry_until;
ALTER TABLE backup_runs DROP COLUMN attempt;
