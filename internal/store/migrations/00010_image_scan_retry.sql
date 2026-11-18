-- +goose Up
-- Transient scan failures are retried with backoff; digests that do not
-- exist in their registry (locally built / retagged) are "unavailable".
ALTER TABLE images ADD COLUMN scan_attempts int NOT NULL DEFAULT 0;
ALTER TABLE images ADD COLUMN next_retry_at timestamptz;
ALTER TABLE images DROP CONSTRAINT images_scan_status_check;
ALTER TABLE images ADD CONSTRAINT images_scan_status_check
  CHECK (scan_status IN ('pending','scanning','scanned','missing_credential','unavailable','failed'));
-- Re-evaluate earlier results with the new classification.
UPDATE images SET scan_status = 'pending', scan_error = '' WHERE scan_status IN ('failed','missing_credential');

-- Target status describes backups only: Vault configure used to mark the
-- target configured, hiding it from Backups › Candidates.
UPDATE targets t SET status = 'candidate' WHERE status = 'configured'
  AND NOT EXISTS (SELECT 1 FROM backup_jobs j WHERE j.target_id = t.id AND j.deleted_at IS NULL);

-- Per-job opt-in for backup.succeeded notifications.
ALTER TABLE backup_jobs ADD COLUMN notify_on_success boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE backup_jobs DROP COLUMN notify_on_success;
UPDATE images SET scan_status = 'failed' WHERE scan_status = 'unavailable';
ALTER TABLE images DROP CONSTRAINT images_scan_status_check;
ALTER TABLE images ADD CONSTRAINT images_scan_status_check
  CHECK (scan_status IN ('pending','scanning','scanned','missing_credential','failed'));
ALTER TABLE images DROP COLUMN next_retry_at;
ALTER TABLE images DROP COLUMN scan_attempts;
