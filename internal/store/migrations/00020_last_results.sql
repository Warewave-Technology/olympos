-- +goose Up
-- F10: no empty UI cells. The last pull through a registry entry, the last
-- delivery to a notification channel and the dry-run checklist of a backup
-- run are recorded (the UI shows "Not yet" until they exist).
ALTER TABLE registries ADD COLUMN last_pull_at timestamptz;
ALTER TABLE registries ADD COLUMN last_pull_ok boolean;
ALTER TABLE registries ADD COLUMN last_pull_error text NOT NULL DEFAULT '';
ALTER TABLE notification_channels ADD COLUMN last_delivery_at timestamptz;
ALTER TABLE notification_channels ADD COLUMN last_delivery_ok boolean;
ALTER TABLE notification_channels ADD COLUMN last_delivery_error text NOT NULL DEFAULT '';
ALTER TABLE backup_runs ADD COLUMN steps jsonb NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE backup_runs DROP COLUMN steps;
ALTER TABLE notification_channels DROP COLUMN last_delivery_error;
ALTER TABLE notification_channels DROP COLUMN last_delivery_ok;
ALTER TABLE notification_channels DROP COLUMN last_delivery_at;
ALTER TABLE registries DROP COLUMN last_pull_error;
ALTER TABLE registries DROP COLUMN last_pull_ok;
ALTER TABLE registries DROP COLUMN last_pull_at;
