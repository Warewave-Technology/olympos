-- +goose Up
-- ClickHouse native backup (issue #62): the number of objects a native run
-- stored, for the run page. NULL for every other run, which is how the run
-- API tells a finished native run from a logical one (method).
ALTER TABLE backup_runs ADD COLUMN objects integer;

-- +goose Down
ALTER TABLE backup_runs DROP COLUMN objects;
