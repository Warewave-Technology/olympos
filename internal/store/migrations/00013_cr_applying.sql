-- +goose Up
-- F4: change requests pass through 'applying' between the approval and the
-- Vault write outcome. Transaction 1 commits 'applying', then Vault is
-- called, then transaction 2 records 'applied' or 'failed'. A request left
-- in 'applying' (commit failed, server killed) is settled by the reconciler
-- from the KV metadata. 'applying' is not terminal: sealed values stay until
-- applied/failed (trigger unchanged).
ALTER TABLE change_requests DROP CONSTRAINT change_requests_status_check;
ALTER TABLE change_requests ADD CONSTRAINT change_requests_status_check
  CHECK (status IN ('pending','approved','applying','applied','rejected','expired','failed','cancelled'));
ALTER TABLE change_requests ADD COLUMN applying_at timestamptz;
-- Machine-readable failure: apply_error, apply_unknown, conflict.
ALTER TABLE change_requests ADD COLUMN failure_code text NOT NULL DEFAULT '';
CREATE INDEX change_requests_applying ON change_requests (applying_at) WHERE status = 'applying';

-- +goose Down
DROP INDEX change_requests_applying;
ALTER TABLE change_requests DROP COLUMN failure_code;
ALTER TABLE change_requests DROP COLUMN applying_at;
UPDATE change_requests SET status = 'failed', failure = 'apply outcome unknown (downgrade)' WHERE status = 'applying';
ALTER TABLE change_requests DROP CONSTRAINT change_requests_status_check;
ALTER TABLE change_requests ADD CONSTRAINT change_requests_status_check
  CHECK (status IN ('pending','approved','applied','rejected','expired','failed','cancelled'));
