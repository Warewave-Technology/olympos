-- +goose Up
-- M3: Vaults + approvals (SPEC §11).

-- Optional PEM bundle used to verify the vault's TLS certificate end-to-end
-- (in addition to the system pool). Not secret.
ALTER TABLE vaults ADD COLUMN ca_bundle text NOT NULL DEFAULT '';
-- KV mounts whose first index has run. The first index of a mount records a
-- baseline (pre-existing versions are not drift).
ALTER TABLE vaults ADD COLUMN indexed_mounts text[] NOT NULL DEFAULT '{}';

-- Drift detection (§11.5): versions <= baseline_version existed before
-- Olympos managed the mount; drift_checked_version is the highest version
-- already evaluated (each unmanaged version is reported once).
ALTER TABLE vault_secret_index ADD COLUMN baseline_version int NOT NULL DEFAULT 0;
ALTER TABLE vault_secret_index ADD COLUMN drift_checked_version int NOT NULL DEFAULT 0;

CREATE INDEX change_requests_pending ON change_requests (expires_at) WHERE status = 'pending';
CREATE INDEX change_requests_vault ON change_requests (vault_id, created_at DESC);
CREATE INDEX change_items_cr ON change_items (cr_id);
CREATE INDEX change_events_cr ON change_events (cr_id, at);

-- Defense in depth for §11.4: whenever a change request reaches a terminal
-- state, the sealed values of its items are dropped, even if application code
-- forgot to.
-- +goose StatementBegin
CREATE FUNCTION olympos_cr_scrub_sealed() RETURNS trigger AS $$
BEGIN
  IF NEW.status IN ('applied','rejected','expired','failed','cancelled') THEN
    UPDATE change_items SET sealed_value = NULL, wrapped_dek = NULL
      WHERE cr_id = NEW.id AND (sealed_value IS NOT NULL OR wrapped_dek IS NOT NULL);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER change_requests_scrub_sealed AFTER UPDATE OF status ON change_requests
  FOR EACH ROW EXECUTE FUNCTION olympos_cr_scrub_sealed();

-- +goose Down
DROP TRIGGER change_requests_scrub_sealed ON change_requests;
DROP FUNCTION olympos_cr_scrub_sealed();
DROP INDEX change_events_cr;
DROP INDEX change_items_cr;
DROP INDEX change_requests_vault;
DROP INDEX change_requests_pending;
ALTER TABLE vault_secret_index DROP COLUMN drift_checked_version;
ALTER TABLE vault_secret_index DROP COLUMN baseline_version;
ALTER TABLE vaults DROP COLUMN indexed_mounts;
ALTER TABLE vaults DROP COLUMN ca_bundle;
