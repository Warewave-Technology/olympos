-- +goose Up
-- Backup destinations of kind s3 (AWS S3 and S3-compatible services via
-- endpoint_override) and nfs (a directory below a volume mounted into the
-- server), next to azure_blob (SPEC §10.3, docs/spec-changes.md).
ALTER TABLE destinations
  ADD COLUMN bucket               text NOT NULL DEFAULT '',
  ADD COLUMN region               text NOT NULL DEFAULT '',
  ADD COLUMN path_style           boolean NOT NULL DEFAULT false,
  ADD COLUMN access_key_id        text NOT NULL DEFAULT '',
  ADD COLUMN secret_credential_id uuid REFERENCES credentials(id),
  ADD COLUMN path                 text NOT NULL DEFAULT '';

ALTER TABLE destinations DROP CONSTRAINT IF EXISTS destinations_kind_check;
ALTER TABLE destinations DROP CONSTRAINT IF EXISTS destinations_auth_check;
ALTER TABLE destinations DROP CONSTRAINT IF EXISTS destinations_check;

ALTER TABLE destinations
  ADD CONSTRAINT destinations_kind_check CHECK (kind IN ('azure_blob','s3','nfs')),
  ADD CONSTRAINT destinations_auth_check CHECK (auth IN ('managed_identity','sas_token','access_key','none')),
  ADD CONSTRAINT destinations_azure_blob_check CHECK (kind <> 'azure_blob' OR (
    account <> '' AND container <> '' AND auth IN ('managed_identity','sas_token')
    AND (auth = 'sas_token') = (sas_credential_id IS NOT NULL)
    AND secret_credential_id IS NULL AND bucket = '' AND path = '')),
  ADD CONSTRAINT destinations_s3_check CHECK (kind <> 's3' OR (
    bucket <> '' AND auth = 'access_key' AND access_key_id <> '' AND secret_credential_id IS NOT NULL
    AND sas_credential_id IS NULL AND path = '')),
  ADD CONSTRAINT destinations_nfs_check CHECK (kind <> 'nfs' OR (
    path <> '' AND auth = 'none' AND sas_credential_id IS NULL AND secret_credential_id IS NULL
    AND bucket = '' AND access_key_id = ''));

-- +goose Down
DELETE FROM destinations WHERE kind <> 'azure_blob';
ALTER TABLE destinations DROP CONSTRAINT destinations_nfs_check;
ALTER TABLE destinations DROP CONSTRAINT destinations_s3_check;
ALTER TABLE destinations DROP CONSTRAINT destinations_azure_blob_check;
ALTER TABLE destinations DROP CONSTRAINT destinations_auth_check;
ALTER TABLE destinations DROP CONSTRAINT destinations_kind_check;
ALTER TABLE destinations
  ADD CONSTRAINT destinations_kind_check CHECK (kind IN ('azure_blob')),
  ADD CONSTRAINT destinations_auth_check CHECK (auth IN ('managed_identity','sas_token')),
  ADD CONSTRAINT destinations_check CHECK ((auth = 'sas_token') = (sas_credential_id IS NOT NULL));
ALTER TABLE destinations
  DROP COLUMN path,
  DROP COLUMN secret_credential_id,
  DROP COLUMN access_key_id,
  DROP COLUMN path_style,
  DROP COLUMN region,
  DROP COLUMN bucket;
