-- +goose Up
-- ClickHouse native backup (issue #62): every native backup or restore run gets its own credential for the ingest
-- endpoint. The secret lives in the server's memory only, because SigV4 needs
-- the secret itself to check a signature; this table is the audit record of
-- each credential, and it has no column that could hold the secret.

-- access_key is the SigV4 access key ID (OLY plus 17 base32 characters). run_id
-- is the backup run, or the restore request, the credential belongs to. scope
-- is {"write": "<run-id>/", "read": ["<run-id>/", ...]}, prefixes relative to
-- the endpoint's bucket. fingerprint is the hm: HMAC fingerprint of the
-- secret. revoked_at and reason are set when the run ends, and by start-up
-- recovery ('server restart') for credentials a restart left open.
CREATE TABLE ingest_credentials (
  access_key  text PRIMARY KEY,
  run_id      uuid NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('backup','restore')),
  scope       jsonb NOT NULL,
  fingerprint text NOT NULL,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz,
  reason      text
);

-- +goose Down
DROP TABLE ingest_credentials;
