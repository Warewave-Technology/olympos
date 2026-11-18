-- +goose Up
-- F3: opt-in Secret inventory (metadata only: names, key names, labels,
-- owners, references). No value is ever stored; there is no column for one.
ALTER TABLE clusters ADD COLUMN secrets_inventory boolean NOT NULL DEFAULT false;
CREATE TABLE k8s_secrets (
  cluster_id         uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace          text NOT NULL,
  name               text NOT NULL,
  type               text NOT NULL DEFAULT '',
  keys               text[] NOT NULL DEFAULT '{}',
  keys_unknown       boolean NOT NULL DEFAULT false,
  labels             jsonb NOT NULL DEFAULT '{}',
  owners             jsonb NOT NULL DEFAULT '[]',
  managed_by         text NOT NULL DEFAULT '',
  referenced_by      text[] NOT NULL DEFAULT '{}',
  created_at         timestamptz,
  first_seen_at      timestamptz NOT NULL DEFAULT now(),
  last_seen_at       timestamptz NOT NULL DEFAULT now(),
  -- last time a workload or ServiceAccount referenced it (secret.unused after 7 days without)
  last_referenced_at timestamptz,
  PRIMARY KEY (cluster_id, namespace, name)
);

-- +goose Down
DROP TABLE k8s_secrets;
ALTER TABLE clusters DROP COLUMN secrets_inventory;
