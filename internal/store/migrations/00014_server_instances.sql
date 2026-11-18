-- +goose Up
-- F5: v0.1 runs as a single server instance. Every instance registers here
-- and heartbeats; a newer instance that sees an older live one (and no
-- experimental.multiReplica) logs an error and reports /readyz not ready.
CREATE TABLE server_instances (
  id           uuid PRIMARY KEY,
  hostname     text NOT NULL,
  version      text NOT NULL DEFAULT '',
  started_at   timestamptz NOT NULL DEFAULT now(),
  heartbeat_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE server_instances;
