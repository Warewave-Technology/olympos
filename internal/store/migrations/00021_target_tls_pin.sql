-- +goose Up
-- Security review v0.1 #1: the TLS name a target is verified against comes
-- from a Service annotation anyone who can edit the Service controls. It is
-- pinned when the target is first seen; a later change waits in
-- tls_server_name_pending until an admin accepts it (NULL: no change).
ALTER TABLE targets ADD COLUMN tls_server_name_pending text;
ALTER TABLE targets ADD COLUMN tls_server_name_changed_at timestamptz;

-- +goose Down
ALTER TABLE targets DROP COLUMN tls_server_name_changed_at;
ALTER TABLE targets DROP COLUMN tls_server_name_pending;
