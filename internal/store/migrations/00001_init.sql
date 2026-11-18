-- +goose Up
-- Olympos schema v1 (SPEC §8). Append-only tables are protected by triggers
-- in addition to role grants, so a bug in the app cannot rewrite history.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- +goose StatementBegin
CREATE FUNCTION olympos_touch_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION olympos_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ---------------------------------------------------------------- identity

CREATE TABLE principals (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             text NOT NULL,
  object_id             text NOT NULL,
  upn_snapshot          text NOT NULL DEFAULT '',
  display_name_snapshot text NOT NULL DEFAULT '',
  user_type             text NOT NULL DEFAULT 'Member',
  account_enabled       boolean NOT NULL DEFAULT true,
  deleted               boolean NOT NULL DEFAULT false,
  synced_at             timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, object_id)
);

CREATE TABLE grants (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id   uuid NOT NULL REFERENCES principals(id),
  role           text NOT NULL CHECK (role IN ('viewer','operator','vault-maker','vault-approver','admin')),
  scope_selector text NOT NULL DEFAULT 'all',
  granted_by     uuid REFERENCES principals(id),
  granted_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  revoked_by     uuid REFERENCES principals(id),
  stale          boolean NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX grants_active ON grants (principal_id) WHERE revoked_at IS NULL;

CREATE TABLE sessions (
  id           text PRIMARY KEY,           -- sha256 of the cookie value
  principal_id uuid NOT NULL REFERENCES principals(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  csrf_token   text NOT NULL
);

-- Short-lived OIDC login state (state, nonce, PKCE verifier).
CREATE TABLE login_states (
  state         text PRIMARY KEY,
  nonce         text NOT NULL,
  code_verifier text NOT NULL,
  return_to     text NOT NULL DEFAULT '/',
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- pki

CREATE TABLE pki_ca (
  id             int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  cert_der       bytea NOT NULL,
  key_ciphertext bytea NOT NULL,
  wrapped_dek    bytea NOT NULL,
  kek_version    text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE revoked_certs (
  serial     text PRIMARY KEY,
  cluster_id uuid,
  revoked_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- clusters

CREATE TABLE clusters (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name               text NOT NULL UNIQUE,
  labels             jsonb NOT NULL DEFAULT '{}',
  provider           text NOT NULL DEFAULT '',
  provider_override  text NOT NULL DEFAULT '',
  region             text NOT NULL DEFAULT '',
  api_version        text NOT NULL DEFAULT '',
  status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','online','offline','revoked')),
  last_seen_at       timestamptz,
  agent_version      text NOT NULL DEFAULT '',
  bench_enabled      boolean NOT NULL DEFAULT false,
  bench_max_parallel int NOT NULL DEFAULT 0,
  cert_serial        text NOT NULL DEFAULT '',
  cert_expires_at    timestamptz,
  transfer_mode      text NOT NULL DEFAULT 'e2e-tls' CHECK (transfer_mode IN ('e2e-tls','compressed')),
  egress_rate_per_gb numeric,
  inventory_at       timestamptz,
  created_by         uuid REFERENCES principals(id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enroll_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
  cluster_id      uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  name            text NOT NULL,
  provider_id     text NOT NULL DEFAULT '',
  kubelet_version text NOT NULL DEFAULT '',
  region          text NOT NULL DEFAULT '',
  zone            text NOT NULL DEFAULT '',
  instance_type   text NOT NULL DEFAULT '',
  cpu_capacity    bigint NOT NULL DEFAULT 0,  -- millicores
  mem_capacity    bigint NOT NULL DEFAULT 0,  -- bytes
  cpu_allocatable bigint NOT NULL DEFAULT 0,
  mem_allocatable bigint NOT NULL DEFAULT 0,
  roles           text[] NOT NULL DEFAULT '{}',
  ready           boolean NOT NULL DEFAULT false,
  seen_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, name)
);

CREATE TABLE namespaces (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  name       text NOT NULL,
  seen_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, name)
);

-- ---------------------------------------------------------------- targets

CREATE TABLE targets (
  id               text PRIMARY KEY,
  cluster_id       uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace        text NOT NULL,
  service          text NOT NULL,
  port             int NOT NULL,
  port_name        text NOT NULL DEFAULT '',
  engine           text NOT NULL DEFAULT '' CHECK (engine IN ('','postgresql','clickhouse','vault','openbao')),
  vault_provider   text NOT NULL DEFAULT '' CHECK (vault_provider IN ('','hashicorp','openbao')),
  tls_server_name  text NOT NULL DEFAULT '',
  detected_version text NOT NULL DEFAULT '',
  tls_ok           boolean,
  status           text NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate','configured','gone')),
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX targets_cluster ON targets (cluster_id);

-- ---------------------------------------------------------------- credentials

CREATE TABLE credentials (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          text NOT NULL CHECK (kind IN ('stored','keyvault_ref')),
  keyvault_name text NOT NULL DEFAULT '',
  secret_name   text NOT NULL DEFAULT '',
  ciphertext    bytea,
  wrapped_dek   bytea,
  kek_version   text NOT NULL DEFAULT '',
  username      text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'stored' AND ciphertext IS NOT NULL AND wrapped_dek IS NOT NULL)
      OR (kind = 'keyvault_ref' AND keyvault_name <> '' AND secret_name <> ''))
);

-- ---------------------------------------------------------------- notifications

CREATE TABLE notification_channels (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind             text NOT NULL DEFAULT 'slack' CHECK (kind IN ('slack')),
  slack_channel_id text NOT NULL,
  name             text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_routes (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type text NOT NULL,
  channel_id uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (event_type, channel_id)
);

CREATE TABLE outbox (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type      text NOT NULL,
  payload         jsonb NOT NULL,
  channel_id      uuid,                   -- optional per-object override
  idempotency_key text NOT NULL UNIQUE,
  created_at      timestamptz NOT NULL DEFAULT now(),
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  delivered_at    timestamptz,
  last_error      text NOT NULL DEFAULT ''
);
CREATE INDEX outbox_pending ON outbox (next_attempt_at) WHERE delivered_at IS NULL;

-- ---------------------------------------------------------------- backups

CREATE TABLE destinations (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name              text NOT NULL UNIQUE,
  kind              text NOT NULL DEFAULT 'azure_blob' CHECK (kind IN ('azure_blob')),
  account           text NOT NULL,
  container         text NOT NULL,
  prefix            text NOT NULL DEFAULT '',
  auth              text NOT NULL CHECK (auth IN ('managed_identity','sas_token')),
  sas_credential_id uuid REFERENCES credentials(id),
  sas_expires_at    timestamptz,
  sas_permissions   text NOT NULL DEFAULT '',
  endpoint_override text NOT NULL DEFAULT '',  -- Azurite / sovereign clouds
  last_test_at      timestamptz,
  last_test_ok      boolean,
  last_test_report  jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CHECK ((auth = 'sas_token') = (sas_credential_id IS NOT NULL))
);

CREATE TABLE backup_jobs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id         text NOT NULL REFERENCES targets(id),
  credential_id     uuid REFERENCES credentials(id),
  destination_id    uuid NOT NULL REFERENCES destinations(id),
  engine_options    jsonb NOT NULL DEFAULT '{}',
  cron              text NOT NULL,
  timezone          text NOT NULL DEFAULT 'UTC',
  retention         jsonb NOT NULL DEFAULT '{"daily":7,"weekly":4,"monthly":12}',
  enabled           boolean NOT NULL DEFAULT false,
  paused_reason     text NOT NULL DEFAULT '',
  notify_channel_id uuid REFERENCES notification_channels(id),
  last_scheduled_for timestamptz,
  created_by        uuid REFERENCES principals(id),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE backup_runs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id        uuid NOT NULL REFERENCES backup_jobs(id),
  trigger       text NOT NULL CHECK (trigger IN ('schedule','manual','test')),
  status        text NOT NULL CHECK (status IN ('queued','running','succeeded','failed','missed')),
  scheduled_for timestamptz,
  tier          text NOT NULL DEFAULT '',
  started_at    timestamptz,
  finished_at   timestamptz,
  bytes         bigint NOT NULL DEFAULT 0,
  wire_bytes    bigint NOT NULL DEFAULT 0,
  blob_path     text NOT NULL DEFAULT '',
  sha256        text NOT NULL DEFAULT '',
  error         text NOT NULL DEFAULT '',
  triggered_by  uuid REFERENCES principals(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX backup_runs_sched ON backup_runs (job_id, scheduled_for) WHERE scheduled_for IS NOT NULL;
CREATE INDEX backup_runs_queued ON backup_runs (created_at) WHERE status = 'queued';

-- +goose StatementBegin
CREATE FUNCTION olympos_backup_runs_freeze() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'backup_runs rows cannot be deleted' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.finished_at IS NOT NULL THEN
    RAISE EXCEPTION 'backup_runs row % is finished and append-only', OLD.id USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER backup_runs_freeze BEFORE UPDATE OR DELETE ON backup_runs
  FOR EACH ROW EXECUTE FUNCTION olympos_backup_runs_freeze();

-- ---------------------------------------------------------------- vaults

CREATE TABLE vaults (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id     text NOT NULL UNIQUE REFERENCES targets(id),
  provider      text NOT NULL CHECK (provider IN ('hashicorp','openbao')),
  version       text NOT NULL DEFAULT '',
  kv_mounts     jsonb NOT NULL DEFAULT '[]',
  auth_method   text NOT NULL DEFAULT 'approle' CHECK (auth_method IN ('approle')),
  role_id       text NOT NULL DEFAULT '',
  secret_id_ref text NOT NULL DEFAULT '',  -- kv://<vault>/<secret>
  secret_id_accessor text NOT NULL DEFAULT '',
  secret_id_rotated_at timestamptz,
  configured_by uuid REFERENCES principals(id),
  configured_at timestamptz,
  status        text NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered','configured','error','gone')),
  last_index_at timestamptz,
  last_error    text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vault_secret_index (
  vault_id        uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  mount           text NOT NULL,
  path            text NOT NULL,
  keys            text[] NOT NULL DEFAULT '{}',
  current_version int NOT NULL DEFAULT 0,
  versions        jsonb NOT NULL DEFAULT '[]',
  updated_time    timestamptz,
  managed         boolean NOT NULL DEFAULT true,
  PRIMARY KEY (vault_id, mount, path)
);

-- Versions written by Olympos (applied change requests). Used for drift detection.
CREATE TABLE vault_managed_versions (
  vault_id   uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  mount      text NOT NULL,
  path       text NOT NULL,
  version    int NOT NULL,
  cr_id      uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (vault_id, mount, path, version)
);

CREATE TABLE change_requests (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id             uuid NOT NULL REFERENCES vaults(id),
  maker_principal_id   uuid NOT NULL REFERENCES principals(id),
  justification        text NOT NULL,
  status               text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','approved','applied','rejected','expired','failed','cancelled')),
  expires_at           timestamptz NOT NULL,
  checker_principal_id uuid REFERENCES principals(id),
  decided_at           timestamptz,
  decision_comment     text NOT NULL DEFAULT '',
  applied_at           timestamptz,
  failure              text NOT NULL DEFAULT '',
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CHECK (checker_principal_id IS NULL OR checker_principal_id <> maker_principal_id)
);

CREATE TABLE change_items (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cr_id            uuid NOT NULL REFERENCES change_requests(id),
  mount            text NOT NULL,
  path             text NOT NULL,
  key              text,
  op               text NOT NULL CHECK (op IN ('create','replace','delete','destroy_history')),
  base_version     int NOT NULL DEFAULT 0,
  versions         int[] NOT NULL DEFAULT '{}',   -- destroy_history only
  sealed_value     bytea,
  wrapped_dek      bytea,
  kek_version      text NOT NULL DEFAULT '',
  hmac_fingerprint text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE change_events (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cr_id              uuid NOT NULL REFERENCES change_requests(id),
  at                 timestamptz NOT NULL DEFAULT now(),
  actor_principal_id uuid REFERENCES principals(id),
  kind               text NOT NULL,
  details            jsonb NOT NULL DEFAULT '{}'
);
CREATE TRIGGER change_events_append_only BEFORE UPDATE OR DELETE ON change_events
  FOR EACH ROW EXECUTE FUNCTION olympos_append_only();

-- ---------------------------------------------------------------- audit

CREATE TABLE audit_schedules (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tool              text NOT NULL CHECK (tool IN ('kubescape','polaris','kube-bench')),
  frameworks        text[] NOT NULL DEFAULT '{}',
  scope_selector    text NOT NULL DEFAULT 'all',
  cron              text NOT NULL,
  timezone          text NOT NULL DEFAULT 'UTC',
  enabled           boolean NOT NULL DEFAULT true,
  notify_channel_id uuid REFERENCES notification_channels(id),
  last_scheduled_for timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_runs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  schedule_id   uuid REFERENCES audit_schedules(id),
  tool          text NOT NULL,
  cluster_id    uuid NOT NULL REFERENCES clusters(id),
  status        text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  scheduled_for timestamptz,
  started_at    timestamptz,
  finished_at   timestamptz,
  score         numeric,
  new_findings  int NOT NULL DEFAULT 0,
  resolved_findings int NOT NULL DEFAULT 0,
  raw_blob_path text NOT NULL DEFAULT '',
  error         text NOT NULL DEFAULT '',
  details       jsonb NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX audit_runs_sched ON audit_runs (schedule_id, cluster_id, scheduled_for) WHERE scheduled_for IS NOT NULL;

CREATE TABLE bench_node_results (
  run_id     uuid NOT NULL REFERENCES audit_runs(id),
  node_name  text NOT NULL,
  benchmark  text NOT NULL,
  state      text NOT NULL,
  pass       int NOT NULL DEFAULT 0,
  fail       int NOT NULL DEFAULT 0,
  warn       int NOT NULL DEFAULT 0,
  info       int NOT NULL DEFAULT 0,
  control_plane_na boolean NOT NULL DEFAULT false,
  message    text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, node_name)
);

CREATE TABLE findings (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source            text NOT NULL CHECK (source IN ('kubescape','polaris','kube-bench','kyverno','netpol','tls','vault-drift','transfer')),
  cluster_id        uuid NOT NULL REFERENCES clusters(id),
  control_id        text NOT NULL,
  severity          text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  resource_ref      text NOT NULL DEFAULT '',
  title             text NOT NULL,
  details           jsonb NOT NULL DEFAULT '{}',
  first_seen_run_id uuid,
  last_seen_run_id  uuid,
  resolved_run_id   uuid,
  first_seen_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at      timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX findings_open_key ON findings (source, cluster_id, control_id, resource_ref) WHERE status = 'open';

-- ---------------------------------------------------------------- security

CREATE TABLE images (
  digest          text PRIMARY KEY,
  repo            text NOT NULL,
  tags            text[] NOT NULL DEFAULT '{}',
  last_scanned_at timestamptz,
  critical        int NOT NULL DEFAULT 0,
  high            int NOT NULL DEFAULT 0,
  medium          int NOT NULL DEFAULT 0,
  low             int NOT NULL DEFAULT 0,
  scan_status     text NOT NULL DEFAULT 'pending'
                  CHECK (scan_status IN ('pending','scanning','scanned','missing_credential','failed')),
  scan_error      text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE image_usage (
  digest        text NOT NULL REFERENCES images(digest),
  cluster_id    uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace     text NOT NULL,
  workload_kind text NOT NULL,
  workload_name text NOT NULL,
  container     text NOT NULL,
  image         text NOT NULL DEFAULT '',
  seen_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (digest, cluster_id, namespace, workload_kind, workload_name, container)
);

CREATE TABLE image_vulns (
  digest     text NOT NULL REFERENCES images(digest),
  cve_id     text NOT NULL,
  severity   text NOT NULL,
  package    text NOT NULL,
  installed  text NOT NULL DEFAULT '',
  fixed_in   text NOT NULL DEFAULT '',
  title      text NOT NULL DEFAULT '',
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (digest, cve_id, package)
);

CREATE TABLE registries (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  host_pattern  text NOT NULL UNIQUE,
  credential_id uuid REFERENCES credentials(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kyverno_policies (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace  text NOT NULL DEFAULT '',
  name       text NOT NULL,
  mode       text NOT NULL,
  rules      text[] NOT NULL DEFAULT '{}',
  ready      boolean NOT NULL DEFAULT true,
  fail_count int NOT NULL DEFAULT 0,
  seen_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, namespace, name)
);

CREATE TABLE network_policy_status (
  cluster_id   uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace    text NOT NULL,
  policy_count int NOT NULL DEFAULT 0,
  default_deny boolean NOT NULL DEFAULT false,
  excluded     boolean NOT NULL DEFAULT false,
  seen_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, namespace)
);

-- ---------------------------------------------------------------- activity

CREATE TABLE activity_log (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  at                 timestamptz NOT NULL DEFAULT now(),
  actor_principal_id uuid REFERENCES principals(id),
  actor_kind         text NOT NULL DEFAULT 'user' CHECK (actor_kind IN ('user','system','agent')),
  action             text NOT NULL,
  object_type        text NOT NULL,
  object_id          text NOT NULL DEFAULT '',
  cluster_id         uuid,
  details            jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX activity_log_at ON activity_log (at DESC);
CREATE TRIGGER activity_log_append_only BEFORE UPDATE OR DELETE ON activity_log
  FOR EACH ROW EXECUTE FUNCTION olympos_append_only();

-- ---------------------------------------------------------------- settings

CREATE TABLE settings (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- updated_at triggers
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['principals','grants','clusters','enroll_tokens','targets','credentials',
    'notification_channels','notification_routes','destinations','backup_jobs','vaults',
    'change_requests','change_items','audit_schedules','audit_runs','findings','images','registries']
  LOOP
    EXECUTE format('CREATE TRIGGER %I_touch BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at()', t, t);
  END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
