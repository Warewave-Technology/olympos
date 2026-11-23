-- +goose Up
-- Synthetic monitoring (docs/design/synthetic-monitoring.md, issue #46): a
-- scenario is defined once, runs from a probe inside each cluster and alerts
-- a channel when it fails. This migration holds the whole schema: the new
-- grant role, the probe's side of the enrollment token and the cluster row,
-- the scenario model, the allowlist, the credentials, and the runs.

-- ---------------------------------------------------------------- access

-- synthetic-editor edits scenarios, the allowlist and synthetic credentials.
ALTER TABLE grants DROP CONSTRAINT grants_role_check;
ALTER TABLE grants ADD CONSTRAINT grants_role_check
  CHECK (role IN ('viewer','operator','vault-maker','vault-approver','admin','synthetic-editor'));

-- ---------------------------------------------------------------- enrollment

-- One token enrolls the agent and the probe (decisions after review, 1): each
-- identity has its own "used" mark, and roles says which of them the token may
-- enroll. Tokens that exist now were made for the agent alone.
ALTER TABLE enroll_tokens RENAME COLUMN used_at TO agent_used_at;
ALTER TABLE enroll_tokens ADD COLUMN probe_used_at timestamptz;
ALTER TABLE enroll_tokens ADD COLUMN roles text[] NOT NULL DEFAULT '{agent}';
ALTER TABLE enroll_tokens ALTER COLUMN roles SET DEFAULT '{agent,probe}';
ALTER TABLE enroll_tokens ADD CONSTRAINT enroll_tokens_roles_check
  CHECK (roles <@ ARRAY['agent','probe'] AND cardinality(roles) > 0);

-- The probe has its own identity and its own state, apart from the agent's.
ALTER TABLE clusters
  ADD COLUMN probe_status text NOT NULL DEFAULT 'not_installed'
    CHECK (probe_status IN ('not_installed','pending','online','offline','revoked')),
  ADD COLUMN probe_version text NOT NULL DEFAULT '',
  ADD COLUMN probe_cert_serial text NOT NULL DEFAULT '',
  ADD COLUMN probe_cert_expires_at timestamptz,
  ADD COLUMN probe_last_seen_at timestamptz,
  ADD COLUMN probe_offline_since timestamptz,
  ADD COLUMN probe_offline_alerted boolean NOT NULL DEFAULT false;

-- ---------------------------------------------------------------- allowlist

-- Hosts a probe may reach (6.1). One rule per pattern and kind, whatever the
-- case of the pattern.
CREATE TABLE synthetic_allowlist (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern    text NOT NULL,
  kind       text NOT NULL CHECK (kind IN ('exact','wildcard','suffix')),
  note       text NOT NULL DEFAULT '',
  created_by uuid REFERENCES principals(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX synthetic_allowlist_pattern ON synthetic_allowlist (lower(pattern), kind);
CREATE TRIGGER synthetic_allowlist_touch BEFORE UPDATE ON synthetic_allowlist
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- A counter that moves with every change of the list, so that a probe can
-- tell that it holds an old copy and a run records which list it ran under.
-- The first version is 1: 0 on a run means "not recorded".
CREATE TABLE synthetic_allowlist_version (
  id      smallint PRIMARY KEY CHECK (id = 1),
  version bigint NOT NULL
);
INSERT INTO synthetic_allowlist_version (id, version) VALUES (1, 1);

-- Once per statement, whatever the number of rows, and for TRUNCATE too.
-- +goose StatementBegin
CREATE FUNCTION olympos_synthetic_allowlist_bump() RETURNS trigger AS $$
BEGIN
  UPDATE synthetic_allowlist_version SET version = version + 1 WHERE id = 1;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER synthetic_allowlist_version_bump
  AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON synthetic_allowlist
  FOR EACH STATEMENT EXECUTE FUNCTION olympos_synthetic_allowlist_bump();

-- ---------------------------------------------------------------- credentials

-- What a scenario may send as authentication (6.2). The secret itself is a
-- row of credentials (stored encrypted, or a Key Vault reference); this row
-- says what it is for and which hosts may receive it.
CREATE TABLE synthetic_credentials (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name            text NOT NULL UNIQUE,
  kind            text NOT NULL CHECK (kind IN ('bearer','basic','header','oauth2_client_credentials')),
  bound_hosts     text[] NOT NULL CHECK (cardinality(bound_hosts) >= 1),
  credential_id   uuid NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
  header_name     text,
  oauth_token_url text,
  oauth_scopes    text NOT NULL DEFAULT '',
  expires_at      timestamptz,
  rotated_at      timestamptz,
  created_by      uuid REFERENCES principals(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER synthetic_credentials_touch BEFORE UPDATE ON synthetic_credentials
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- ---------------------------------------------------------------- scenarios

CREATE TABLE scenarios (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name               text NOT NULL,
  type               text NOT NULL CHECK (type IN ('http_flow','http','dns','tcp','tls')),
  owner_selector     text NOT NULL DEFAULT '',
  interval_seconds   int NOT NULL DEFAULT 60 CHECK (interval_seconds >= 30),
  timeout_seconds    int NOT NULL DEFAULT 10 CHECK (timeout_seconds BETWEEN 1 AND 60),
  step_retries       int NOT NULL DEFAULT 0 CHECK (step_retries BETWEEN 0 AND 2),
  enabled            boolean NOT NULL DEFAULT true,
  run_on             text NOT NULL DEFAULT 'all' CHECK (run_on IN ('all','selector')),
  run_on_selector    text NOT NULL DEFAULT '',
  exclude_selectors  text[] NOT NULL DEFAULT '{}',
  store_responses    boolean NOT NULL DEFAULT true,
  created_by         uuid REFERENCES principals(id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER scenarios_touch BEFORE UPDATE ON scenarios
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- A credential in use cannot be removed (409 in the API, with the scenarios'
-- names): RESTRICT is the backstop.
CREATE TABLE scenario_steps (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id   uuid NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
  position      int NOT NULL CHECK (position >= 0),
  kind          text NOT NULL CHECK (kind IN ('dns','http','tcp','tls')),
  spec          jsonb NOT NULL DEFAULT '{}',
  credential_id uuid REFERENCES synthetic_credentials(id) ON DELETE RESTRICT,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scenario_id, position)
);
CREATE INDEX scenario_steps_credential ON scenario_steps (credential_id) WHERE credential_id IS NOT NULL;
CREATE TRIGGER scenario_steps_touch BEFORE UPDATE ON scenario_steps
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

CREATE TABLE scenario_assertions (
  id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  step_id  uuid NOT NULL REFERENCES scenario_steps(id) ON DELETE CASCADE,
  position int NOT NULL CHECK (position >= 0),
  subject  text NOT NULL,
  operator text NOT NULL CHECK (operator IN ('equals','not_equals','contains','matches','less_than','greater_than','exists','length_greater_than')),
  value    text NOT NULL DEFAULT '',
  UNIQUE (step_id, position)
);

-- Only the names of extracted values are ever stored (3): they may be tokens.
CREATE TABLE scenario_extracts (
  id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  step_id uuid NOT NULL REFERENCES scenario_steps(id) ON DELETE CASCADE,
  name    text NOT NULL,
  source  text NOT NULL CHECK (source IN ('json_path','header','regex')),
  expr    text NOT NULL
);
CREATE INDEX scenario_extracts_step ON scenario_extracts (step_id);

-- One row per scenario. No channel means the routes of the synthetic.*
-- events decide (and a deleted channel falls back to them).
CREATE TABLE scenario_alerts (
  scenario_id             uuid PRIMARY KEY REFERENCES scenarios(id) ON DELETE CASCADE,
  cluster_fail_after      int NOT NULL DEFAULT 3 CHECK (cluster_fail_after >= 1),
  fleet_critical_clusters int NOT NULL DEFAULT 3 CHECK (fleet_critical_clusters >= 1),
  channel_id              uuid REFERENCES notification_channels(id) ON DELETE SET NULL,
  critical_channel_id     uuid REFERENCES notification_channels(id) ON DELETE SET NULL,
  recovery_after          int NOT NULL DEFAULT 2 CHECK (recovery_after >= 1),
  send_recovery           boolean NOT NULL DEFAULT true,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER scenario_alerts_touch BEFORE UPDATE ON scenario_alerts
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- ---------------------------------------------------------------- runs

-- One row per scenario, cluster and scheduled slot. A test run (from the
-- editor) has no slot to keep, never alerts and may have no saved scenario:
-- then test_spec holds what was tried.
CREATE TABLE synthetic_runs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id       uuid REFERENCES scenarios(id) ON DELETE CASCADE,
  cluster_id        uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  scheduled_for     timestamptz NOT NULL DEFAULT now(),
  started_at        timestamptz,
  finished_at       timestamptz,
  status            text NOT NULL DEFAULT 'scheduled'
    CHECK (status IN ('scheduled','running','passed','failed','error','skipped')),
  failed_step       int,
  failure_reason    text NOT NULL DEFAULT '',
  total_ms          int,
  probe_version     text NOT NULL DEFAULT '',
  test              boolean NOT NULL DEFAULT false,
  test_spec         jsonb,
  requested_by      uuid REFERENCES principals(id),
  allowlist_version bigint NOT NULL DEFAULT 0,
  remote_ip         text NOT NULL DEFAULT '',
  probe_ip          text NOT NULL DEFAULT '',
  created_at        timestamptz NOT NULL DEFAULT now(),
  CHECK (scenario_id IS NOT NULL OR test)
);
CREATE UNIQUE INDEX synthetic_runs_slot ON synthetic_runs (scenario_id, cluster_id, scheduled_for) WHERE NOT test;
CREATE INDEX synthetic_runs_scenario ON synthetic_runs (scenario_id, cluster_id, scheduled_for DESC);
CREATE INDEX synthetic_runs_cluster ON synthetic_runs (cluster_id, scheduled_for DESC);
CREATE INDEX synthetic_runs_open ON synthetic_runs (status) WHERE status IN ('scheduled','running');
CREATE INDEX synthetic_runs_created ON synthetic_runs (created_at);

-- Append-only once finished: whatever code does, a run in a terminal state
-- cannot be changed again (a delete, for retention or a removed scenario, is
-- not an update).
-- +goose StatementBegin
CREATE FUNCTION olympos_synthetic_runs_freeze() RETURNS trigger AS $$
BEGIN
  IF OLD.status IN ('passed','failed','error','skipped') THEN
    RAISE EXCEPTION 'synthetic_runs rows are append-only once finished' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER synthetic_runs_freeze BEFORE UPDATE ON synthetic_runs
  FOR EACH ROW EXECUTE FUNCTION olympos_synthetic_runs_freeze();

-- What each step did. The excerpt is at most 2 KiB (3); extracted values are
-- never stored, only their names.
CREATE TABLE synthetic_step_results (
  run_id          uuid NOT NULL REFERENCES synthetic_runs(id) ON DELETE CASCADE,
  position        int NOT NULL,
  status          text NOT NULL CHECK (status IN ('passed','failed','error','skipped')),
  status_code     int,
  timings         jsonb NOT NULL DEFAULT '{}',
  assertions      jsonb NOT NULL DEFAULT '[]',
  excerpt         bytea CHECK (octet_length(excerpt) <= 2048),
  extracted_names text[] NOT NULL DEFAULT '{}',
  error           text NOT NULL DEFAULT '',
  PRIMARY KEY (run_id, position)
);

-- ---------------------------------------------------------------- alerts

-- cluster_id NULL is the fleet alert. clusters lists the clusters failing
-- when it opened. Only one alert per scenario and cluster (or fleet) is
-- firing; resolved ones stay as history.
CREATE TABLE synthetic_alerts (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id          uuid NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
  cluster_id           uuid REFERENCES clusters(id) ON DELETE CASCADE,
  state                text NOT NULL CHECK (state IN ('firing','resolved')),
  reason               text NOT NULL DEFAULT '',
  clusters             text[] NOT NULL DEFAULT '{}',
  opened_at            timestamptz NOT NULL DEFAULT now(),
  resolved_at          timestamptz,
  last_run_id          uuid REFERENCES synthetic_runs(id) ON DELETE SET NULL,
  notified_at          timestamptz,
  resolved_notified_at timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX synthetic_alerts_one_firing
  ON synthetic_alerts (scenario_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid))
  WHERE state = 'firing';
CREATE INDEX synthetic_alerts_cluster ON synthetic_alerts (cluster_id) WHERE cluster_id IS NOT NULL;
CREATE TRIGGER synthetic_alerts_touch BEFORE UPDATE ON synthetic_alerts
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- Where each scenario stands on each cluster, so that the evaluator does not
-- count runs. blocked_reason says why runs do not happen (allowlist, probe).
CREATE TABLE synthetic_state (
  scenario_id          uuid NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
  cluster_id           uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  consecutive_failures int NOT NULL DEFAULT 0,
  consecutive_passes   int NOT NULL DEFAULT 0,
  last_run_id          uuid REFERENCES synthetic_runs(id) ON DELETE SET NULL,
  last_status          text CHECK (last_status IN ('passed','failed','error','skipped')),
  last_finished_at     timestamptz,
  blocked_reason       text NOT NULL DEFAULT '',
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scenario_id, cluster_id)
);
CREATE INDEX synthetic_state_cluster ON synthetic_state (cluster_id);
CREATE TRIGGER synthetic_state_touch BEFORE UPDATE ON synthetic_state
  FOR EACH ROW EXECUTE FUNCTION olympos_touch_updated_at();

-- The roll-up that outlives the runs (8): one row per scenario, cluster and hour.
CREATE TABLE synthetic_hourly (
  scenario_id uuid NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
  cluster_id  uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  hour        timestamptz NOT NULL,
  runs        int NOT NULL DEFAULT 0,
  passed      int NOT NULL DEFAULT 0,
  failed      int NOT NULL DEFAULT 0,
  p50_ms      int NOT NULL DEFAULT 0,
  p95_ms      int NOT NULL DEFAULT 0,
  PRIMARY KEY (scenario_id, cluster_id, hour)
);
CREATE INDEX synthetic_hourly_cluster ON synthetic_hourly (cluster_id, hour);

-- ---------------------------------------------------------------- routes

-- synthetic.allowlist_changed (a new event, not opt-in) goes wherever
-- grant.changed goes today, as backup.partial did in 00022 and restore.failed
-- in 00023: routes are explicit rows with no default, and the dispatcher
-- drops an event with no route. Changing the allowlist is a change of what
-- the probes may reach, as a grant is a change of who may act: the same
-- people want to hear of both. The other synthetic events are left to the
-- operator.
INSERT INTO notification_routes (event_type, channel_id)
  SELECT 'synthetic.allowlist_changed', channel_id FROM notification_routes WHERE event_type = 'grant.changed'
  ON CONFLICT (event_type, channel_id) DO NOTHING;

-- +goose Down
-- Production never migrates down. Refuse rather than lose data that the old
-- schema cannot represent.
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM grants WHERE role = 'synthetic-editor') THEN
    RAISE EXCEPTION 'cannot migrate down: synthetic-editor grants exist';
  END IF;
END
$$;
-- +goose StatementEnd
-- The old schema knows no synthetic.allowlist_changed event. Only that
-- event's routes go: 00024 made no others.
DELETE FROM notification_routes WHERE event_type = 'synthetic.allowlist_changed';

DROP TABLE synthetic_hourly;
DROP TABLE synthetic_state;
DROP TABLE synthetic_alerts;
DROP TABLE synthetic_step_results;
DROP TRIGGER synthetic_runs_freeze ON synthetic_runs;
DROP FUNCTION olympos_synthetic_runs_freeze();
DROP TABLE synthetic_runs;
DROP TABLE scenario_alerts;
DROP TABLE scenario_extracts;
DROP TABLE scenario_assertions;
DROP TABLE scenario_steps;
DROP TABLE scenarios;
DROP TABLE synthetic_credentials;
DROP TRIGGER synthetic_allowlist_version_bump ON synthetic_allowlist;
DROP FUNCTION olympos_synthetic_allowlist_bump();
DROP TABLE synthetic_allowlist_version;
DROP TABLE synthetic_allowlist;

ALTER TABLE clusters
  DROP COLUMN probe_offline_alerted,
  DROP COLUMN probe_offline_since,
  DROP COLUMN probe_last_seen_at,
  DROP COLUMN probe_cert_expires_at,
  DROP COLUMN probe_cert_serial,
  DROP COLUMN probe_version,
  DROP COLUMN probe_status;

-- A probe-only token has nothing for the old code to enroll.
DELETE FROM enroll_tokens WHERE NOT ('agent' = ANY(roles));
ALTER TABLE enroll_tokens DROP CONSTRAINT enroll_tokens_roles_check;
ALTER TABLE enroll_tokens DROP COLUMN roles;
ALTER TABLE enroll_tokens DROP COLUMN probe_used_at;
ALTER TABLE enroll_tokens RENAME COLUMN agent_used_at TO used_at;

ALTER TABLE grants DROP CONSTRAINT grants_role_check;
ALTER TABLE grants ADD CONSTRAINT grants_role_check
  CHECK (role IN ('viewer','operator','vault-maker','vault-approver','admin'));
