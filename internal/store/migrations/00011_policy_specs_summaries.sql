-- +goose Up
-- Policy specs for the Security page detail views, the NetworkPolicy
-- simulator's label data, per-cluster summary indexes, audit run logs and
-- scan-by-tag results.

-- Kyverno: the policy spec as reported by the agent (trimmed: no status,
-- managedFields or foreign annotations). NULL for agents that do not send it.
ALTER TABLE kyverno_policies ADD COLUMN api_version  text NOT NULL DEFAULT '';
ALTER TABLE kyverno_policies ADD COLUMN annotations  jsonb NOT NULL DEFAULT '{}';
ALTER TABLE kyverno_policies ADD COLUMN spec         jsonb;
ALTER TABLE kyverno_policies ADD COLUMN spec_omitted boolean NOT NULL DEFAULT false;

-- Non-passing results (fail, warn, error) of the current reports, attributed
-- to their policy; replaced per report.
CREATE TABLE kyverno_violations (
  cluster_id         uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  kind               text NOT NULL,
  namespace          text NOT NULL DEFAULT '',
  name               text NOT NULL,
  rule               text NOT NULL DEFAULT '',
  result             text NOT NULL,
  severity           text NOT NULL DEFAULT '',
  message            text NOT NULL DEFAULT '',
  resource_kind      text NOT NULL DEFAULT '',
  resource_namespace text NOT NULL DEFAULT '',
  resource_name      text NOT NULL DEFAULT ''
);
CREATE INDEX kyverno_violations_policy ON kyverno_violations (cluster_id, kind, namespace, name);

-- NetworkPolicies with their spec; replaced per report.
CREATE TABLE network_policies (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace  text NOT NULL,
  name       text NOT NULL,
  spec       jsonb,
  seen_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cluster_id, namespace, name)
);

-- Namespace labels and up to ~50 workloads per namespace (pod template
-- labels and container ports), example data for the policy simulator.
ALTER TABLE network_policy_status ADD COLUMN labels jsonb NOT NULL DEFAULT '{}';
CREATE TABLE namespace_workloads (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  namespace  text NOT NULL,
  kind       text NOT NULL,
  name       text NOT NULL,
  labels     jsonb NOT NULL DEFAULT '{}',
  ports      int[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (cluster_id, namespace, kind, name)
);

-- Audit: full captured tool output of a failed run (redacted, capped);
-- error keeps a short reason. Existing rows are not backfilled.
ALTER TABLE audit_runs ADD COLUMN log text NOT NULL DEFAULT '';
CREATE INDEX audit_runs_cluster_tool ON audit_runs (cluster_id, tool, created_at DESC);

-- Images: how the stored results were obtained. "tag" = the running digest
-- is not in the registry; the registry's image with the same tag was scanned.
ALTER TABLE images ADD COLUMN scanned_by text NOT NULL DEFAULT '' CHECK (scanned_by IN ('', 'digest', 'tag'));
ALTER TABLE images ADD COLUMN scan_note text NOT NULL DEFAULT '';
UPDATE images SET scanned_by = 'digest' WHERE last_scanned_at IS NOT NULL AND scan_status = 'scanned';
-- Digests missing from their registry get the tag fallback on the next tick.
UPDATE images SET scan_status = 'pending' WHERE scan_status = 'unavailable';

-- +goose Down
ALTER TABLE images DROP COLUMN scan_note;
ALTER TABLE images DROP COLUMN scanned_by;
DROP INDEX audit_runs_cluster_tool;
ALTER TABLE audit_runs DROP COLUMN log;
DROP TABLE namespace_workloads;
ALTER TABLE network_policy_status DROP COLUMN labels;
DROP TABLE network_policies;
DROP TABLE kyverno_violations;
ALTER TABLE kyverno_policies DROP COLUMN spec_omitted;
ALTER TABLE kyverno_policies DROP COLUMN spec;
ALTER TABLE kyverno_policies DROP COLUMN annotations;
ALTER TABLE kyverno_policies DROP COLUMN api_version;
