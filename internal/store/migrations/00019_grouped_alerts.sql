-- +goose Up
-- F9: new critical CVEs are collected per cluster during a scan run and
-- sent as one vuln.critical message per cluster (counts + top 5) when the
-- run ends; every item is still recorded in the activity log. Sent items
-- stay (sent_at) so a CVE that disappears and comes back is not re-sent.
CREATE TABLE pending_vuln_alerts (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  digest     text NOT NULL,
  image      text NOT NULL,
  cve_id     text NOT NULL,
  package    text NOT NULL DEFAULT '',
  fixed_in   text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at    timestamptz,
  PRIMARY KEY (cluster_id, digest, cve_id)
);
CREATE INDEX pending_vuln_alerts_unsent ON pending_vuln_alerts (cluster_id) WHERE sent_at IS NULL;

-- +goose Down
DROP TABLE pending_vuln_alerts;
