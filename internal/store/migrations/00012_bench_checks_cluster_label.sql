-- +goose Up
-- Every kube-bench check per node (status, description, remediation) for the
-- node detail view; counts alone did not say what failed.
ALTER TABLE bench_node_results ADD COLUMN checks jsonb NOT NULL DEFAULT '[]';

-- Every cluster carries the reserved, read-only label olympos.io/cluster=<name>
-- so scopes (grants, audit schedules) can target exactly one cluster.
UPDATE clusters SET labels = labels || jsonb_build_object('olympos.io/cluster', name);

-- +goose Down
UPDATE clusters SET labels = labels - 'olympos.io/cluster';
ALTER TABLE bench_node_results DROP COLUMN checks;
