-- +goose Up
-- Kyverno ≥ 1.17 adds policies.kyverno.io policy kinds next to the legacy
-- kyverno.io ClusterPolicy/Policy; a name is unique only per kind.
ALTER TABLE kyverno_policies ADD COLUMN kind text NOT NULL DEFAULT '';
UPDATE kyverno_policies SET kind = CASE WHEN namespace = '' THEN 'ClusterPolicy' ELSE 'Policy' END;
ALTER TABLE kyverno_policies DROP CONSTRAINT kyverno_policies_pkey;
ALTER TABLE kyverno_policies ADD PRIMARY KEY (cluster_id, kind, namespace, name);

-- +goose Down
DELETE FROM kyverno_policies WHERE kind NOT IN ('ClusterPolicy', 'Policy');
ALTER TABLE kyverno_policies DROP CONSTRAINT kyverno_policies_pkey;
ALTER TABLE kyverno_policies ADD PRIMARY KEY (cluster_id, namespace, name);
ALTER TABLE kyverno_policies DROP COLUMN kind;
