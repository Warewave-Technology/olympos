-- +goose Up
-- F2: sensitive-data (credentials in ConfigMaps, scanned on the agent) and
-- F3: k8s-secrets (opt-in Secret inventory, key names only).
ALTER TABLE findings DROP CONSTRAINT findings_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_source_check
  CHECK (source IN ('kubescape','polaris','kube-bench','kyverno','netpol','tls','vault-drift','transfer','sensitive-data','k8s-secrets'));

-- +goose Down
DELETE FROM findings WHERE source IN ('sensitive-data','k8s-secrets');
ALTER TABLE findings DROP CONSTRAINT findings_source_check;
ALTER TABLE findings ADD CONSTRAINT findings_source_check
  CHECK (source IN ('kubescape','polaris','kube-bench','kyverno','netpol','tls','vault-drift','transfer'));
