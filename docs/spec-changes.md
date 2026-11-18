# Changes to SPEC v0.1

Decisions taken during implementation that changed a **MUST** in `SPEC.md`. Each was approved before merge.

| Date | Section | Change | Reason |
|---|---|---|---|
| 2026-11-18 | §4.2, §13.1 | Agent ClusterRole also reads `policies.kyverno.io/v1` validatingpolicies, namespacedvalidatingpolicies, imagevalidatingpolicies, namespacedimagevalidatingpolicies. | Kyverno 1.20 removed execution of legacy `kyverno.io/v1` policies; without this the Security page shows nothing for current Kyverno installs. |
| 2026-11-18 | §4.2 | Read-only `configmaps` in the kubescape/polaris extras. | Polaris aborts without listing ConfigMaps; §4.2 only forbids ConfigMap writes. |
| 2026-11-18 | §11.1 | Olympos Vault policy adds `update` on `auth/approle/role/olympos/secret-id` and `.../secret-id-accessor/destroy`. | Monthly secret_id rotation is impossible once the root token is gone. No read on secret data is added. |
| 2026-11-18 | §12.3.4 | The kube-bench Kyverno `PolicyException` is opt-in (`bench.kyverno.legacyException`, `bench.kyverno.policyRefs`) instead of auto-rendered. | Kyverno 1.20 rejects `kyverno.io/v2` exceptions; `policies.kyverno.io/v1` exceptions must name each policy. |
