# Changes to SPEC v0.1

Decisions taken during implementation that changed a **MUST** in `SPEC.md`. Each was approved before merge.

| Date | Section | Change | Reason |
|---|---|---|---|
| 2026-11-18 | §4.2, §13.1 | Agent ClusterRole also reads `policies.kyverno.io/v1` validatingpolicies, namespacedvalidatingpolicies, imagevalidatingpolicies, namespacedimagevalidatingpolicies. | Kyverno 1.20 removed execution of legacy `kyverno.io/v1` policies; without this the Security page shows nothing for current Kyverno installs. |
| 2026-11-18 | §4.2 | Read-only `configmaps` in the kubescape/polaris extras. | Polaris aborts without listing ConfigMaps; §4.2 only forbids ConfigMap writes. |
| 2026-11-18 | §11.1 | Olympos Vault policy adds `update` on `auth/approle/role/olympos/secret-id` and `.../secret-id-accessor/destroy`. | Monthly secret_id rotation is impossible once the root token is gone. No read on secret data is added. |
| 2026-11-18 | §12.3.4 | The kube-bench Kyverno `PolicyException` is opt-in (`bench.kyverno.legacyException`, `bench.kyverno.policyRefs`) instead of auto-rendered. | Kyverno 1.20 rejects `kyverno.io/v2` exceptions; `policies.kyverno.io/v1` exceptions must name each policy. |
| 2026-11-18 | §10.3 | §10.3 destinations: S3 (incl. S3-compatible via endpoint override; static access key, delete refused by policy) and NFS (directory below a volume mounted under `backup.nfsRoot`; the server can technically delete there, always reported as a can-delete warning; retention by storage snapshots / WORM) added; Azure endpoint override exposed. Retention stays lifecycle rules (S3: filtered by tag `olympos-tier`). | On-prem and non-Azure installs need a backup target. The server is still the only writer and has no delete code path except the probe delete check. |
| 2026-11-19 | §7 | In `e2e-tls` mode a target without TLS no longer falls back to plaintext with a password: PostgreSQL only with SCRAM-SHA-256 (auth request checked before the password is sent), ClickHouse and Vault refused with a clear error; `compressed` mode unchanged; `tls.missing` opens in every case. | v1 release fix F1: ClickHouse native and PostgreSQL MD5/cleartext would expose the password to the agent and the node network. |
