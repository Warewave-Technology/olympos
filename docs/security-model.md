# Olympos security model

This document explains what Olympos protects, against whom, and which mechanism enforces each
property. The SPEC (§0, §18) is normative; this is the rationale and the map to code.

## Assets

| Asset | Where it lives | Who can use it |
|---|---|---|
| Database / ClickHouse passwords | Key Vault (`kv://` ref, recommended) or Postgres, envelope-encrypted | Server workers, in memory, per run |
| Vault AppRole secret_id | Key Vault | Server (index, changes, snapshots) |
| New secret values in change requests | `change_items.sealed_value` (envelope), nulled at every terminal state | Server, at apply time only |
| Blob credentials (MI or SAS) | MI: none stored. SAS: Key Vault ref or envelope-encrypted | Server only |
| Registry credentials | Key Vault ref or envelope-encrypted | Server (trivy child env) |
| Backups | Azure Blob, immutable versions, lifecycle retention | Written by the server; deleted only by lifecycle rules |
| Agent identity | Client cert + key in the agent's own Secret | The agent |
| Internal CA key | Postgres, envelope-encrypted | Server |

## Trust boundaries

```
 user ──HTTPS──▶ server (BFF) ──Managed Identity──▶ Key Vault / Blob / Graph
                    ▲
                    │ gRPC, mTLS, agent dials out
                 agent (per cluster) ──TCP──▶ discovered Service only
```

1. **Cluster ↛ credentials.** No credential, SAS or Blob key is ever sent to an agent
   (`internal/gateway/proto_test.go` scans every proto field). Work needing credentials runs on the
   server and reaches targets through the tunnel, speaking TLS end-to-end (`e2e-tls`, default): the
   agent sees ciphertext only. Exception: a PostgreSQL target without TLS is backed up with SCRAM-SHA-256
   only (no password crosses the agent), so the agent sees the data in the clear; the target gets the
   `tls.missing` finding. `compressed` mode trades that for egress cost; enabling it always opens
   the `transfer.compressed_mode` finding.
2. **Server ↛ arbitrary hosts in a cluster.** `OpenTunnel` carries a `target_id`, never `host:port`.
   The agent looks it up in its *own* discovered set (annotated Services) and refuses anything else.
   The server also recomputes target IDs and ignores agent-supplied IDs that do not match. Tested in unit
   tests and the e2e (`TestM1TunnelRealAgent`).
3. **Agent is narrow.** Distroless, non-root, read-only root FS, no capabilities, seccomp
   RuntimeDefault, no listening port (health is localhost, probed by exec). RBAC is read-only and has
   no Secrets unless the opt-in Secret inventory is enabled (`list`/`watch`, see below; golden-file test
   `deploy/helm/chart_test.go`); its single writable object is its own
   identity Secret (resourceNames-restricted). The kube-bench exception is opt-in, in its own PSA
   `privileged` namespace, with a Job spec compiled into the agent and a pinned image digest.
4. **Read-only API proxy** for kubescape/polaris: the agent injects its own ServiceAccount token,
   accepts only `GET`, rejects upgrades, `exec/attach/portforward/proxy` and any path under Secrets
   (after path normalisation), and strips client `Authorization`/`Impersonate-*` headers.
5. **Agent identity.** One-time bootstrap token (hashed, TTL 1 h, single use) → ECDSA P-256 key
   generated in memory → CSR → client cert with CN = cluster UUID chosen by the server (CSR subject
   ignored), 30-day validity, renewed at 2/3 lifetime. Revocation adds the serial to a deny list, marks
   the cluster revoked (every RPC re-checks) and drops open streams.

## People

- Sign-in is Entra ID OIDC (code + PKCE) handled by the server (BFF). The SPA never sees tokens; it
  holds an `HttpOnly; Secure; SameSite=Strict` session cookie plus a CSRF token for writes. Sessions:
  8 h absolute, 30 min idle, server-side rows.
- Tokens must match `iss = …/<tenant>/v2.0`, `tid`, `aud`, `exp`, `nbf`, `nonce`
  (`internal/server/oidc_test.go` includes foreign-tenant tokens).
- Authorization is by Entra **object ID** grants stored in Olympos (group claims ignored), with label
  scopes. Out-of-scope objects answer 404. Grants of disabled/deleted users go **stale** daily and stop
  authorizing. `vault-approver` (and admin) cannot be granted to guests, and guests can never approve.
- **Maker/checker** for every Vault change: maker ≠ checker by `(tenant_id, object_id)`, enforced in
  code *and* by a DB check constraint; no role bypasses it, admin included.

## Secrets never shown

- Vault: the Olympos policy has **no read on `<mount>/data/*`** — keys come from `subkeys` (values
  null), changes are JSON merge `PATCH` with `cas`. Even a compromised server cannot read secret values
  through its token (e2e asserts 403). Root tokens are used once for setup and never stored.
- API: no endpoint returns a secret value; write-only fields only. Checkers see HMAC fingerprints
  (`HMAC-SHA256`, key from Key Vault), never plain hashes.
- Logs: a redaction layer masks credential-shaped attributes and known token formats; integration tests
  assert canary secrets never reach logs.

## Auditability

Append-only by trigger (not only by grants): `activity_log`, `change_events`, and `backup_runs` once
finished. Every user action and every sensitive system transition writes an activity row in the same
transaction as the change; notifications go through a transactional outbox.

## Backups

The server is the only writer to Blob and has no delete permission (custom role without
`blobs/delete`); retention is lifecycle rules on the `olympos-tier` tag; versions are immutable for the
longest retention. *Test destination* verifies delete is refused and warns otherwise.

## ConfigMaps and Secrets in clusters

- **ConfigMaps** are readable by the agent (read-only, deviation #2). The agent scans their values for
  credentials (gitleaks rules + key names) inside the informer transform and keeps only metadata; the
  `SensitiveDataReport` it sends carries where a match is and which rule matched — never the value, a
  part of it or a hash (enforced by a proto test, e2e canary checks of the server's database and logs).
- **kubescape and polaris do see ConfigMap values.** They run on the server and read the cluster through
  the agent's read-only API proxy, which serves ConfigMaps and pod specs (with literal `env` values) by
  design: the controls need them. The values exist only in the tool process's memory. The raw report
  Olympos stores (when a raw-report destination is set) is redacted first: ConfigMap/Secret `data`,
  `binaryData` and `stringData`, container `env[].value`, `last-applied-configuration` and
  `managedFields` are replaced (security review v0.1 #4). Keep credentials out of ConfigMaps and env
  literals regardless — that is what *Sensitive data* reports.
- **Secrets** are never read by default, except the agent's own identity Secret. The opt-in Secret
  inventory (`secretsInventory.enabled`) lists them with their key names only.
  **Kubernetes RBAC has no "metadata only" permission.** Listing Secret metadata requires `list` on
  `secrets`, and the same token could read values with a normal request. Olympos code never requests
  values — the agent uses only the metadata client (PartialObjectMetadata), reads key names from
  `managedFields`, drops every annotation (kubectl's `last-applied-configuration` carries the data) and a
  test fails the build if any other client touches Secrets — but a stolen agent token could. Therefore
  the inventory is **opt-in and off by default**, like kube-bench. The API proxy keeps rejecting every
  Secret path and the server never reads Secrets. Prefer server-side apply (or `kubectl create`) for
  Secrets: client-side `kubectl apply` stores the values in an annotation that every metadata reader
  (not only Olympos) receives.

## Residual risks / accepted trade-offs

- A compromised server can *write* Vault secrets (create/patch) but still cannot read them; drift
  detection only catches writes that bypass Olympos, so the change-request trail is the control here.
- In `compressed` transfer mode the agent can observe backup data in cleartext (visible finding).
- kube-bench pods are privileged-adjacent (`hostPID`, read-only host mounts) by necessity; opt-in only.
- Dev mode (local key vault, dev login) must never be enabled in production; the server logs a loud
  warning and the config validator refuses `keyVault.provider=local` without it.
