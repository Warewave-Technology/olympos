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
   agent sees ciphertext only. `compressed` mode trades that for egress cost; enabling it always opens
   the `transfer.compressed_mode` finding.
2. **Server ↛ arbitrary hosts in a cluster.** `OpenTunnel` carries a `target_id`, never `host:port`.
   The agent looks it up in its *own* discovered set (annotated Services) and refuses anything else.
   The server also recomputes target IDs and ignores agent-supplied IDs that do not match. Tested in unit
   tests and the e2e (`TestM1TunnelRealAgent`).
3. **Agent is narrow.** Distroless, non-root, read-only root FS, no capabilities, seccomp
   RuntimeDefault, no listening port (health is localhost, probed by exec). RBAC is read-only and has
   no Secrets (golden-file test `deploy/helm/chart_test.go`); its single writable object is its own
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

## Residual risks / accepted trade-offs

- A compromised server can *write* Vault secrets (create/patch) but still cannot read them; drift
  detection only catches writes that bypass Olympos, so the change-request trail is the control here.
- In `compressed` transfer mode the agent can observe backup data in cleartext (visible finding).
- kube-bench pods are privileged-adjacent (`hostPID`, read-only host mounts) by necessity; opt-in only.
- Dev mode (local key vault, dev login) must never be enabled in production; the server logs a loud
  warning and the config validator refuses `keyVault.provider=local` without it.
