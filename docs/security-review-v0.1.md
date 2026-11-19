# Security review v0.1

Independent review of `internal/agent`, `internal/authz`, `internal/approvals` and `internal/secrets`
(release fix F11), done on 2026-11-19 by a reviewer that had not written the code and was not told what
to expect. Data flows were followed into the server where they decide whether an agent-side guarantee
holds. Every finding below was fixed or explicitly accepted; fixes carry a regression test.

Together with the review: `FuzzAPIProxy` (about 1 M executions, clean), the tunnel allowlist tests and
the route × role authorization matrix (`internal/app/authz_matrix_test.go`, every route for viewer,
scoped operator and admin).

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| F11 | High | The API proxy's Secret filter missed the legacy `/api/v1/watch/.../secrets` path; with the Secret inventory on, it would have returned Secret values. Found while writing the fuzz test. | **Fixed** (e29eebc): a `secrets` path segment is refused anywhere, also after a second decode; method-override headers refused |
| 1 | High | A target's TLS name came from a Service annotation and was verified against public CAs: whoever could edit the Service could point it at a pod with a public certificate for a domain they own and receive database passwords, the Vault root token or the AppRole `secret_id`. | **Fixed** (9cd5ec1): the name is pinned at first sight; a change waits for an admin of the cluster (Needs attention, *Backups*); targets trust only `targetTLS.caBundleFile` and per-target CAs, public CAs only with `targetTLS.systemRoots` |
| 2 | High (with #1) | `kv://` references were unrestricted: a scoped operator could have any Key Vault secret (another team's, or Olympos' own HMAC key) resolved and sent to their target. | **Fixed** (0c19a77): Olympos' own secrets are never resolved for a user; global admins may reference others; everyone else only what a `keyVault.references` rule (glob + cluster scope) allows |
| 3 | Medium | Approve took a blocking advisory lock on a pool connection before any authorization, then needed a second connection: parallel approve calls from any viewer could hold the whole pool. | **Fixed** (d91bb19): read-only authorization first; `pg_try_advisory_lock` with the connection returned between attempts, 409 after 15 s; both transactions on the locked connection |
| 4 | Medium | kubescape's raw report embeds the objects it scanned (ConfigMap data, literal env values) and was stored unredacted; the docs said ConfigMap values never leave the cluster. | **Fixed** (73753ce): stored reports are redacted; docs corrected (the tools read ConfigMaps through the read-only proxy, in memory) |
| 5 | Low | A Vault timeout or transport error was recorded as a definite failure although the write may have landed (drift then reported Olympos' own write). | **Fixed** (d91bb19): timeouts, transport errors and 5xx stay `applying`; the reconciler settles them |
| 6 | Low | The reconciler read KV metadata before taking the vault lock. | **Fixed** (d91bb19): lock first, then read; a vault an apply holds is skipped |
| 7 | Low | A failed pre-read let approve continue without the vault lock. | **Fixed** (d91bb19): 500; the locked vault must be the request's |
| 8 | Low | Requests stuck in `applying` kept their sealed values indefinitely (revoked cluster, unreachable vault). | **Fixed** (d91bb19): after 24 h they fail as `unverified` and are scrubbed |
| 9 | Low | Headless targets resolved through any EndpointSlice, including hand-made and FQDN ones. | **Fixed** (73753ce): controller-made IPv4/IPv6 slices only; no loopback, link-local or unspecified addresses |
| 10 | Low | Strip transforms skipped objects carrying user-settable `olympos.io/*` annotations. | **Fixed** (73753ce): a per-process nonce marks the agent's own output |
| 11a | Info | Sensitive data sent the exact value length. | **Fixed**: power-of-two bucket |
| 11b | Info | The agent proxy forwarded `X-Remote-*` / `X-Forwarded-*`. | **Fixed**: dropped (harmless with token auth; defense in depth) |
| 11c | Info | The local audit proxy (127.0.0.1) had no authentication: on a systemd host any local process could read the cluster with the agent's identity during a run. | **Fixed**: per-run TLS certificate and token in the generated kubeconfig |
| 11d | Info | `renewLoop` spun without delay on an unparsable certificate. | **Fixed**: backs off |
| 11e | Info | Log redaction did not recurse into a `LogValuer` that resolves to a group. | **Fixed** |
| 11f | Info | `TestNoSecretValueClients` is regex-based; a raw REST client on `secrets` would pass it. | **Accepted**: the agent's RBAC is still `list, watch` only (no `get`) and the proxy refuses Secret paths; an import-graph check is a follow-up |
| 11g | Info | Guest detection relies on Graph `userType`; bootstrap admins are "Member" until the first sync, and a principal that later becomes a Guest keeps grants until then. | **Accepted**: approve re-checks the user type at decision time |
| 11h | Info | Plaintext copies (`secretValue.UnmarshalJSON`, `string(v)` in apply) are not zeroed. | **Accepted**: best effort in Go, documented in `security-model.md` |

## Accepted trade-offs

- **Destinations and notification channels are readable by every signed-in user** (names, kinds,
  endpoints, last test or delivery result). They are global configuration that every job and schedule
  form needs to offer; credentials are never returned, and changing them requires global admin.
- **kubescape and polaris see ConfigMap values and pod specs** through the read-only API proxy: their
  controls need them. Values stay in the tool process's memory; stored raw reports are redacted.
- **The Secret inventory needs `list` on `secrets`** (Kubernetes has no metadata-only permission), so a
  stolen agent token could read values. It is opt-in and off by default (see `security-model.md`).

## Checked and found sound

- API proxy: GET only; upgrades and method overrides refused; client `Authorization` and
  `Impersonate-*` stripped before the agent's token is added; path tricks (`//`, `.`/`..`, `%2F`,
  `%2e`, double encoding, case, `/watch/`, every API group) caught; `exec`, `attach`, `portforward`,
  `proxy` blocked, and the RBAC lacks `pods/log`, `nodes/proxy`, `services/proxy`; absolute-form
  request targets cannot change the upstream host.
- Tunnels open only to targets the agent discovered itself; the server never supplies host or port;
  ExternalName Services are not followed.
- Secret inventory uses only the metadata client; key names from `managedFields`; no values or
  annotations in reports. The ConfigMap scanner strips data in the transform; gitleaks logging is
  silenced.
- Agent identity: P-256 key generated in memory, server CA pinned, TLS 1.3, bootstrap token dropped
  after enrollment.
- authz: stale grants and disabled principals never authorize; malformed scopes dropped; `CanGlobal`
  needs scope `all`; bootstrap admins only while the grants table is empty; the subject is reloaded per
  request; writes need the CSRF token.
- approvals: maker ≠ checker in code and by a database CHECK, admin included; one approval only (row
  lock + state machine); no lock-order cycle between the vault lock and row locks; out-of-scope requests
  are 404; sealed values scrubbed on every terminal transition (and by a trigger); views never select
  values; Slack gets a link only.
- secrets: a fresh 256-bit DEK and 96-bit nonce per record, AAD bound to the row; RSA-OAEP-256 key wrap
  with the KEK version recorded; the local key vault exists only in `-tags dev` builds; Key Vault and
  secret names validated, so a reference cannot inject a host.
