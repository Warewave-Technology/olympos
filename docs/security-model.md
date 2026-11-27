# Olympos security model

This document explains what Olympos protects, against whom, and which mechanism enforces each
property. The SPEC (§0, §18) is normative; this is the rationale and the map to code.

## Assets

| Asset | Where it lives | Who can use it |
|---|---|---|
| Database / ClickHouse passwords | Key Vault (`kv://` ref, recommended) or Postgres, envelope-encrypted | Server workers, in memory, per run |
| Vault AppRole secret_id | Key Vault | Server (index, changes, snapshots) |
| New secret values in change requests | `change_items.sealed_value` (envelope), nulled at every terminal state | Server, at apply time only |
| Restore target credentials (admin login of the new database) | Key Vault ref, or a `credentials` row envelope-encrypted; deleted at every terminal state of the restore request | Server, at the check and while the restore runs; never returned by the API |
| Vault restore tokens (token of the new Vault) | `restore_requests.sealed_token` (envelope, AAD `restore_requests:<id>`), wiped at every terminal state | Server, at the check and for `snapshot-force` only |
| Blob credentials (MI or SAS) | MI: none stored. SAS: Key Vault ref or envelope-encrypted | Server only |
| Native ClickHouse ingest credentials (one per backup or restore run) | Server memory only, for the run; the database keeps the key ID, scope, expiry and an HMAC fingerprint | ClickHouse, for its own run's prefix only ([below](#native-clickhouse-backups-the-ingest-endpoint)) |
| Manifest signing key (`olympos-manifest`) | Key Vault, in the KEK's vault; never leaves it | Server: signs (`keys/sign`) and reads the public key (`keys/get`) |
| Registry credentials | Key Vault ref or envelope-encrypted | Server (trivy child env) |
| Backups | Azure Blob or S3 (versioned, lifecycle retention, immutable only where the storage owner turns it on), or NFS | Written by the server; deleted only by lifecycle rules (on NFS, by the storage) |
| Synthetic monitoring credentials (bearer, basic, header, OAuth2 client) | Key Vault ref, or a `credentials` row (envelope-encrypted) that `synthetic_credentials` names with its bound hosts | Server, per run; sealed to one probe connection for that run ([below](#synthetic-monitoring-credentials-in-the-cluster)) |
| Agent identity | Client cert + key in the agent's own Secret | The agent |
| Probe identity | Client cert + key in `olympos-probe-identity`, written and renewed by the agent | The probe (read-only mount) |
| Internal CA key | Postgres, envelope-encrypted | Server |

## Trust boundaries

```
 user ──HTTPS──▶ server (BFF) ──Managed Identity──▶ Key Vault / Blob / Graph
                    ▲      ▲
                    │      └── HTTPS, SigV4 per run: ClickHouse (native backups, when ingest.url is set)
                    │ gRPC, mTLS, agent dials out
                 agent (per cluster) ──TCP──▶ discovered Service only
                    │ gRPC, mTLS, probe dials out (own identity)
                 probe (per cluster) ──HTTP/DNS/TCP/TLS──▶ allowlisted hosts only
```

1. **Cluster ↛ credentials.** No credential, SAS or Blob key is ever sent to an agent
   (`internal/gateway/proto_test.go` scans every proto field). Work needing credentials runs on the
   server and reaches targets through the tunnel, speaking TLS end-to-end (`e2e-tls`, default): the
   agent sees ciphertext only. Exception: a PostgreSQL target without TLS is backed up with SCRAM-SHA-256
   only (no password crosses the agent), so the agent sees the data in the clear; the target gets the
   `tls.missing` finding. `compressed` mode trades that for egress cost; enabling it always opens
   the `transfer.compressed_mode` finding. Second exception: synthetic monitoring sends the credentials
   a scenario uses to the cluster's probe for each run
   ([below](#synthetic-monitoring-credentials-in-the-cluster)). Third exception (SPEC §0's second): a native ClickHouse backup
   or restore gives ClickHouse a credential of its own, for that run's prefix of the ingest endpoint only,
   short-lived and never a storage credential ([below](#native-clickhouse-backups-the-ingest-endpoint)).
   The agent still never receives one.
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
6. **Probe identity.** The probe has no Kubernetes API access, so the agent enrolls it (after its own
   identity exists, with the same one-time token, `probe` role, or a probe-only token from *Install
   probe*) and keeps its certificate (CN `<cluster-uuid>/probe`) in `olympos-probe-identity`, the one
   extra Secret name in the agent's Role. Its serial is stored apart from the agent's: only the current
   probe certificate may connect, the previous one only to retry a renewal whose answer was lost. A probe
   identity may only use `ProbeGateway` (no tunnel, inventory or API proxy) and an agent identity never
   may. Revoking the cluster revokes both; *Revoke probe* revokes the probe alone and drops its stream.
   The probe pod: distroless, non-root, read-only root FS, no capabilities, a ServiceAccount with no
   bindings and no token, the key mounted 0440 for its group only.

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
`blobs/delete`; on S3, a policy without `s3:DeleteObject`); retention is lifecycle rules on the
`olympos-tier` tag. *Test destination* verifies delete is refused and warns otherwise. Native ClickHouse
backups keep this: ClickHouse writes to the server's ingest endpoint, never to storage, and the server writes
each object to the destinations itself, never over an existing one
([below](#native-clickhouse-backups-the-ingest-endpoint)).

No delete permission is not, on its own, "a compromised server cannot destroy the backups". The server needs
`blobs/write` and `blobs/tags/write` (S3: `s3:PutObject`, `s3:PutObjectTagging`) to write backups and set
their tier, and with them a compromised server, or a stolen credential, can re-tag a backup to a short tier
such as `test`, or overwrite it, and let the lifecycle rules delete it. Storage immutability is what closes
that gap. It is the storage owner's choice, off in the Bicep module by default
([install › Immutability (optional)](install.md#immutability-optional), SPEC §10.3.1 step 4,
`docs/spec-changes.md` #29):

- **With immutability on** (an Azure container default policy, an S3 Object Lock default retention in
  compliance mode), no version can be deleted or overwritten during the policy's period, so neither a re-tag
  nor an overwrite destroys a backup within it. A default applies to every object, whatever its tier: it holds
  every backup, dry run and probe for at least that long, and the lifecycle rules wait for it. Only a default
  of at least the longest tier protects every backup for its whole retention; a shorter one protects each
  backup for its first days. Who can weaken it:
  - Azure: an unlocked container policy can be shortened by its owner and removed once the module's
    `CanNotDelete` resource lock is lifted; the version policies under it can be shortened or removed by a
    holder of `blobs/immutableStorage/runAsSuperUser/action`; a locked policy by no one.
  - S3: the compliance retention of each object version can be shortened or removed by no one, not even root.
    The bucket's default retention, though, is a bucket setting that a principal allowed
    `s3:PutBucketObjectLockConfiguration` can lower or remove for new versions; the documented bucket policy
    leaves that to the break-glass role.

  The server has none of these permissions.
- **With it off**, the server still cannot delete, but a re-tag or an overwrite leads to a deletion through
  the lifecycle rules: a backup re-tagged `test` at the rules' next runs, usually within a day or two (the
  rules count from when the backup was written); an overwritten version when the version rules reach it, or
  sooner if the old version is re-tagged too (on S3, 1 day after the overwrite in the documented rules). On
  Azure the deleted version stays soft-deleted for the soft-delete period (30 days in the module) and can be
  restored in that time; S3 has no soft delete. A new Azure install without a policy has a plain container;
  an account deployed with the module before v0.4.0 keeps version-level support on the account and the
  container, where lifecycle deletes are expected to work once no policy covers a version, including a
  version whose shortened 1-day policy has expired (to be verified on a real account, #79).
- **On NFS** the server can delete files itself (`docs/spec-changes.md` #13); protection is storage-side
  snapshots or WORM, and the destination shows a permanent warning.

Per-tier locks, in which the server locks each object for its own tier at write time, are planned for v0.5
([#79](https://github.com/Warewave-Technology/olympos/issues/79)).

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

## Synthetic monitoring: credentials in the cluster

SPEC §0 principle 1 says credentials never enter a cluster. Synthetic monitoring is a **documented
exception** (like the `compressed` transfer mode): a scenario that logs in to a service needs its
credential where the request is made, inside the cluster. It is contained like this:

- **Stored like backup credentials**: a Key Vault reference or envelope encryption, write-only in the API,
  created and rotated by global admins only. Editors can use a credential, never read it.
- **Sealed per run, per connection.** For each connection the probe makes an HPKE key pair (RFC 9180,
  DHKEM(X25519)) in memory and sends the public key inside its mTLS stream. The server seals each run's
  credentials (only those the scenario uses) to that key, with the run and the cluster as associated
  data. Another probe, or the same probe after a reconnect, cannot open them, and a captured message
  cannot be replayed elsewhere. The certificate key only signs; it never decrypts.
- **In memory only on the probe**: never logged, never written to disk, zeroed after the run.
- **Bound hosts.** A credential is attached only to requests whose host matches its bound hosts (each
  inside the allowlist) and removed when a redirect leaves them. Values extracted from a credentialed
  exchange, or from any response of a bound host, are tainted and may only be sent to that credential's
  bound hosts (checked at save and at run time, on every redirect hop). A response that echoes the
  credential in any encoding gives no extracts at all.
- **Redaction before anything leaves the probe**: `Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, `X-Api-Key`, the credential's own header, sensitive header and JSON field names (as for
  ConfigMaps) and gitleaks matches; every form of the run's credentials and tainted values is scrubbed
  from excerpts, assertion values and error messages. Excerpts are cut to 2 KiB after redaction and can
  be switched off per scenario. Messages never carry a credential or a response body.

### The SSRF boundary

A probe makes requests from inside the cluster network, so where it may go is bounded:

- **The allowlist** (global, admin only, every change notified): a host must match a rule by whole labels.
- **Always denied**, whatever the rules: IP literals; the names `localhost` and `*.localhost`,
  `kubernetes`, `kubernetes.default` and `kubernetes.default.svc*` (any name containing the labels
  `kubernetes.default.svc`); and resolved addresses in loopback, link-local, cloud metadata
  (`169.254.169.254`, `fd00:ec2::254`, Alibaba `100.100.100.200`, Oracle `192.0.0.192`), unspecified,
  multicast, broadcast, and the Kubernetes API service IP.
- **One resolution, the checked address dialled.** The probe resolves each name once with its own stub
  resolver (it does not read `/etc/hosts` and uses no search list), checks every answer and connects to the
  address it checked, so a second DNS answer cannot rebind the connection.
- **Every redirect hop** is checked again the same way (`redirect_blocked`, `ip_denied`).
- The allowlist travels with each run with its version; a probe refuses a run that carries an older one.

### Residual risks

- A **cooperating bound server** (one inside a credential's bound hosts) can transform a credential
  (reverse, interleave) or echo part of it, so that redaction does not recognise it, and it then shows up
  in a response excerpt of a step on a bound host. A DNS alias of a bound server is not tainted, because
  taint follows names. Both need a server you already trust with the credential. `store_responses=false`
  removes the excerpt path.
- The **endpoint IPs** of the Kubernetes API server are not denied (only its service IP and names). The
  probe has no ServiceAccount token, so it reaches them unauthenticated, like any pod.
- A **compromised probe** sees the credentials of the runs sent to it while it is compromised. Revoke the
  probe (or the cluster) and rotate the credentials.
- The chart renders `olympos-probe-identity` with what is in it on every upgrade, so the probe's key ends up
  in the Helm release history; `helm rollback` or a GitOps renderer without `lookup` can overwrite the
  Secret. The agent's Secret has the same limitations.

## Native ClickHouse backups: the ingest endpoint

A native ClickHouse backup ([ClickHouse backups](clickhouse-backups.md)) is taken by ClickHouse's own `BACKUP`,
which writes to the Olympos server as if it were S3; a native restore is ClickHouse's `RESTORE`, reading back
through the same endpoint. This adds four things to the model (SPEC §0 principle 1 and §10.4, spec-changes
#27). It is all off until `ingest.url` is set.

**A listening port.** `listen.ingest` (`:9444`) speaks a small part of S3 on one bucket: list, put, the multipart
upload calls, get, and the delete of a run's `.lock`, which lives in the run's memory and never reaches storage.
Everything else (head, other deletes, copies, bucket operations) is refused `403`. Every request is signed (SigV4)
with the credential of one run; the signature is checked before a body is read, and the body's SHA-256 (and
`Content-MD5` when sent) while it streams. Over HTTPS the endpoint also accepts `UNSIGNED-PAYLOAD`, because
ClickHouse's S3 client sends it on every request over HTTPS; over plain HTTP (`devMode` only) the body must be
signed with its SHA-256, and `aws-chunked` is always refused. With `UNSIGNED-PAYLOAD` the signature no longer
covers the body, so a PutObject or UploadPart must carry a `Content-MD5` that the signature covers, which binds the
body again through its MD5 (ClickHouse 24.8 sends one, signed, on both). TLS protects the body in transit, and the
endpoint's own SHA-256 of every object goes into the signed manifest. A CompleteMultipartUpload has no
`Content-MD5`; its part list must match the parts received. Over TLS the signature then binds the body only through
its MD5: someone who saw a request's headers within the 15 minutes of clock skew (a TLS-terminating middlebox,
ClickHouse's trace log of S3 requests) could replay them, onto a key the run has not written yet, only with a body
of the same MD5, which for a body they did not choose takes an MD5 second preimage ([spec-changes](spec-changes.md)
#28). The port serves HTTPS (TLS 1.2 or later, HTTP/1.1 only), plain HTTP only in a dev build with `devMode`.
Limits per run bound what a misbehaving client can do: bytes written ([configuration](configuration.md#ingest)),
200 requests a second (30 seconds over it stops the run), the run's duration, and `ingest.maxRuns` runs at once.

**A credential that enters the cluster** (the third exception to [Cluster ↛ credentials](#trust-boundaries),
SPEC §0's second).
Each backup or restore run mints an access key and secret just before it sends its statement, and sends them
inside the `BACKUP` or `RESTORE` statement over the run's connection to the target (through the agent tunnel,
TLS end to end in `e2e-tls`). Its scope is the run:

- a backup writes and lists its own run prefix, and reads its base chain (an incremental);
- a restore reads only what its `RESTORE` reads of the copy's chain: the `.backup` file of every run, the
  definitions of the selected databases themselves (`metadata/<db>.sql`), and the definitions and data of the
  objects it creates, each resolved as ClickHouse resolves it (by size and checksum). Every other object of the
  chain is refused `403`: anything of a database left unselected, and the definition and data of an object left
  out (whose definition can hold an external source's credentials in plain text: an S3, URL or MySQL table, a
  remote dictionary). The target holds the credential while the restore runs, so the request's approval bounds
  what the target can read of the backup, not only what it creates. The `.backup` files are served whole, as
  ClickHouse needs them, and they list the name, size and checksum of every file of the backup, of the
  databases left unselected too: the target learns the backup's object and file names and sizes, not their
  contents.

It can never delete (except its own `.lock`) or overwrite: a stored object is written once, a repeat with the
same body is answered with the stored one, and another body stops the run. It ends when the run ends, after
`ingest.maxRunDuration` (6 hours), or when no signed request came in the 5 minutes after the run sent its
statement, and a server restart ends every one. The secret lives only in the server's memory; the database
keeps the key ID, the scope, the expiry and an HMAC fingerprint, and the secret is never logged, stored or
returned by the API (Olympos logs the statement with the secret replaced). ClickHouse 24.8 and 25.8 mask it
themselves (`[HIDDEN]`) in `query_log`, `system.backups`, the process list and their log, and the server
checks that a target runs 24.8 or later before it sends the statement, so an older one never receives a
secret. A stolen credential can write into its own run, up to that run's limits, or read what its restore
reads, until its run ends; it reaches no other run and no storage credential.

**A signing key.** The server signs every native run's manifest (the objects ClickHouse declared, with sizes
and SHA-256, the databases, objects and rows) with the Key Vault key `olympos-manifest` (EC P-256, ES256,
`keys/sign`), and verifies locally with its public key (`keys/get`, kept for an hour). Verification pins the key
name and the run: a manifest signed by another key of the vault, or copied from another run, does not verify,
and neither does a chain whose links (each base's run and manifest hash) do not hold. A native run whose
manifests do not verify is not restored and is not a base. Verification fails closed: when Key Vault does not
answer, an incremental becomes a full and a restore check is refused. A disabled key version stops verifying
within the hour. The signature proves that the backup is what Olympos stored; it does not prove that the source
was healthy when it was backed up.

**SQL text from the backup runs on the target.** A native `RESTORE` runs the backup's own `metadata/*.sql`, so
the rule of logical restores, "no SQL text from the backup runs on the target", is replaced for native ones by
an allowlist (SPEC §10.4). Before a restore is checked, Olympos reads every object's definition from the
verified manifests with a strict lexer (no comments, no query parameters, nothing it does not read) and lets an
object be created only when a rule matches it:

- table engines: MergeTree-family, their Replicated variants, Log-family and Memory, by name, and only on the
  `default` disk and storage policy (another disk or policy, or a disk defined inline, can be outside the
  server: an S3 disk, for example). GraphiteMergeTree and encryption codecs, which need the target's
  configuration, are left out;
- what views, materialized views and dictionaries read: every `FROM` and `JOIN` source (a `SAMPLE … OFFSET` or
  an alias does not end the clause), `IN <table>` (bare or in brackets, and the second argument of the `in`
  function family: `in`, `notIn`, `globalIn`, `globalNotIn`, `nullIn`, `notNullIn`, their `global` and
  `IgnoreSet` forms), and the object of a `dictGet*` or `joinGet` must be an object that is restored, named with
  its database (ClickHouse would resolve a name without one against the restore's session); a source followed by
  `(` is a table function and is refused, whatever its name; a dictionary's source must be the local ClickHouse
  (no `HOST` or `PORT`), with a layout from a list.

**The definition read is the one `RESTORE` runs.** ClickHouse reads a file of a backup by its size and
checksum, from the first file its `.backup` lists with them (and from the base by the same pair), and never
checks the checksum against the bytes. So a backup is refused when a definition is not the first file of its
size and checksum, when two files it wrote share a size and checksum but not their bytes, or when an unchanged
definition is held in the base under another name; an unchanged definition is taken from the base by size and
checksum, as ClickHouse takes it.

Everything else is left out with `EXCEPT TABLES` and listed with the reason. The request records that list
when it is opened and shows it to the checker; when the restore starts, the chain is checked again and the
restore refuses to start when it would leave out anything else. Replicated tables are created by Olympos from
the backup's own text with only the Keeper path and replica rewritten (`/olympos-restore/<request id>/…`) and
the backup's UUID removed, so a restored table never joins the source's replicas; a materialized view whose
inner table is Replicated is left out, because `RESTORE` would create that table with the source's path. Only
`Atomic` databases are restored. The `RESTORE` reads only the objects of the verified manifests it needs, each
checked against its SHA-256 while it streams (and served whole: a ranged read is refused), and ClickHouse's
server-side S3 copy is off (`allow_s3_native_copy = 0`), so nothing reaches the target past that check. It runs
with the first restored database as its session's database, which held nothing before the restore, so a name
without its database could only reach what the restore creates. After the `RESTORE` (also one that failed or was
ended), each allowed object's engine and `create_table_query` must be its approved definition (without its
UUIDs, a dictionary's password shown as `[HIDDEN]`), which the allowlist must allow again; an object other than
approved, or one that was left out, is dropped and the restore fails naming it. An object the restore was not
to create at all is named, never dropped. ClickHouse shows the arguments of `encrypt`, `decrypt`, `tryDecrypt`,
`aes_encrypt_mysql` and `aes_decrypt_mysql` from the second on as one `'[HIDDEN]'`, and that form is accepted:
what those arguments hold on the target is the one part of a definition this comparison cannot see. So the
allowlist takes only a literal or a column name there, which cannot read anything (an object with a call, a
subquery, an expression or a table name there is left out, *it calls decrypt with an argument that is not a
literal or a column …*), and the checks of the backup's files above bind the text.

**Checks are bounded.** Checking a native copy holds its chain in memory. The API's checks share 2 slots and a
user runs one at a time (a second is refused at once); the check at the start of an approved restore has a
slot of its own, so checks sent in a loop cannot hold up an approved restore; a check ends after 5 minutes. ClickHouse's error
messages, which can quote the DDL, are kept only as code, name and the start of their first line.

What the allowlist does **not** check, by design or because it cannot:

- **Scalar functions** are checked against a list of functions known to read outside the server (`url`, `s3`,
  `file`, `remote`, `mysql`, `executable` and the other table-function names, `hasColumnInTable`, the model
  evaluation functions), not against an allowlist. A function outside that list that reads outside the server
  is not caught. **Executable user-defined functions** are defined in the target's own configuration, so a
  call to one looks like any other function call: the allowlist cannot tell. They exist only on a target whose
  administrator configured them.
- `x IN f(…)` is read as a table function for any `f` other than `tuple` and `array`, so an object that uses a
  scalar function there (`IN range(10)`) is left out although it is harmless: the safe direction.
- A dictionary with a local ClickHouse source keeps its `USER` and `PASSWORD`: they are part of the backup's DDL
  and are restored with it.

### Residual risks

- **A compromised source** can write what it wants into its own run, up to the run's byte limit, and declare it
  in its `.backup`; the signature then vouches for what it sent. The allowlist bounds what that DDL can do on a
  target, and a restore never goes into the source itself.
- **ClickHouse 24.8 stores a dead secret.** An incremental's `.backup` on 24.8 keeps the run's own secret in its
  `<base_backup>` setting, so the stored backup holds a credential. It was revoked when the run ended and lived
  only in that run's session, so it opens nothing. 25.8 stores none.
- **In `compressed` transfer mode** the statement, and with it the run's credential, crosses the agent and the
  node network in the clear, as the backup data does there for logical backups (the `transfer.compressed_mode`
  finding). The backup data of a native run never crosses the agent: ClickHouse sends it to the endpoint over
  HTTPS.
- **New egress from the cluster.** The ClickHouse pods connect to the server's ingest port, a path into the
  server besides the agents' gateway. It accepts only signed requests of a running run.

## Residual risks / accepted trade-offs

- A compromised server can *write* Vault secrets (create/patch) but still cannot read them; drift
  detection only catches writes that bypass Olympos, so the change-request trail is the control here.
- In `compressed` transfer mode the agent can observe backup data in cleartext (visible finding).
- **Backups without storage immutability** can be destroyed by a compromised server through a re-tag or an
  overwrite and the lifecycle rules, though it cannot delete them ([Backups](#backups)). Immutability is the
  storage owner's choice in v0.4, and a default keeps every object at least its period; per-tier locks are
  planned for v0.5 ([#79](https://github.com/Warewave-Technology/olympos/issues/79)).
- **Restores write to clusters.** A restore is the one path where the server writes data into a target:
  the new server it restores into, through that target's agent tunnel, with the admin login or Vault
  token given for the request. Controls: only targets the agent discovered, never the backup's own, no
  drop or overwrite, the SHA-256 checked before any write, a second person's approval or a recorded,
  notified break-glass, and the credential deleted when the request ends. A compromised server could still
  write to any discovered target whose admin credential it is given.
- In `compressed` transfer mode the agent can also observe **restore** data in cleartext, and the restore
  credential too when the target has no TLS: the same trade-off and finding as for backups.
- kube-bench pods are privileged-adjacent (`hostPID`, read-only host mounts) by necessity; opt-in only.
- Dev mode (local key vault, dev login) must never be enabled in production; the server logs a loud
  warning and the config validator refuses `keyVault.provider=local` without it.
