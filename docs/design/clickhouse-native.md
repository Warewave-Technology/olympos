# ClickHouse native backup through an Olympos S3 endpoint (#62)

Status: approved by the owner on 2026-11-25, with option 1 of *Owner decision* below (an allowlist on the
parsed definitions, no opt-in). The decisions marked *my call* came from an independent builder check. The approach (ClickHouse writes to Olympos, which looks like
S3) was approved in the v0.4 plan. This page turns it into a design, with the spike's findings
([clickhouse-native-spike.md](clickhouse-native-spike.md)) and the code as it is today.

## Why

Today's ClickHouse backup is logical: one `SELECT` per partition, and a restore that regenerates DDL. It loses
views, materialized views, dictionaries, defaults, TTLs, skip indexes and codecs, and it is not consistent
across a table. ClickHouse's own `BACKUP`/`RESTORE` keeps all of that, is consistent per table, fast and
compressed, and supports incrementals. Letting ClickHouse write straight to Blob or S3 would break the rule that
the Olympos server is the only writer to backup storage, so ClickHouse writes to Olympos.

## Goals

- A ClickHouse job can be **native**: a full backup and optional incrementals, stored on the job's destination
  or destination group like any other backup, restored into a new target through the existing maker/checker
  restore.
- Nothing about storage changes for the operator: same destinations, same tiers, same "the server never
  deletes".
- What enters the cluster is one short-lived credential per run, scoped to that run.

Non-goals: restoring native backups in place (into the source database); point-in-time restore; ClickHouse on
S3 disks copying server-side (disabled, below); backups of `system` databases.

Anti-goals: a restored Replicated table that joins the source's replica set; a backup that reports success
without a signed manifest; any path that lets ClickHouse delete or overwrite stored objects.

## Approaches

**The endpoint.**

1. **Our own minimal S3 handler (chosen).** About seven operations on one bucket, deny by default. The spike's
   277-line version ran full, incremental and restore unchanged on 24.8 and 25.8.
2. *gofakes3.* Rejected: it has no SigV4 check, and its whole-object backend model fights the write-through.
3. *versitygw.* Rejected: a full gateway with its own IAM and backends, which is a large dependency for a part
   of the security model.

**How ClickHouse reaches the endpoint.** The v0.4 plan decided this: directly over TLS, not through the agent
tunnel (point 8 of #62). The alternative is an S3 proxy in the agent that forwards over the tunnel; it would
keep the cluster's only egress at the gateway, at the cost of all backup bytes going through the agent and of a
listening port in the agent. It stays out.

**The lock file.** A refused delete of `.lock` fails the backup (spike §2), so the endpoint keeps each run's
`.lock` in memory, and its delete is real. The alternative, telling ClickHouse that a delete succeeded when
nothing was deleted, was rejected.

## Design

### 1. The ingest endpoint

- **Listener and certificate.**
  - Config: `listen.ingest` (default `:9444`; empty turns the endpoint off) and `ingest.url`, the base URL
    clusters use (for example `https://olympos-ingest.contoso.internal:9444`).
  - Certificate: `ingest.tlsCertFile` and `ingest.tlsKeyFile`, reloaded on SIGHUP like the gateway's. Without
    them the server uses an internal-CA certificate for the host of `ingest.url`.
  - Helm: `ingestTLSSecret`, a Service port and a container port, the same as the gateway.
  - It is a fourth listener in `internal/app` (raise the `errc` channel).
- **One bucket.** Every request is under `/olympos/`; the URL given to ClickHouse is
  `<ingest.url>/olympos/<run-id>/`. Virtual-host style addressing is refused.
- **Operations.** Only these; everything else gets `403 AccessDenied`:

  | Operation | Allowed when |
  |---|---|
  | `ListObjects` v1 (bucket level, `prefix`, `max-keys`, `marker`) | `prefix` lies inside a prefix the credential may read or write |
  | `PutObject`, `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` | write credential, key inside its own run prefix |
  | `GetObject` (`Range` supported, though not seen) | read: a credential that may read that prefix; a backup also reads back its own `.lock` and `.backup` |
  | `DeleteObject <run-id>/.lock` | write credential of that run (memory only, see below) |

  Never allowed: other deletes, `DeleteObjects`, `CopyObject`, `UploadPartCopy`, `HeadBucket` and other bucket
  operations, and `ListObjectsV2`. `ListObjectsV2` can be added if a ClickHouse version needs it, with the same
  prefix rule.
- **SigV4.**
  - The header signature is checked before the body is read. Errors are `SignatureDoesNotMatch` and
    `InvalidAccessKeyId`.
  - The body's SHA-256 is computed while it streams and compared with `x-amz-content-sha256` at the end, and
    the same for `Content-MD5` when it is sent.
  - `UNSIGNED-PAYLOAD` and `aws-chunked` are refused.
  - The signature code is tested against AWS's published SigV4 test vectors.
- **The `.lock`.** `PUT`, `GET` and `List` of `<run-id>/.lock` use a map in the run's session; `DELETE` removes
  it. It never reaches storage, and it is not in the manifest.
- **Refusals.** Every deliberate refusal is a `403` with an S3 error body, because ClickHouse does not retry
  those on `List`. A failure during the run is never handed back for ClickHouse to retry: a retried `PutObject`
  would hit an object that already exists, and a streamed multipart cannot be resumed.
- **A destination fails one object (my call).** Its copy is detached for the rest of the run, as `FanOut`
  detaches a failing destination today. The request still succeeds while at least one destination took the
  object. The run ends `partial` with that copy failed, and the copy's objects stay `incomplete`. When no
  destination is left, the request gets `403` and the run is ended (§4, step 6).
- **A body does not match its hash** (`x-amz-content-sha256` or `Content-MD5`), or the connection drops in the
  middle of a body. The object has already streamed to the destinations, so the run fails: `400 BadDigest` (or
  nothing, on a dropped connection), then `KILL QUERY`. ClickHouse sends correct bodies over TLS, so either case
  means a fault worth stopping for.
- **Decided while building Milestone A.**
  - The endpoint is on only when `ingest.url` is set; `listen.ingest` is the address used then (R14). This
    replaces "empty `listen.ingest` turns the endpoint off" above.
  - An `http://` `ingest.url` serves plain HTTP and is accepted only with `devMode` (R16).
  - The listener speaks HTTP/1.1 only, as ClickHouse does, and drops idle connections after 120 s. A body has no
    read or write timeout; the session bounds the run.

### 2. Per-run credentials

- **Minting.** A backup run mints an access key ID (`OLY` plus 17 random base32 characters) and a 40-character
  secret just before it sends the statement.
- **Scope.** The scope is tied to the run:
  - **backup:** write and list its own prefix; read and list its base chain (an incremental, spike §5);
  - **restore:** read and list the chain of the selected copy.
- **Lifetime (my call).** Jobs have no timeout today, so the credential ends at the earliest of:
  - the run's end;
  - `ingest.maxRunDuration` after it is minted (default 6 h, configurable). A run that reaches it is ended
    with `KILL QUERY`.
  A restore's credential is minted when the restore starts executing, not when it is approved, and has the same
  limit.
- **Storage (my call: memory only).** SigV4 needs the secret itself to check a signature, so a hash cannot
  verify requests. The secret lives only in the server's memory for the run. The database records the key ID,
  the scope, the expiry, and an `hm:` fingerprint for audit; the secret is never logged, persisted or returned
  by the API. A server restart ends every running native run (its credentials are gone), and the scheduler's
  retry rules apply. That is acceptable for a single-replica server.
- **Never logged.** The agent and the server never log the statement that carries the secret; they log the
  run ID and the statement with the secret replaced. The spike showed that ClickHouse masks the secret
  (`[HIDDEN]`) in `query_log`, `system.backups`, `processes` and its server log (24.8, 25.8). `docs/install.md`
  says so and points to `query_masking_rules` for older versions.

### 3. Storage layout and write-through

- A native run is a directory:
  `<dest prefix>/<cluster>/<ns>/<service>/clickhouse/YYYY/MM/DD/<run-id>/<key>`, where `<key>` is
  ClickHouse's own (`.backup`, `metadata/…`, `data/…`). The manifest is `<run-id>.manifest.json` next to the
  directory, as for logical runs.
- Each object streams through `blob.Writer.Upload` to every destination of the job (the existing
  `NewFanOut`) with the tags `olympos-state=incomplete` and `olympos-tier=<tier>`.
  - It is not staged first.
  - It is not overwritten: `Upload` already refuses an existing name.
  - The endpoint keeps each object's size and SHA-256 per destination for the manifest.
- **Multipart.** Parts are not stored as parts. The endpoint streams `UploadPart` bodies in order into one
  `Upload` per object. A part that arrives out of order is held on local disk, under a per-run byte limit, until
  its turn. `CompleteMultipartUpload` closes the stream. ClickHouse sends parts in order (spike), so the disk
  limit is a safeguard.
- **Decided while building Milestone A (R18).** This replaces "ClickHouse sends parts in order, so the disk limit
  is a safeguard" above.
  - ClickHouse uploads parts in parallel, so parts do arrive out of order.
  - An out-of-order part whose `Content-Length` would take the run's spill over its 1 GiB budget gets
    `503 SlowDown` before its body is read. ClickHouse sends it again later; the run continues.
  - The next part in order is always accepted, so an upload always moves on. One that arrives while the
    previous part is still being written is held on disk without the budget check, so the spill can exceed
    1 GiB by one part.
  - An `UploadPart` without a `Content-Length` is refused `403`. A full budget never ends a run; a disk error
    while holding a part still does.
- **Lifecycle.** A lifecycle rule (Bicep and docs) deletes objects tagged `olympos-state=incomplete` after 7
  days. With the container's version-level immutability as it is today (the longest retention), that rule, like
  the existing 7-day daily rule, cannot delete before the immutability period ends. That is an existing issue of
  the storage template, tracked on its own; native backups add nothing to it. NFS has no tags-based lifecycle: incomplete runs are listed
  in the docs' NFS cleanup procedure, like today's partial files.

### 4. The backup run

1. The worker checks the target:
   - ClickHouse 24.8 or later (`version()`);
   - the databases;
   - no sharding (my call): a selected database with a `Distributed` table, or a host in a `system.clusters`
     cluster with more than one shard, is refused for the native method with a message. A `BACKUP` without
     `ON CLUSTER` would save one shard and report success. `ON CLUSTER` is a later step.
2. It mints the credential and opens an ingest session for the run.
3. It opens **one** connection to the target through the tunnel (`Dial` and ch-go, as the logical engine
   does) and keeps it for the run. The statement, the polls and a `KILL` all go over it: `system.backups` is per
   node, and a Service may route a new connection to another pod. If the connection drops, the run fails; the
   credential is revoked, so the pod's backup can write nothing more. It sends:
   ```sql
   BACKUP DATABASE db1, DATABASE db2 TO S3('<url>/olympos/<run-id>/', '<key>', '<secret>')
   SETTINGS async = 1, allow_s3_native_copy = 0, id = '<run-id>'
            [, base_backup = S3('<url>/olympos/<base-run-id>/', '<key>', '<secret>')]
   ```
4. It polls `system.backups WHERE id = '<run-id>'` every 5 s over that connection.
5. On `BACKUP_CREATED`:
   1. The endpoint gets the `.backup` metadata, which it kept a copy of while the object streamed.
   2. It parses `.backup` (XML: files, sizes, checksums, base backup) and checks that every file it lists
      that is not in the base was written and closed.
   3. It builds the manifest (§5), signs it and writes it to each destination.
   4. It re-tags every object to `olympos-state=complete` with its tier (`SetTags`).
   5. It revokes the credential, and the run succeeds.
6. On failure (`BACKUP_FAILED`, a timeout, a quota, a lost tunnel), the server sends `KILL QUERY WHERE
   query_id = …` and checks that `system.backups` reports `BACKUP_FAILED` (spike §3). It then revokes the
   credential, and the run fails. The objects stay `incomplete`.

**Test runs (R40).** A test run (the wizard's dry run) sends the same statement with `structure_only = 1`.
ClickHouse then writes only `metadata/*.sql` and `.backup` (seen on 24.8 and 25.8), so the run checks egress,
the certificate, the credential, the signed manifest and the tags in seconds, whatever the databases hold. Its
manifest records the setting and has no part rows. It is not the last full of the byte limit (§9), and not a
base (§7).

**Left-over backups (R41).** A server crash or a lost agent can leave a run's `BACKUP` running on the target,
retrying refused uploads, with nothing to end it. Before its `BACKUP` every run reads the native backups running
on the server it reached (`system.processes`, query ids `olympos-backup-<run-id>`), and the worker ends with
`KILL QUERY … SYNC`, on the run's connection, those whose runs are not `running` in the database. The backup of
a run still running (another job on the same target) is never ended, nor one of a run the database does not
know. The error of a run that may have left one, and the restart error, name the `KILL QUERY` to run by hand.

### 5. The signed manifest

- **Format.** `olympos.clickhouse.native/v1`, inside the existing sidecar's `Details`:
  - every object: key, size, SHA-256;
  - ClickHouse version, backup settings, base run ID and its manifest's SHA-256;
  - the databases, tables, dictionaries and views, from the `metadata/*.sql` objects;
  - rows per table: the endpoint keeps the body of every part's `count.txt` (a few bytes) while it streams, and
    the manifest sums them per table. Parts that an incremental takes from its base are counted from the base's
    manifest. This is the count of the `BACKUP` snapshot itself, so the post-restore check compares like with
    like.
- **Signature.** A new Key Vault key `keyVault.manifestKeyName` (default `olympos-manifest`, EC P-256, sign and
  verify only) signs the manifest's canonical JSON (ES256). The sidecar carries `signature` and `key_id` (the
  key version).
  - `secrets.KeyVault` gains `Sign(ctx, name, digest)` and `Verify(ctx, keyID, digest, sig)`: `azkeys` in
    Azure, a key file in the dev Key Vault.
  - The install docs add the key, and the managed identity's `keys/sign` and `keys/get` permissions on it.
- **Key versions.** A version that signed a manifest stays enabled for as long as any backup it signed is
  within retention (the longest tier, plus the time a restore may take). The install docs say so, and
  rotation keeps old versions.
- **No signature, no run.** A native run whose manifest does not verify does not exist for restore. Logical
  runs keep their unsigned sidecars, unchanged.
- **Decided while building Milestone B.**
  - The managed identity needs `keys/get`, not `keys/verify` (R25): Olympos verifies locally with the public
    key it fetches (cached for an hour), and never calls the vault's verify.
  - A DDL key may name an object of any run in the chain, not only the manifest's own run (R23): ClickHouse
    stores unchanged metadata once and an incremental reuses its base's. A single manifest checks its own
    keys: every object is under its run, every DDL key is `<run-id>/<path>`, and a DDL key under its own run
    is one of its objects. `VerifyChain` verifies a chain, base first. It checks:
    - the links: each base run ID and canonical SHA-256 is the previous manifest's;
    - that the last manifest is the expected run;
    - that every DDL key is one of the chain's objects;
    - that no run is in the chain twice.

    A full backup is a chain of one.
  - `VerifySigned` takes the expected run ID and refuses another run's manifest before the vault is asked
    (R24), so a sidecar copied from another run does not verify.
  - Run IDs, base run IDs and the run part of a DDL key are canonical lower-case UUIDs (as `uuid.UUID.String()`
    writes them), and a base is never the run itself.

### 6. Restore

The existing flow, with these changes for a native source:

- **Check** (`POST /restores/check`):
  - Verify the manifest signature of the selected copy and of every base in its chain.
  - List the databases, tables, dictionaries and views from the manifest.
  - Decide what is restored with the allowlist (*Owner decision*, option 1): Olympos parses each object's
    `metadata/*.sql` from the verified manifest. Whatever is not allowed goes into `EXCEPT TABLES` and is
    listed in the request and the result with the reason; the maker cannot select it.
- **Names and targets.** As today: the databases keep their names, and the target is another service (a new
  target, never the source). Renaming is not part of this.
- **Execute:**
  1. Mint a read-only credential over the chain.
  2. Create the target databases.
  3. Create every Replicated table from the backup's own `CREATE TABLE` text, changing only the
     `ReplicatedMergeTree` engine's first two arguments to `/olympos-restore/<request id>/<db>/<table>` and
     `{replica}` (`keeperPath`, spike §8). The text is not rebuilt by today's parser, which would drop codecs,
     TTLs and indexes. A statement whose engine arguments cannot be found exactly is refused at check time.
  4. Run:
     ```sql
     RESTORE DATABASE db1 [EXCEPT TABLES …] FROM S3('<url>/olympos/<run-id>/', '<key>', '<secret>')
     SETTINGS async = 1, allow_different_table_def = 1, id = '<request-id>'
     ```
     `allow_different_table_def` applies only to tables that already exist, which are the Replicated tables
     Olympos just created from the backup's own DDL.
  5. Poll as in a backup.
- **Serving reads.**
  - The endpoint serves only objects listed in a verified manifest of the chain.
  - It reads them from the copy's destination and checks each object's SHA-256 while streaming. On a mismatch
    it aborts the connection, so the `GET` fails and the restore with it, and it reports the object.
- **Afterwards.** The existing post-restore checks run: row counts per table against the manifest.

### 7. Incrementals

- **Job option.** `incremental`: off, or "weekly full, daily incrementals" (a full on the first run of the
  week, by the job's timezone, an incremental otherwise).
- **The base (my call).** The latest run of the same job that **succeeded on every destination** and whose
  manifests verify. One `BACKUP` statement writes the same backup to every destination, so its base must exist,
  identical, on each of them. A `partial` run is never a base, and the next run after one is a full. A test run
  is never a base either: it holds no data (R40). The base's
  reads are served from the first destination of the group that holds it.
- **Repairs (my call).** They are off for native runs. A repair runs the engine again, so it would be a
  different backup, with a different snapshot, under the same run. The next scheduled run (a full after a
  partial one) is the remedy, and the run page says so.
- **Retention.** A base must outlive every incremental that depends on it. When an incremental's tier is longer
  than its base's (a monthly incremental on a weekly full), the server re-tags the base chain's objects and
  manifests to that tier.
- **Restore.** A restore resolves the chain from the manifests and verifies every link (§6).

### 8. Network and TLS

- ClickHouse connects to `ingest.url` directly, so the cluster needs egress from the ClickHouse pods to the
  Olympos server on that port. The docs give a NetworkPolicy example.
- ClickHouse must trust the endpoint's certificate:
  - **Recommended:** a certificate from the customer's PKI or a public CA.
  - **Otherwise:** the Olympos CA in ClickHouse's `openSSL.client.caConfig`. The docs show the config.d file.
- Transfer modes (`e2e-tls`, `compressed`) do not apply to this path. The job page says so.

### 9. Limits and metrics

- **Bytes per run (R39).** A run may write the largest of twice its job's last full native run (not a test
  run), 1.5 times the size on disk of its databases (`bytes_on_disk` of their active parts, read on the target
  before the `BACKUP`) and 1 GiB. `ingest.maxRunBytes` replaces it when set. Bytes ClickHouse sends again for an
  object already stored (a repeat, R35) are drained and not counted.
- **Requests per run.** 200 per second.
- **Concurrent runs.** At most `ingest.maxRuns` (default 4).
- **Over a limit.** The request gets `403`, and the run is ended with `KILL QUERY`.
- **Metrics.** `/metrics`: `olympos_ingest_requests_total{op,code}`, `olympos_ingest_bytes_total`,
  `olympos_ingest_runs` and `olympos_ingest_refused_total{reason}`.
- **Decided while building Milestone A.**
  - Over the request rate the endpoint answers `503 SlowDown` before the body is read, and the run continues.
    Only 30 s in a row over the rate stops the run (R17). For the rate, this replaces "over a limit → `403` and
    `KILL`"; the byte quota keeps `403` and `KILL`.
  - The endpoint is on only with `ingest.url`, plain HTTP only with `devMode` (R14, R16); see §1.
  - An extra metric, `olympos_ingest_stops_total{reason}`, counts the runs the endpoint stopped, by reason.

### 10. Job setting, UI, docs

- **Job setting.** `engine_options.method`: `native` or `logical` (the default for existing jobs, which keep
  their behaviour). New ClickHouse jobs default to `native` when the endpoint is configured and the target is
  24.8 or later.
- **UI.** The backup wizard gets a ClickHouse step:
  - the method;
  - incrementals (native only);
  - a note on egress and the certificate.

  The restore dialog shows the object list with the risky ones flagged. Mockups come first:
  `backup-wizard-2-credentials.html` (or a new step) and the restore dialog.
- **Docs.**
  - `docs/backup-engines.md` (or the ClickHouse section): native vs logical, versions, what is kept,
    incrementals.
  - `docs/install.md`: the endpoint, its certificate, the Key Vault key, egress.
  - `docs/security-model.md`: the new listener and the per-run credential entering the cluster.
  - A `docs/spec-changes.md` row (27), the CHANGELOG, OpenAPI.

## Owner decision: SQL text from the backup on the target (decided: option 1)

SPEC §10.4 says: "ClickHouse: no SQL text from the backup runs on the target." Olympos generates the DDL
instead. It was decided for v0.2 (spec-changes row 20) because validating source DDL "could be bypassed again
and again in review". A native `RESTORE` cannot keep that rule: ClickHouse runs the backup's own
`metadata/*.sql`. That is also how it keeps views, materialized views, dictionaries, codecs and TTLs, which is
the point of #62. The manifest's signature proves the DDL is what Olympos stored; it does not prove the source
was not compromised when it was backed up.

Options; the owner chose **1** on 2026-11-25:

1. **Allowlist on the parsed definitions (recommended).** Olympos parses every object in the manifest and
   restores only what it can prove harmless:
   - MergeTree-family, Replicated, Log and Memory tables, with any column and table features (codecs, TTL,
     defaults, indexes, projections, settings). These cannot reach outside the server;
   - views and materialized views whose query reads only tables in the restored set, with no table functions;
   - dictionaries with a local ClickHouse source in the restored set.

   Everything else is left out (`EXCEPT TABLES`) and listed for the operator, as today. That covers other
   engines, anything the parser cannot read with certainty, and anything that names a host, a URL, a file or a
   command. The parser gates what is allowed; it does not filter what is denied. A mistake can therefore only
   leave something out, never let something in. SPEC §10.4 gets a native rule, and spec-changes row 27.
2. *Allowlist, with an opt-in.* As 1, but the maker may select a left-out object, and the checker sees it
   flagged before approving. Not chosen: a left-out object is re-applied by the operator after the restore,
   as today.
3. **Denylist** (as #62 is written). Restore everything except known risky constructs. Rejected by me: it is
   the validation the v0.2 decision distrusted.

## Security model

This is a security-model change (`internal/secrets` gains Sign and Verify), so its release needs an RC, a
focused lab test plan and an independent review (#60). New in the model:

- a listening port, authenticated per run;
- a credential that enters the cluster: short-lived, scoped to one run prefix, write-only for a backup and
  read-only for a restore. It is a documented exception to "Cluster ↛ credentials";
- a signing key in Key Vault;
- backup SQL text running on the target, limited by the allowlist: SPEC §10.4 and spec-changes row 27.

## Tests

- **Unit.**
  - SigV4 against the AWS test vectors.
  - Every handler operation, allowed and refused: prefix, scope, expiry, `.lock`, deletes, out-of-order parts.
  - The manifest's canonical JSON and its signature.
  - The `.backup` parser on a real `.backup` from 24.8 and 25.8.
- **Integration** (Docker, 24.8 and 25.8):
  - full and incremental to Azurite and to MinIO, restore into a new database, hashes;
  - a refused `DELETE` of data;
  - a credential used after its run;
  - one byte changed in an object or in the manifest is refused;
  - `KILL` on a quota.
- **e2e** (the done-when of #62):
  - a ClickHouse with codecs, a TTL, defaults, skip indexes, a dictionary, a view, an MV feeding an aggregate,
    and a `ReplicatedMergeTree`;
  - backed up natively (full and one incremental) to Blob and to S3, and restored into a new target;
  - the MV keeps working, counts and hashes match, and the source's replica set is untouched;
  - tampering is refused, a `DELETE` from ClickHouse is refused, and the credential stops working after the
    run;
  - the secret is in no Olympos log or table.

## Left to the builder

The package layout (`internal/ingest` is the obvious one); the exact canonical JSON; the poll and retry
intervals; the metric label sets; how the wizard step is split.
