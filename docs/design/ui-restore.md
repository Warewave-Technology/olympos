# Restore from the UI into a new target, with approval

Status: design, approved by the owner on 2026-11-23. Tracks issue #22 (milestone v0.2).

## Intent

Restore is manual today: every successful run shows ready-to-copy commands for its copy (download, verify,
restore) and `docs/restore.md` has the procedures. In a disaster this means someone with storage access,
the right client tools and the target's credentials types the commands by hand, under pressure.

The owner's use case is **disaster recovery**: the source is gone or broken, and a backup must be loaded into
a new database or Vault quickly and correctly so that applications can be pointed at it. Olympos already holds
everything needed: the backup copies with their manifests and checksums, the tunnels into every cluster, and
the engines that wrote the backups.

## Decisions taken with the owner

1. **Use case: disaster recovery.** Speed and correctness matter more than convenience features (no restore
   tests, schedules or result comparison in this work).
2. **Approval: maker/checker with a break-glass path.** A restore copies production data into another
   system, so it is a data exfiltration path: it needs a second person, like Vault changes. An admin may
   start their own request at once as **break-glass**, with a mandatory justification; that is recorded in the
   audit log and sends a critical notification (`restore.break_glass`).
3. **Target: a target Olympos discovered, in any cluster, never the source.** Olympos does not create
   targets: the operator deploys the new PostgreSQL, ClickHouse or Vault, annotates its Service, and the agent
   discovers it. It may be in another cluster than the backup's source (the source cluster may be gone).
4. **No overwrite.** A restore is refused when any database it would create already exists on the target
   with data in it. Nothing on the target is dropped or replaced. For Vault, the target must not be a Vault
   configured in Olympos. (My call, from the builder check: the databases every fresh server has, PostgreSQL's
   `postgres` and ClickHouse's `default`, are in most backups; such a database that exists on the target but
   holds no user objects counts as empty and is restored into, without `CREATE DATABASE`.)
5. **Engines: PostgreSQL, ClickHouse and Vault/OpenBao** in this work.
6. **ClickHouse data goes through `clickhouse-client`,** added to the server image, so tables with types the
   Go client cannot decode are restored too (the image grows; accepted).
7. **Approach 1 of the three below:** restore requests are their own object with their own tables; the
   maker/checker rules are shared with Vault change requests.

## Goals

- Start a restore from a run's details (*Restore…*): pick the copy (for group runs), the target, the
  databases (PostgreSQL, ClickHouse; default all in the backup), the target's admin credential, and a
  justification. Admins see *Break-glass: start now*.
- The request appears under *Approvals* next to Vault change requests; a checker approves or rejects it;
  pending requests expire.
- The server runs the approved restore through the target's agent tunnel, reading the copy directly from
  its destination: no temporary files, nothing sent to the cluster but the target's own protocol.
- The backup is verified before anything is written: the copy's SHA-256 against the run's copy row and
  manifest, and every zip entry's CRC while reading.
- Progress while it runs (current database or table, bytes read) and a result per database (or for the
  snapshot): status, bytes, duration, tables restored, rows written (ClickHouse), errors.
- Vault/OpenBao: the snapshot is loaded with `snapshot-force` using a token of the new Vault given once for
  this request; the result screen says that the new Vault must now be unsealed with the **source's** unseal
  keys (or the same auto-unseal KMS) and that its root token and policies are the source's.
- Events `restore.requested`, `restore.approved`, `restore.rejected`, `restore.started`,
  `restore.succeeded`, `restore.failed`, `restore.break_glass`; every step in the audit log.
- Docs: a *Restore from the UI* section in `docs/restore.md` with lab screenshots, the Vault unseal caveat,
  events in `docs/findings-and-events.md`, SPEC §10.4 and a spec-changes row.

## Non-goals

- Restoring over the source target, or over existing databases on any target (no `--clean`, no drop).
- Creating targets, namespaces or users; unsealing Vault; pointing applications at the new target.
- Point-in-time recovery, WAL replay, table-level PostgreSQL restore (databases only; ClickHouse also
  databases only in the UI, the archive keeps tables).
- Scheduled or automatic restore tests, comparing restored data with the source.
- Restoring `olympos-self` from the UI (Olympos' own database is restored with the server stopped:
  `docs/restore-olympos.md`).
- Cleaning up after a failed restore: databases the restore created stay, are listed in the result, and are
  the operator's to drop.

## Anti-goals (failures even if everything "works")

- Any write to the source target, or a change to existing data on the target.
- A restore that starts writing before the backup is verified, or that reports success for a corrupted copy.
- One person moving data out of a cluster without a second person's approval, except through the recorded,
  notified break-glass path.
- Target credentials or a Vault token kept after the request ends, logged, or sent to a cluster.
- Rows or tables silently missing: every entry of the archive is either restored or reported.

## Constraints

- Plain pgx, goose migrations, append-only audit/activity, Turkish to the owner but English in code, docs
  and UI.
- Tunnels only to targets the agent discovered; the server is the only reader of backup storage (the
  existing destination credentials need read, which they have: the destination test reads its probe back).
- Authorization (no new roles): the maker needs `read` on the run's cluster and `operate` on the target's
  cluster; the checker must be another person with `operate` on both clusters; break-glass needs `admin` on
  both clusters. Checker and maker are compared by (tenant, object id), as for Vault changes.
- Request credentials and the Vault token are envelope-encrypted while the request is open (like
  `change_items.sealed_value`) or given as Key Vault references; they are wiped in every terminal state.
- One restore at a time per target; restores count against the agent's tunnel limit like backups.
- PostgreSQL tools: `pg_restore` (major ≥ the dump's) is already in the server image; `globals.sql` is
  executed over the tunnel connection (simple protocol), no `psql` needed.
- ClickHouse tools: `clickhouse-client` (a pinned version, checksum-verified like the other tools in
  `deploy/tools.env`) is added to the server image; the `.deb`/`.rpm` recommend the distribution's
  `clickhouse-client`, and the server finds it like `pg_dump` (`backup.clickhouseClient` path setting). The
  image grows by the size of the ClickHouse binary; that cost was accepted.

## Approaches considered

1. **Restore requests as their own object (chosen).** New `restore_requests` table with its lifecycle
   (`pending → approved → running → succeeded | failed`, plus `rejected`, `expired`, `cancelled`). The pure
   maker/checker rules in `internal/approvals` (who may open, decide, cancel; expiry) are extracted so both
   kinds use one implementation. The backup worker claims approved restores the way it claims runs (only
   when the target's agent is connected to this replica). Engines gain a restore direction. The *Approvals*
   page lists both kinds.
2. **Generalise `change_requests`.** `vault_id` optional, a `kind` column, a restore as a change item.
   Reuses the API and UI, but that table is tied to Vault (CAS versions, sealed values per key, the
   reconciler that settles requests from KV metadata); mixing restores in would complicate both.
3. **A restore as a kind of backup run.** Reuses the worker, but backup runs are append-only records of
   backups (retention tiers, copies, dashboard counts all assume a backup) and have no approval flow.
   Rejected.

## Design

### Data model (one migration)

- `restore_requests`: `id`, `source_run_id` (→ `backup_runs`), `source_destination_id` (the copy, →
  `destinations`), `source_engine`, `target_id` (→ `targets`), `databases text[]` (empty for Vault),
  `options jsonb` (e.g. `globals`, and an optional `tls_ca_pem` to verify the target's certificate, since a
  new target has no job whose options carry one; shown to the checker), `credential_id` (→ `credentials`, the target's admin login; stored or
  Key Vault reference), `sealed_token`/`wrapped_dek` (Vault only), `maker_principal_id`, `justification`,
  `break_glass bool`, `status` (as above), `expires_at`, `checker_principal_id`, `decided_at`,
  `decision_comment`, `started_at`, `finished_at`, `progress jsonb`, `result jsonb` (per database / the
  snapshot), `error`, timestamps. `CHECK (checker_principal_id IS NULL OR checker_principal_id <>
  maker_principal_id)`; with `break_glass` the maker is recorded as the decider and `checker_principal_id`
  stays NULL.
- Terminal states wipe `sealed_token`, `wrapped_dek` and delete a stored `credential_id` row (a Key
  Vault reference row is deleted too; the secret in Key Vault is the operator's).
- A partial unique index allows one `approved` or `running` request per target.
- Pending requests expire like Vault change requests; **approved requests that have not started expire 24
  hours after approval** (agent offline, for example), which frees the target and wipes the credential and
  token. (My call.)

### Rules checked when a request is opened (and again when it starts)

- The source run is `succeeded` or `partial`, not a test run, and the chosen copy is a `succeeded` copy of
  it (or of one of its repairs, as the restore guide offers).
- The target has the same engine as the run, is not the run's own target, is discovered (not gone), and is
  not configured as a Vault in Olympos (Vault).
- PostgreSQL/ClickHouse: the selected databases are in the backup (manifest `details.databases`), and
  **none of them exists on the target with user objects in it** (checked over the tunnel with the given
  credential, so the credential is also tested; an existing database without user tables, views, functions
  or sequences counts as empty). Re-checked when the restore starts, because time passes between approval and
  start.
- PostgreSQL: the open-time check reports whether the credential is a superuser. With a superuser the restore
  keeps owners, privileges and globals. Without one (CloudNativePG's default) it runs with `--no-owner
  --no-privileges`, skips globals, and says so in the request (the checker sees it) and in the result. (My
  call.)
- Vault: the target is initialized and unsealed, and the given token can call `sys/storage/raft/
  snapshot-force` (capabilities check), without writing anything.

### Reading the backup

- New `blob.Reader`: `Open(ctx, path) (ReaderAt + Size)` for Azure Blob (range GETs), S3 (range GETs) and NFS
  (file). The PostgreSQL archive stores entries with data descriptors and no sizes in the local headers, so
  it cannot be read front to back; `archive/zip` over the ReaderAt reads the central directory and then each
  entry by range. No temporary file.
- Before writing anything, one sequential pass computes the copy's SHA-256 and compares it with the copy
  row (and the manifest); a mismatch fails the request before any connection to the target writes.
- While restoring, each entry's CRC-32 is checked by the zip reader; a mismatch fails the database being
  restored.

### Engines

A new optional engine interface `Restorer` (`Restore(ctx, RestoreContext) (*RestoreResult, error)`),
registered like engines; `RestoreContext` carries the tunnel dialer for the target, the credential, the
archive (ReaderAt) or snapshot reader, the selected databases, options and a progress callback.

- **PostgreSQL:** `globals.sql` first when `globals` is on (default on, superuser only), executed statement
  by statement. Roles that do not exist on the target are created with all their statements (`CREATE ROLE`,
  `ALTER ROLE … WITH …`, `ALTER ROLE … SET`, memberships). **For a role that already exists, every statement
  about it is skipped** and reported: `pg_dumpall` follows each `CREATE ROLE` with an `ALTER ROLE` that sets the
  source's password and attributes, which would change the target's admin login or an operator-managed role
  (an anti-goal). `CREATE TABLESPACE` is skipped and reported (the paths do not exist on a new server), and
  `pg_restore` runs with `--no-tablespaces`. psql meta-commands (`\restrict`, `\unrestrict` in recent
  `pg_dumpall`) are skipped. Any other error fails the restore. (My call, from the builder check.)
  Then, per selected database: `CREATE DATABASE` (from `template0`, with the owner, encoding and locale of
  the dump's TOC), then `pg_restore -d <db> --exit-on-error` with owners and privileges kept (the roles come
  from globals). The archive entry is streamed to `pg_restore`'s stdin, and `pg_restore` connects through the
  same local-listener bridge to the tunnel that the backup uses. Result per database: status, bytes,
  duration, number of tables (from `pg_restore -l`).
- **ClickHouse:** per selected database, the archive's schema statements, then each table's data entries
  through **`clickhouse-client`** (owner decision 2026-11-23): `INSERT INTO … FORMAT Native` or `FORMAT
  RowBinaryWithNamesAndTypes` with the entry streamed to its stdin, `clickhouse-client` connecting through the
  same local-listener bridge to the tunnel as `pg_restore` does. The native protocol does not accept
  pre-formatted data from a client library, and ch-go cannot decode the types the backup exports as RowBinary
  (`AggregateFunction`, `Tuple`, `JSON`/`Variant`, `LowCardinality(Nullable(…))`); the official client parses
  every format, so every table is restored. Rows written per table are compared with the rows the backup
  streamed for that table (`rows` in the archive's manifest); a difference fails the table.
- **ClickHouse objects (changed during implementation for security; recreate views, MVs and dictionaries
  from your schema):**
  - **Created:** databases (`Replicated` is refused, because its Keeper path could collide with the source's
    when Keeper is shared) and tables of the MergeTree family, their `Replicated*` variants, the Log family and
    Memory. Each table's data follows.
  - **Materialized views:** each one's inner table is restored as `<view>__restored_data` with its rows, and the
    result says to recreate the view with `TO` that table. A view with `TO` needs nothing more, because its
    target is a table of the backup.
  - **Checks on a table definition:** it must be a single `CREATE TABLE` of the manifest's database and name. It
    may not be `AS …` or `EMPTY AS`. Only an allowlist of storage settings is accepted. Expressions may not
    contain a subquery, `IN`, or any function outside an allowlist of pure scalar functions.
  - **Keeper paths:** `Replicated*MergeTree` paths are rewritten to `/olympos-restore/<request id>/…`, with
    `{uuid}` replaced by `{database}/{table}` (the UUID clause is dropped), and reported.
  - **Not created, reported by name and reason (never with their DDL):** views, materialized views,
    dictionaries, live and window views, and tables of any other engine (Kafka, S3, URL, MySQL, PostgreSQL,
    Distributed, Merge, Buffer, Join, Set, KeeperMap, EmbeddedRocksDB, …). The same applies to tables whose
    definition fails the checks.
  - **Why:** the review showed that query text in view definitions, dictionary sources and settings can read or
    send any data the definer can reach. A restore cannot prove such text confined to the restored databases;
    its job is the data.
- **Vault/OpenBao:** the snapshot (the blob, not a zip) is streamed to `POST /v1/sys/storage/raft/
  snapshot-force` with the request's token. The result explains the unseal step.

### Execution

- The backup worker (same claim loop and per-cluster limits) also claims `approved` restore requests whose
  target's agent is connected here; it sets `running`, heartbeats `progress`, and finishes with
  `succeeded`/`failed`, `result`, `error`. A request left `running` by a stopped replica is failed by the
  stale-run reaper (as backups), with the databases it created listed.
- No retries: a failed restore is a new request (it may need a different target or credential).

### API, UI, notifications

- `POST /api/v1/restores` (open; `break_glass: true` for admins), `GET /api/v1/restores`,
  `GET /api/v1/restores/{id}`, `POST /api/v1/restores/{id}/approve|reject|cancel`. Credentials are
  write-only like job credentials.
- UI: *Restore…* on a run's details opens a dialog (copy, target, databases, credential, justification,
  break-glass for admins) with the open-time checks shown inline; *Approvals* lists restore requests with a
  kind column; a restore detail view shows the request, the decision, progress and the result (with the Vault
  unseal note).
- Events as listed in Goals, routed like other events; `restore.break_glass` and `restore.failed` are not
  opt-in.

## Left to the builder

- The exact split of `internal/approvals` into a shared rules part and the Vault part.
- Progress granularity and how often it is written.
- How the PostgreSQL TOC is read for `CREATE DATABASE` (owner, encoding, locale) and how `pg_restore -l`
  is used for the table count.
- UI layout (mockups in `docs/design/` first), event payload fields, API error texts.
- Lab: second PostgreSQL, ClickHouse and Vault targets to restore into (e2e test per engine; the Vault
  test unseals the restored Vault with the lab source's keys).
