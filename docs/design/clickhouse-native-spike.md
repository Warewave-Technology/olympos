# ClickHouse native backup: spike results (#62)

Status: spike done on 2026-11-25, input to the design of #62. The spike code was throwaway and is not in the
repository; this page records what it showed.

## What was run

- ClickHouse **24.8.14** (the version of the integration tests and the lab) and **25.8.33** (the current LTS),
  each in Docker, with a database that has what the logical backup loses:
  - a `MergeTree` table with codecs, a default, a skip index and a TTL;
  - an `AggregatingMergeTree` fed by a materialized view;
  - a view;
  - a dictionary with a ClickHouse source;
  - 64 MiB of data, so that one file goes up in multipart.
- **A logging proxy in front of MinIO.** It records every S3 request, and optionally refuses deletes or fails
  chosen uploads.
- **A minimal S3 endpoint of our own**, 277 lines of Go:
  - one bucket, one prefix, one key pair;
  - SigV4 checked, the payload hash and `Content-MD5` checked;
  - objects on local disk.
- **Statements run:** `BACKUP DATABASE … TO S3(…)`, an incremental `BACKUP … SETTINGS base_backup = S3(…)`, and
  `RESTORE DATABASE … AS … FROM S3(…)`. They ran through the proxy and then directly against the minimal
  endpoint.

## Findings

### 1. The operations ClickHouse uses

The same on both versions:

| Operation | When |
|---|---|
| `ListObjects` (**v1**, bucket level, `prefix=<run>/.backup` and `<run>/.lock`, `max-keys=1`) | start of a backup: does it exist already |
| `PutObject` | every file of a part, the metadata `.sql` files, `.lock`, `.backup` |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload` | files above the single-part limit |
| `AbortMultipartUpload` | a failed multipart upload |
| `GetObject` (no `Range`) | `.lock` checks, the base backup's `.backup` and checksums (incremental), every file (restore) |
| `DeleteObject <run>/.lock` | end of every successful backup |
| `DeleteObjects` (bulk), `DeleteObject <run>/.backup` | cleanup after a failed or killed backup |

Never seen: `HeadObject`, `CopyObject`, `UploadPartCopy`, ranged `GetObject` and `ListObjectsV2`. ClickHouse
uses server-side copies only when the source table lives on an S3 disk. Statements from Olympos can set
`allow_s3_native_copy = 0`, so that every byte passes through Olympos.

### 2. A refused delete fails the backup

ClickHouse writes `<run>/.lock` at the start and deletes it at the end, after `.backup` is written. When the
delete is refused, the backup ends `BACKUP_FAILED` (`removeLockFile`), although every object is in place: a
restore from it worked. "Always refuse deletes" (point 1 of #62) does not work as it stands.

What worked: the endpoint keeps the run's `.lock` **in memory only**. `PUT`, `GET` and `List` serve it from
memory, and `DELETE` removes it from memory. The lock never reaches backup storage, and nothing is ever deleted
there. Every other delete is refused; after a failure that leaves the run `incomplete`, as point 5 intends, and
the backup still ends `BACKUP_FAILED` at once.

### 3. Refusals during a run are retried almost forever

- **Failed uploads:** when the proxy answered `500` to uploads, ClickHouse retried them for over 10 minutes
  (2,526 requests) and the backup stayed `CREATING_BACKUP`. With `403 AccessDenied` instead, `UploadPart` was
  still retried every couple of seconds, with no end.
- **Refusals at the start:** these failed the backup at once. They covered a wrong signature, a prefix outside
  the run, and a bucket operation, all on the first `ListObjects`.
- **Consequences:**
  - When Olympos stops a run in the middle (quota, run window, credential expired), refusing requests is not
    enough. The server must also end it on ClickHouse with `KILL QUERY … SYNC` through the agent tunnel; the
    spike's `KILL` ended it at once as `BACKUP_FAILED`.
  - Rate limits (point 9) must hold against retry storms.

### 4. Requests are signed with the real payload hash

Every request carried `x-amz-content-sha256` with the hex SHA-256 of the body (never `UNSIGNED-PAYLOAD` or
`aws-chunked`), and every upload a `Content-MD5`. (The spike ran over plain HTTP. The lab showed later that over
HTTPS ClickHouse sends `UNSIGNED-PAYLOAD` on every request, and a signed `Content-MD5` on every PutObject and
UploadPart; see the design's SigV4 notes and spec-changes #28.) The endpoint can verify the header signature before it reads
a byte, stream the body to the destination while hashing it, and fail the object if the hash differs. That is
the write-through of point 3.

### 5. An incremental reads its base

An incremental backup reads the base run's `.backup` and the checksums of its parts with `GetObject`, and lists
its prefix. It copies nothing. A restore of an incremental reads both runs. The per-run credential of point 2 is
therefore:

- **an incremental backup:** write and list its own prefix, read and list the prefixes of its base chain;
- **a restore:** read and list the whole chain.

### 6. The credential is masked

On both versions the secret of `S3(url, key, secret)` shows as `[HIDDEN]` in `system.query_log`,
`system.backups`, `system.processes` and the server log. A search of every `system.*` log table and of
`clickhouse-server.log` for the secret found only the search queries themselves. Exception messages sent to
the client do not contain it. `clickhouse-client` prints the statement it ran next to an error, but that is
the client's own text. The agent must not log the statement it sends. `query_masking_rules` are not needed on
these versions.

### 7. What the restore keeps

A native restore, through MinIO and through the minimal endpoint alike:

- **data:** row counts and a hash over all rows match;
- **the materialized view:** it keeps feeding its aggregate (an insert into the restored source updated the
  restored aggregate);
- **dictionary and view:** both work.

### 8. A native restore joins the source's replica set

A second run covered `ReplicatedMergeTree`. Two ClickHouse 24.8 servers shared one Keeper, as in #57's test,
and the tables had an explicit Keeper path and a `{database}/{table}` macro path. `RESTORE DATABASE` on the
second server created the tables with the **source's Keeper paths**:

- they joined the source's replica set as `r2`, and the source showed `total_replicas = 2`;
- the restore stopped only because the tables "already contain some data", which they had fetched from the
  source through replication.

Dropping the restored database took `r2` out of the set again.

What worked: create the Replicated tables first, with the backup's DDL and a new Keeper path
(`/olympos-restore/<request id>/<db>/<table>`, the layout of #57), then run
`RESTORE … SETTINGS allow_different_table_def = 1`. The data went into the new tables, and the source kept one
replica. `{uuid}` paths and empty `ReplicatedMergeTree` arguments are refused on an Atomic database outside
`ON CLUSTER` (24.8), so explicit and macro paths are the cases to handle.

So the native restore never lets ClickHouse create a Replicated table itself. Olympos writes the
`CREATE TABLE` from the backup's metadata, with the path rewritten, and the restore only fills it.
`allow_different_table_def` is set only for those tables, and the restore check compares the rest of the
definition.

## Library or own handler

The surface is about seven operations, deny by default, on one bucket and one prefix per run. The endpoint must:

- verify SigV4 against a credential minted per run;
- enforce read or write per prefix;
- keep the lock in memory;
- stream to Blob, S3 and NFS through `internal/blob` while hashing.

The spike's own handler covered the protocol in 277 lines and ClickHouse worked against it unchanged.

- **gofakes3** has no SigV4 check and stores whole objects through its own backend model. We would replace
  the parts that matter.
- **versitygw** is a full gateway with its own IAM and backends: a large dependency for an endpoint that is
  part of the security model.

**Recommendation: our own minimal handler** with:

- SigV4 tested against AWS's published test vectors;
- every operation listed above, explicitly, and every other request refused with `403`;
- the `.lock` in memory.

## Changes to #62

- **Point 1:** the operations are those in the table above, with `ListObjects` v1 instead of
  `ListObjectsV2`. `UploadPartCopy` and `CopyObject` are dropped, and `allow_s3_native_copy = 0` is set in the
  statements. Deletes:
  - the run's `.lock` is kept in memory and its delete succeeds;
  - every other delete is refused.
- **Point 2:** an incremental's credential also reads its base chain; a restore's reads the chain.
- **Point 9:** stopping a run means `KILL QUERY` through the tunnel as well as refusing requests; rate limits
  are sized for ClickHouse's retries.
- **Point 2, masking:** confirmed on 24.8 and 25.8; the agent must not log the statement.
- **Point 6, Replicated tables:** Olympos creates them with a rewritten Keeper path before the `RESTORE`.
  Otherwise the restored tables join the source's replica set.
