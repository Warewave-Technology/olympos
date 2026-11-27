# Security review v0.4

Independent review of the changes from v0.3.1 to `origin/main` at 148a1ed (`git diff v0.3.1..origin/main`), read
against [`security-model.md`](security-model.md). It was done on 2026-11-27 by a reviewer that had not written the
code and was not told what to expect. The release adds one large change to the security model: native ClickHouse
backups. That means the ingest endpoint, a per-run credential that enters the cluster, signed manifests and verified
chains, and SQL text from the backup running on a restore target under an allowlist. It also adds GitOps-safe
identity Secrets (#59) and the release-candidate rule for security-model changes (#60).

**Method.** Data flows were followed across components: from the ClickHouse statement, through the ingest handler,
the sink and the destinations, to the signed manifest; and from the restore request, through the chain check, the
allowlist and the executor, to what ClickHouse creates on the target. Every guarantee in the security model that
the diff touches was checked against the code, and so were the guarantees a reader would assume but the model does
not state. Each finding was verified in one of three ways:

- a throwaway Go test run with `-tags dev`;
- a statement run against a local ClickHouse 24.8.14 container (the release's minimum version);
- a precise trace through the code.

The throwaway tests and the container are gone; nothing was committed with this review. No product code was changed.
The owner decides fixes and acceptances. The owner decided on 2026-11-27 to fix all six before the release
candidate; each fix carries a regression test from the review's reproduction, and findings 1 to 5 a case against
ClickHouse 24.8 and 25.8 (`TestRestoreNativeAgainstIngest`). The reviewer then verified the fixes; fix round 1
closed what that verification found (the `in(` spellings after `TOP` and `DISTINCT ON`, the definitions of
left-out objects served, the encrypt functions' masked arguments).

## Findings

| # | Severity | Finding | Recommendation | Status |
|---|---|---|---|---|
| 1 | High | **The DDL that the allowlist reads is not always the DDL that `RESTORE` runs.** Olympos takes an object's definition from the stored object of the same name (`native_manifest.go:634-648`). `ParseBackupMeta` refuses a file name listed twice, but it accepts two written files with the same size and checksum (`backupmeta.go:198-211`). ClickHouse resolves a file of a backup by (size, checksum), and the first file listed with that pair wins. It does not check the checksum against the bytes it reads. **Attack:** a compromised source writes a `.backup` that lists `zz/holder` first, with the size and checksum of `metadata/src/v.sql`. The holder's body is any DDL of that size; `v.sql` stays harmless. **Verified:** on ClickHouse 24.8, `RESTORE DATABASE src AS dst` of such a backup created `dst.v` from the holder's text (`… FROM system.users`), not from `v.sql`. The same directory fed to `BuildNativeManifest` was accepted, listing and serving `zz/holder`, and `Classify` allowed `src.v` from `v.sql`. Run alone, the holder's text is refused. The check after RESTORE (`restoredObjects`, `native_restore.go:835`) compares names only, so a holder that keeps the name passes, and the object exists on the target before any check runs. **Impact:** the allowlist, which replaces "no SQL from the backup runs on the target" for native backups, can be bypassed completely by the attacker the model names ("a compromised source"): any engine, a dictionary with a remote `HOST`, a URL or S3 table, a materialized view on the target's other tables writing to such a table, or a Replicated table on the source's Keeper path. A second test, with `v.sql` edited and the `.backup` left as it was, showed that ClickHouse used the edited bytes: the `.backup` checksum binds nothing on read. | Resolve every `metadata/*.sql` exactly as ClickHouse does, from the `.backup`'s (size, checksum) to the first file listed with that pair. Refuse a `.backup` in which two written files share a (size, checksum) but differ in body, or in which a metadata file is not the first holder of its pair. Do the same for files taken from the base (`baseObject` picks by name, ClickHouse by size and checksum). Defence in depth: after RESTORE, compare each object's `engine` and `create_table_query` in `system.tables` with what was allowed, and run the allowlist on `create_table_query` again. | **Fixed** (5a5dcad, d6057dd): each definition is resolved by size and checksum as `RESTORE` does, in the run and through the base; a `.backup` whose definition is not the first holder of its pair, or with two written files of one pair and other bytes, is refused; after `RESTORE` (also a failed one) every allowed object's `engine` and `create_table_query` are compared with the approved definition and allowlisted again, and a mismatch is dropped and named; the encrypt functions' arguments that ClickHouse shows as `'[HIDDEN]'` are accepted in exactly that form (b59cb76, fix round 1) |
| 2 | Medium | **A source joined with a comma after `SAMPLE … OFFSET` (or after a source aliased `limit` or `offset`) is not checked.** `OFFSET` and `LIMIT` are in `fromEnds` (`allowlist.go:120-122`), so `walk` leaves the FROM clause at them (`allowlist.go:949`), and the next `,` no longer starts a source. **Verified:** `CREATE VIEW db.x AS SELECT * FROM db.events SAMPLE 1/2 OFFSET 1/2, other.secret` and the same with `, merge('system', '^users$')` are allowed. Without the `SAMPLE` clause both are refused, which shows it is the reset at `OFFSET`. On ClickHouse 24.8 the view was created, and a view of this form (`SAMPLE 1 OFFSET 0, other.secret`) returned the rows of `other.secret`, a table outside the backup. **Impact:** a view or materialized view restored from a compromised source reads any table of the target server, and table functions that `outsideCalls` does not list. Anyone who can read the restored database reads them through it. | End the FROM clause on these words only at the clause's own nesting level, and treat `SAMPLE … OFFSET` as part of the table expression. Treat any word followed by `(` in a source position as a table function, wherever the source is. | **Fixed** (1c653b0): `SAMPLE k [OFFSET m]` is read as part of the table expression, the word after `AS` is an alias, and a clause word followed by a comma is not read with certainty |
| 3 | Medium | **The function form of `IN`, and a table name in parentheses after `IN`, are not read as tables.** `walk` recognises only the keyword `IN` (`allowlist.go:938`, `inTable` at `allowlist.go:1043`). A bracket that follows it is walked as an expression. **Verified:** `… WHERE in(id, other.ids)`, `… WHERE id IN (other.ids)` (and `globalNotIn` and the other forms of the `in` family, per the same code path) are allowed. On ClickHouse 24.8 both views returned exactly the rows of `db.events` whose `id` is in `other.ids`, a table outside the backup. **Impact:** a membership oracle on any table of the target, from a restored view, materialized view or column default. | Treat `in`, `notIn`, `globalIn`, `globalNotIn`, `nullIn`, `notNullIn` and their `global` forms as the keyword `IN`. Read a lone (qualified) identifier in parentheses after `IN` as a table. | **Fixed** (d8d3d56, 1bc5346): the `in` family (with its `global` and `IgnoreSet` forms) is read as `IN`, its second argument and a (qualified) name in brackets after `IN` as a table, `f(…)` there as a table function; after SELECT's modifiers (`TOP n`, `DISTINCT ON (…)`) and an index's name `in(` is the function (1bc5346, fix round 1) |
| 4 | Medium | **Unqualified names are checked against the object's database but resolved against the session's database, `system`.** The allowlist takes an unqualified name as one of the object's own database (`allowlist.go:32`, `allowlist.go:889-901`); its own tests allow `CREATE VIEW db.x AS SELECT id FROM events`. The restore connection opens with `Database: "system"` (`conn.go:100`). **Verified:** with a harmless `src.users` in the backup and `v.sql` reading `FROM users`, `RESTORE … AS dst3` on ClickHouse 24.8, run in database `system`, created `dst3.v` as `… FROM system.users`. RESTORE then failed with `CANNOT_RESTORE_TABLE`, but the view stayed on the target and returned `system.users` rows. Olympos does not drop what a failed restore created. **Impact:** a compromised source gets a view on the target over any table of `system` (users, grants, `query_log`, `processes`) whose name it also gives a harmless table in its backup. | Refuse unqualified table names in views, materialized views, dictionaries and `dictGet`/`joinGet` names. ClickHouse stores the definitions it writes itself qualified, so honest backups lose nothing. Or open the restore connection with no default database that holds tables. | **Fixed** (d71bd52): a table named without its database is refused (views, materialized views and their `TO`, dictionaries' expressions, defaults, `dictGet*`/`joinGet`); the `RESTORE` runs with the first restored database as its session's; the 24.8 and 25.8 testdata classifies as before |
| 5 | Medium | **A restore's credential reads every object of the chain, not only what was approved.** `NewNativeRestoreSource` serves every object of every verified manifest (`native_restore.go:441-470`). The executor builds it from the whole chain and gives the credential every run's prefix (`native_execute.go:116`, `native_execute.go:166`). The selected databases and the `EXCEPT TABLES` list bound only the `RESTORE` statement. **Verified:** a throwaway test built the source for a backup of databases `a` and `b` and opened `metadata/b/secrets.sql` and `data/b/secrets/…/x.bin` with it. The handler serves whatever the source opens in a read prefix (`handler.go:916`, `serveSource`). **Scenario:** a maker with `operate` on a dev cluster where they run the target (or a stand-in that speaks the native protocol) has a checker approve "restore database `a`". The `RESTORE` statement carries the credential to the target, so the target's operator holds it. Until the restore ends (up to 6 h), they can read every database of the backup and every table that was left out, through the ingest endpoint. A logical restore sends the target only the selected data. The model says "a restore reads only the chain of the copy it restores": true, but a reader assumes the approval bounds it. | Serve a restore only what its `RESTORE` needs: the `.backup` files, the metadata of the selected databases, and the data of the allowed objects. Refuse the rest as `ErrNotServed`. Or state in the security model and in the checker's view that the target can read the whole backup. | **Fixed** (ee42bd9, cf9701c): the restore source serves only what the `RESTORE` reads (the `.backup` files, the selected databases' own definitions, the allowed objects' definitions and data, resolved by size and checksum), every other key 403, a left-out object's definition included (cf9701c, fix round 1); the checker's note and `security-model.md` say so |
| 6 | Low | **One server-wide slot serves both the API's native restore checks and the executor's check at start.** `nativeRestoreSlots` has capacity 1 (`native_restore.go:167`). `POST /restores/check` and `POST /restores` take it (`restore/api.go:666`), and so does the executor's re-check before an approved restore (`native_execute.go:104`). There is no limit per user. A check of a 32-run chain reads up to 32 sidecars and every DDL object. **Verified:** a dev-tagged DB test held the slot with one check; an executor-style call then failed with `context deadline exceeded` after 2 s. **Scenario:** a user with `read` on a cluster with a long native chain and `operate` on any target sends checks in a loop. An approved disaster-recovery restore waits in *verify* behind them. It is delayed, never bypassed. | Give the executor its own slot, or priority over API checks. Limit concurrent checks per user, and put a timeout on a check. | **Fixed** (b2bea7c): the executor's check has its own slot, the API's checks share 2, a user runs one at a time, and a check ends after 5 minutes (`docs/restore.md`) |

## Checked and found sound

- **Ingest endpoint.**
  - SigV4 is checked before a body is read. `host`, `x-amz-date` and `x-amz-content-sha256` must be signed, and the clock skew is 15 min. `UNSIGNED-PAYLOAD` is accepted only when `r.TLS` is set, and then needs a signed `Content-MD5` on PutObject and UploadPart. `aws-chunked` is refused.
  - The key comes from the decoded path that is signed, and an encoded `/` is refused. Keys are plain UTF-8 with no empty, `.` or `..` segments.
  - Operations are classified before any credential is looked up, and only the eight served ones pass. A run's own objects are not read back, except its `.lock` and its kept bodies.
  - Objects are written once, and a repeat with another body stops the run. A Complete's part list must name exactly the parts received.
  - A restore source serves only keys of its verified manifests. The size is checked at open, and the SHA-256 before the last bytes go out (`checkedObject` holds back the final read). Ranged GETs of such a source are refused.
  - `http` `ingest.url` is refused without `devMode`, and `devMode` only exists in dev builds. `ingest.url` is refused with `experimental.multiReplica`.
- **Credential.**
  - The access key has 85 random bits and the secret 240. The secret is kept in memory only.
  - The database row holds the key, scope, expiry and an HMAC fingerprint, and has no column that could hold the secret. `String`, `GoString` and `LogValue` redact it, and the statement is logged redacted.
  - Sessions are revoked on every way out, expire at the TTL even with no request, and are all revoked at start-up. The version check (24.8+) runs before the statement is sent, on backup and on restore.
- **Manifests and chains.**
  - The encoding is canonical: stored manifests with duplicate, unknown or case-variant keys are refused. Every field the restore trusts is signed.
  - The key name is pinned before verification, and the manifest's run must be the expected one and its hash the copy row's.
  - Chain links are checked from the last run back to the full. The depth limit of 32 is enforced on the backup, the restore and the source. A base from another job is impossible.
  - A Key Vault error fails closed: an incremental becomes a full, and a restore check is refused.
  - The local key vault is in `//go:build dev` files only. The Bicep template gives the server Crypto User on the manifest key, so it cannot add key versions.
  - ES256 signatures are malleable (a high-S twin verifies), but nothing uses a signature as an identifier: copy rows and links use the canonical manifest's hash.
  - `publicKey` ignores a key version's expiry and not-before dates. Key Vault itself still verifies with an expired key, and the model promises only that a disabled version stops verifying, which holds.
- **Allowlist (what holds).**
  - The lexer refuses comments, query parameters, non-ASCII outside quotes and unknown escapes.
  - Engine names match exactly. Inline `disk(...)`, other disks and policies, encryption codecs, `AS f(…)`, `CLONE AS` and `EMPTY AS` are refused.
  - FROM/JOIN sources followed by `(` (outside finding 2) and computed `dictGet` names are refused. Dictionary sources with `HOST`, `PORT` or `NAME` are refused, and their embedded queries must qualify their tables.
  - The Keeper path rewrite replaces path and replica with an escaped `/olympos-restore/<id>/<db>/<table>`, and refuses omitted arguments and `ON CLUSTER`.
  - `EXCEPT TABLES` names are quoted strictly. The executor re-decides at start and refuses a change against what the checker approved.
  - Not findings, after testing on 24.8:
    - `SETTINGS additional_result_filter = '…url(…)…'` in a view was not applied when the view was read.
    - `TTL … TO DISK` is bounded by the storage policy, which the allowlist pins to `default`.
- **Blob.**
  - The filesystem destination keeps its reserved suffixes, so an object key cannot write another object's tags sidecar.
  - `SetTags` is widened only to native run objects and manifests, and only to regular files.
  - The new lifecycle rule deletes `olympos-state=incomplete` objects. Like the tier rules, it waits for the container's immutability.
- **#59 GitOps install.**
  - With `identity.manageSecrets=false` the chart renders no identity Secret.
  - The generated commands put the one-time token only in `kubectl create secret … | kubectl apply`, never in Git values.
  - The probe Secret gets the cluster token as it already did with plain Helm.

## Addendum: v0.4.0-rc.2

The diff since `v0.4.0-rc.1` (`68f11d8..b33b7d1`, PR #99) was reviewed independently on 2026-11-27, read against
`docs/security-model.md`. PR #99 adds a 5-minute first-request limit to the native ingest session and a
restore-specific orphan error.

**Verdict.** Neither change weakens the security model:

- Only a request whose SigV4 signature has verified counts as the first request. A forged or unauthenticated
  request cannot hold a session open, and no request can shorten one.
- A session stopped for *no request* takes the same path as every other stop reason:
  - its key is refused at once;
  - the engine ends the statement with `KILL QUERY`, falling back to a new connection;
  - the credential is revoked and its slot freed.
- The new error text holds only `ingest.url` and a duration, and passes through the existing scrubbers.
- A target or network attacker gains nothing beyond a failed run: without a captured `.backup` no manifest is
  signed.
- `ErrNativeRestoreOrphan` still unwraps to `ErrNativeOrphan` for the caller that looks for it.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Low | The window counted from when the credential was minted, before the engine connected. Slow work before the statement counted against it: reading sizes, ending left-over backups (up to 30 s each), and a restore's `CREATE DATABASE` and Replicated `CREATE TABLE`s. That work could fail a large restore, or a backup with many orphans, every time, with advice to check the egress. Only availability was affected. | **Fixed** (rc.3): the engine calls `Sent` just before the `BACKUP` or `RESTORE` is sent, and the window starts then (`ingest.Session.Sent`). Tests: a slow start of a backup and of a restore succeeds. |
| 2 | Info | Doc sentences were slightly off about when the window starts, and about the `KILL QUERY` of a statement that had not been sent. | **Fixed** (rc.3): the window starts at the statement, so a stopped session always has one to end. The docs say so. |
| 3 | Info | Races at the 5-minute boundary, which change only an error's wording and one metric. A timer that fired as the run ended could still `Stop` a revoked session. The restore executor read the stop reason after `Revoke`. | **Fixed** (rc.3), except one race that comes with any deadline: `Stop` does nothing once the session is revoked, and the executor reads the reason before `Revoke`. A signed request that arrives at the very moment the window ends can still lose to the timer, and the run then fails as *no request*. That outcome is harmless. |
