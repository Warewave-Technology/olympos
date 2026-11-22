# Destination groups: one backup, several destinations

Status: implemented for v0.2 (#32).

## Intent

Today a backup job writes to exactly one destination (`backup_jobs.destination_id`). A 3-2-1 setup needs a
second, independent copy of the same backup, ideally in another place and with other credentials: Azure Blob
in the region plus an S3 bucket elsewhere, or Blob plus an NFS share with storage snapshots. The need is
strongest for `olympos-self`: losing the only copy of Olympos' own database loses the KEK-wrapped credentials,
grants and history at once.

The owner's requirement, in their words: the same backup can be written to two different backends, through
an object like a destination group.

## Decisions taken with the owner

1. **A destination group is its own object.** A named set of destinations, managed where destinations are
   managed. Jobs point at a group; changing the group's members changes every job that uses it.
2. **Partial success is a status of its own.** One run streams one dump to every member. Every member's
   result is recorded. All copies written: `succeeded`. At least one written, at least one not: `partial`
   (with an alert naming the missing destinations). None written: `failed`.
3. **A missing copy is completed by a fresh dump inside the retry window.** Within the job's retry window
   (half the interval to the next activation, as for agent disconnects today) and below `MaxAttempts`, a new
   run is queued that dumps again and writes **only** to the destinations that are missing. Nothing is
   spooled to disk; the completed copy reflects a slightly later moment than the others.
4. **Approach 1 of the three below:** a job points at either one destination or one group; per-copy results
   live in a new table; the worker always works on a list of destinations.

## Goals

- Create, edit and delete destination groups (Settings › Destinations), two to four members, members of any
  kind (`azure_blob`, `s3`, `nfs`) mixed freely.
- Pick a group wherever a destination can be picked today: the backup wizard (step 3), the job edit form and
  the Olympos self-backup card.
- One dump per run, streamed to all members at once. Every copy has identical bytes (one sha256 per run,
  verified per copy by size and hash of what was sent).
- Per-copy results stored and shown: destination, blob path, bytes, sha256, error, timings.
- `partial` status in the API, UI, metrics, notifications and dashboard summaries.
- Automatic completion of missing copies (decision 3).
- Restore guide per copy: the run page lets the reader pick which copy to restore from; commands use that
  copy's destination.
- Existing jobs, runs and installs are unchanged after the upgrade.

## Non-goals

- Copying existing backups to a destination that is added to a group later (backfill). Only runs after the
  change write to the new member; the UI says so when a member is added.
- Spooling the dump to disk, or any other way to make a completed copy byte-identical to the first ones.
- Required versus best-effort members, weights, or a primary member with different semantics.
- Retention configured in Olympos. Retention stays lifecycle rules in each storage, by the `olympos-tier` tag.
- An approval (maker/checker) flow for group changes. Group changes are audited like destination changes.
- Replication done by the storage itself (Azure GRS/ORS, S3 replication). It stays a valid alternative and
  the docs mention it; Olympos does not configure it.
- Restoring from Olympos (still out of scope, SPEC §10.4).

## Anti-goals (failures even if everything "works")

- One failing or slow-to-fail destination makes the run lose the copies that could be written. A branch that
  fails is detached; the others go on.
- A `partial` run looks like a success anywhere: a green badge, a `backup.succeeded` event, or a dashboard
  count that hides the missing copy.
- Copies of one run with different content.
- Any change to existing jobs or to the behaviour of single-destination jobs after the upgrade, beyond the
  new per-copy records.
- Olympos gaining delete rights or deleting anything in a destination (SPEC §10.3 stays as it is).
- Removing a destination that a group or job still uses.
- A restore guide that points at a destination the backup was never written to. (Today the guide joins the
  job's *current* destination, so a job whose destination was changed gets wrong commands for old runs.
  Per-copy records fix this for new runs.)

## Constraints

- Plain pgx, goose migrations, append-only `backup_runs` (the freeze trigger stays), soft-deleted jobs.
- The dump path stays streaming, no temp files (SPEC §10.2): target → agent → server → destinations.
- Destination credentials stay on the server; nothing new crosses to a cluster.
- Permissions: groups are managed by whoever may manage destinations today (admin) and are readable by
  whoever may read destination names today (`/api/v1/destinations/{id}` is open to all signed-in users
  because cluster-scoped operators pick from them). The authz matrix test covers the new routes.
- Public open-source docs: every user-visible change lands with docs and real lab screenshots
  (`docs/getting-started.md`, `docs/restore.md`, `docs/restore-olympos.md`), an updated SPEC §10 with a row
  in `docs/spec-changes.md`, `docs/openapi.yaml`, and the CHANGELOG.

## Approaches considered

1. **Group as its own object; a job points at a destination or a group (chosen).** New tables for groups,
   members and per-copy results; `backup_jobs` gains `destination_group_id` next to `destination_id`, exactly
   one of them set. The worker resolves the job to a list of destinations (one element for a plain
   destination), so there is one code path. Existing jobs and runs are not migrated.
2. **Everything becomes a group.** The migration creates a hidden one-member group per destination and moves
   every job to it. One shape in the schema, but the migration touches every install and the UI shows groups
   nobody created. Approach 1 gets the same single code path in the worker without that risk.
3. **One run per destination.** A group run fans out into one run per member, each with its own dump.
   Simplest code, but the copies are different dumps taken at different times and the source database carries
   N times the load. It contradicts "the same backup in two places". Rejected.

## Design

### Data model (one new migration)

- `destination_groups`: `id`, `name` (unique, shares the namespace rules of destination names but not the
  namespace itself), `description`, `created_at`, `updated_at`.
- `destination_group_members`: `group_id`, `destination_id`, `position` (order shown in the UI and used to
  pick the default restore copy). Primary key `(group_id, destination_id)`. Between 2 and 4 members, enforced
  by the API (a group that would drop below two members is refused: use the destination directly instead).
- `backup_jobs.destination_id` becomes nullable; new `backup_jobs.destination_group_id`
  (`REFERENCES destination_groups(id)`); `CHECK (num_nonnulls(destination_id, destination_group_id) = 1)`.
  The self-backup row follows the same rule.
- `backup_runs.status` gains `partial`. New `backup_runs.repair_of uuid REFERENCES backup_runs(id)`: set on a
  run that completes missing copies of an earlier run; it always points at the original (first) run, never
  at a previous repair. New `backup_runs.destination_ids uuid[]`: the destinations the run set out to write,
  fixed when the run is queued (repairs) or starts (all others).
- `backup_run_copies`: `run_id`, `destination_id`, `status` (`succeeded` | `failed`), `blob_path`, `bytes`,
  `sha256`, `tier`, `error`, `started_at`, `finished_at`. Primary key `(run_id, destination_id)`. Written when
  the run finishes, one row per destination in `destination_ids` whose upload was attempted, for every new run
  including single-destination ones. A run whose engine failed before any data reached the uploads has no
  copy rows. Append-only like `backup_runs` (same kind of freeze trigger).
- `backup_runs.blob_path`, `sha256`, `bytes` and `tier` keep being filled, from the first succeeded copy in
  member order, so existing readers keep working. New readers use `backup_run_copies`.
- Destinations used by a group are "in use": the delete check counts group memberships as well as jobs. A
  group used by a job (or by the self-backup) cannot be deleted.

### Which destinations a run writes to

- Resolved when the run starts: the job's destination, or the group's members at that moment. Changes to the
  group during a run do not affect it.
- A repair run (`repair_of` set) writes only to the **missing set**: the original run's `destination_ids`
  minus every destination that has a succeeded copy in the original run or in any of its repairs, and
  restricted to destinations that are still in the job's current target. If the set is empty, no repair is
  queued.

### Streaming to several destinations

- The engine writes into one fan-out writer. Each member has its own pipe and its own `Upload` goroutine.
  The sha256 and byte count of the stream are computed once, at the fan-out.
- A branch whose upload fails is closed and detached; its error is kept; writes continue to the others.
  When every branch has failed, the engine context is cancelled and the run fails with the first upload
  error as the root cause (today's `uploadFirst` logic, generalised).
- The slowest live branch sets the pace (no unbounded buffering). A destination that stalls rather than
  fails is detached as `stalled` (added during implementation): a member that accepts no data for 10
  minutes, or does not finish within 10 minutes after the end of the stream, gets a failed copy and the
  others go on.
- Two members that write to the same location (same kind and endpoint, account and container, bucket or NFS
  path, and the same prefix) are refused when a group is saved and when a member destination is edited
  (added during implementation): such a "copy" would be the same object twice in one place.
- After the data blob, each successful branch writes its manifest next to its blob. A manifest failure fails
  that copy only.

### Retention tier per copy

- The GFS tier is decided **per destination**: a copy is `monthly` when that destination has no successful
  scheduled copy of this job in the month yet, and so on (`TierFor` counts `backup_run_copies` of the same
  destination instead of runs). A repair run therefore gives the completed copy the tier it would have had,
  and a destination that was down for a week does not end up without its monthly copy.
- Copies of one run may carry different tags. The run's `tier` column keeps the first copy's tier.
- Runs from before the upgrade have no copy rows. `TierFor` counts them (succeeded scheduled runs without
  copy rows) for every destination of the job, so the first runs after the upgrade do not tag an extra
  `monthly`/`weekly` copy. (My call. Cost: a destination added in the first month after the upgrade may get
  its first monthly copy only the next month.) A destination added to a group, or a job moved to a group,
  later than that gets `monthly` on its first copy, which is intended: that destination has none yet.

### Status, retry and repair

- Engine fails: `failed` (no copy can exist). Engine succeeds: `succeeded` / `partial` / `failed` from the
  copies as in decision 2.
- `partial`: queue a repair run (`repair_of` = the original run, same `trigger`, same `scheduled_for`,
  `attempt + 1`, same `retry_until`). The partial run stays `partial`; it is the record of what happened.
- Repairs are spaced (owner decision 2026-11-22, replacing back-to-back repairs within `MaxAttempts`): the
  k-th repair of an original run gets `not_before = now + RepairDelays[k-1]` with `RepairDelays` = 5 min,
  30 min, 2 h, so at most `MaxRepairs` = 3 repairs. `now` is when the run before it finished; k is 1 + the
  repairs of that original run that have a `not_before`. A repair whose `not_before` would be after
  `retry_until` is not queued. Both runners skip queued runs whose `not_before` is still ahead.
- A repair run ends `succeeded` (every missing copy written), `partial` (some), or `failed` (none, for any
  reason: upload, engine, credential); a `partial` or `failed` repair queues the next repair while the
  delays and the window allow. Repairs exist only after a `partial` run: a plain run that fails entirely is
  not retried, as today.
- Agent disconnects keep their current rule (`disconnectedOutcome`, `MaxAttempts`), for plain and repair
  runs alike; the retry of a disconnected repair keeps `repair_of` and the missing set, has no
  `not_before` (it starts when the agent is back) and so counts as the same repair.
- A repair waiting for its `not_before` does not make the job busy (*Run now* and dry runs are accepted)
  and is not the job's `last_run`. The partial run's detail carries `next_repair_at`; `backup.partial`
  carries `next_attempt_at`.
- Test runs (`trigger = 'test'`, the wizard's dry run) write to every member, get copy rows and the
  `partial` status like other runs, are never repaired, and the dry-run checklist shows one upload step per
  destination. The wizard's rule for enabling after a dry run applies to "every copy succeeded".
- When no repair is left (three used, or the next would start after the window), the copy stays missing;
  the next scheduled run writes to every member again.

### Notifications, metrics, dashboard

- New event `backup.partial` (warning): job, run, the destinations that are missing with their errors, and
  whether a repair is queued. A repair that completes every missing copy emits `backup.succeeded` with
  `repair_of` (subject to the job's success opt-in, as today); a repair that gives up emits `backup.failed`
  with `repair_of`. The notification catalog and
  default routes list `backup.partial` next to `backup.failed`.
- `olympos_backup_runs_total` gets `status="partial"`. New `olympos_backup_copies_total{destination,status}`.
- Dashboard and cluster summaries: a `partial` run counts as a restorable backup for "last backup", and is
  counted separately (not as ok) in the 24-hour figures. The job page shows, per destination, the time of
  the last successful copy.

### API and UI

- `/api/v1/destination-groups` (list, get, create, update, delete), same permission model as destinations.
  Like destinations today, responses carry the member destinations (as the destination read shows them) and
  only a **count** of jobs using the group, never the jobs themselves: cluster-scoped operators may read
  groups but not other clusters' jobs. The edit dialog's "affects N jobs" warning uses the count.
- Job and self-backup payloads accept `destination_group_id` as an alternative to `destination_id`;
  validation refuses both or neither.
- Run payloads gain `copies[]` and `repair_of`.
- Settings › Destinations: a "Groups" section. The edit dialog lists members in order, warns how many jobs the
  change affects, and says that existing backups are not copied to an added destination.
- Destination pickers (wizard step 3, job edit, self-backup card) offer destinations and groups in one list,
  groups marked as such with their members.
- Runs list: `partial` badge (warning colour, not green). Run detail: a copies table; the restore guide has
  a copy selector, defaulting to the first successful copy in member order.
- Restore guide: built from a `backup_run_copies` row (its destination), falling back to today's join for
  runs from before the upgrade.

### Self-backup

- `olympos-self` gets everything above: a group as its target, fan-out, copy rows, `partial`, repairs inside
  its retry window and `backup.partial`. It has its own runner today (`internal/backup/self.go`: claim,
  perform, finish, notify) that does not use `finishRunTx` or `disconnectedOutcome`. The fan-out writer,
  copy-row writing, status decision and repair queueing are written once and used by both runners (my call);
  how far the two runners are merged beyond that is left to the builder.

### Audit

- `destination_group.created`, `.updated` (with member diff), `.deleted`; job and self-backup audit entries
  record `destination_group_id` changes.

## Left to the builder

- The fan-out writer's structure, pipe buffer sizes, and how per-branch hashes are checked.
- Whether the manifest format version changes (fields added are `destination` and, for group runs, `group`
  with the member names) and how `docs/restore.md` presents it.
- Exact event payload fields, UI layout and copy (following the existing pages and `docs/design/` mockups;
  a mockup for the groups section and the copies table first).
- Migration number and the down migration.
- Test layout. Expected at least: fan-out with one branch failing mid-stream, all branches failing, a slow
  branch; status and repair logic incl. window and attempt limits; per-destination tiers; API validation and
  the authz matrix; an end-to-end lab run with Azurite plus NFS (and S3 where the lab has it) that kills one
  destination and sees `partial`, the alert, and the repair.
