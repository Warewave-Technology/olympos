# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-24

Synthetic monitoring: scenarios defined once in Olympos run from a probe inside every cluster they target.

### Added
- **Synthetic monitoring** ([#46](https://github.com/Warewave-Technology/olympos/issues/46)): scenarios
  (HTTP requests and flows, DNS, TCP, TLS, with assertions and extracts) defined once in Olympos run from
  inside every cluster they target, and alert when they keep failing. New **Monitoring › Synthetic** area: a
  scenario × cluster matrix with 24-hour availability and p95, scenario details with a 48 × 30-minute
  timeline and alert history, run details with a per-step waterfall, assertions, redacted excerpts and *Copy
  as curl*, and an editor with test runs on one cluster. *Run now* counts toward alerts, test runs never do;
  each person can start 6 of each a minute. See `docs/synthetic-monitoring.md` and `docs/getting-started.md`
  (step 12).
  - **`olympos-probe`**, a new image and Deployment that the agent chart installs next to the agent
    (`probe.enabled: true`; `false` opts out). The probe has no RBAC and no Kubernetes API token; it dials
    out with its own identity (CN `<cluster-uuid>/probe`), which the agent enrolls with the same install
    token, keeps in the Secret `olympos-probe-identity` and renews. Clusters added before: `helm upgrade`,
    then *Settings › Clusters & agents › Install probe* (a probe-only token); the *Status* column shows the
    probe and offers *Revoke probe*. Optional egress NetworkPolicy (`probe.networkPolicy.*`).
  - **Host allowlist** (*Settings › Synthetic monitoring*, admins): exact, wildcard and suffix rules by whole
    labels, *check a host*. IP literals, `localhost`, the Kubernetes API and loopback, link-local, cloud
    metadata, multicast and broadcast addresses are always denied; the probe resolves each name once,
    without the search list, dials the address it checked and checks every redirect hop.
  - **Credentials for scenarios** (bearer, basic, header, OAuth2 client credentials), stored encrypted or as
    Key Vault references, bound to hosts, with expiry. This is a documented exception to "credentials never
    enter the cluster": each run's credentials are sealed with HPKE to the probe's connection, kept in memory,
    attached only to bound hosts and removed on redirects; values derived from them may only go to those
    hosts; responses are redacted on the probe. See `docs/security-model.md`. A header credential cannot use
    a header the probe would never send it in (`Host`, `Cookie`, `Content-Type`, `Accept-Encoding`, `Range`,
    the transport's headers, …): it is refused when saved.
  - Alerts per cluster after N failed runs, a critical fleet alert at N failing clusters, recovery after N
    passes, one message per open and resolve, a per-scenario channel. New events `synthetic.failing`,
    `synthetic.critical`, `synthetic.recovered`, `probe.offline`, `probe.online`,
    `synthetic.credential_expiring` and `synthetic.allowlist_changed`; on upgrade, every channel that gets
    `grant.changed` is routed `synthetic.allowlist_changed` too.
  - New role **`synthetic-editor`** (scenarios in its scope; not for guests). Admins manage the allowlist and
    the credentials.
  - Rate caps (600 requests a minute per cluster, 120 per scenario and cluster, worst case counted) and
    retention (runs 30 days, hourly aggregates 400 days, excerpts and test runs 7 days, alerts forever).
    New server keys `synthetic.runRetention`, `synthetic.aggregateRetention`, `synthetic.excerptRetention`,
    `synthetic.maxRequestsPerMinutePerCluster`, `synthetic.maxRequestsPerMinutePerScenario` and
    `synthetic.probeOfflineAlertAfter`.
  - API `/api/v1/synthetic/*`, `POST /api/v1/clusters/{id}/probe-token` and `DELETE /api/v1/clusters/{id}/probe`
    (OpenAPI updated). Migration `00024` (down refused while `synthetic-editor` grants exist).
  - After a restore of the Olympos database, probes reconnect by themselves: the server moves the allowlist
    version ahead at start-up. Probes whose certificate was renewed after the dump need *Install probe*, and
    credentials rotated after it must be rotated again. See `docs/restore-olympos.md`
    (*Synthetic monitoring after a restore*).
- Lab: `synth-web` in both lab clusters, with CoreDNS answering every `*.olympos-lab.test` name with it and
  `metadata.olympos-lab.test` with `169.254.169.254`; the e2e test `TestM9SyntheticMonitoring` (a second
  Olympos cluster `lab-b` in the same kind cluster).

### Upgrade notes
From v0.2.0 nothing needs action on the server; the migrations run at start.
- Migration `00024` adds synthetic monitoring and the `synthetic-editor` role. Every Slack channel that
  receives `grant.changed` is routed `synthetic.allowlist_changed` too (the migration adds those routes).
  The other new events get no route: add them under *Settings › Notifications › Routing*.
- The agent chart installs the probe by default (`probe.enabled: true`). A `helm upgrade` of an agent adds
  the probe Deployment, which waits until *Settings › Clusters & agents › Install probe* gives it a token.
  Set `probe.enabled=false` to leave it out.
- Mirrored or air-gapped registries need the new image `olympos-probe` next to `olympos-agent`; verify it
  with cosign as described in `docs/install.md`.

## [0.2.0] - 2026-11-23

Restore from the UI, destination groups, a signed kube-bench image.

### Since v0.2.0-rc.1

#### Fixed
- Editing a backup job whose password is stored in Olympos failed with "Invalid job" and no highlighted
  field, unless the password was typed again (also in v0.1.0). The form now keeps the stored password as
  it says, asks for a new one only when the user changes, and shows a refused field on its step.

### Added
- **Restore from the UI into a new target, with approval** ([#22](https://github.com/Warewave-Technology/olympos/issues/22)):
  *Restore…* on a succeeded or partial run loads its copy into a new PostgreSQL, ClickHouse or
  Vault/OpenBao target that Olympos discovered, in any cluster, never the backup's own. The dialog checks
  the target over its tunnel with the given credential (nothing written); the request then waits on
  *Approvals* for another person with `operate` on both clusters (the maker needs `read` on the backup's
  cluster and `operate` on the target's). Admins on both clusters can start it at once as **break-glass**
  with a justification (event `restore.break_glass`). Pending requests expire after `changeRequests.ttl`,
  approved ones that do not start within 24 hours. The server checks the target again, verifies the copy's
  SHA-256 before writing anything and every zip entry's CRC while restoring, never drops or overwrites
  anything (a database with user objects on the target refuses the request), and shows progress and a
  result per database. The target credential and the Vault token are deleted when the request ends. API
  `/api/v1/restores` (`/check`, `/{id}/approve`, `/reject`, `/cancel`); events `restore.requested`,
  `restore.approved`, `restore.rejected`, `restore.started`, `restore.succeeded`, `restore.failed`,
  `restore.break_glass`. See `docs/restore.md` (Restore from the UI) and `docs/getting-started.md` (step 9).
  - PostgreSQL: `pg_restore` of the target's major version (the dump's must be the same or older); roles
    from `globals.sql` with a superuser only, roles that exist on the target are left alone.
  - ClickHouse, deliberately conservative: databases and MergeTree-family, Replicated, Log and Memory tables
    with their data, from DDL Olympos generates (no SQL text from the backup runs on the target). Views,
    materialized views, dictionaries, other engines and secondary table features (defaults, TTL, indexes,
    codecs, settings, …) are listed in the result to re-apply from your schema.
  - Vault/OpenBao: `snapshot-force` with a token of the new Vault (default policy plus `update` and `sudo`
    on `sys/storage/raft/snapshot-force`) into an initialized, unsealed, active node that is not configured
    in Olympos; unseal it afterwards with the source's keys.
- Lab: new, empty restore targets `restore-pg` (PostgreSQL 16, TLS), `restore-ch` (ClickHouse) and
  `restore-vault` (Vault, raft, TLS), and the e2e test `TestM8Restores`.
- The server image and the packages ship the pinned official `clickhouse` binary (LTS) as the restore client;
  new key `backup.clickhouseClient`. Size: packages grow by about 200-230 MB per architecture
  (about 750 MB more under `/usr/lib/olympos/bin`) and the server image goes from about 0.8 to 1.8 GB. See
  `docs/configuration.md`.
- **Signed kube-bench image** ([#26](https://github.com/Warewave-Technology/olympos/issues/26)): upstream
  kube-bench images are not signed, so each release copies the digest the agent pins to
  `ghcr.io/warewave-technology/kube-bench` and signs it with the release identity. New agent chart value
  `bench.imageRepository` pulls that digest from this or your own mirror; the digest never changes with the
  repository. An example Kyverno `ImageValidatingPolicy` is in `deploy/kyverno/kube-bench-signature.yaml`. See
  `docs/install.md` (The kube-bench image).
- **Destination groups** ([#32](https://github.com/Warewave-Technology/olympos/issues/32)): a named list of
  two to four destinations of any kinds (Azure Blob, S3, NFS), under *Settings › Destinations › Groups*
  (`/api/v1/destination-groups`). A backup job, or the Olympos database backup, writes to one destination or
  to a group: wizard step 3, job edit and the *Olympos database* card (`destination_group_id` in the API).
  Each run makes one dump and streams it to every member at once; each copy is verified by size and
  SHA-256. Two members that write to the same location are refused. A destination in a group, and a group
  that a job uses, cannot be deleted. See `docs/getting-started.md` (step 6).
- Per-copy results: a *Copies* table on each run (`copies` in run responses), and manifests name their
  `destination` and `group`. The *Olympos database* card shows the copies of its last run.
- The last successful copy per destination: `destinations_last_success` on jobs and on
  `GET /api/v1/backup/self`; a group job's row on *Backups › Jobs* and the *Olympos database* card list each
  member with the time of its last copy.
- Run status **Partial**: some copies written, not all. Amber badge and *Runs* filter, its own count in the
  24-hour summaries, the event `backup.partial` (not opt-in), and the *Needs attention* items *Backup
  incomplete* (`backup_partial`) and *Olympos backup incomplete* (`self_backup_partial`).
- **Repair runs**: after a partial run, a new dump is written to the missing destinations only
  (`repair_of` names the original run). Up to three repairs, spaced out: 5 minutes after the partial run,
  30 minutes after the first repair, 2 hours after the second, each inside the job's retry window. A
  waiting repair is `queued` with `not_before`; the partial run's details carry `next_repair_at`, and
  `backup.partial` carries `next_attempt_at`. It does not block *Run now*. A repair that completes every
  copy sends `backup.succeeded` (opt-in); one that gives up sends `backup.failed` with the missing
  destinations. A repair that comes due while its job is disabled or paused is skipped quietly.
- Stall detection: a destination that takes no data for 10 minutes, or does not finish within 10 minutes
  after the end of the stream, is detached so the other copies can finish. An upload that does not return
  within 30 seconds after that (blocked in the kernel on a hard NFS mount) is abandoned and logged.
- Restore from a chosen copy: *Restore from copy* on a run and on the *Olympos database* card, and
  `?copy=<destination id>` on `GET /api/v1/backup/runs/{id}` and `GET /api/v1/backup/self`. A destination
  whose copy failed in the run is listed but cannot be chosen; a copy a repair wrote there is restored from
  the repair run (in the API, `?copy=` on the original run still returns it).
- Metric `olympos_backup_copies_total{destination,status}`; `olympos_backup_runs_total` counts
  `status="partial"`.

### Changed
- The retention tier (`olympos-tier`) is decided per destination: a copy is `monthly` or `weekly` when that
  destination has no such copy of the job yet. Copies of one run can carry different tiers.
- The 24-hour counts on *Backups* and the Dashboard count original runs only: repair runs are not counted,
  and a partial run counts as succeeded once a repair has written its missing copies.
- A destination that holds copies of backup runs (`copies` on the destination) cannot be deleted, even when
  no job uses it any more: those runs' restore commands point at it. The refusal says so (409 *destination
  holds copies of N backup run(s)*) and the *Delete* confirmation explains it. Destinations that only hold
  runs from before this release can still be deleted.
- A run's restore commands use the destination the run was written to. Before, they used the job's current
  destination, so after a job moved to another destination, older runs showed commands for the wrong
  storage. Runs from before this release still use the job's destination.

### Upgrade notes
From v0.1.0 nothing needs action; the migrations run at start.
- The server image grows from about 0.8 to 1.8 GB and the packages by about 200-230 MB per architecture
  (the `clickhouse` restore client). Plan node disk and registry space for it.
- Migration `00023` adds restore requests. The new events `restore.failed` and `restore.break_glass` are
  routed to every Slack channel that receives `backup.failed` (the migration adds those routes). The other
  `restore.*` events get no route: add them, or move these two, under *Settings › Notifications › Routing*.
- Migration `00022` runs at start. Existing jobs, runs and single-destination backups are unchanged.
- The new event `backup.partial` is routed to every Slack channel that receives `backup.failed` (the
  migration adds those routes). Review *Settings › Notifications › Routing* if you want it elsewhere.

### Documentation
- `docs/openapi.yaml` listed `notify_on_success` twice in `BackupJobInput`, which strict YAML parsers
  reject.
- The Graph permission `User.ReadBasic.All` was documented on the Entra app registration, where it has no
  effect: Olympos calls Graph as the server's managed identity (or service principal), so the person search
  and the daily principal sync failed with `403 Forbidden`. `docs/azure.md` now assigns the Graph app role to
  that identity with `az rest`, and `docs/troubleshooting.md` covers the error.

## [0.1.0] - 2026-11-21

First public release.

### Upgrade notes
A new installation needs none of this: start with `docs/install.md` (Kubernetes) or
`docs/install-systemd.md` (Linux VM).

From a release candidate: nothing to do. The *Since v0.1.0-rc.N* sections of `CHANGELOG.md` list what
changed.

From a build before v0.1.0-rc.1: these changes came from the security review
(`docs/security-review-v0.1.md`) and can stop backups until the setting is made:
1. **Targets no longer trust public CAs.** Add the CA to `targetTLS.caBundleFile`, or set
   `targetTLS.systemRoots: true`. The error message names the setting.
2. **`kv://` references need a rule for non-global-admin users.** Add a `keyVault.references` rule
   (glob on `<vault>/<secret>` plus cluster label scope); without one, only global admins can enter them.
3. **TLS names are pinned.** When a target's `olympos.io/tls-server-name` annotation changes, the target
   keeps the pinned name until an admin of the cluster accepts the new one (*Needs attention* →
   "TLS name changed", then *Backups*).
4. **One server replica.** The Helm chart refuses `replicas > 1` unless `experimental.multiReplica: true`
   (unsupported; multi-replica is planned for v0.2).

### Since v0.1.0-rc.3
Found by installing the rc.3 packages and charts from scratch. Nothing needs action when upgrading from
rc.3; on Rocky/Alma, install `postgresql16-contrib` if the first start failed with `pgcrypto`.

#### Fixed
- `check-config -db` printed `config ok` for a Key Vault the server could not use; the server then stopped
  at start (`load hmac key`). It now reads the HMAC secret and wraps and unwraps with the KEK like the server,
  checks that the `pgcrypto` extension is available, and (also without `-db`) parses the target and storage CA
  bundles and the `keyVault.references` rules.
- systemd: the documented `sudo olympos-server check-config -db` and `migrate` ran as root and failed against
  the local database (`role "root" does not exist`); they are `sudo -u olympos …` now, in the package's
  post-install message too.
- Rocky/Alma: the install guide missed `postgresql16-contrib` (the schema needs `pgcrypto`) and used the
  x86_64 PGDG repository package, which fails on arm64; the `.rpm` now recommends `postgresql16-contrib`. On
  Azure Database for PostgreSQL, `pgcrypto` has to be allowed in `azure.extensions` (documented).

### Since v0.1.0-rc.2
For anyone testing the release candidates. Nothing here needs action when upgrading from rc.2.

#### Added
- *Audit › Raw reports*: choose where raw Kubescape, Polaris and kube-bench reports are kept
  (`GET`/`PUT /api/v1/audit/settings`, global admin). Before, the `audit.raw_destination_id` setting could
  only be set with SQL.

#### Fixed
- Helm: setting `olympos.listen`, `olympos.experimental` or (with `gatewayTLSSecret`) `olympos.gateway` wrote
  the section twice and the server did not start (duplicate YAML key). The chart now merges its own keys
  with yours, so UI TLS (`listen.tlsCertFile`) and `gateway.extraSANs` can be set. `postgresql.bundled=false`
  without `olympos.database.dsnRef` (or `dsn`) now fails the render instead of starting without a database.
- UI and error messages pointed to *Security* for `tls.missing` and `transfer.compressed_mode`, and to
  *Settings › Clusters*; the Key Vault *Needs attention* items linked to the Access page.
- Scheduler leaders held their advisory lock on a pool connection; on a host with 4 CPUs (pgxpool's default
  pool size) they took the whole pool and the server never became ready. Locks now use their own
  connections; the pool has at least 16 connections unless the DSN sets `pool_max_conns`.
- Release checksums (`SHA256SUMS-<arch>`) and signature bundles name pre-release packages the way GitHub
  stores them (`~` becomes `.`); `sha256sum -c` against v0.1.0-rc.2 found no files.
- Dashboard › Needs attention: the Key Vault items (`kek_purgeable`, `kek_recovery_unknown`) were checked
  only at server start and stayed after the vault was fixed; the server now checks every hour and logs
  when the result changes. The *Agent offline* item used a fixed 5 minutes; it now waits for
  `agents.offlineAlertAfter`, like the `agent.offline` message.
- UI: a backup run's restore commands were squeezed into a narrow column; the Jobs table showed the next run
  in the browser's time zone next to a schedule in the job's zone (now both in the job's zone); change
  requests showed the vault as `cluster / namespace / namespace/service`.

#### Documentation
- New pages: [Configuration](docs/configuration.md) (every server setting, Helm value and environment
  variable), [Access](docs/access.md) (roles, scopes, the first admin, guests),
  [Findings and events](docs/findings-and-events.md) (what each finding, *Needs attention* item and
  notification means and how to fix it), [Troubleshooting](docs/troubleshooting.md),
  [Upgrading](docs/upgrade.md) and [Azure prerequisites](docs/azure.md) (managed identity, Workload Identity,
  the Bicep templates).
- `docs/install.md` set `keyVault.managedIdentityClientID` in the Helm example; with Workload Identity it
  must stay empty (setting it bypasses Workload Identity).
- [Getting started](docs/getting-started.md): the local lab step by step, with a screenshot for every step
  taken by `web/scripts/docs-tour.mjs` (`pnpm docs-tour`), which also checks that the steps still work.
- README: requirements up front (Entra ID and Azure Key Vault are required), a working try-it path
  (`./test/e2e/env.sh`), real screenshots instead of mock data; [docs/README.md](docs/README.md) maps all docs.
- Documentation paths in the UI (restore commands, the Olympos database card) link to the docs on GitHub.

#### Changed
- `release.yml` runs as a dry run on pull requests and main pushes that touch the release inputs, and
  checks checksums and package versions strictly; signed releases verify their own signatures.
- `E2E_CPUS=4 ./test/e2e/run.sh` runs the kind e2e on 4 CPUs, like a CI runner.

### Added
- Cluster inventory through a read-only, outbound-only agent (enrollment with one-time tokens, mTLS, pinned
  internal CA); dashboard with versions, providers, end-of-life and Needs attention.
- Backups of PostgreSQL, ClickHouse and Vault/OpenBao (raft) through the agent tunnel to Azure Blob (managed
  identity, no delete), S3 (and S3-compatible) or NFS; GFS retention by tags and lifecycle rules; missed-run
  detection; dead man's switch; per-run restore commands.
- Vault/OpenBao secret changes with maker/checker approval, envelope-encrypted values, check-and-set writes,
  an `applying` state with reconciliation, and drift detection.
- Audits: kubescape (frameworks baked in, works air-gapped), polaris and opt-in kube-bench, with
  per-check details.
- Security: running images by digest with trivy, Kyverno policies and violations, NetworkPolicy coverage
  with a connection simulator, credentials in ConfigMaps, opt-in Secret inventory (key names only).
- Notifications to Slack with routing; noisy events grouped per cluster and scan.
- Agent reconnect semantics: state snapshots with generations, buffered kube-bench results, retries after
  reconnect, debounced offline/online/flapping alerts.
- Deployment with Helm (bundled PostgreSQL by default) or as a hardened systemd service (`.deb`, `.rpm`,
  tarball); built-in `olympos-self` backup of Olympos' own database.
- Signed releases (cosign keyless) with SBOMs (SPDX, CycloneDX) and provenance.

### Security
- No password crosses a non-TLS connection in `e2e-tls` mode (PostgreSQL only with SCRAM-SHA-256).
- Dev login and the local key vault exist only in development builds.
- Target TLS names are pinned (changes need an admin) and targets trust only configured CAs.
- Key Vault references users enter are limited by `keyVault.references`; Olympos' own secrets are never
  referenceable.
- Findings of the independent review fixed or accepted: [docs/security-review-v0.1.md](docs/security-review-v0.1.md).

[Unreleased]: https://github.com/Warewave-Technology/olympos/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Warewave-Technology/olympos/releases/tag/v0.3.0
[0.2.0]: https://github.com/Warewave-Technology/olympos/releases/tag/v0.2.0
[0.1.0]: https://github.com/Warewave-Technology/olympos/releases/tag/v0.1.0
