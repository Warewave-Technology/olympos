# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation
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

[Unreleased]: https://github.com/Warewave-Technology/olympos/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Warewave-Technology/olympos/releases/tag/v0.1.0
