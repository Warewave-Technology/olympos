# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Scheduler leaders held their advisory lock on a pool connection; on a host with 4 CPUs (pgxpool's default
  pool size) they took the whole pool and the server never became ready. Locks now use their own
  connections; the pool has at least 16 connections unless the DSN sets `pool_max_conns`.
- Release checksums (`SHA256SUMS-<arch>`) and signature bundles name pre-release packages the way GitHub
  stores them (`~` becomes `.`); `sha256sum -c` against v0.1.0-rc.2 found no files.

### Changed
- `release.yml` runs as a dry run on pull requests and main pushes that touch the release inputs, and
  checks checksums and package versions strictly; signed releases verify their own signatures.
- `E2E_CPUS=4 ./test/e2e/run.sh` runs the kind e2e on 4 CPUs, like a CI runner.

## [0.1.0] - unreleased

First public release.

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
