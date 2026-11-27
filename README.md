<p align="center"><img src="web/src/assets/logo.svg" alt="Olympos" width="96"></p>

<h1 align="center">Olympos</h1>

<p align="center">Backups, Vault change control, audits and security for a fleet of Kubernetes clusters — self-hosted,
with an agent that only ever dials out.</p>

Olympos gives platform teams one place for the chores every cluster needs: it inventories the fleet, backs up
PostgreSQL, ClickHouse and Vault/OpenBao on a schedule to storage it cannot delete from, changes Vault
secrets only through maker/checker approval, runs kubescape, polaris and kube-bench, and shows running images
with their CVEs, Kyverno violations, NetworkPolicy gaps and credentials left in ConfigMaps. One server runs in
your environment (Kubernetes or a systemd VM); a small, read-only agent per cluster connects out to it over
mTLS. Credentials are never stored in a cluster or sent to the agent, and the agent has no listening port.
The agent cannot read Secret values other than its own identity. An optional inventory lists Secret metadata
(names, key names) only; it is off by default, and Kubernetes has no metadata-only permission, so with it on a
stolen agent token could read values ([trade-offs](docs/security-review-v0.1.md#accepted-trade-offs)).

![Fleet overview](docs/images/dashboard.png)

> **Status:** v0.3.1 is the latest release: synthetic monitoring from a probe in every cluster, with one alert
> per synthetic credential that cannot be resolved, on top of v0.2's restore from the UI and destination
> groups, on one server instance with Microsoft Entra ID and Azure Key Vault. v0.4.0-rc.2 is the release
> candidate for v0.4.0 (native ClickHouse backups and restores through the server, installs with Argo CD or
> Flux).
> Changes are in [CHANGELOG.md](CHANGELOG.md), what comes next under [Roadmap](#roadmap).

## Is it for you?

Olympos fits a platform team that runs several Kubernetes clusters and wants backups, Vault change control,
audits and security findings in one self-hosted place. A production installation needs:

| | |
|---|---|
| **Sign-in** | Microsoft Entra ID (OIDC). Access is granted per person in Olympos. |
| **Keys and secrets** | Azure Key Vault: the key that encrypts stored credentials, and any `kv://` secret you reference. |
| **Server** | Kubernetes ≥ 1.27 (Helm chart) or a Linux VM (`.deb`, `.rpm`, systemd), with PostgreSQL 16 (bundled by default). |
| **Backup storage** | Azure Blob, S3 or S3-compatible (MinIO, Ceph RGW, …), or NFS. |
| **Clusters** | Any Kubernetes. The agent needs no inbound port: it dials out to the server's gateway (`:8443`, mTLS). |

Entra ID and Azure Key Vault are required in release builds; there is no other identity or key provider
yet. To try Olympos without Azure, use the local lab below.

## Architecture

```mermaid
flowchart LR
  user([People<br/>Entra ID SSO]) -->|HTTPS| server
  subgraph env [Your environment]
    server[olympos-server<br/>API + UI + schedulers]
    db[(PostgreSQL<br/>bundled or external)]
    kv[(Key Vault<br/>KEK, secrets)]
    storage[(Backup storage<br/>Blob / S3 / NFS<br/>no delete *)]
    server --- db
    server --- kv
    server -->|write, no delete *| storage
  end
  subgraph c1 [Each cluster]
    agent[olympos-agent<br/>read-only RBAC]
    targets[(PostgreSQL · ClickHouse<br/>Vault / OpenBao)]
    agent -. tunnel .-> targets
  end
  agent ==>|gRPC mTLS, dials out| server
```

\* Azure Blob (SAS) and S3 (policy) credentials cannot delete; a file system cannot enforce that, so NFS
destinations show a permanent warning and need storage-side snapshots or WORM.

- **Server**: Go, PostgreSQL, React SPA. Backups run on the server and reach targets through a byte tunnel the
  agent opens on request. In `e2e-tls` mode (default) the server speaks TLS end to end and the agent sees
  ciphertext; a PostgreSQL target without TLS is backed up only with SCRAM, so the agent sees the data but
  never the password, and the target is flagged `tls.missing`.
- **Agent**: distroless, read-only ClusterRole, discovery by Service annotations, reports state snapshots.
- **Security model** (details in [docs/security-model.md](docs/security-model.md)): maker ≠ checker for every
  Vault change, envelope encryption with a Key Vault KEK, blob credentials without delete, no password over
  plaintext in `e2e-tls` mode, dev login compiled out of release builds, signed releases with SBOMs.

| Security | Backups | Approvals |
|---|---|---|
| ![Security](docs/images/security.png) | ![Backups](docs/images/backups.png) | ![Approvals](docs/images/approvals.png) |

## Try it locally

A local lab with two kind clusters, databases, Vaults and backup storage, and a development build of the
server (dev login, local key vault: no Azure needed). Requires Docker, [kind](https://kind.sigs.k8s.io),
`kubectl`, Helm, Go and `openssl`:

```bash
./test/e2e/env.sh
```

Then follow **[Getting started](docs/getting-started.md)**: add both clusters, back up a database, change a
Vault secret with a second person's approval, restore a backup into a new server, and run audits and image
scans, with a screenshot for every step. `./test/e2e/env.sh down` removes the lab.

## Install

- Kubernetes: [docs/install.md](docs/install.md) (Helm; bundled PostgreSQL by default).
- Linux VM as a systemd service: [docs/install-systemd.md](docs/install-systemd.md) (`.deb`, `.rpm`, tarball).
- Verify release signatures before installing: [docs/install.md#verifying-releases](docs/install.md#verifying-releases).

## Roadmap

Released in v0.3 ([all roadmap issues](https://github.com/Warewave-Technology/olympos/issues?q=is%3Aissue+label%3Aroadmap)):

- Synthetic monitoring: scenarios that run from every cluster, with alerts ([#46](https://github.com/Warewave-Technology/olympos/issues/46))

Released in v0.2:

- Restore from the UI into a new target, with approval ([#22](https://github.com/Warewave-Technology/olympos/issues/22))
- More than one destination per backup job, one dump stored in each ([#32](https://github.com/Warewave-Technology/olympos/issues/32))
- Signature verification of the pinned kube-bench image ([#26](https://github.com/Warewave-Technology/olympos/issues/26))

Planned for v0.4 ([milestone](https://github.com/Warewave-Technology/olympos/milestone/3)):

- ClickHouse backups with ClickHouse's own `BACKUP`/`RESTORE`, written through Olympos ([#62](https://github.com/Warewave-Technology/olympos/issues/62))
- Before v0.4.0: an acceptance run on real Azure ([#58](https://github.com/Warewave-Technology/olympos/issues/58)), identity
  Secrets that survive GitOps syncs ([#59](https://github.com/Warewave-Technology/olympos/issues/59)), a release candidate for
  every security-model change ([#60](https://github.com/Warewave-Technology/olympos/issues/60)), and published recovery time
  and data-loss figures ([#61](https://github.com/Warewave-Technology/olympos/issues/61))

Planned for v0.5 ([milestone](https://github.com/Warewave-Technology/olympos/milestone/6)):

- Runtime security: what running containers do, seen by Falco, detection only ([#63](https://github.com/Warewave-Technology/olympos/issues/63))

Later, not scheduled ([milestone](https://github.com/Warewave-Technology/olympos/milestone/4)): more than one approval for
Vault changes ([#23](https://github.com/Warewave-Technology/olympos/issues/23)), S3 destinations with IAM roles
([#24](https://github.com/Warewave-Technology/olympos/issues/24)), image scans from ACR with the server's managed identity
([#25](https://github.com/Warewave-Technology/olympos/issues/25)).
- Restore: an admin can cancel an approved request; an event when a request expires ([#42](https://github.com/Warewave-Technology/olympos/issues/42), [#43](https://github.com/Warewave-Technology/olympos/issues/43))

Ideas and comments are welcome on the issues.

## Documentation

Start with [Getting started](docs/getting-started.md); the full map is in [docs/README.md](docs/README.md).

| | |
|---|---|
| [Getting started](docs/getting-started.md) | The local lab, step by step with screenshots |
| [Azure prerequisites](docs/azure.md) · [Install on Kubernetes](docs/install.md) · [on a Linux VM](docs/install-systemd.md) | Production installation |
| [Configuration](docs/configuration.md) · [Upgrading](docs/upgrade.md) · [Troubleshooting](docs/troubleshooting.md) | Running it |
| [Access](docs/access.md) · [Findings and events](docs/findings-and-events.md) | Roles and scopes; what each finding and notification means |
| [Security model](docs/security-model.md) · [Security review v0.1](docs/security-review-v0.1.md) | Trust boundaries, what is enforced where, accepted trade-offs |
| [Restore](docs/restore.md) · [Restoring Olympos](docs/restore-olympos.md) | Recovering targets and Olympos itself |
| [REST API](docs/openapi.yaml) | OpenAPI description of `/api/v1` |
| [SPEC.md](SPEC.md) | The specification |

## Development

```bash
make dev-db && OLYMPOS_REQUIRE_DB=1 go test -tags dev ./...   # unit + integration (dev build)
make test-release                                             # release build checks
cd web && pnpm install && pnpm test && pnpm build             # SPA
./test/e2e/run.sh                                             # kind e2e suite
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
Versioning follows [SemVer](https://semver.org); changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](LICENSE).
