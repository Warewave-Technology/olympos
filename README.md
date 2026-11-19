<p align="center"><img src="web/src/assets/logo.svg" alt="Olympos" width="96"></p>

<h1 align="center">Olympos</h1>

<p align="center">Backups, Vault change control, audits and security for a fleet of Kubernetes clusters — self-hosted,
with an agent that only ever dials out.</p>

Olympos gives platform teams one place for the chores every cluster needs: it inventories the fleet, backs up
PostgreSQL, ClickHouse and Vault/OpenBao on a schedule to storage that cannot delete backups, changes Vault
secrets only through maker/checker approval, runs kubescape, polaris and kube-bench, and shows running images
with their CVEs, Kyverno violations, NetworkPolicy gaps and credentials left in ConfigMaps. One server runs in
your environment (Kubernetes or a systemd VM); a small, read-only agent per cluster connects out to it over
mTLS. Credentials never enter a cluster, and the agent has no listening port and no access to Secrets.

![Fleet overview](docs/images/dashboard.png)

## Architecture

```mermaid
flowchart LR
  user([People<br/>Entra ID SSO]) -->|HTTPS| server
  subgraph env [Your environment]
    server[olympos-server<br/>API + UI + schedulers]
    db[(PostgreSQL<br/>bundled or external)]
    kv[(Key Vault<br/>KEK, secrets)]
    storage[(Backup storage<br/>Blob / S3 / NFS<br/>no delete)]
    server --- db
    server --- kv
    server -->|write only| storage
  end
  subgraph c1 [Each cluster]
    agent[olympos-agent<br/>read-only RBAC]
    targets[(PostgreSQL · ClickHouse<br/>Vault / OpenBao)]
    agent -. tunnel .-> targets
  end
  agent ==>|gRPC mTLS, dials out| server
```

- **Server**: Go, PostgreSQL, React SPA. Backups run on the server and reach targets through a byte tunnel the
  agent opens on request (TLS end to end; the agent never sees plaintext in `e2e-tls` mode).
- **Agent**: distroless, read-only ClusterRole, discovery by Service annotations, reports state snapshots.
- **Security model** (details in [docs/security-model.md](docs/security-model.md)): maker ≠ checker for every
  Vault change, envelope encryption with a Key Vault KEK, blob credentials without delete, no password over
  plaintext, dev login compiled out of release builds, signed releases with SBOMs.

| Security | Backups | Approvals |
|---|---|---|
| ![Security](docs/images/security.png) | ![Backups](docs/images/backups.png) | ![Approvals](docs/images/approvals.png) |

## Quick start (kind)

Requirements: Docker, [kind](https://kind.sigs.k8s.io), Helm, Go. This builds the images, creates a two-node
kind cluster with PostgreSQL, ClickHouse, Vault, OpenBao, Azurite and MinIO, installs the server (development
build: local key vault, dev login) and enrolls nothing:

```bash
SETUP_ONLY=1 ./test/e2e/run.sh
open http://127.0.0.1:28080/auth/dev-login?oid=00000000-0000-0000-0000-00000000ad01&name=Admin
```

Then *Dashboard › Add cluster*, run the generated Helm command against the lab
(`KUBECONFIG=test/e2e/.work/kubeconfig`), and back up `orders-pg` from *Backups*. `./test/e2e/env.sh` builds a
browsable lab with two clusters; `./test/e2e/run.sh` runs the whole e2e suite.

## Install

- Kubernetes: [docs/install.md](docs/install.md) (Helm; bundled PostgreSQL by default).
- Linux VM as a systemd service: [docs/install-systemd.md](docs/install-systemd.md) (`.deb`, `.rpm`, tarball).
- Verify release signatures before installing: [docs/install.md#verifying-releases](docs/install.md#verifying-releases).

## Documentation

| Doc | |
|---|---|
| [SPEC.md](SPEC.md) | The specification (source of truth) |
| [docs/security-model.md](docs/security-model.md) | Trust boundaries and how each property is enforced |
| [docs/restore.md](docs/restore.md) · [docs/restore-olympos.md](docs/restore-olympos.md) | Restoring targets · restoring Olympos itself |
| [docs/runbooks/vault-break-glass.md](docs/runbooks/vault-break-glass.md) | Vault break-glass |
| [docs/openapi.yaml](docs/openapi.yaml) | REST API |
| [docs/development.md](docs/development.md) | Conventions, tests, migrations |
| [docs/spec-changes.md](docs/spec-changes.md) | Decisions that changed SPEC MUSTs |

## Development

```bash
make dev-db && OLYMPOS_REQUIRE_DB=1 go test -tags dev ./...   # unit + integration (dev build)
make test-release                                             # release build checks
cd web && pnpm install && pnpm test && pnpm build             # SPA
./test/e2e/run.sh                                             # kind e2e (M1–M7)
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
Versioning follows [SemVer](https://semver.org); changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](LICENSE).
