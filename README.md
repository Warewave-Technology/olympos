# Olympos

Self-hosted management platform for a fleet of Kubernetes clusters: inventory, backups (PostgreSQL,
ClickHouse, Vault/OpenBao), Vault secret changes with maker/checker approval, audits (kubescape, polaris,
kube-bench) and security (images + trivy, Kyverno, NetworkPolicy). One server in your Azure subscription,
one agent per cluster; agents dial out, credentials never enter a cluster.

`SPEC.md` is the source of truth. Start with:

| Doc | |
|---|---|
| [docs/install.md](docs/install.md) | Installing server + agents, Entra, Key Vault, hardened Blob storage |
| [docs/security-model.md](docs/security-model.md) | Trust boundaries and how each property is enforced |
| [docs/restore.md](docs/restore.md) | Manual restore per engine |
| [docs/runbooks/vault-break-glass.md](docs/runbooks/vault-break-glass.md) | Vault break-glass |
| [docs/openapi.yaml](docs/openapi.yaml) | REST API |
| [docs/development.md](docs/development.md) | Conventions, tests |
| [test/e2e/README.md](test/e2e/README.md) | kind lab |
| [docs/spec-changes.md](docs/spec-changes.md) | Approved changes to SPEC MUSTs |

```bash
make dev-db && OLYMPOS_REQUIRE_DB=1 go test -tags dev ./...   # unit + integration
cd web && pnpm install && pnpm test && pnpm build   # SPA
./test/e2e/run.sh                                   # kind lab e2e (M1–M6)
go run ./cmd/olympos-server -config deploy/dev/config.yaml   # local dev server
```
