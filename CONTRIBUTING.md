# Contributing to Olympos

Thanks for helping. Olympos manages backups, Vault changes and security data for whole fleets, so changes
are reviewed for safety first: please read [SPEC.md](SPEC.md) (§0 principles) and
[docs/security-model.md](docs/security-model.md) before larger changes, and open an issue to discuss them.

## Development

- Go (see `go.mod`), Node 22 + pnpm, Docker, `kind`, `helm`, `protoc` for proto changes.
- Conventions and test setup: [docs/development.md](docs/development.md).

```bash
make dev-db                                   # PostgreSQL 16 for tests
OLYMPOS_REQUIRE_DB=1 go test -tags dev ./...  # unit + integration (dev build)
make test-release                             # release build: no dev login, no local key vault
cd web && pnpm install && pnpm lint && pnpm test
./test/e2e/run.sh                             # kind e2e (see test/e2e/README.md)
```

Install the pre-commit hooks (gitleaks, gofmt): `pre-commit install`.

## Pull requests

- One topic per pull request, with tests. Security-relevant behaviour (credentials, RBAC, the agent, the
  API proxy, approvals) needs a test that fails without the change.
- Changing a **MUST** in `SPEC.md` needs an entry in [docs/spec-changes.md](docs/spec-changes.md) and an owner
  decision.
- New migrations take a number above the latest on `main`; never edit a released migration.
- UI copy is short, specific and English; code, commits and docs are English.
- Keep the agent narrow: no new RBAC, no write verbs, no listening ports without a spec change.
- Add a line under *Unreleased* in [CHANGELOG.md](CHANGELOG.md).

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).

## Reporting security issues

Never in public issues: see [SECURITY.md](SECURITY.md).
