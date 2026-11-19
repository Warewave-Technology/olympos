# Development guide

Read `SPEC.md` first: it is the source of truth. `docs/openapi.yaml` is the REST contract shared by the
backend and the SPA — keep handlers and the SPA in sync with it (extend it in the same change if needed).

## Layout and conventions

- Go module `github.com/Warewave-Technology/olympos`, Go ≥ 1.23, `gofmt`, `go vet` clean.
- **Queries**: plain `pgx` next to the domain code (no sqlc). Each module owns its SQL.
- **Migrations**: `internal/store/migrations/NNNNN_<name>.sql` (goose). `00001_init.sql` has the full v1 schema.
  Milestone modules that need schema changes add their own file: M2 → `00002_*`, M3 → `00003_*`,
  M4 → `00004_*`, M5 → `00005_*`, M6 → `00006_*`. Never edit an earlier migration.
- **API modules** implement `server.Module` (`Routes(r chi.Router)`), mounted under `/api/v1` behind
  session auth + CSRF. Use `internal/httpx` helpers: `Subject(r)`, `JSON`, `Error`, `FieldErrors`,
  `Decode`, `CanCluster` (404 when out of scope, never 403), `ScopedClusters`, `Record` (activity log).
- **Wiring**: each module registers itself in `internal/app/modules_<name>.go` via `app.Register(func(d *app.Deps) (app.Wiring, error))`
  returning its API modules and background workers. Do not edit `app.go` for module wiring.
- **Agent features** register in `internal/agent/<feature>.go` via `registerExtender` (reporters, bench runner).
- **Events**: `notify.Emit(ctx, tx, notify.Event{...})` in the same transaction as the state change.
- **Activity**: every user action → `httpx.Record` (or `activity.Record`) in the same transaction.
- **Findings**: `internal/findings` (`Open`, `Resolve`, `Reconcile`).
- **Scheduling**: `internal/schedule` (`Parse`, `Next`, `RunLeader` with an advisory lock key).
- **Secrets**: `secrets.Envelope` for stored values (AAD = "<table>:<id>"), `secrets.Resolve` for `kv://` refs,
  `secrets.Zero` after use. Never log or return secret values; the slog handler redacts common shapes but
  do not rely on it. HMAC fingerprints via `secrets.Fingerprinter`.
- **Backups**: engines implement `backup.Engine` and `backup.RegisterEngine` in `init()`; storage via `blob.Resolver`.
- Authorization: `authz.Subject.Can(perm, clusterLabels)`; global objects (destinations, channels, grants,
  registries) need `CanGlobal`. Controls the role does not allow are hidden in the SPA (use `/me.permissions`).

## Running tests

```bash
make dev-db                   # Postgres 16 on 127.0.0.1:55432 (olympos/olympos)
OLYMPOS_REQUIRE_DB=1 go test -tags dev ./...
```

Development builds use the `dev` build tag: only they contain the dev login (`/auth/dev-login`) and the local
Key Vault, so tests, lab and e2e images are built with `-tags dev` (`--build-arg GO_TAGS=dev` for the server
image). Release builds have neither and refuse `devMode: true` at startup. `make test-release` runs the
untagged tests and `scripts/check-release-binary.sh` (symbol and string check).

`internal/testutil.DB(t)` creates a fresh migrated database per test. `internal/apitest` starts the full HTTP
API with dev login: `e := apitest.New(t, apitest.Options{Modules: ...}); c := e.Login(e.Principal("ada", "Member", "operator@env=prod"))`.
`e.LogBuf` holds redacted logs for canary-secret checks.

## Migrations

`internal/store/migrations/NNNNN_name.sql` (goose, embedded in the binary, applied at start-up and by
`olympos-server migrate`). Numbers have gaps (00004, 00006, 00009–00011 were folded into others before the
first release); renumbering is not needed. Rules:

- A new migration takes a number **strictly greater** than the latest one on `main`
  (`scripts/check-migrations.sh origin/main`, run in CI for pull requests). goose runs without
  `allow-missing`: an older number added later would make `Up` fail on every database that is already past
  it ("missing migrations"), so a late, lower number is never silently skipped or applied out of order.
- Every file has `-- +goose Up` and `-- +goose Down`. `Down` exists for development; production never
  migrates down.
- The server refuses to start on a schema newer than the binary (no downgrades); restore the dump taken
  before the upgrade instead.
- Upgrade test (`e2e.yml`, job `upgrade`): install the latest `v*` release, create data, upgrade to `HEAD`,
  run the smoke tests.

## Lab

Kind runs on OrbStack's Docker. **Never touch other kube contexts**: e2e uses its own kubeconfig
(`test/e2e/.work/kubeconfig`). See `test/e2e/README.md`.

## Repository settings

Settings that live in GitHub, not in the code (v0.1.0 final checklist C). Set with `gh api`; check with the
same calls without `-X`.

| Setting | State | Set on | How |
|---|---|---|---|
| Private vulnerability reporting (SECURITY.md links to it) | on | 2026-11-20 | `gh api -X PUT repos/Warewave-Technology/olympos/private-vulnerability-reporting` |
| Secret scanning | on | 2026-11-20 | `gh api -X PATCH repos/Warewave-Technology/olympos` with `security_and_analysis.secret_scanning.status=enabled` |
| Secret scanning push protection | on | 2026-11-20 | same call, `secret_scanning_push_protection` |
| Dependabot alerts | on | before 2026-11-20 | `repos/…/vulnerability-alerts` (204 = on) |
| Dependabot security updates | on | 2026-11-20 | `gh api -X PUT repos/Warewave-Technology/olympos/automated-security-fixes` |
| Dependabot version updates | weekly, minor/patch grouped | 2026-11-20 | `.github/dependabot.yml` (gomod, npm `web/`, github-actions, docker `deploy/docker/`) |

Branch protection, tag rulesets and OpenSSF Scorecard (checklist C2, C5, C6) are not set yet.
