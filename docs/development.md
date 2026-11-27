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

The web UI is embedded in the server binary (`web/embed.go`). The committed `web/dist/index.html` is a
placeholder that loads no assets, so the server builds without Node. `make web` replaces it with the built UI;
do not commit that file, whose assets are never committed (`TestEmbeddedAssetsExist` fails). The server image
builds the UI itself, and `scripts/package.sh` builds it before the binary and stops when the binary does not
embed what `index.html` loads.

Tests that need Docker skip without it, or fail with `OLYMPOS_REQUIRE_DOCKER=1`. `OLYMPOS_SKIP_DOCKER=1` skips them
even then: CI's release-build job sets it, since the dev-build job runs the same Docker tests and what differs
between the builds is not in them.

`internal/testutil.DB(t)` creates a fresh migrated database per test. `internal/apitest` starts the full HTTP
API with dev login: `e := apitest.New(t, apitest.Options{Modules: ...}); c := e.Login(e.Principal("ada", "Member", "operator@env=prod"))`.
`e.LogBuf` holds redacted logs for canary-secret checks.

### Fake secrets in tests

CI runs gitleaks over the full history (`.gitleaks.toml`, job `hygiene`). A test that needs a value that
looks like a secret (a canary that redaction must catch, a fake credential) marks its line with
`gitleaks:allow` in a comment, for example `"AKIA…", // gitleaks:allow`. The marker is in the line, so it
survives the squash merge. Do not allowlist a test file by path: a real secret added to it later would go
unnoticed. The values that older commits hold without the marker are listed one by one in `.gitleaks.toml`.

## Migrations

`internal/store/migrations/NNNNN_name.sql` (goose, embedded in the binary, applied at start-up and by
`olympos-server migrate`). Numbers have gaps (00004, 00006, 00009–00011 were folded into others before the
first release); renumbering is not needed. Rules:

- A new migration takes a number **strictly greater** than the latest one on `main`
  (`scripts/check-migrations.sh origin/main`, run in CI on pull requests and on `main`). goose runs without
  `allow-missing`: an older number added later would make `Up` fail on every database that is already past
  it ("missing migrations"), so a late, lower number is never silently skipped or applied out of order.
- **A merged migration is immutable**: never edit, rename or delete it, even before it is released. A
  database that already ran it never runs it again, so an edit reaches only new installs, and the two drift
  apart (a lab server once failed to start this way). Fix a merged migration with a new one. The same
  script fails when a file that exists on the base branch changed, or when a file of the latest `v*` tag
  is not byte-identical on `HEAD`.
- Every file has `-- +goose Up` and `-- +goose Down`. `Down` exists for development; production never
  migrates down.
- The server refuses to start on a schema newer than the binary (no downgrades); restore the dump taken
  before the upgrade instead.
- Upgrade test (`e2e.yml`, job `upgrade`): install the latest `v*` release, create data, upgrade to `HEAD`,
  run the smoke tests.

## Releases

A release is a `v*` tag on `main`, pushed by a maintainer (ruleset *release tags* below); `release.yml`
builds, signs and publishes it. Release candidates are `vX.Y.Z-rc.N`.

**Security-model changes ship a release candidate first** (#60, `docs/design/rc-rule.md`). A release changes
the security model when a commit since the previous final release touches one of the files that
`scripts/security-model-paths.sh` lists: `docs/security-model.md`, `proto/`, `internal/secrets/`,
`internal/probe/`, `internal/agent/`, `internal/ingest/` (the native backup endpoint),
`internal/backup/engines/clickhouse/native_manifest.go` (the signed native manifest),
`internal/backup/engines/clickhouse/backupmeta.go` (what a native manifest lists),
`internal/backup/engines/clickhouse/native.go` (the native run, which hands the run's credential to ClickHouse),
`internal/backup/native.go` (the worker's native run: the credential's scope, the signed manifest, the objects' tags),
`internal/backup/native_chain.go` (an incremental's base chain: what its credential reads and which stored objects it is served),
`internal/app/ingest.go` (the ingest endpoint's listener: its TLS and timeouts), `internal/blob/fs.go` (the NFS
writer, whose `SetTags` rewrites the tags of stored backups), or the agent chart's RBAC templates (`clusterrole.yaml`, `bench.yaml`).
CI labels such pull requests `security-model`. Such a release:

1. ships at least one release candidate, and its latest RC contains every one of those commits. `release.yml`
   checks this first on a final tag and fails before anything is built or published; the message names the
   commits. Delete the final tag, tag a new RC, and tag the final again after the steps below;
2. is tested in the lab on that RC with a **focused test plan**, written in the RC's preparation pull request:
   what the change does and how the test exercises it, on both lab clusters, failure paths as well as the
   success path. The results go into the pull request of the final release. An idle lab proves nothing, so
   the plan, not a number of days, decides when the test is done;
3. passes an independent security review before the final tag, like
   [the v0.1 review](security-review-v0.1.md): a reviewer that did not write the change reads the diff since
   the previous final release against `docs/security-model.md`, and the findings are fixed or accepted in
   writing.

A file that should be on the list goes into `scripts/security-model-paths.sh` (and its test,
`scripts/test-security-model-paths.sh`, which CI runs).

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
| Dependabot version updates | weekly, minor/patch grouped; no Node image majors | 2026-11-20 | `.github/dependabot.yml` (gomod, npm `web/`, github-actions, docker `deploy/docker/`) |
| Branch protection on `main` | on, admins included | 2026-11-20 | `gh api -X PUT repos/Warewave-Technology/olympos/branches/main/protection` (body below) |
| Ruleset "release tags" | active | 2026-11-20 | `gh api -X POST repos/Warewave-Technology/olympos/rulesets` (body below) |

`main` protection: a pull request is required (no approval count: a sole maintainer cannot approve their own
pull request); the `ci` jobs `go`, `web`, `hygiene` and `image build` must pass, pinned to the GitHub Actions
app (id 15368) so another source cannot satisfy them; the branch does not have to be up to date; linear
history (squash or rebase merges; the merge-commit button fails); no force pushes, no deletion. `e2e` is not
required: it runs on `main` and nightly, so a failure there shows after the merge. Pull requests that change
`.github/workflows/` can only be merged by a token with the `workflow` scope (the web UI, or
`gh auth refresh -s workflow`).

```json
{"required_status_checks": {"strict": false, "checks": [{"context": "go", "app_id": 15368}, {"context": "web", "app_id": 15368},
  {"context": "hygiene", "app_id": 15368}, {"context": "image build", "app_id": 15368}]},
 "enforce_admins": true, "required_pull_request_reviews": {"required_approving_review_count": 0},
 "restrictions": null, "required_linear_history": true, "allow_force_pushes": false, "allow_deletions": false}
```

Ruleset "release tags": creating, moving or deleting a `refs/tags/v*` tag is refused for everyone except
the repository roles admin (id 5) and maintain (id 2). A `v*` tag starts the release workflow, so only
maintainers can publish. Check the bypass roles by name with GraphQL
(`repository.rulesets.bypassActors.repositoryRoleName`).

```json
{"name": "release tags", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
 "bypass_actors": [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
                   {"actor_type": "RepositoryRole", "actor_id": 2, "bypass_mode": "always"}]}
```

OpenSSF Scorecard (checklist C5) is not set up yet.
