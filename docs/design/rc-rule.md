# Security-model changes ship a release candidate first (#60)

Status: approved by the owner on 2026-11-25, with a focused test plan instead of a fixed two days in the lab.

## Why

A release that changes the security model needs more than a green CI run. v0.3.0 added a component (the probe)
with no release candidate before it. v0.3.1 showed what an RC test should look like: a short lab test that
exercises the change found two problems. Two days of an idle lab would have found nothing.

## Rule

A release changes the security model when a commit since the previous final release touches one of:

- `docs/security-model.md`
- `proto/`
- `internal/secrets/`, `internal/probe/`, `internal/agent/`
- the agent chart's RBAC templates: `deploy/helm/olympos-agent/templates/clusterrole.yaml`, `bench.yaml`

Such a release:

1. ships at least one release candidate (`vX.Y.Z-rc.N`), and every one of those commits is in an RC tag of the
   same version;
2. is tested in the lab on that RC with a **focused test plan**: written in the RC's preparation pull request,
   it says what the change does and how the test exercises it (real clusters, both lab clusters, the failure
   paths as well as the success path). The results go into the pull request of the final release;
3. passes an independent security review before the final tag, like the v0.1 review
   (`docs/security-review-v0.1.md`): a reviewer that did not write the change reads the diff since the previous
   final release against `docs/security-model.md`. The findings are fixed or accepted in writing.

## Approaches

1. **The release workflow checks the commits (chosen).** On a final tag, the workflow lists the commits since
   the previous final tag that touch the paths above and fails, before anything is built or published, unless
   the latest RC tag of the same version contains all of them. It cannot be forgotten, and it needs no API.
2. A `security-model` label on pull requests decides. Rejected as the check: a label can be forgotten or removed.
   It stays, for visibility only.
3. A required review on such pull requests. Rejected: there is a sole maintainer, who cannot approve their own
   pull request.

## Design

- `scripts/security-model-paths.sh`: the path list, one place. `--check <tag>` runs the check for a final tag;
  `--files` reads file names on stdin and says whether any is on the list (for the label).
- `release.yml`: a first job `rc-rule`, needed by every other job, runs `--check "$GITHUB_REF_NAME"` on a final
  tag (no `-` in the version). An RC tag and the dry runs skip it. The failure message names the rule, the
  commits and `docs/development.md` › Releases.
- The label: a `ci.yml` step on pull requests lists the changed files and adds `security-model` when one is on
  the list. A fork's token cannot add labels, so that step is skipped for forks; the release check still
  applies.
- Test: `scripts/test-security-model-paths.sh` builds a throwaway git repository with tags and checks four
  cases: no change (passes), a change in an RC (passes), a change after the last RC (fails, naming the
  commit), a change with no RC at all (fails). It runs in the `hygiene` job.
- Docs: `docs/development.md` › Releases (the rule, the test plan, the review), `CONTRIBUTING.md` (one line),
  CHANGELOG *Unreleased*.

## Left to the builder

The exact wording of the failure message; how the script finds the previous final tag (version sort of
`v*` tags without `-`).
