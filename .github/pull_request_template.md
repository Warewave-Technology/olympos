## What and why

<!-- One topic per pull request. Link the issue. -->

## Checklist

- [ ] Tests cover the change (security-relevant behaviour has a test that fails without it)
- [ ] `go test -tags dev ./...`, `make test-release` and `pnpm test` pass locally
- [ ] SPEC MUST changed? Entry in `docs/spec-changes.md` with an owner decision
- [ ] New migration numbered above `main`'s latest
- [ ] `CHANGELOG.md` updated under *Unreleased*
