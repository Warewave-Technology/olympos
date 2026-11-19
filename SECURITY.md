# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub Security Advisories:
<https://github.com/Warewave-Technology/olympos/security/advisories/new>. Do not open a public issue,
pull request or discussion for a suspected vulnerability.

Include what you found, how to reproduce it, the version (`olympos-server version`, agent image tag) and the
impact you expect. We acknowledge within 3 working days, agree on a fix and a disclosure date with you, and
credit you in the advisory unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes (latest patch release) |
| < 0.1 | no |

## Scope

Olympos holds sensitive capabilities (backup credentials, Vault change approval, a read-only agent in every
cluster). The security model, its trust boundaries and the accepted trade-offs are in
[docs/security-model.md](docs/security-model.md); the independent review of v0.1 is in
[docs/security-review-v0.1.md](docs/security-review-v0.1.md). Reports about anything that lets a principal or
an agent go beyond what those documents allow are in scope, for example:

- reading a secret value through the agent, the API proxy or the Secret inventory;
- bypassing maker/checker, grants or cluster scopes;
- a backup credential that can delete backups without the destination test flagging it;
- a password sent over a non-TLS connection in `e2e-tls` mode.

## Verifying releases

Every release artifact is signed (cosign keyless) and has an SBOM and provenance; see
[docs/install.md#verifying-releases](docs/install.md#verifying-releases).
