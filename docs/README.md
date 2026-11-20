# Olympos documentation

New to Olympos? Start with **[Getting started](getting-started.md)**: a local lab, every step with a
screenshot, no Azure account needed.

## Use

| | |
|---|---|
| [Getting started](getting-started.md) | Add clusters, back up a database, change a Vault secret with approval, run audits and image scans |
| [Restoring backups](restore.md) | PostgreSQL, ClickHouse and Vault/OpenBao restores, the backup format and manifests |
| [Restoring Olympos itself](restore-olympos.md) | Recovering the server from its `olympos-self` backup |
| [Runbook: Vault break-glass](runbooks/vault-break-glass.md) | When Olympos' Vault access is lost or must be bypassed |

## Install and operate

| | |
|---|---|
| [Installing on Kubernetes](install.md) | Prerequisites (Entra ID, Key Vault, storage), the Helm charts, agents, storage hardening, notifications, verifying releases |
| [Installing on a Linux VM](install-systemd.md) | `.deb` / `.rpm` packages, the hardened systemd unit, local PostgreSQL |
| [Repository settings](development.md#repository-settings) | How the public repository is protected (for maintainers) |

## Understand

| | |
|---|---|
| [Security model](security-model.md) | Trust boundaries and how each property is enforced |
| [Security review v0.1](security-review-v0.1.md) | Findings of the independent review and the accepted trade-offs |
| [SPEC.md](../SPEC.md) | The specification: what Olympos must do, and why |
| [Changes to the specification](spec-changes.md) | Decisions that changed or extended a requirement |
| [REST API](openapi.yaml) | OpenAPI description of `/api/v1` |

## Contribute

| | |
|---|---|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to propose changes |
| [Development guide](development.md) | Layout, conventions, tests, migrations, the lab |
| [The e2e lab](../test/e2e/README.md) | What the kind lab contains and how the e2e suite uses it |
| [SECURITY.md](../SECURITY.md) | Reporting a vulnerability privately |

`docs/design/` holds the HTML mockups the UI was built from; they are not user documentation.
