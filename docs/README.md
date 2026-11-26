# Olympos documentation

New to Olympos? Start with **[Getting started](getting-started.md)**: a local lab, every step with a
screenshot, no Azure account needed.

## Use

| | |
|---|---|
| [Getting started](getting-started.md) | Add clusters, back up a database, change a Vault secret with approval, restore a backup into a new server, run audits and image scans, watch a service from every cluster |
| [Access](access.md) | Roles, scopes, granting access, guests and the first admin |
| [Findings and events](findings-and-events.md) | What each finding, *Needs attention* item and notification means, and how to fix it |
| [Restoring backups](restore.md) | Restore from the UI into a new target with approval (and what each engine restores), restores by hand, the backup format and manifests, choosing a copy |
| [ClickHouse backups](clickhouse-backups.md) | Native or logical: what each keeps, what a native backup needs (versions, egress, trust, privileges), incrementals, limits |
| [Restoring Olympos itself](restore-olympos.md) | Recovering the server from its `olympos-self` backup |
| [Synthetic monitoring](synthetic-monitoring.md) | Scenarios that run from inside every cluster: the probe, the host allowlist, credentials, results, alerts, roles |
| [Runbook: Vault break-glass](runbooks/vault-break-glass.md) | When Olympos' Vault access is lost or must be bypassed |

## Install and operate

| | |
|---|---|
| [Azure prerequisites](azure.md) | Entra app, managed identity and Workload Identity, Key Vault and backup storage with the Bicep templates |
| [Installing on Kubernetes](install.md) | Prerequisites (Entra ID, Key Vault, storage), the Helm charts, agents, storage hardening, notifications, verifying releases |
| [Installing on a Linux VM](install-systemd.md) | `.deb` / `.rpm` packages, the hardened systemd unit, local PostgreSQL |
| [Configuration](configuration.md) | Every server setting, Helm value and environment variable |
| [Upgrading](upgrade.md) | Upgrading the server and agents, downgrades, uninstalling |
| [Troubleshooting](troubleshooting.md) | Common problems by what you see, with the fix |
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

`docs/design/` holds the HTML mockups the UI was built from and the designs of features in progress
([destination groups](design/destination-groups.md), [restore from the UI](design/ui-restore.md),
[synthetic monitoring](design/synthetic-monitoring.md), [native ClickHouse backups](design/clickhouse-native.md)),
with the decisions taken while building them; they are not user documentation.
