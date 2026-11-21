# Troubleshooting

Each section starts with what you see, then the cause and the fix. Error messages are quoted as Olympos
shows them. The server log is the first place to look:

```bash
kubectl -n olympos logs deploy/olympos            # Helm
journalctl -u olympos-server -e                   # systemd
kubectl -n olympos-system logs deploy/olympos-agent   # an agent, in its cluster
```

## A cluster stays pending: the agent does not connect

**The install command was not run in time, or twice.** The bootstrap token in the command is valid for one
hour and can be used once. Open *Settings › Clusters & agents*, select the cluster and choose **Show install
command**; it issues a fresh token. Run it again.

**The agent cannot reach the gateway.** The agent dials `agentGatewayURL` (server configuration), port
`8443` by default. Check from the cluster that the name resolves to the gateway Service (a LoadBalancer by
default, internal on Azure) and that the port is open. The connection is mutual TLS with client certificates:
a proxy or load balancer in between must pass TCP through, not terminate TLS.

**The agent trusts a different CA.** The command carries `serverCA`, the CA that signs the gateway
certificate. If you replaced the gateway certificate (`gatewayTLSSecret`) after generating the command,
generate it again.

## The server is not ready

`/readyz` (on the metrics port, `9090`) fails when the database is unreachable, or when a second server
instance uses the same database. In that case the log says:

> another olympos-server instance (…) uses this database; v0.1 supports a single instance

v0.1 runs one instance: keep `replicas: 1`. During a rolling restart the new instance becomes ready once
the old one has stopped (instances heartbeat every 10 seconds and count as gone after 30). See
[Configuration](configuration.md) for the database settings.

## The server stops at start: pgcrypto is not available

> migrate: ERROR 00001_init.sql: … ERROR: extension "pgcrypto" is not available

Olympos' schema uses the `pgcrypto` extension. On Rocky/Alma install `postgresql16-contrib` (Debian and
Ubuntu ship it in `postgresql-16`); on Azure Database for PostgreSQL allow it in the server parameter
`azure.extensions` (`PGCRYPTO`). `sudo -u olympos olympos-server check-config -db` reports this before the
first start.

## Backups fail with a TLS error

> no CA is trusted for targets: set targetTLS.caBundleFile (PEM with the CAs that issue your targets'
> certificates), a per-target CA, or targetTLS.systemRoots: true

Targets do not trust public CAs by default, so that someone who can edit a Service cannot point Olympos at a
server with a public certificate for a domain they own. Put the CAs that issue your databases' and vaults'
certificates in a PEM file and set `targetTLS.caBundleFile`, or set `targetTLS.systemRoots: true` if your
targets use publicly trusted certificates ([install](install.md#target-certificates)).

**A target's certificate name does not match.** Olympos verifies the name in the
`olympos.io/tls-server-name` annotation, or `<service>.<namespace>.svc` without it. The name is pinned the
first time the target is seen. If the annotation changes, the Dashboard shows *TLS name changed* under
*Needs attention*; an admin of that cluster accepts the new name under *Backups* (only if the change was
expected).

## A target without TLS is refused

In the default transfer mode (`e2e-tls`) no password crosses a connection without TLS:

- **PostgreSQL** without TLS is backed up only when the server asks for SCRAM-SHA-256. MD5 or cleartext
  password authentication is refused: use `scram-sha-256` in `pg_hba.conf` and reset the password, or enable
  TLS.
- **ClickHouse** and **Vault/OpenBao** without TLS are refused: enable TLS.

The other way out is the cluster's transfer mode `compressed` (*Settings › Clusters & agents*): traffic
inside the cluster is then plaintext and visible to the agent. Olympos opens the
`transfer.compressed_mode` finding on that cluster for as long as it is set. Every target without TLS also
gets the `tls.missing` finding.

## A Key Vault reference is refused

> this Key Vault reference is not allowed for this cluster: an admin has to allow it (keyVault.references)

People without `admin` with scope `all` can only use `kv://` references that a `keyVault.references` rule
allows for that cluster ([configuration](configuration.md)). Olympos' own secrets can never be referenced:

> this Key Vault secret is used by Olympos itself and cannot be referenced

## Key Vault purge protection is off

> Key Vault purge protection is off: the KEK can be purged and every Olympos backup of its own database
> becomes useless

Olympos' own backups can only be restored with the same Key Vault key. Turn on soft delete and purge
protection on that vault (it cannot be turned off again):

```bash
az keyvault update --name <vault> --enable-purge-protection true
```

*could not check purge protection of the KEK (needs keys/get)* means the server's identity cannot read the
key's properties; grant it `keys/get` (the *Key Vault Crypto User* role includes it).

The server checks again every hour, so the Dashboard item goes away within an hour of the fix (a restart
checks at once). When the check passes again, the log says *Key Vault purge protection is on: the KEK is
recoverable*.

## A destination's SAS token expired

Olympos warns 14 and 3 days before an Azure Blob SAS token expires (`sas.expiring`) and backups to that
destination fail once it has. Issue a new SAS with the same permissions (read, create, write, tag; no
delete) and paste it under *Settings › Destinations*, or update the Key Vault secret it references.

## Approving a change answers "try again"

> another change to this vault is being applied; try again in a moment

Changes to one vault are applied one at a time; approve waits up to 15 seconds for the previous one. Approve
again. A request whose Vault write timed out stays *applying* until Olympos has checked the vault; it then
becomes *applied* or *failed*.

## Images are not scanned

Each image row on *Security* says why it was not scanned. Common causes:

- **A private registry.** Add a pull credential for it under *Settings › Registries*.
- **The registry is not reachable from the server.** Images are scanned with Trivy on the server, which
  needs network access to the registries your workloads pull from and to Trivy's vulnerability database
  (or a mirror; see [install](install.md#restricted-networks)).
- **The running digest is gone from the registry** (rebuilt or retagged image). The image with the same tag is
  scanned instead and marked *Scanned by tag*: its results may differ from what runs.

Failed scans are retried automatically; operators can retry now from the row.

## kube-bench has not run

kube-bench needs a privileged Job on every node, so it is off until enabled on the cluster's agent:

```bash
helm upgrade olympos-agent <chart> -n olympos-system --reuse-values --set bench.enabled=true
```

or tick *Enable kube-bench* when adding the cluster.

## Someone signs in and sees "no access"

They have no grant yet. An admin grants roles under *Settings › Access* ([Access](access.md)). If they
cannot sign in at all, check that they are assigned to the Olympos enterprise application in Entra
(*Assignment required*).

## The person search fails

> Entra ID directory search failed; check the Graph permission User.ReadBasic.All

*Settings › Access › Grant access* cannot find anyone, and the server log has `directory search` with
`403 Forbidden`. The daily principal sync fails the same way (`principal sync`, `403 Forbidden`), so grants of
disabled or deleted accounts are not marked stale. Olympos calls Microsoft Graph as the server's identity
(its managed identity, or the service principal on a VM outside Azure), not as the Entra sign-in app: a
Graph permission on the app registration has no effect. Give the server's identity the Graph app role
`User.ReadBasic.All` ([Azure prerequisites › Microsoft Graph](azure.md#microsoft-graph)), then restart the
server.

## Still stuck

Open an issue with the server version (`olympos-server version`, or the image tag), the agent version
(*Settings › Clusters & agents*), the exact message and what you were doing. Do not paste secrets, tokens or connection strings. Security problems go
to [SECURITY.md](../SECURITY.md), not to a public issue.
