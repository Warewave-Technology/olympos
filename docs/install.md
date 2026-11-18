# Installing Olympos

Olympos is one installation per customer: a server in your Azure subscription and one agent per
Kubernetes cluster. Agents dial out to the server; the server never connects into a cluster.

## 1. Prerequisites

| Item | Notes |
|---|---|
| AKS (or any Kubernetes ≥ 1.27) for the server | Helm chart `deploy/helm/olympos-server` |
| PostgreSQL 16 | Azure Database for PostgreSQL Flexible Server recommended; in-cluster is fine for small installs |
| User-assigned **Managed Identity** for the server | Used for Key Vault, Blob and (optionally) Graph via Azure Workload Identity |
| **Azure Key Vault** | Holds the KEK (RSA key), the HMAC key and every `kv://` secret |
| **Azure Blob Storage** | Backup destination, hardened as in §4 below |
| **Entra ID app registration** | Web platform, redirect URI `https://<publicURL>/auth/callback`, ID tokens |
| Network | Users → server `:443`; agents → server gateway `:8443` (mTLS). Nothing else inbound. |

### Entra ID

1. Register an app (single tenant). Add redirect URI `https://olympos.contoso.internal/auth/callback`.
2. Create a client secret and store it in Key Vault (`olympos-oidc-client-secret`).
3. Graph application permission **`User.ReadBasic.All`** (grant admin consent) — used for the person
   search in *Grant access* and the daily principal sync (disabled/deleted accounts → stale grants).
4. Enterprise application → Properties → **Assignment required = Yes** and assign the people who may
   sign in. This is a second gate in front of Olympos's own grants.
5. Note the tenant ID and client ID. Olympos validates `iss`, `tid`, `aud`, `exp`, `nbf` on every token
   and ignores group claims.

### Key Vault

```bash
az keyvault key create --vault-name kv-platform-weu --name olympos-kek --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault secret set --vault-name kv-platform-weu --name olympos-hmac --value "$(openssl rand -hex 32)"
az keyvault secret set --vault-name kv-platform-weu --name olympos-db-dsn \
  --value 'postgres://olympos:<password>@<server>.postgres.database.azure.com:5432/olympos?sslmode=verify-full'
```

Grant the server identity: *Key Vault Crypto User* on the key (wrap/unwrap), *Key Vault Secrets User*
on the secrets it reads, and *Key Vault Secrets Officer* if Vault AppRole secret IDs should be stored
there (Vaults › Configure writes `olympos-vault-<id>-secret-id`).

## 2. Server

```yaml
# values.yaml
workloadIdentity: {enabled: true, clientID: <managed identity client id>}
olympos:
  publicURL: https://olympos.contoso.internal
  agentGatewayURL: olympos-gw.contoso.internal:8443
  entra:
    tenantID: <tenant guid>
    clientID: <app client id>
    clientSecretRef: kv://kv-platform-weu/olympos-oidc-client-secret
  bootstrapAdmins: [<object id of the first admin>]   # used only while no grants exist
  keyVault:
    name: kv-platform-weu
    kekName: olympos-kek
    hmacSecretName: olympos-hmac
    managedIdentityClientID: <managed identity client id>
  database:
    dsnRef: kv://kv-platform-weu/olympos-db-dsn
  slack:
    botTokenRef: kv://kv-platform-weu/olympos-slack-bot-token   # chat:write
  deadMansSwitch:
    url: https://heartbeat.example/olympos                       # strongly recommended
  targetTLS:
    caBundleFile: /etc/olympos/target-ca/ca.crt                  # private CAs of your databases
ingress: {enabled: true, className: nginx, host: olympos.contoso.internal, tlsSecretName: olympos-tls}
```

```bash
helm upgrade --install olympos deploy/helm/olympos-server -n olympos --create-namespace -f values.yaml
```

The gateway (`:8443`) is exposed by an internal LoadBalancer by default. Its TLS certificate is
issued by Olympos's internal CA for the host of `agentGatewayURL` (agents pin that CA); set
`gatewayTLSSecret` to use your own. **Do not terminate TLS for `:8443` in a proxy** — mTLS must reach
the server.

Run more than one replica if you like: the backup and audit schedulers hold a Postgres advisory lock
(one active scheduler), and workers claim runs with `SKIP LOCKED`. A tunnel can only be opened on the
replica the agent is connected to, so workers only pick runs for agents connected to themselves.

## 3. Agents

In the UI: **Dashboard › Add cluster** → name, labels, kube-bench opt-in → copy the generated Helm
command (it contains a one-time bootstrap token valid for 1 h and the server CA) and run it against the
cluster. The cluster turns *online* within seconds. Re-issue the command from *Settings › Clusters*
if the token expired.

For on-prem clusters set `--set providerOverride=onprem` (or change it later in *Settings › Clusters*).

Annotate Services to be discovered (`olympos.io/backup`, `olympos.io/vault`, `olympos.io/port`,
`olympos.io/tls-server-name`, see SPEC §5).

## 4. Backup storage hardening (required)

Use `deploy/bicep/backup-storage.bicep`, or apply the same settings by hand:

1. Public network access **disabled**; access only through a **Private Endpoint** in the server VNet.
2. Managed Identity option: `allowSharedKeyAccess = false`.
3. Data-plane RBAC only for the server MI, custom role with `blobs/read`, `blobs/write`,
   `blobs/add/action`, `blobs/tags/read`, `blobs/tags/write` — **no `blobs/delete`**. No human data-plane
   roles; break-glass through a PIM time-bound assignment.
4. Blob **versioning + soft delete + version-level immutability** ≥ the longest retention tier.
5. Resource lock `CanNotDelete` on the account.
6. Azure Policy: deny public network access and shared-key re-enablement.
7. Diagnostic logs to Log Analytics; alert on any data-plane operation by a principal other than the
   server MI.

**Retention is done by lifecycle rules, not by Olympos.** Every backup blob carries the index tag
`olympos-tier=daily|weekly|monthly` (GFS decided at write time) and dry runs carry `olympos-tier=test`.
The Bicep module renders one lifecycle rule per tier. The server has no delete permission and no
delete code path; *Settings › Destinations › Test destination* warns if the credential can delete.

### SAS token option

If Managed Identity is not possible, paste a **container-scoped SAS** with permissions `r c w t` only
(no `d`, no `l`). Olympos parses `se` and raises `sas.expiring` 14 and 3 days before expiry; runs fail
fast after expiry. Account/service SAS requires shared-key access on the account.

### Audit raw results

Raw kubescape/polaris JSON is uploaded to `audit/{cluster}/{tool}/{run_id}.json` on the destination set
in the `audit.raw_destination_id` setting. Add a lifecycle rule deleting `audit/` after 400 days.

## 5. Notifications

Create a Slack app with the `chat:write` bot scope, store the bot token in Key Vault, invite the bot to
the channels, then add channels and routes in *Settings › Notifications*. Messages contain links only —
no buttons, never secret values.

## 6. Operating

- `/metrics` on `:9090` (agents online, tunnels, backup durations/results, scheduler lag, outbox
  backlog, change requests). `/healthz`, `/readyz`.
- Logs are JSON (slog) with a redaction layer.
- Upgrade: `helm upgrade`. Migrations run at start-up.
- Restore procedures: `docs/restore.md`. Vault break-glass: `docs/runbooks/vault-break-glass.md`.
