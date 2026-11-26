# Azure prerequisites

A production Olympos needs four things in Azure: an **Entra ID app registration** for sign-in, a
**managed identity** for the server, a **Key Vault**, and (if you back up to Azure) a **storage account**.
This page sets them up in order. The examples use the names from [install](install.md); replace them with
yours.

```bash
RG=rg-olympos-weu          # resource group
LOC=westeurope
MI=id-olympos-server       # the server's user-assigned managed identity
KV=kv-platform-weu         # Key Vault
SA=stolympweu01            # backup storage account
```

## 1. Entra ID app registration

Follow [install › Entra ID](install.md#entra-id): a single-tenant app with the redirect URI
`https://<publicURL>/auth/callback`, a client secret stored in Key Vault, and *Assignment required* on the
enterprise application. The app registration needs no Graph API permission: Olympos calls Graph as the
server's managed identity ([below](#microsoft-graph)).

## 2. The server's managed identity

```bash
az group create -n $RG -l $LOC
az identity create -g $RG -n $MI
CLIENT_ID=$(az identity show -g $RG -n $MI --query clientId -o tsv)
PRINCIPAL_ID=$(az identity show -g $RG -n $MI --query principalId -o tsv)
```

How the server uses it depends on where it runs:

| Server runs on | Set | Leave empty |
|---|---|---|
| AKS, with [Workload Identity](https://learn.microsoft.com/azure/aks/workload-identity-overview) | Helm `workloadIdentity.enabled: true`, `workloadIdentity.clientID: $CLIENT_ID` | `olympos.keyVault.managedIdentityClientID` |
| An Azure VM (systemd) with the identity assigned to the VM | `keyVault.managedIdentityClientID: $CLIENT_ID` in `/etc/olympos/config.yaml` | — |

With `managedIdentityClientID` empty, the server uses the Azure SDK's default credential chain, which picks
up the Workload Identity token the AKS webhook injects. Setting it makes the server ask the VM's or node's
managed identity endpoint for that identity instead, which is what a VM needs and what breaks Workload
Identity on AKS.

### Workload Identity on AKS

The cluster needs the OIDC issuer and Workload Identity enabled. Then trust the server's ServiceAccount,
which is named after the Helm release (`olympos` in `olympos` here):

```bash
az aks update -g <aks-rg> -n <aks> --enable-oidc-issuer --enable-workload-identity
ISSUER=$(az aks show -g <aks-rg> -n <aks> --query oidcIssuerProfile.issuerUrl -o tsv)
az identity federated-credential create -g $RG --identity-name $MI --name olympos-server \
  --issuer "$ISSUER" --subject system:serviceaccount:olympos:olympos --audiences api://AzureADTokenExchange
```

The chart annotates the ServiceAccount with the client ID and labels the pod
(`azure.workload.identity/use: "true"`) when `workloadIdentity.enabled` is true.

### Microsoft Graph

The person search in *Settings › Access › Grant access* and the daily principal sync (which marks grants of
disabled or deleted accounts stale) call Microsoft Graph with the same identity the server uses for Key
Vault. Give that identity the Graph **app role** `User.ReadBasic.All`. A managed identity has no app
registration, so the portal's *API permissions* page cannot do this; assign the role through Graph. This
needs *Privileged Role Administrator* or *Global Administrator* in Entra ID:

```bash
GRAPH_SP=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)   # Microsoft Graph
ROLE_ID=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 \
  --query "appRoles[?value=='User.ReadBasic.All'].id" -o tsv)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PRINCIPAL_ID/appRoleAssignments" \
  --headers Content-Type=application/json \
  --body "{\"principalId\":\"$PRINCIPAL_ID\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ROLE_ID\"}"
```

`$PRINCIPAL_ID` (the identity's `principalId`) is the object ID of its service principal.
`00000003-0000-0000-c000-000000000000` is Microsoft Graph's application ID in every tenant; the role ID is
read from its `appRoles` rather than copied. Check the assignment:

```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PRINCIPAL_ID/appRoleAssignments" \
  --query "value[].{resource:resourceDisplayName, appRoleId:appRoleId}" -o table
```

On a VM outside Azure the server signs in as a service principal (`AZURE_CLIENT_ID`,
[systemd install](install-systemd.md#1-prerequisites)); run the same commands with
`PRINCIPAL_ID=$(az ad sp show --id <AZURE_CLIENT_ID> --query id -o tsv)`. That principal has an app
registration, so *API permissions › Microsoft Graph › Application permissions › User.ReadBasic.All* with
*Grant admin consent* in the portal works too.

A token the server already holds keeps its old permissions until it expires, and Azure can cache managed
identity tokens for up to 24 hours. After assigning the role, restart the server; if the search still fails,
wait for the cached token to expire. Without the role, the search answers *Entra ID directory search
failed* ([troubleshooting](troubleshooting.md#the-person-search-fails)).

## 3. Key Vault

`deploy/bicep/keyvault.bicep` creates a vault with soft delete and **purge protection** on (it cannot be
turned off again), the key encryption key `olympos-kek` (RSA 3072, wrap/unwrap only), the key `olympos-manifest`
that signs the manifests of native ClickHouse backups (EC P-256, sign/verify only), the server's role
assignments, and optionally a private endpoint:

```bash
az deployment group create -g $RG -f deploy/bicep/keyvault.bicep \
  -p vaultName=$KV serverIdentityPrincipalId=$PRINCIPAL_ID
#   privateEndpointSubnetId=<subnet id>   # optional: no public network access
```

It does not create secrets. Add them yourself (as someone with *Key Vault Secrets Officer* on the vault):

```bash
az keyvault secret set --vault-name $KV --name olympos-hmac --value "$(openssl rand -hex 32)"
az keyvault secret set --vault-name $KV --name olympos-oidc-client-secret --value '<Entra client secret>'
# only with an external database (postgresql.bundled=false):
az keyvault secret set --vault-name $KV --name olympos-db-dsn --value 'postgres://…?sslmode=verify-full'
```

The roles the template gives the server's identity:

| Role | On | Why |
|---|---|---|
| *Key Vault Crypto User* | the key `olympos-kek` | wrap and unwrap the per-record keys; read the key's properties to check purge protection |
| *Key Vault Crypto User* | the key `olympos-manifest` | sign the manifest of each native ClickHouse backup (`keys/sign`) and read the public key the server verifies it with (`keys/get`) |
| *Key Vault Secrets Officer* | the vault | read `kv://` secrets, and write Vault AppRole secret IDs when you configure a Vault (`olympos-vault-<id>-secret-id`) |

If you never connect a Vault or OpenBao to Olympos, *Key Vault Secrets User* (read only) is enough instead
of *Secrets Officer*; change the role in the template before deploying.

Why purge protection matters: Olympos encrypts stored credentials with `olympos-kek`, and its own database
backup is useless without that key ([Restoring Olympos](restore-olympos.md)). A native ClickHouse backup is
restored only while the version of `olympos-manifest` that signed it can be read
([install › The manifest key](install.md#the-manifest-key)). The server checks the KEK at start and shows *Key
Vault · purge protection is off* under *Needs attention* otherwise; purge protection is a setting of the vault,
so the check covers `olympos-manifest` as well.

## 4. Backup storage (Azure Blob)

`deploy/bicep/backup-storage.bicep` creates a storage account hardened for backups: a private endpoint,
versioning, soft delete, lifecycle rules that delete each tier (by the `olympos-tier` index tag) after its
retention, a resource lock, optional diagnostics, and a **custom data-plane role that can read, write and tag
blobs but not delete them**, assigned to the server's identity. A container default immutability policy is
optional (`defaultImmutabilityDays`, 0 by default, which also leaves version-level immutability support off on
the container; the account setting is sent only with `accountVersionLevelSupport=true`, for accounts deployed
with the module before v0.4.0). Within its period it keeps a compromised server from
having backups deleted by re-tagging or overwriting them, and it keeps every backup at least that long,
whatever its tier. A container gets version-level support when it is created, or later only by a migration,
so decide per container ([install › Immutability (optional)](install.md#immutability-optional)):

```bash
az deployment group create -g $RG -f deploy/bicep/backup-storage.bicep \
  -p accountName=$SA serverIdentityPrincipalId=$PRINCIPAL_ID privateEndpointSubnetId=<subnet id>
#   dailyDays=7 weeklyDays=28 monthlyDays=372 defaultImmutabilityDays=0 logAnalyticsWorkspaceId=<id>
#   accountVersionLevelSupport=true   # only for an account deployed with the module before v0.4.0
```

Creating the custom role needs *Owner* or *User Access Administrator*. The private endpoint's DNS zone link
depends on your network and is not part of the template. Then add the account as a destination in
*Settings › Destinations* with managed identity authentication; the destination test checks that delete is
refused. S3, S3-compatible storage and NFS are set up as described in [install](install.md).

## Next

Install the server: [on Kubernetes](install.md#2-server) or [on a Linux VM](install-systemd.md). All
settings are listed in [Configuration](configuration.md).
