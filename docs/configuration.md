# Configuration reference

This page lists every setting of `olympos-server` and of the two Helm charts. For a guided install see
[install.md](install.md) (Kubernetes) or [install-systemd.md](install-systemd.md) (Linux VM).

## Where the configuration lives

- **systemd (packages):** `/etc/olympos/config.yaml`. The unit starts
  `olympos-server -config /etc/olympos/config.yaml`.
- **Helm:** the chart renders the `olympos:` values into a ConfigMap `<release>-config`. The pod mounts it at
  `/etc/olympos/config/config.yaml` and starts the server with `-config /etc/olympos/config/config.yaml`.
  A change of the rendered config changes the pod's `checksum/config` annotation, so `helm upgrade` rolls
  the pod.
- **Without `-config`:** the server reads the path in `OLYMPOS_CONFIG`; if that is empty, it reads
  `/etc/olympos/config.yaml` when that file exists. With no file at all, only defaults and the
  [environment overrides](#environment-variables) apply.

The file is YAML. Keys may sit under a top-level `olympos:` key (as the chart and the packaged file do) or
at the top level. **Unknown keys are ignored without a warning**, so a typo in a key name silently falls
back to the default. Durations use Go syntax: `72h`, `5m`, `30m`.

### Validating

```bash
olympos-server check-config [-config FILE] [-db]
```

On systemd, run it as the service user, `sudo -u olympos olympos-server check-config -db`: the local
database authenticates the operating system user, so as root it fails with `role "root" does not exist`.

`check-config` loads the file, applies defaults and environment overrides, and runs the validation
below. It then checks that these files exist: `listen.tlsCertFile`, `listen.tlsKeyFile`,
`gateway.tlsCertFile`, `gateway.tlsKeyFile`, `database.passwordFile`, `targetTLS.caBundleFile`. It loads
the `listen` key pair, and looks up `audit.kubescapeBin`, `audit.polarisBin` and `security.trivyBin`
on `PATH` (and `backup.clickhouseClient`, with a warning only), parses the `targetTLS.caBundleFile` and
`backup.storageCABundleFile` certificates and the `keyVault.references` rules. With
`-db` it also builds the Key Vault client, resolves `database.dsnRef`, connects to the database and checks
that the `pgcrypto` extension is available, reads the
HMAC secret and wraps and unwraps a test value with the KEK, as the server does at start. Purge protection
off is printed as a warning. It prints `config ok` on success.

In Kubernetes:

```bash
kubectl -n <namespace> exec deploy/<release> -- \
  /olympos-server check-config -config /etc/olympos/config/config.yaml -db
```

Other commands: `olympos-server migrate [-config FILE]` applies database migrations and exits (the server
also migrates at start), and `olympos-server version` prints the version and whether the binary is a
release or a dev build.

### Reloading

`SIGHUP` reloads **only certificate files**: `listen.tlsCertFile`/`tlsKeyFile` and
`gateway.tlsCertFile`/`tlsKeyFile`. If a reload fails the server logs an error and keeps the current
certificate. Every other change needs a restart; the server logs `SIGHUP: other configuration changes
need a restart`. On systemd, `systemctl reload olympos-server` sends `SIGHUP`. The Helm chart sends no
signal: restart the pod after a certificate Secret changes.

The gateway certificate from the internal CA (the default) is not a file. It is valid for 90 days and is
re-issued when fewer than 30 days are left, without a reload.

### Key Vault references

Settings ending in `Ref` take a reference of the form `kv://<vault>/<secret>`. The server reads the secret
from Azure Key Vault when it is needed. Vault and secret names may contain only letters, digits and `-`
(1–127 characters). The secrets referenced by `database.dsnRef`, `entra.clientSecretRef` and
`slack.botTokenRef`, plus the KEK and HMAC secret, are reserved: users can never reference them from the
UI or API. See [security-model.md](security-model.md).

## Server `config.yaml`

"Required" means validation fails without it. Keys marked **dev build only** are accepted only by binaries
built with `-tags dev`; release binaries and images reject them.

### Top level

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `publicURL` | string | — | yes | URL users open. Must be absolute and `https` (plain `http` only with `devMode`). The sign-in redirect is `<publicURL>/auth/callback`; notification links use it too. |
| `agentGatewayURL` | string | — | yes | `host:port` agents dial (no scheme). The internal CA issues the gateway certificate for this host, and the generated agent install command uses it as `server`. |
| `devMode` | bool | `false` | no | **Dev build only.** Enables the local Key Vault, the dev login, plain-HTTP `publicURL` and non-secure cookies. |
| `bootstrapAdmins` | list of strings | `[]` | no | Entra object IDs that get a global admin grant. Applied at sign-in only while the grants table is empty. |

### `experimental`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `experimental.multiReplica` | bool | `false` | no | Allows more than one server instance on the same database. Unsupported. When `false`, a second live instance reports `/readyz` not ready. |

### `listen`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `listen.http` | string | `:8080` | no | UI and REST API listener. |
| `listen.gateway` | string | `:8443` | no | Agent gateway listener (gRPC, mTLS). Do not terminate TLS in front of it. |
| `listen.metrics` | string | `:9090` | no | `/metrics`, `/healthz`, `/readyz`. |
| `listen.tlsCertFile` | path | — | no | Serve the UI over HTTPS directly (no ingress or proxy). Set together with `tlsKeyFile`. Reloaded on `SIGHUP`. |
| `listen.tlsKeyFile` | path | — | no | Key for `tlsCertFile`. |

### `entra`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `entra.tenantID` | string | — | yes (not with `devMode`) | Entra tenant ID. |
| `entra.clientID` | string | — | yes (not with `devMode`) | App registration client ID. Entra sign-in is enabled only when this is set. |
| `entra.clientSecretRef` | `kv://` ref | — | no | Client secret of the app registration. Not checked by validation; when empty the server sends an empty client secret in the token exchange. |
| `entra.authorityHost` | URL | `https://login.microsoftonline.com` | no | Change for sovereign clouds. |
| `entra.graphURL` | URL | `https://graph.microsoft.com` | no | Microsoft Graph endpoint for the person search and the daily principal sync. Called as the server's Azure identity, which needs the Graph app role `User.ReadBasic.All` ([Azure prerequisites](azure.md#microsoft-graph)). |

### `keyVault`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `keyVault.provider` | string | `azure` | no | `azure`, or `local` (**dev build only**, and only with `devMode`). Any other value fails at start. |
| `keyVault.name` | string | — | yes (with `azure`) | Vault that holds the KEK and the HMAC secret. |
| `keyVault.kekName` | string | `olympos-kek` | no | Name of the RSA key used for envelope encryption. |
| `keyVault.hmacSecretName` | string | `olympos-hmac` | no | Secret that holds the HMAC key. The server does not start if it cannot read it. |
| `keyVault.managedIdentityClientID` | string | — | no | When set, the server authenticates with the managed identity endpoint (IMDS) for this client ID. When empty, it uses the Azure SDK default credential chain (environment `AZURE_*` variables, Workload Identity, managed identity, Azure CLI). |
| `keyVault.localDir` | path | `/var/lib/olympos/localkv` | no | **Dev build only.** Storage of the local Key Vault. |
| `keyVault.references` | list | `[]` | no | Rules that let users other than global admins enter `kv://` references. Without rules only global admins may. See below. |

Each `keyVault.references` entry:

| Key | Type | Description |
|---|---|---|
| `ref` | string | Glob on `<vault>/<secret>` (a leading `kv://` is stripped; matching is case-insensitive), e.g. `kv-platform-weu/dev-*`. Must contain `/`. |
| `scope` | string | Kubernetes label selector on the cluster's labels, e.g. `env=dev`. Empty or `all` matches every cluster. |

A bad glob or selector stops the server at start (`keyVault.references[<n>].ref ...` /
`keyVault.references[<n>].scope: ...`).

### `database`

Olympos' own PostgreSQL.

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `database.dsn` | string | `postgres:///olympos?host=/var/run/postgresql` (only when `dsnRef` is empty) | no | Connection string. The default is the local server over the Unix socket with peer auth, database and role `olympos`. |
| `database.dsnRef` | `kv://` ref | — | no | Connection string stored in Key Vault, for external databases. Do not set together with `dsn`. |
| `database.passwordFile` | path | — | no | File holding the password for `dsn` (kept out of the DSN). Surrounding whitespace is trimmed. |

At start the server retries the connection for up to two minutes.

### `gateway`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `gateway.tlsCertFile` | path | — | no | Externally issued gateway certificate. Set together with `tlsKeyFile`. Reloaded on `SIGHUP`. Empty: the internal CA issues one. |
| `gateway.tlsKeyFile` | path | — | no | Key for `tlsCertFile`. |
| `gateway.extraSANs` | list of strings | `[]` | no | Extra names for the internal-CA gateway certificate (in addition to the host of `agentGatewayURL`). Ignored when `tlsCertFile` is set. |

### `targetTLS`

How the server verifies the TLS certificates of backup and Vault targets, end to end through the tunnel.

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `targetTLS.caBundleFile` | path | — | no | PEM with the CAs that issue your targets' certificates. Read at start; an unreadable file or one without certificates stops the server. |
| `targetTLS.systemRoots` | bool | `false` | no | Also trust the system (public) CAs for targets. |

With neither set and no per-target CA, connections to TLS targets fail with "no CA is trusted for
targets".

### `slack`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `slack.botTokenRef` | `kv://` ref | — | no | Slack bot token (`chat:write`) for notifications. |
| `slack.apiURL` | URL | — | no | Test use only. |

### `deadMansSwitch`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `deadMansSwitch.url` | URL | — | no | The backup scheduler sends `GET` to this URL after every successful loop (10 s timeout). Failures are logged as warnings. Empty: no ping. |

### `backup`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `backup.globalConcurrency` | int | `4` | no | Maximum concurrent backup runs on this server instance. `0` or less uses the default. |
| `backup.perClusterConcurrency` | int | `2` | no | Maximum running backups per cluster. Running restores into the cluster's targets count too (a server runs at most two restores at once). `0` or less uses the default. |
| `backup.pgDumpDir` | string | `/usr/lib/postgresql` | no | Where to find `pg_dump`/`pg_dumpall`. A `:`-separated list. Each entry is either a directory holding `<major>/bin/` or a pattern with `{major}` (e.g. `/usr/pgsql-{major}/bin`). The closest major version at or above the target server's is used; `pg_dump` on `PATH` is the fallback. |
| `backup.clickhouseClient` | string | `clickhouse` | no | The `clickhouse` binary restores of ClickHouse backups run as `clickhouse client`. It must be the `clickhouse` binary itself, not `clickhouse-client`, because Olympos adds the `client` argument. Path or name on `PATH`; the image and the packages ship the pinned official binary (`/usr/lib/olympos/bin/clickhouse` on systemd). Missing: the server starts with a warning and ClickHouse restores fail with a clear message. |
| `backup.nfsRoot` | path | `/var/lib/olympos/nfs` | no | Every first-level subdirectory is one volume NFS destinations may write to. |
| `backup.storageCABundleFile` | path | — | no | PEM CAs added to the system roots for S3 endpoints (for example MinIO behind an internal CA). Separate from `targetTLS`. An unreadable file or one without certificates stops the server at start. |
| `backup.s3PartSizeMiB` | int | `32` | no | Multipart part size for S3 uploads, in MiB. Must be 5–5120. Memory per running upload; the largest object is 10 000 parts. |

### `changeRequests`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `changeRequests.ttl` | duration | `72h` | no | Lifetime of a Vault change request and of a restore request. Pending requests past it move to `expired` (an approved restore that has not started expires 24 hours after its approval). |

### `agents`

Alert debounce for agent connectivity. Zero or negative values use the default.

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `agents.offlineAlertAfter` | duration | `5m` | no | `agent.offline` fires after an agent has been offline this long. The Dashboard's *Agent offline* item uses the same delay. |
| `agents.flappingDisconnects` | int | `5` | no | Number of disconnects within `flappingWindow` that fires `agent.flapping`. |
| `agents.flappingWindow` | duration | `30m` | no | Window for `flappingDisconnects`. |

### `audit`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `audit.kubescapeBin` | string | `kubescape` | no | Path or name on `PATH`. |
| `audit.kubescapeArtifacts` | path | `/usr/share/olympos/kubescape-artifacts` | no | Frameworks and controls downloaded at build time, for scans without internet access. If the directory is unreadable, the server logs a warning and kubescape downloads them at scan time. |
| `audit.polarisBin` | string | `polaris` | no | Path or name on `PATH`. |

### `security`

| Key | Type | Default | Required | Description |
|---|---|---|---|---|
| `security.trivyBin` | string | `trivy` | no | Path or name on `PATH`. |
| `security.trivyCacheDir` | path | `/var/cache/trivy` | no | trivy DB cache (several GiB). |
| `security.trivyDBRepo` | string | — | no | Mirror for the vulnerability DB (`--db-repository`), for restricted networks. |
| `security.systemNamespaces` | list of globs | `[kube-system, kube-public, kube-node-lease, olympos-system, olympos-bench]` | no | Namespaces excluded from the default-deny NetworkPolicy check, sensitive-data findings and Secret inventory findings. An explicit `[]` excludes nothing. |
| `security.secretsInventory.reportUnmanaged` | bool | `true` | no | Raise `secret.unmanaged` (info) for Secrets not owned by External Secrets, Vault Secrets Operator, sealed-secrets or cert-manager. Needs the agent's opt-in Secret inventory. |

### Validation errors

Validation collects every problem and fails with `invalid config: <problem>; <problem>`. The problems are:

| Message | Fix |
|---|---|
| `publicURL is required` | Set `publicURL`. |
| `publicURL must be an absolute URL` | Include scheme and host, e.g. `https://olympos.example.com`. |
| `publicURL must be https (set devMode for local http)` | Use `https`. `devMode` exists only in dev builds. |
| `agentGatewayURL is required` | Set `agentGatewayURL` (`host:port`). |
| `entra.tenantID and entra.clientID are required` | Set both. |
| `keyVault.name is required` | Set `keyVault.name` (provider `azure`). |
| `keyVault.provider=local is only allowed with devMode` | Use `azure`. |
| `devMode is only available in development builds (go build -tags dev); ...` | Remove `devMode` and `OLYMPOS_DEV_MODE`. |
| `listen.tlsCertFile and listen.tlsKeyFile must be set together` | Set both or neither. |
| `gateway.tlsCertFile and gateway.tlsKeyFile must be set together` | Set both or neither. |
| `backup.s3PartSizeMiB must be between 5 and 5120` | Fix the value. |
| `set database.dsn or database.dsnRef, not both` | Remove one. `OLYMPOS_DATABASE_DSN` counts as `dsn`. |

YAML errors appear as `parse <file>: ...`. Errors the server reports only at start include
`unknown keyVault.provider`, `azure credential: ...`, `resolve database dsn: ...`,
`read database.passwordFile: ...`, `load hmac key: ...`, `read target CA bundle: ...` and
`backup.storageCABundleFile: ...`. See [troubleshooting.md](troubleshooting.md).

## Server Helm values (`deploy/helm/olympos-server`)

| Value | Default | What it sets |
|---|---|---|
| `image.repository` | `ghcr.io/warewave-technology/olympos-server` | Server image. |
| `image.tag` | `""` (chart `appVersion`) | Image tag. |
| `image.digest` | `""` | When set, used instead of the tag (`repository@digest`). Pin by digest in production. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | Pod `imagePullSecrets`. |
| `replicas` | `1` | Deployment replicas. Values above 1 fail the render unless `experimental.multiReplica` is `true`. |
| `experimental.multiReplica` | `false` | Renders `experimental.multiReplica` into the config. When `false` the Deployment uses the `Recreate` strategy. |
| `olympos.*` | see below | Rendered into `config.yaml` under `olympos:`. |
| `postgresql.bundled` | `true` | Deploy a single-instance PostgreSQL (StatefulSet, Service, NetworkPolicy that admits only the server pods, and a Secret `<release>-postgresql` with a generated password kept across upgrades and uninstall). |
| `postgresql.image` | `docker.io/library/postgres:16.11-bookworm@sha256:…` | Bundled PostgreSQL image. |
| `postgresql.size` | `8Gi` | PVC size. |
| `postgresql.storageClass` | `""` | PVC storage class (cluster default when empty). |
| `postgresql.resources` | requests `100m`/`256Mi`, limit `1Gi` memory | |
| `postgresql.nodeSelector` | `{}` | |
| `workloadIdentity.enabled` | `true` | Adds the pod label `azure.workload.identity/use: "true"` and mounts the service account token. |
| `workloadIdentity.clientID` | `""` | ServiceAccount annotation `azure.workload.identity/client-id` (only when set and `enabled`). |
| `service.type` / `service.port` / `service.nodePort` | `ClusterIP` / `80` / `null` | UI Service `<release>` (targets container port 8080). |
| `gatewayService.type` / `port` / `nodePort` | `LoadBalancer` / `8443` / `null` | Gateway Service `<release>-gateway` (targets container port 8443). |
| `gatewayService.annotations` | `service.beta.kubernetes.io/azure-load-balancer-internal: "true"` | Gateway Service annotations. |
| `ingress.enabled` | `false` | Render an Ingress to the UI Service. |
| `ingress.className` | `""` | `ingressClassName`. |
| `ingress.host` | `olympos.contoso.internal` | Ingress host. |
| `ingress.tlsSecretName` | `""` | TLS Secret for the Ingress; no `tls` block when empty. |
| `ingress.annotations` | `{}` | |
| `gatewayTLSSecret` | `""` | A `kubernetes.io/tls` Secret with your own gateway certificate. Mounted at `/etc/olympos/gateway-tls` and rendered as `gateway.tlsCertFile`/`tlsKeyFile`. |
| `localKeyVault.persistence.enabled` / `size` / `storageClass` | `false` / `64Mi` / `""` | **Dev only.** PVC for `keyVault.provider: local`; an `emptyDir` is used when disabled. |
| `trivyCache.persistent` | `true` | PVC `<release>-trivy-cache` at `/var/cache/trivy`. When `false`, an `emptyDir` with `sizeLimit` = `size`. |
| `trivyCache.size` / `storageClass` | `10Gi` / `""` | |
| `resources` | requests `200m`/`256Mi`, limit `1Gi` memory | Server container. |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Server pod. |
| `podAnnotations` | `{}` | Server pod. |
| `nfsMounts` | `[]` | Volumes for NFS destinations: each entry is `name` plus any Kubernetes volume source, mounted at `/var/lib/olympos/nfs/<name>`. |
| `extraEnv` | `[]` | Extra container environment variables. |
| `extraVolumes` / `extraVolumeMounts` | `[]` / `[]` | Extra volumes and mounts for the server container. |

The `olympos:` defaults in `values.yaml` are: `publicURL: https://olympos.contoso.internal`,
`agentGatewayURL: olympos-gw.contoso.internal:8443`, `devMode: false`, empty `entra.*`, `bootstrapAdmins: []`,
`keyVault: {provider: azure, name: "", kekName: olympos-kek, hmacSecretName: olympos-hmac,
managedIdentityClientID: ""}`, `database.dsnRef: ""`, `slack.botTokenRef: ""`, `deadMansSwitch.url: ""`,
`backup: {globalConcurrency: 4, perClusterConcurrency: 2}`, `changeRequests.ttl: 72h`. You must at least
set `publicURL`, `agentGatewayURL`, `entra.tenantID`, `entra.clientID` and `keyVault.name`.

### What the chart sets for you

- **`listen`:** always `http: ":8080"`, `gateway: ":8443"`, `metrics: ":9090"`, because the container ports are
  fixed to match. Other `olympos.listen` keys you set are kept, so `listen.tlsCertFile`/`tlsKeyFile` (UI over
  HTTPS without an ingress) work with a mounted Secret.
- **`experimental.multiReplica`:** from the top-level `experimental.multiReplica` value.
- **`gateway.tlsCertFile`/`tlsKeyFile`:** when `gatewayTLSSecret` is set; other `olympos.gateway` keys such as
  `extraSANs` are kept.
- **`database`:** with `postgresql.bundled: true` the chart replaces the whole `olympos.database` section with
  `dsn: postgres://olympos@<release>-postgresql.<namespace>.svc:5432/olympos?sslmode=disable` and
  `passwordFile: /etc/olympos/db/password`. Setting `olympos.database.dsn` or `dsnRef` together with
  `bundled: true` fails the render. With `bundled: false`, `olympos.database.dsnRef` (or `dsn`) is required;
  the render fails without one.
- **Environment:** `TMPDIR=/tmp` and `HOME=/tmp`.

### Setting a config key that has no Helm value

The `olympos:` block is passed through as is, so any key from the tables above can be set under it, for
example:

```yaml
olympos:
  backup:
    s3PartSizeMiB: 64
  agents:
    offlineAlertAfter: 10m
  security:
    trivyDBRepo: registry.example.internal/trivy-db
```

The sections the chart sets (above) are merged with yours: the listen addresses, `experimental.multiReplica`
and, with `gatewayTLSSecret`, the gateway certificate files are the chart's; everything else you set in
them is kept. `olympos.database` is replaced when `postgresql.bundled` is `true`.

Keys that point at files (`targetTLS.caBundleFile`, `backup.storageCABundleFile`, `audit.kubescapeArtifacts`,
`database.passwordFile` with an external database) need the file in the pod. Mount it with `extraVolumes`
and `extraVolumeMounts`:

```yaml
olympos:
  targetTLS:
    caBundleFile: /etc/olympos/target-ca/ca.crt
extraVolumes:
  - name: target-ca
    configMap: {name: olympos-target-ca}
extraVolumeMounts:
  - {name: target-ca, mountPath: /etc/olympos/target-ca, readOnly: true}
```

`extraEnv` can set the [environment variables](#environment-variables) the server reads, including the
overrides `OLYMPOS_PUBLIC_URL`, `OLYMPOS_ENTRA_TENANT_ID`, `OLYMPOS_ENTRA_CLIENT_ID` and
`OLYMPOS_DATABASE_DSN`.

## Agent Helm values (`deploy/helm/olympos-agent`)

*Dashboard › Add cluster* generates the install command with `server`, `clusterName`, `bootstrapToken`,
`serverCA` (and `bench.enabled=true` when chosen). The agent is configured only through environment
variables that the chart renders; the chart has no `extraEnv`.

| Value | Default | What it sets |
|---|---|---|
| `server` | `""` | **Required.** Gateway `host:port` (`OLYMPOS_SERVER`). |
| `bootstrapToken` | `""` | **Required on first install.** One-time enrollment token (valid 1 h), stored in the Secret `olympos-agent-identity` (and, while the probe has no certificate, in `olympos-probe-identity`: the same token enrolls the agent and the probe once each). Once the agent has enrolled (the Secret holds `tls.crt`), upgrades keep the Secret and ignore this value. |
| `serverCA` | `""` | **Required.** Base64-encoded PEM of the Olympos internal CA. Rendered into the ConfigMap `olympos-agent-ca` and mounted at `/etc/olympos/ca.crt`; the agent pins it. |
| `serverName` | `""` | TLS server name override (`OLYMPOS_SERVER_NAME`). Empty: the host part of `server`. |
| `clusterName` | `""` | Not used by any chart template. The agent's identity comes from its enrolled certificate. |
| `providerOverride` | `""` | `OLYMPOS_PROVIDER_OVERRIDE`. One of `azure`, `aws`, `gcp`, `oracle`, `huawei`, `onprem` (`on-prem` is accepted as `onprem`); other values are ignored. Applied only while the cluster has no override set in the UI. |
| `image.repository` | `ghcr.io/warewave-technology/olympos-agent` | |
| `image.tag` | `""` (chart `appVersion`) | |
| `image.digest` | `""` | When set, used instead of the tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `maxTunnels` | `16` | Concurrent tunnels the agent accepts (`OLYMPOS_MAX_TUNNELS`). |
| `manageNamespace` | `false` | Render the release Namespace with Pod Security `restricted` (enforce and warn) labels. Set when Helm should own the namespace. |
| `sensitiveData.enabled` | `true` | Scan ConfigMaps for credentials on the agent (`OLYMPOS_SENSITIVE_DATA`). Only the location and rule are reported. |
| `sensitiveData.excludeNamespaces` | `[kube-system, kube-public, kube-node-lease, olympos-system, olympos-bench]` | Namespace globs not scanned (`OLYMPOS_SENSITIVE_DATA_EXCLUDE`). Also applies to the Secret inventory. An empty list excludes nothing. |
| `secretsInventory.enabled` | `false` | Opt-in Secret inventory (key names only). Adds `list`/`watch` on `secrets` to the agent's ClusterRole and sets `OLYMPOS_SECRETS_INVENTORY`. Read [security-model.md](security-model.md) first: RBAC cannot limit this to metadata. |
| `bench.enabled` | `false` | Enable kube-bench (`OLYMPOS_BENCH_ENABLED`). Renders the bench Namespace (Pod Security `privileged`), a Role/RoleBinding there, and the optional Kyverno exceptions. |
| `bench.maxParallel` | `3` | Concurrent kube-bench jobs (`OLYMPOS_BENCH_MAX_PARALLEL`; values below 1 become 1). |
| `bench.namespace` | `olympos-bench` | Namespace for kube-bench jobs (`OLYMPOS_BENCH_NAMESPACE`). |
| `bench.imageRepository` | `""` (Docker Hub) | Pull the pinned kube-bench digest from a mirror (`OLYMPOS_BENCH_IMAGE_REPOSITORY`), e.g. `ghcr.io/warewave-technology/kube-bench`, signed by each release. A repository only: a tag or digest is refused. The digest stays the one in the agent binary. See [Installing › The kube-bench image](install.md#the-kube-bench-image). |
| `bench.imagePattern` | `""` | Image match in the legacy Kyverno PolicyException only; `""` follows `bench.imageRepository` (`<repository>:*@sha256:*`). |
| `bench.kyverno.legacyException` | `false` | Render a `kyverno.io/v2` PolicyException for all policies (Kyverno ≤ 1.19 with `kyverno.io` policies; Kyverno 1.20 rejects this kind). |
| `bench.kyverno.policyRefs` | `[]` | Render a `policies.kyverno.io/v1` PolicyException naming these policies (Kyverno CEL policies), e.g. `[{name: require-run-as-nonroot, kind: ValidatingPolicy}]`. |
| `resources` | requests `50m`/`64Mi`, limit `256Mi` memory | |
| `nodeSelector` / `tolerations` / `affinity` / `podAnnotations` | `{}` / `[]` / `{}` / `{}` | Agent pod. |
| `probe.enabled` | `true` | Install `olympos-probe` (synthetic monitoring) next to the agent: the Deployment, ServiceAccount and Secret `olympos-probe-identity`, the agent's Role on that Secret, and `OLYMPOS_PROBE_ENABLED`. The probe's ServiceAccount has no RBAC and no token. `false`: none of these, and the cluster shows *Probe: not installed*. |
| `probe.replicas` | `1` | Probe replicas. Runs are idempotent by run id. |
| `probe.image.repository` | `ghcr.io/warewave-technology/olympos-probe` | |
| `probe.image.tag` | `""` (chart `appVersion`) | |
| `probe.image.digest` | `""` | When set, used instead of the tag. |
| `probe.image.pullPolicy` | `IfNotPresent` | |
| `probe.bootstrapToken` | `""` | One-time probe token from *Settings › Clusters & agents › Install probe*. The chart adds it to the Secret `olympos-probe-identity` and keeps what is there; the agent enrolls the probe with it. A new cluster does not need it: the agent enrolls the probe with `bootstrapToken`. Without either, the upgrade succeeds and the probe waits. The chart does not write the same token twice (it keeps the token's SHA-256 in the annotation `olympos.io/bootstrap-token-sha256`), so `--reuse-values` does not replay a spent token. |
| `probe.maxConcurrency` | `20` | Runs one replica runs at once (`OLYMPOS_PROBE_MAX_CONCURRENCY`, 1 to 1000). |
| `probe.networkPolicy.egressCIDRs` | `[]` | Non-empty: a NetworkPolicy lets the probe pods reach only these CIDRs, plus the cluster DNS (`probe.networkPolicy.dns`). Include the Olympos gateway (`server`) and the allowlisted hosts. The host allowlist in Olympos applies either way. |
| `probe.networkPolicy.dns.namespaceSelector` / `.podSelector` / `.ports` | empty: `kubernetes.io/metadata.name: kube-system` / `k8s-app: kube-dns` / UDP and TCP 53 | The DNS pods the NetworkPolicy allows. A field you set replaces its default as a whole; an unset or empty one keeps it (the defaults are in the template, so Helm does not merge your labels into them). **OpenShift**: `namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: openshift-dns}}`, `podSelector: {matchLabels: {dns.operator.openshift.io/daemonset-dns: default}}`, `ports: [{protocol: UDP, port: 5353}, {protocol: TCP, port: 5353}]` (the DNS pods listen on 5353). **NodeLocal DNSCache**: the cache answers on the node, not in a DNS pod, so add the nameserver address from the pod's `/etc/resolv.conf` to `egressCIDRs` (usually `169.254.20.10/32`, or the `kube-dns` Service IP when the cache listens on it). |
| `probe.resources` | requests `20m`/`32Mi`, limit `128Mi` memory | `GOMEMLIMIT` follows the memory limit. |
| `probe.nodeSelector` / `probe.tolerations` / `probe.affinity` | `{}` / `[]` / `{}` | Probe pods. `imagePullSecrets` applies to them too. |

## Environment variables

### Server

| Variable | Effect |
|---|---|
| `OLYMPOS_CONFIG` | Config file path when `-config` is not given. |
| `OLYMPOS_PUBLIC_URL` | Overrides `publicURL` when non-empty. |
| `OLYMPOS_ENTRA_TENANT_ID` | Overrides `entra.tenantID` when non-empty. |
| `OLYMPOS_ENTRA_CLIENT_ID` | Overrides `entra.clientID` when non-empty. |
| `OLYMPOS_DATABASE_DSN` | Overrides `database.dsn` when non-empty. Fails validation if `database.dsnRef` is also set. |
| `OLYMPOS_DEV_MODE` | `1` sets `devMode: true`. **Dev build only**; a release binary then refuses the config. |
| `OLYMPOS_AGENT_CHART` | Chart reference in the generated agent install command. Default `oci://ghcr.io/warewave-technology/charts/olympos-agent`. |
| `OLYMPOS_AGENT_INSTALL_SETS` | Extra `--set` entries for the generated agent install command, as `k=v,k2=v2` (e.g. an image mirror). Entries without `=`, or containing spaces, tabs or any of `` ; \| & $ ` ' " ``, are dropped without a warning. |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_CERTIFICATE_PATH`, … | Read by the Azure SDK default credential chain, used when `keyVault.managedIdentityClientID` is empty. On systemd, put them in `/etc/olympos/environment` (the unit's optional `EnvironmentFile`). |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lower case) | Used by the S3 client and passed to trivy, kubescape and polaris. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Passed to trivy, kubescape and polaris. `SSL_CERT_FILE` is also the CA bundle for `pg_dump` when its libpq is older than 16. |
| `PATH` | Used to find `kubescape`, `polaris`, `trivy` (when not absolute paths) and the fallback `pg_dump`. |

Child processes (trivy, kubescape, polaris) see only the variables above, never the full server
environment. `OLYMPOS_TEST_PG_DSN`, `OLYMPOS_REQUIRE_DB` and `OLYMPOS_REQUIRE_DOCKER` are for the test suite
only.

### Agent

The chart sets all of these except `OLYMPOS_HEALTH_ADDR` and `OLYMPOS_IDENTITY_SECRET`, which keep their
defaults.

| Variable | Default | Effect |
|---|---|---|
| `OLYMPOS_SERVER` | — | **Required.** Gateway `host:port`. |
| `OLYMPOS_SERVER_NAME` | host of `OLYMPOS_SERVER` | TLS server name. |
| `OLYMPOS_SERVER_CA_FILE` | `/etc/olympos/ca.crt` | Pinned server CA. |
| `POD_NAMESPACE` | `olympos-system` | Namespace of the identity Secret (the chart sets it from the pod). |
| `OLYMPOS_IDENTITY_SECRET` | `olympos-agent-identity` | Identity Secret name. The chart's Role allows only the default name. |
| `OLYMPOS_PROVIDER_OVERRIDE` | — | See `providerOverride`. |
| `OLYMPOS_MAX_TUNNELS` | `16` | Integer. |
| `OLYMPOS_BENCH_ENABLED` | off | On only when `true`. |
| `OLYMPOS_BENCH_NAMESPACE` | `olympos-bench` | |
| `OLYMPOS_BENCH_MAX_PARALLEL` | `3` | Integer. |
| `OLYMPOS_SENSITIVE_DATA` | on | Off only when `false`. |
| `OLYMPOS_SENSITIVE_DATA_EXCLUDE` | the five system namespaces | Comma-separated globs. Unset: the default list. Set but empty: nothing excluded. |
| `OLYMPOS_SECRETS_INVENTORY` | off | On only when `true`. |
| `OLYMPOS_PROBE_ENABLED` | off | On only when `true` (`probe.enabled`): the agent enrolls and renews the probe's identity. |
| `OLYMPOS_PROBE_IDENTITY_SECRET` | `olympos-probe-identity` | Secret the agent keeps the probe's identity in. The chart's Role allows only the default name. |
| `OLYMPOS_HEALTH_ADDR` | `127.0.0.1:8081` | Health endpoint used by `olympos-agent health` (the liveness probe). Must start with `127.0.0.1:` or `localhost:`. |

A non-integer `OLYMPOS_MAX_TUNNELS` or `OLYMPOS_BENCH_MAX_PARALLEL`, a missing `OLYMPOS_SERVER`, or a
non-local `OLYMPOS_HEALTH_ADDR` stops the agent at start.

### Probe

The chart sets all of these. The probe reads no Kubernetes API and gets no token.

| Variable | Default | Effect |
|---|---|---|
| `OLYMPOS_SERVER` | — | **Required.** Gateway `host:port`, the agent's. |
| `OLYMPOS_SERVER_NAME` | host of `OLYMPOS_SERVER` | TLS server name. |
| `OLYMPOS_PROBE_IDENTITY_DIR` | `/etc/olympos-probe` | `tls.crt` and `tls.key` from `olympos-probe-identity` and `ca.crt` from `olympos-agent-ca`, in one projected volume. The probe reloads them when they change. |
| `OLYMPOS_PROBE_MAX_CONCURRENCY` | `20` | Integer, 1 to 1000. |
| `OLYMPOS_HEALTH_ADDR` | `127.0.0.1:8082` | Health endpoint used by `olympos-probe health` (the liveness probe). Loopback only. |
| `GOMEMLIMIT` | the memory limit | Go runtime soft memory limit. |

A missing `OLYMPOS_SERVER`, an out-of-range `OLYMPOS_PROBE_MAX_CONCURRENCY` or a non-loopback
`OLYMPOS_HEALTH_ADDR` stops the probe at start.

## Examples

### Minimal `config.yaml` (systemd)

This passes validation. The tool and `pg_dump` paths are the ones the package installs; with the
defaults (`kubescape`, `polaris`, `trivy` on `PATH`) `check-config` would fail on a host where they are not
on `PATH`.

```yaml
olympos:
  publicURL: https://olympos.example.internal
  agentGatewayURL: olympos.example.internal:8443
  entra:
    tenantID: <tenant-id>
    clientID: <client-id>
    clientSecretRef: kv://<vault>/olympos-oidc-client-secret
  bootstrapAdmins: [<admin-object-id>]
  keyVault:
    name: <vault>
  # database: default is the local PostgreSQL over the Unix socket (role and database "olympos")
  backup:
    pgDumpDir: /usr/lib/olympos/pg:/usr/lib/postgresql:/usr/pgsql-{major}/bin
    clickhouseClient: /usr/lib/olympos/bin/clickhouse
  audit:
    kubescapeBin: /usr/lib/olympos/bin/kubescape
    polarisBin: /usr/lib/olympos/bin/polaris
  security:
    trivyBin: /usr/lib/olympos/bin/trivy
    trivyCacheDir: /var/lib/olympos/trivy-cache
```

Behind a reverse proxy the UI listens on `:8080`. To serve HTTPS directly, add `listen.tlsCertFile` and
`listen.tlsKeyFile`.

### Minimal Helm values

Uses the bundled PostgreSQL and Azure Workload Identity. The image already has the tools on `PATH` and
`pg_dump` under `/usr/lib/postgresql`, so the defaults apply.

```yaml
workloadIdentity:
  enabled: true
  clientID: <managed-identity-client-id>
olympos:
  publicURL: https://olympos.example.internal
  agentGatewayURL: olympos-gw.example.internal:8443
  entra:
    tenantID: <tenant-id>
    clientID: <client-id>
    clientSecretRef: kv://<vault>/olympos-oidc-client-secret
  bootstrapAdmins: [<admin-object-id>]
  keyVault:
    name: <vault>
ingress:
  enabled: true
  className: <ingress-class>
  host: olympos.example.internal
  tlsSecretName: <tls-secret>
```

With `keyVault.managedIdentityClientID` empty, the server uses the Azure SDK default credential chain,
which picks up the Workload Identity variables the webhook injects into the pod. Setting it switches the
server to the managed identity endpoint only.

For an external database add `postgresql: {bundled: false}` and
`olympos.database.dsnRef: kv://<vault>/olympos-db-dsn`.

See also [getting-started.md](getting-started.md) for a local lab, [access.md](access.md) for grants, and
[troubleshooting.md](troubleshooting.md).
