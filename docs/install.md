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

**Soft delete and purge protection must be on.** Olympos encrypts its secrets with a KEK in Key Vault
(envelope encryption): a dump of the Olympos database (the built-in `olympos-self` backup) is useless
without that key. `deploy/bicep/keyvault.bicep` creates a vault with both enabled, the KEK and the role
assignments. The server checks the KEK's recovery level at startup (needs `keys/get`, part of *Key Vault
Crypto User*) and shows "Key Vault · purge protection is off" in *Needs attention* otherwise.

```bash
az keyvault update --name kv-platform-weu --enable-purge-protection true   # existing vault
az keyvault key create --vault-name kv-platform-weu --name olympos-kek --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault secret set --vault-name kv-platform-weu --name olympos-hmac --value "$(openssl rand -hex 32)"
# only for an external database (postgresql.bundled=false):
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
    # Who besides global admins may enter kv:// references (backup credentials), and for which
    # clusters. Without rules only global admins can. Olympos' own secrets are never referenceable.
    # references:
    #   - {ref: "kv-platform-weu/dev-*", scope: "env=dev"}
    #   - {ref: "kv-platform-weu/prod-*", scope: "env=prod"}
    managedIdentityClientID: <managed identity client id>
  # database: by default the chart runs a bundled PostgreSQL 16 in the same namespace
  # (postgresql.bundled=true). For an external one: postgresql.bundled=false and
  #   database: {dsnRef: kv://kv-platform-weu/olympos-db-dsn}
  slack:
    botTokenRef: kv://kv-platform-weu/olympos-slack-bot-token   # chat:write
  deadMansSwitch:
    url: https://heartbeat.example/olympos                       # strongly recommended
  targetTLS:
    caBundleFile: /etc/olympos/target-ca/ca.crt                  # CAs that issue your targets' certificates
    # systemRoots: false   # public CAs are not trusted for targets unless set (see below)
ingress: {enabled: true, className: nginx, host: olympos.contoso.internal, tlsSecretName: olympos-tls}
```

```bash
helm upgrade --install olympos deploy/helm/olympos-server -n olympos --create-namespace -f values.yaml
```

The gateway (`:8443`) is exposed by an internal LoadBalancer by default. Its TLS certificate is
issued by Olympos's internal CA for the host of `agentGatewayURL` (agents pin that CA); set
`gatewayTLSSecret` to use your own. **Do not terminate TLS for `:8443` in a proxy** — mTLS must reach
the server.

### Target certificates

The server verifies every target's certificate end to end against `targetTLS.caBundleFile` (and a
per-target CA where one is set). **Public CAs are not trusted for targets by default**: the name a
target is verified against comes from its Service (`olympos.io/tls-server-name`), and anyone who can
edit that Service could otherwise point it at a pod with a public certificate for a domain they own.
Set `targetTLS.systemRoots: true` only if your targets really use publicly issued certificates.

The TLS name is pinned when Olympos first sees a target. If the annotation changes later, backups and
Vault calls keep verifying the pinned name, *Needs attention* shows "TLS name changed", and an admin of
that cluster accepts the new name under *Backups* (or reverts the annotation).

### Olympos' own database

By default the chart deploys a single-instance PostgreSQL 16 next to the server (`postgresql.bundled:
true`): the official `postgres` image pinned by digest, a PVC (`postgresql.size`, default 8 Gi), a
NetworkPolicy that admits only the server pods, and a generated password in the Secret
`<release>-postgresql` (kept on upgrade and uninstall). Host connections use SCRAM-SHA-256. For an
external database (Azure Database for PostgreSQL) set `postgresql.bundled: false` and
`olympos.database.dsnRef`.

Its state (grants, the internal CA key, change requests, schedules) must survive a lost cluster: after
installing, open **Backups › Olympos database** and choose a destination. The built-in job
`olympos-self` (`pg_dump -Fc`, daily by default, same manifest, tags and retention as every job) cannot
be deleted; the Dashboard shows *Needs attention* until it has a destination. Restore:
`docs/restore-olympos.md`.

**v0.1 runs as a single replica.** Availability comes from Kubernetes restarting the pod; agents reconnect
automatically. Multi-replica is planned for v0.2. A tunnel can only be opened on the replica the agent is
connected to, so more replicas would work only sometimes: the chart refuses `replicas > 1` and uses the
`Recreate` strategy. Every server instance registers in the database; if a second live instance appears
(two hosts pointed at the same database, a stuck old pod), the newer one logs an error and reports
`/readyz` not ready until the older one is gone. `experimental.multiReplica: true` lifts both checks and
is unsupported.

## Restricted networks

Olympos works without internet egress from the server:

- **kubescape**: the frameworks, controls, exceptions and control inputs are downloaded when the image and
  the packages are built (`/usr/share/olympos/kubescape-artifacts`) and scans run with
  `--use-artifacts-from`, so no call to the ARMO API is made. They are as recent as the Olympos release; to
  refresh them in between, run `kubescape download artifacts --output <dir>` on a connected host, copy the
  directory in (a volume in Helm, any path for systemd) and set `audit.kubescapeArtifacts: <dir>`.
- **trivy**: the vulnerability DB is pulled from an OCI registry; mirror `ghcr.io/aquasecurity/trivy-db`
  (and `trivy-java-db`) into your registry and set `security.trivyDBRepo: <your-registry>/trivy-db`. The
  server updates the DB at most once an hour and keeps scanning with the last one while the mirror is
  unreachable.
- **Images and charts**: mirror `ghcr.io/warewave-technology/*` and use `OLYMPOS_AGENT_INSTALL_SETS` to make
  the generated agent install command point at the mirror.
- **Entra ID, Key Vault, backup storage** need private endpoints (see §1 and §4).

## Verifying releases

Every release (tag `v*`) is built by `.github/workflows/release.yml` and signed keyless with cosign through
GitHub's OIDC identity: images, binaries, tarballs, `.deb`/`.rpm` and both Helm charts. Each artifact has an
SBOM (SPDX and CycloneDX) and SLSA provenance. Signatures and GitHub attestations are made only while the
repository is public (keyless signing writes to the public Rekor log); a release from the private repository
carries the SBOMs and `SHA256SUMS-<arch>` only. Verify before installing (`v0.1.0` as an example):

```bash
ID='^https://github.com/Warewave-Technology/olympos/.github/workflows/release.yml@refs/tags/v'
ISSUER=https://token.actions.githubusercontent.com

# Images (signature, SBOM attestation)
cosign verify ghcr.io/warewave-technology/olympos-server:0.1.0 --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"
cosign verify-attestation --type spdxjson ghcr.io/warewave-technology/olympos-server:0.1.0 \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" >/dev/null && echo sbom ok

# Helm charts (OCI)
cosign verify ghcr.io/warewave-technology/charts/olympos-server:0.1.0 --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"
helm install olympos oci://ghcr.io/warewave-technology/charts/olympos-server --version 0.1.0 -n olympos --create-namespace -f values.yaml

# Packages and tarballs (bundle next to each file)
cosign verify-blob olympos-server_0.1.0-1_amd64.deb --bundle olympos-server_0.1.0-1_amd64.deb.sigstore.json \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"

# Checksum of exactly the file you downloaded (same for the .rpm and the tarball)
f=olympos-server_0.1.0-1_amd64.deb   # olympos-server-0.1.0-1.x86_64.rpm, olympos-server_0.1.0_linux_amd64.tar.gz
grep " $f\$" SHA256SUMS-amd64 > check.sha256 && sha256sum -c --strict check.sha256

# Build provenance (GitHub attestation)
gh attestation verify olympos-server_0.1.0-1_amd64.deb --repo Warewave-Technology/olympos
```

The checksum step must print `<file>: OK`. Anything else, or no output at all, means the file was not verified:
do not install it. Checking the whole `SHA256SUMS` file while skipping missing files is not enough: that
succeeds when none of the listed files is present (with a renamed download, for example). On macOS,
`sha256sum` (macOS 14+) works the same way.

Pin images by digest in production (`image.digest` in the chart values).

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

### Azure endpoint override

`endpoint_override` (Settings › Destinations, or the API) replaces
`https://<account>.blob.core.windows.net` — for sovereign clouds, private DNS names or Azurite
(`http://azurite.olympos.svc:10000/devstoreaccount1`). The scheme decides TLS.

### S3 and S3-compatible storage

Kind **s3** writes to an AWS S3 bucket, or to any S3-compatible service (MinIO, Ceph RGW, NetApp
StorageGRID, Wasabi, …) through `endpoint_override` (`https://minio.example.internal:9000`; the scheme
decides TLS; empty = `https://s3.<region>.amazonaws.com`, region default `us-east-1`). Most
S3-compatible services need **path-style** addressing; AWS uses virtual-hosted style. Auth is a static
access key: the access key ID is shown in the UI, the secret key is stored envelope-encrypted or as a
`kv://` reference and is read at use time. Private CAs: set `olympos.backup.storageCABundleFile` (PEM,
added to the system roots; independent of `targetTLS`).

```yaml
olympos:
  backup:
    storageCABundleFile: /etc/olympos/storage-ca/ca.crt   # optional
    s3PartSizeMiB: 32        # multipart part size; memory per running upload; max object = 10 000 parts
```

Uploads stream (no temp file) as multipart uploads, compute sha256 on the fly, set the object tag
`olympos-tier` with the upload and never overwrite an existing key (HEAD before every upload; objects
up to 8 MiB additionally use `If-None-Match: *`).

**Policy — no `s3:DeleteObject`.** Give the Olympos user exactly this (AWS IAM policy; MinIO and Ceph
accept the same document):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"],
     "Resource": "arn:aws:s3:::olympos-backups"},
    {"Effect": "Allow",
     "Action": ["s3:PutObject", "s3:GetObject", "s3:PutObjectTagging", "s3:GetObjectTagging",
                "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
     "Resource": "arn:aws:s3:::olympos-backups/*"}
  ]
}
```

`s3:ListBucket` is needed so that a missing key answers 404 (the existence check before each upload)
and for the bucket check of *Test destination*. On AWS, add a bucket policy statement that denies
deletes to everyone but a break-glass role:

```json
{"Effect": "Deny", "Principal": "*",
 "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutLifecycleConfiguration", "s3:PutBucketObjectLockConfiguration"],
 "Resource": ["arn:aws:s3:::olympos-backups", "arn:aws:s3:::olympos-backups/*"],
 "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::<account>:role/backup-break-glass"}}}
```

*Test destination* checks the endpoint (reachable, TLS verified, bucket exists), writes/reads/tags a
probe under `{prefix}/.olympos-probe/` and expects the delete of the probe to be refused
(`AccessDenied`); if the delete succeeds the destination is saved with a **can delete** warning.

**Object Lock.** Create the bucket with Object Lock enabled (implies versioning) and a default retention
in **compliance** mode ≥ the longest tier, e.g.
`aws s3api put-object-lock-configuration --bucket olympos-backups --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":400}}}'`
(MinIO: `mc retention set --default compliance 400d <alias>/olympos-backups`). Compliance mode cannot be
shortened or removed, not even by the root user.

**Retention = lifecycle rules filtered by the `olympos-tier` tag** (Olympos never deletes):

```json
{"Rules": [
  {"ID": "daily",   "Status": "Enabled", "Filter": {"Tag": {"Key": "olympos-tier", "Value": "daily"}},   "Expiration": {"Days": 8},   "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
  {"ID": "weekly",  "Status": "Enabled", "Filter": {"Tag": {"Key": "olympos-tier", "Value": "weekly"}},  "Expiration": {"Days": 29},  "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
  {"ID": "monthly", "Status": "Enabled", "Filter": {"Tag": {"Key": "olympos-tier", "Value": "monthly"}}, "Expiration": {"Days": 366}, "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
  {"ID": "test",    "Status": "Enabled", "Filter": {"Tag": {"Key": "olympos-tier", "Value": "test"}},    "Expiration": {"Days": 7},   "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
  {"ID": "audit",   "Status": "Enabled", "Filter": {"Tag": {"Key": "olympos-tier", "Value": "audit"}},   "Expiration": {"Days": 400}, "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
  {"ID": "probe",   "Status": "Enabled", "Filter": {"Prefix": "olympos/.olympos-probe/"},                 "Expiration": {"Days": 1}},
  {"ID": "mpu",     "Status": "Enabled", "Filter": {}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2}}
]}
```

Apply with `aws s3api put-bucket-lifecycle-configuration --bucket olympos-backups --lifecycle-configuration file://lifecycle.json`
(MinIO: `mc ilm import`). Choose `Days` from the job retention (`daily: 7` → 8 days, …) and adjust the
probe prefix to your destination prefix. With Object Lock, an expiration only adds a delete marker
until the lock period of the version has ended.

### NFS

Kind **nfs** writes files below a volume mounted into the server. Volumes live under
`olympos.backup.nfsRoot` (default `/var/lib/olympos/nfs`); **every first-level subdirectory is one
mount** (the Helm value `nfsMounts: [{name, <volume source>}]` mounts each at
`/var/lib/olympos/nfs/<name>`; hidden names and symlinks are ignored). *Settings › Destinations* lists
them (`GET /destinations/mounts`, with a writable check). A destination `path` must resolve — after
cleaning and symlink evaluation — inside a mount, e.g. `/var/lib/olympos/nfs/backup-nas/olympos`; `..`
is rejected. The pod runs as uid/gid 65532 with fsGroup 65532: export the share so that this user can
write (e.g. `all_squash,anonuid=65532,anongid=65532`, or a directory owned by 65532).

```yaml
olympos:
  backup:
    nfsRoot: /var/lib/olympos/nfs   # default
```

Each file is written as `<file>.partial` (0640, created exclusively) → fsync → hard-linked to its
final name (never replaces an existing file; filesystems without hard links fall back to check +
rename) → `.partial` removed; directories are 0750. Tags are stored next to each file in
`<file>.tags.json` (`{"olympos-tier":"daily"}`) and the tier is also in the manifest.

**Retention is the storage's job.** Olympos never deletes backups, but on a filesystem it technically
*can* (the server user owns the files), so *Test destination* reports **can delete** with a warning.
Protect backups on the storage side with read-only **snapshots** on their own schedule or **WORM**
(NetApp SnapLock, PowerScale SmartLock, ZFS snapshots with holds), and expire files by tier with a
storage-side job that reads the `.tags.json` sidecars or the manifests.

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
- Restore procedures: `docs/restore.md` (targets) and `docs/restore-olympos.md` (Olympos itself).
  Vault break-glass: `docs/runbooks/vault-break-glass.md`.
