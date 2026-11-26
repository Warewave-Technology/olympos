# Installing Olympos as a systemd service

Besides Kubernetes (Helm, `docs/install.md`), olympos-server runs as a plain, hardened systemd service on a
Linux VM — for example an Azure VM with a managed identity. v0.1 is a **single instance**: availability comes
from systemd restarting the service; agents reconnect by themselves. Two hosts pointed at the same database
are detected: the newer one stays *not ready* (`/readyz`) and logs an error.

Supported: Ubuntu 24.04 / Debian 12 (`.deb`), Rocky / Alma Linux 9 (`.rpm`), amd64 and arm64. Other
distributions: the static tarball.

## 1. Prerequisites

Everything in `docs/install.md` §1 applies (Entra app registration, Key Vault with **soft delete and purge
protection**, backup storage). The VM needs:

- outbound HTTPS to Entra ID, Key Vault and your backup destinations;
- inbound `:8443` from every agent (gRPC, mTLS — do not put a TLS-terminating proxy in front of it) and the UI
  port from users;
- **Key Vault access:** on an Azure VM assign a user-assigned managed identity and set
  `keyVault.managedIdentityClientID` (the server then asks the VM's managed identity endpoint, IMDS, for it;
  on AKS the server uses Workload Identity instead, see [Azure prerequisites](azure.md)). On other hosts use a service principal with a
  certificate: put `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_CERTIFICATE_PATH` (PEM, readable by the
  `olympos` user, e.g. `/etc/olympos/sp.pem` 0640 root:olympos) in `/etc/olympos/environment` and leave
  `managedIdentityClientID` empty.
- **Microsoft Graph:** the same identity (the VM's managed identity or the service principal, not the Entra
  app registration) needs the Graph app role `User.ReadBasic.All` for the person search and the daily
  principal sync; [Azure prerequisites › Microsoft Graph](azure.md#microsoft-graph) has the commands.

## 2. Olympos' own database (local PostgreSQL)

Olympos keeps its state in a PostgreSQL **on the same host**, reached over the Unix socket with peer
authentication (no password, no TCP). Install PostgreSQL 16 from the PGDG repositories — they also provide
the `pg_dump` 13–17 that backups of your targets need (Olympos picks a `pg_dump` with a major version ≥ the
target's):

```bash
# Ubuntu / Debian (PGDG: https://www.postgresql.org/download/linux/ubuntu/)
sudo apt install -y postgresql-common && sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
sudo apt install -y postgresql-16 postgresql-client-17
```

```bash
# Rocky / Alma 9 (PGDG: https://www.postgresql.org/download/linux/redhat/)
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-$(uname -m)/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql
sudo dnf install -y postgresql16-server postgresql16-contrib postgresql17
sudo /usr/pgsql-16/bin/postgresql-16-setup initdb && sudo systemctl enable --now postgresql-16
```

On Rocky/Alma, `postgresql16-contrib` is required: Olympos' schema uses the `pgcrypto` extension, which
Debian and Ubuntu ship in `postgresql-16` itself. Take the PGDG repository package for your architecture
(`$(uname -m)`); the x86_64 one fails on arm64 with a GPG signature error.

Create the role and database (the package creates the `olympos` system user, so install it first or create
the role after step 3):

```bash
sudo -u postgres createuser olympos
sudo -u postgres createdb -O olympos olympos
```

The default `pg_hba.conf` already has `local all all peer`. The DSN in `/etc/olympos/config.yaml` is
`postgres:///olympos?host=/var/run/postgresql` (RHEL: the socket is in `/var/run/postgresql` as well).
An external database (Azure Database for PostgreSQL) works too: `database.dsnRef: kv://<vault>/olympos-db-dsn`.

## 3. Install the package

Download the package for your architecture from the release, **verify it** (see `docs/install.md`
"Verifying releases": `cosign verify-blob` with the `.sigstore.json` bundle), then:

```bash
sudo apt install ./olympos-server_0.1.0-1_amd64.deb      # Ubuntu / Debian
sudo dnf install ./olympos-server-0.1.0-1.x86_64.rpm   # Rocky / Alma
```

What it installs:

| Path | |
|---|---|
| `/usr/bin/olympos-server` | static binary (release build: no dev login, no local key vault) |
| `/usr/lib/olympos/bin/{trivy,kubescape,polaris,clickhouse}` | pinned tools, verified against the upstream checksums at build time. `clickhouse` is the static ClickHouse client used for ClickHouse restores: about 750 MB installed, and each package is about 200-230 MB larger per architecture |
| `/etc/olympos/config.yaml` | configuration, `0640 root:olympos`, kept on upgrade |
| `/usr/lib/systemd/system/olympos-server.service` | the hardened unit |
| `/var/lib/olympos` | state: trivy DB cache, NFS mount roots, temp files (`olympos` user, 0750) |
| system user `olympos` | runs the service |

Logs go to journald: `journalctl -u olympos-server` (JSON lines, secrets redacted).

## 4. Configure

Edit `/etc/olympos/config.yaml` (every key: [Configuration](configuration.md)): at least `publicURL`,
`agentGatewayURL`, `entra`, `bootstrapAdmins`, `keyVault`. Then:

```bash
sudo -u olympos olympos-server check-config -db    # validates files, tools and the database login
sudo systemctl enable --now olympos-server
curl -fsS http://127.0.0.1:9090/readyz
```

### TLS

- **UI:** either a reverse proxy in front of `listen.http` (`:8080`), or HTTPS directly with
  `listen.tlsCertFile` / `listen.tlsKeyFile`. Binding below 1024 needs
  `sudo systemctl edit olympos-server` with `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`; otherwise keep a high port.
- **Gateway (`:8443`):** by default the internal CA issues the certificate (agents pin that CA) and renews it
  itself. An own certificate: `gateway.tlsCertFile` / `gateway.tlsKeyFile`.
- **Ingest (`:9444`, optional):** only for native ClickHouse backups, and only when `ingest.url` is set. ClickHouse
  connects to it directly, so open the port in the firewall for the ClickHouse hosts. The internal CA issues
  its certificate for the host of `ingest.url`; an own one: `ingest.tlsCertFile` / `ingest.tlsKeyFile`. See
  [Installing › Native ClickHouse backups](install.md#5-native-clickhouse-backups-optional).
- Renewed certificate files are picked up with `sudo systemctl reload olympos-server` (SIGHUP; no restart, no
  dropped agent streams). Other configuration changes need a restart.

### NFS destinations

Mount the exports with the OS (`/etc/fstab` or systemd mount units) under `/var/lib/olympos/nfs/<name>`,
writable by the `olympos` user, then add an NFS destination with that name in *Settings › Destinations*. The
same path traversal and symlink protections as in Kubernetes apply; retention/WORM must come from the storage.

```ini
# /etc/systemd/system/var-lib-olympos-nfs-backup\x2dnas.mount
[Mount]
What=nas.contoso.internal:/exports/olympos
Where=/var/lib/olympos/nfs/backup-nas
Type=nfs
Options=vers=4.1,hard,noexec,nosuid,nodev
[Install]
WantedBy=multi-user.target
```

## 5. Hardening

The unit runs with `NoNewPrivileges`, `ProtectSystem=strict` (writable: `/var/lib/olympos` only),
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, no capabilities, `RestrictAddressFamilies=AF_INET AF_INET6
AF_UNIX`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute` and a `MemoryMax` (4 G; change with
`systemctl edit`). Check it:

```bash
systemd-analyze security olympos-server     # CI requires an exposure ≤ 3.0
```

## 6. Upgrade

Install the newer package. It restarts a running service; migrations run at start-up. A **downgrade is
refused**: an older binary does not start on a schema migrated by a newer one (restore the dump taken before
the upgrade instead, `docs/restore-olympos.md`). To migrate separately (e.g. in a maintenance window):

```bash
sudo systemctl stop olympos-server
sudo -u olympos olympos-server migrate
sudo systemctl start olympos-server
olympos-server version
```

## 7. Back up Olympos itself

Open **Backups › Olympos database** and choose a destination: the built-in `olympos-self` job dumps the local
database daily. The dump is useless without the Key Vault KEK, so keep purge protection on.
`docs/restore-olympos.md` describes the restore on a new host (same Key Vault, `pg_restore`, start).

## 8. Uninstall

```bash
sudo systemctl disable --now olympos-server
sudo apt remove olympos-server      # or: sudo dnf remove olympos-server
```

The package keeps `/etc/olympos`, `/var/lib/olympos` and the database. To remove everything (after taking a
final `olympos-self` backup if you might come back): `sudo rm -rf /etc/olympos /var/lib/olympos`,
`sudo -u postgres dropdb olympos && sudo -u postgres dropuser olympos`, `sudo userdel olympos`. Uninstall the
agents from the clusters (`helm uninstall olympos-agent -n olympos-system`).
