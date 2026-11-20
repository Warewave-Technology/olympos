# Upgrading Olympos

## Before you upgrade

1. **Read the release's upgrade notes.** Each release page, and the version's section in
   [CHANGELOG.md](../CHANGELOG.md), lists behaviour changes you may have to act on under *Upgrade notes*.
2. **Back up Olympos itself.** On *Backups*, the *Olympos database* card has **Run now**. Wait for the run to
   succeed. Downgrades are not supported: if you have to go back, you restore this dump
   ([Restoring Olympos](restore-olympos.md)).
3. **Verify the release** you are about to install ([Verifying releases](install.md#verifying-releases)).

## Server on Kubernetes (Helm)

```bash
helm upgrade olympos oci://ghcr.io/warewave-technology/charts/olympos-server \
  --version <version> -n olympos -f values.yaml
```

The new server applies database migrations when it starts. v0.1 runs a single instance and the chart uses the
`Recreate` strategy, so the server is briefly unavailable; agents reconnect on their own within a minute.

## Server on a Linux VM (systemd)

```bash
sudo apt install ./olympos-server_<version>-1_amd64.deb      # Ubuntu / Debian
sudo dnf install ./olympos-server-<version>-1.x86_64.rpm     # Rocky / Alma
```

The package restarts a running service, which migrates the database at start. To migrate separately
first, stop the service and run `sudo -u olympos olympos-server migrate`.
`sudo -u olympos olympos-server check-config -db` validates `/etc/olympos/config.yaml`, the database
connection and Key Vault access. Run both as `olympos`: the local database authenticates the operating
system user (peer), and only the `olympos` role exists.

## Agents

Upgrade the server first, then each cluster's agent to the same release:

```bash
helm upgrade olympos-agent oci://ghcr.io/warewave-technology/charts/olympos-agent \
  --version <version> -n olympos-system --reuse-values
```

`--reuse-values` keeps the agent's identity settings and options such as `bench.enabled`. The agent keeps
its client certificate (in the `olympos-agent-identity` Secret), so it does not enroll again.
*Settings › Clusters & agents* shows each cluster's agent version. Olympos does not check agent and server
versions against each other; the upgrade notes say when a release needs agents upgraded with it.

## Downgrades

Not supported. A server older than the database schema refuses to start:

> the database schema is at version N, newer than this olympos-server (M): downgrades are not supported;
> run the newer version or restore a dump taken before the upgrade

To go back, restore the `olympos-self` dump taken before the upgrade into an empty database and install
the older version ([Restoring Olympos](restore-olympos.md)).

## Uninstall

```bash
helm uninstall olympos -n olympos
```

The bundled PostgreSQL's volume claim (`<release>-postgresql`) is kept on uninstall and on upgrade, so a new
installation in the same namespace finds the old data. Delete it explicitly to start over. Backups in your
storage are never deleted by Olympos; your lifecycle rules decide how long they stay.
