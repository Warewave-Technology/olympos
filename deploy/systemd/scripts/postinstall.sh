#!/bin/sh
# olympos-server package post-install: user, directories, config ownership.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/olympos.conf
elif ! getent passwd olympos >/dev/null; then
  useradd --system --home-dir /var/lib/olympos --shell /usr/sbin/nologin --user-group olympos
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/olympos.conf
fi
chown root:olympos /etc/olympos /etc/olympos/config.yaml
chmod 0750 /etc/olympos
chmod 0640 /etc/olympos/config.yaml
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  # Upgrades: restart a running server; migrations run at start-up and a
  # downgrade is refused (the old version keeps the database untouched).
  if systemctl is-active --quiet olympos-server; then
    systemctl restart olympos-server
  else
    echo "olympos-server installed. Edit /etc/olympos/config.yaml, then:"
    echo "  sudo -u olympos olympos-server check-config -db && sudo systemctl enable --now olympos-server"
  fi
fi
