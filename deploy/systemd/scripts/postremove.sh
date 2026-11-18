#!/bin/sh
# Config, state (/var/lib/olympos) and the database are kept on remove;
# docs/install-systemd.md "Uninstall" lists what to delete by hand.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
