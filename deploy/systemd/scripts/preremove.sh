#!/bin/sh
# Stop the service before its files go (not on upgrade: postinstall restarts it).
set -e
case "$1" in
  0|remove|purge)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now olympos-server >/dev/null 2>&1 || true
    fi ;;
esac
