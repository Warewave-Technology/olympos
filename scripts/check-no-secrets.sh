#!/usr/bin/env bash
# Fails if any known fake secret (canary) used by tests appears in test logs
# or build output. Tests write redacted logs to $OLYMPOS_LOG_DIR when set.
set -euo pipefail
dir="${OLYMPOS_LOG_DIR:-/tmp/olympos-test-logs}"
[ -d "$dir" ] || { echo "no test log dir ($dir); skipping"; exit 0; }
if grep -rIl -E 'CANARY[-_A-Za-z0-9]*' "$dir"; then
  echo "secret canary found in logs above" >&2
  exit 1
fi
echo "no canaries in $dir"
