#!/usr/bin/env bash
# The lab working directory (kubeconfigs, CA keys, vault unseal keys) and
# local reports must never be tracked (F12).
set -euo pipefail
cd "$(dirname "$0")/.."
bad=$(git ls-files test/e2e/.work OLYMPOS-RAPOR.md dist .env 2>/dev/null || true)
if [ -n "$bad" ]; then
  echo "tracked files that must stay local:" >&2; echo "$bad" >&2; exit 1
fi
grep -qx 'test/e2e/.work/' .gitignore || { echo ".gitignore must list test/e2e/.work/" >&2; exit 1; }
echo "no lab state tracked"
