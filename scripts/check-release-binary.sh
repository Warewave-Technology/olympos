#!/usr/bin/env bash
# Verifies a release build of olympos-server contains no dev login and no
# local key vault (F6). The symbol check needs an unstripped build; the
# string check runs on the stripped release flags too.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$tmp/syms" ./cmd/olympos-server
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$tmp/release" ./cmd/olympos-server
fail=0
if go tool nm "$tmp/syms" | grep -E 'handleDevLogin|LocalKeyVault|localKeyVault' ; then
  echo "release binary contains dev-only symbols" >&2; fail=1
fi
if grep -a -c 'dev-login' "$tmp/release" >/dev/null; then
  echo "release binary contains the string dev-login" >&2; fail=1
fi
[ "$fail" = 0 ] && echo "release binary ok: no dev login, no local key vault"
exit "$fail"
