#!/usr/bin/env bash
# Tests scripts/security-model-paths.sh (#60) in a throwaway git repository:
# a final tag passes with no security-model change or with the change in an
# RC of the same version, and fails with a change after the last RC or with
# no RC at all.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/security-model-paths.sh"
repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
cd "$repo"
git init -q -b main
git config user.email test@example.invalid
git config user.name test
git config tag.gpgSign false
fail=0

change() { # change <file>: one commit that touches file
  mkdir -p "$(dirname "$1")"
  echo "$RANDOM" >>"$1"
  git add "$1"
  git commit -q -m "change $1"
}
expect() { # expect pass|fail <tag> [text the output must contain]
  local out rc=0
  out=$("$script" --check "$2" 2>&1) || rc=$?
  if { [ "$1" = pass ] && [ $rc -ne 0 ]; } || { [ "$1" = fail ] && [ $rc -eq 0 ]; } ||
    { [ -n "${3:-}" ] && ! grep -qF -- "$3" <<<"$out"; }; then
    echo "FAIL: --check $2: want $1${3:+ with \"$3\"}, got exit $rc:" >&2
    echo "$out" >&2
    fail=1
  fi
}

change README.md
git tag v1.0.0
expect pass v1.0.0

# No security-model change since v1.0.0.
change README.md
git tag v1.1.0
expect pass v1.1.0

# The change is in an RC of the same version.
change internal/agent/agent.go
git tag v1.2.0-rc.1
expect pass v1.2.0-rc.1 "not a final tag"
change README.md
git tag v1.2.0
expect pass v1.2.0

# A change after the last RC.
change internal/secrets/kv.go
git tag v1.3.0-rc.1
change proto/olympos/v1/agent.proto
late=$(git rev-parse --short HEAD)
git tag v1.3.0
expect fail v1.3.0 "$late"
expect fail v1.3.0 "docs/development.md"

# A change to a single listed file (not a directory) after the last RC.
git tag v1.3.1-rc.1
change internal/backup/engines/clickhouse/native_manifest.go
manifest=$(git rev-parse --short HEAD)
git tag v1.3.1
expect fail v1.3.1 "$manifest"

# No RC at all.
change deploy/helm/olympos-agent/templates/clusterrole.yaml
git tag v1.4.0
expect fail v1.4.0 "no release candidate"

# File names for the pull request label.
if ! out=$(printf 'web/src/x.ts\ninternal/probe/run.go\n' | "$script" --files) || [ "$out" != internal/probe/run.go ]; then
  echo "FAIL: --files with a probe file: exit $?, output \"$out\"" >&2
  fail=1
fi
if ! out=$(printf 'web/src/x.ts\ninternal/ingest/sigv4.go\n' | "$script" --files) || [ "$out" != internal/ingest/sigv4.go ]; then
  echo "FAIL: --files with an ingest file: exit $?, output \"$out\"" >&2
  fail=1
fi
# A single file on the list matches as itself, and only itself.
if ! out=$(printf 'internal/backup/engines/clickhouse/engine.go\ninternal/backup/engines/clickhouse/native_manifest.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/native_manifest.go ]; then
  echo "FAIL: --files with the native manifest: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/native_manifest_test.go\ninternal/backup/engines/clickhouse/native_manifest.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the native manifest" >&2
  fail=1
fi
# The native backup's metadata parsers decide which objects the restore's
# allowlist sees.
if ! out=$(printf 'internal/backup/engines/clickhouse/ddl.go\ninternal/backup/engines/clickhouse/backupmeta.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/backupmeta.go ]; then
  echo "FAIL: --files with the native metadata parsers: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/backupmeta_test.go\ninternal/backup/engines/clickhouse/backupmeta_capture_test.go\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a test next to the native metadata parsers" >&2
  fail=1
fi
if printf 'web/src/x.ts\ndocs/install.md\n' | "$script" --files >/dev/null; then
  echo "FAIL: --files without a security-model file matched" >&2
  fail=1
fi

[ "$fail" = 0 ] && echo "security-model-paths ok"
exit $fail
