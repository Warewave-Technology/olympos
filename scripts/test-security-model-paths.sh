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
# The restore allowlist decides which objects of a backup a native RESTORE
# creates on the target.
if ! out=$(printf 'internal/backup/engines/clickhouse/restore.go\ninternal/backup/engines/clickhouse/allowlist.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/allowlist.go ]; then
  echo "FAIL: --files with the restore allowlist: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/allowlist_test.go\ninternal/backup/engines/clickhouse/allowlist.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the restore allowlist" >&2
  fail=1
fi
# The strict lexer the allowlist and the metadata parsers read statements
# with; the logical restore's engine parser next to it is not on the list.
if ! out=$(printf 'internal/backup/engines/clickhouse/ddl.go\ninternal/backup/engines/clickhouse/sqllex.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/sqllex.go ]; then
  echo "FAIL: --files with the SQL lexer: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/sqllex_test.go\ninternal/backup/engines/clickhouse/sqllex.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the SQL lexer" >&2
  fail=1
fi
# The native restore's Replicated DDL rewrite decides which Keeper path a
# restored table joins; the logical restore's table generator is not on the
# list.
if ! out=$(printf 'internal/backup/engines/clickhouse/table.go\ninternal/backup/engines/clickhouse/replicated.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/replicated.go ]; then
  echo "FAIL: --files with the Replicated DDL rewrite: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/replicated_test.go\ninternal/backup/engines/clickhouse/replicated.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the Replicated DDL rewrite" >&2
  fail=1
fi
# The native run puts the run's credential into the BACKUP statement and
# keeps it out of the logs.
if ! out=$(printf 'internal/backup/engines/clickhouse/nativeformat.go\ninternal/backup/engines/clickhouse/native.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/native.go ]; then
  echo "FAIL: --files with the native run: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/native_run_test.go\ninternal/backup/engines/clickhouse/native_integration_test.go\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a test next to the native run" >&2
  fail=1
fi
# The worker's native run scopes the run's credential and decides what its
# signed manifest says and when its objects are complete.
if ! out=$(printf 'internal/backup/worker.go\ninternal/backup/native.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/native.go ]; then
  echo "FAIL: --files with the worker's native run: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/native_test.go\ninternal/backup/native_internal_test.go\ninternal/backup/engines/native.go\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the worker's native run" >&2
  fail=1
fi
# The base chain of an incremental: which runs its credential reads, and
# which stored objects the endpoint serves it.
if ! out=$(printf 'internal/backup/copies.go\ninternal/backup/native_chain.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/native_chain.go ]; then
  echo "FAIL: --files with the base chain: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/native_chain_test.go\ninternal/backup/native_chain.go.orig\n' | "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the base chain" >&2
  fail=1
fi
# The restore check of a native copy: which chain a restore reads, from
# where, whether it verifies, and what of it the restore creates.
if ! out=$(printf 'internal/backup/copies.go\ninternal/backup/native_restore.go\ninternal/backup/engines/clickhouse/native_restore.go\n' |
  "$script" --files) || [ "$out" != $'internal/backup/native_restore.go\ninternal/backup/engines/clickhouse/native_restore.go' ]; then
  echo "FAIL: --files with the native restore check: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/native_restore_test.go\ninternal/backup/engines/clickhouse/native_restore_test.go\ninternal/backup/native_restore.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the native restore check" >&2
  fail=1
fi
# What a native restore created, compared with what was approved, and what
# of it is dropped (security review v0.4, finding 1).
if ! out=$(printf 'internal/backup/engines/clickhouse/restore.go\ninternal/backup/engines/clickhouse/native_verify.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/native_verify.go ]; then
  echo "FAIL: --files with the native restore's comparison: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/native_verify_test.go\ninternal/backup/engines/clickhouse/native_verify.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the native restore's comparison" >&2
  fail=1
fi
# Which copy a restore reads (FindRestoreSource), and the open-time rules
# that keep a native run whose chain does not verify from being restored.
if ! out=$(printf 'internal/backup/restore_guide.go\ninternal/restore/executor.go\ninternal/restore/api.go\n' | "$script" --files) ||
  [ "$out" != $'internal/backup/restore_guide.go\ninternal/restore/api.go' ]; then
  echo "FAIL: --files with the restore source and open-time rules: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/restore_guide_test.go\ninternal/restore/api_test.go\ninternal/restore/rules.go\ninternal/restore/api.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the restore source or the open-time rules" >&2
  fail=1
fi
# The helpers that decide what a restore creates (quoting, the databases it
# creates or refuses, the schema bound); the files they were moved out of
# are not on the list.
if ! out=$(printf 'internal/backup/engines/clickhouse/restore_shared.go\ninternal/backup/engines/clickhouse/conn.go\ninternal/backup/engines/clickhouse/restore.go\ninternal/backup/engines/clickhouse/table.go\ninternal/backup/engines/clickhouse/options.go\ninternal/restore/request.go\n' | "$script" --files) ||
  [ "$out" != internal/backup/engines/clickhouse/restore_shared.go ]; then
  echo "FAIL: --files with the restore's shared helpers: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/backup/engines/clickhouse/restore_shared_test.go\ninternal/backup/engines/clickhouse/restore_shared.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the restore's shared helpers" >&2
  fail=1
fi
# The execution of a native restore: the decisions approved (R50), the
# read-only credential over the chain and the source it is served from.
if ! out=$(printf 'internal/restore/executor.go\ninternal/restore/native_execute.go\n' | "$script" --files) ||
  [ "$out" != internal/restore/native_execute.go ]; then
  echo "FAIL: --files with the native restore's execution: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/restore/native_test.go\ninternal/restore/native_execute_test.go\ninternal/restore/native_execute.go.orig\n' |
  "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the native restore's execution" >&2
  fail=1
fi
# The ingest endpoint's listener (its TLS and timeouts) and the NFS writer,
# whose SetTags rewrites the tags of stored backups.
if ! out=$(printf 'internal/app/app.go\ninternal/app/ingest.go\n' | "$script" --files) || [ "$out" != internal/app/ingest.go ]; then
  echo "FAIL: --files with the ingest listener: exit $?, output \"$out\"" >&2
  fail=1
fi
if ! out=$(printf 'internal/blob/s3.go\ninternal/blob/fs.go\n' | "$script" --files) || [ "$out" != internal/blob/fs.go ]; then
  echo "FAIL: --files with the NFS writer: exit $?, output \"$out\"" >&2
  fail=1
fi
if printf 'internal/app/ingest_test.go\ninternal/blob/fs_test.go\ninternal/blob/fs.go.orig\n' | "$script" --files >/dev/null; then
  echo "FAIL: --files matched a file next to the ingest listener or the NFS writer" >&2
  fail=1
fi
if printf 'web/src/x.ts\ndocs/install.md\n' | "$script" --files >/dev/null; then
  echo "FAIL: --files without a security-model file matched" >&2
  fail=1
fi

[ "$fail" = 0 ] && echo "security-model-paths ok"
exit $fail
