#!/usr/bin/env bash
# New migrations must be numbered strictly above the latest one on the base
# branch (F13). goose runs with allow-missing semantics off: an older number
# added later would never run on databases that are already past it.
set -euo pipefail
base=${1:-origin/main}
cd "$(dirname "$0")/.."
dir=internal/store/migrations
latest=$(git ls-tree --name-only "$base" "$dir/" | sed -n 's#.*/\([0-9]\{5\}\)_.*#\1#p' | sort -n | tail -1)
latest=${latest:-0}
fail=0
for f in $(git diff --name-only --diff-filter=A "$base"...HEAD -- "$dir"); do
  n=$(basename "$f" | cut -d_ -f1)
  if [ $((10#$n)) -le $((10#$latest)) ]; then
    echo "$f: number $n is not above the latest migration on $base ($latest)" >&2; fail=1
  fi
done
# Every migration needs Up and Down sections.
for f in "$dir"/*.sql; do
  grep -q -- '-- +goose Up' "$f" && grep -q -- '-- +goose Down' "$f" || { echo "$f: missing goose Up/Down" >&2; fail=1; }
done
[ "$fail" = 0 ] && echo "migrations ok (latest on $base: $latest)"
exit $fail
