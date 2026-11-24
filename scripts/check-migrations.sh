#!/usr/bin/env bash
# Migrations (docs/development.md › Migrations):
# - new ones are numbered strictly above the latest one on the base branch
#   (F13). goose runs with allow-missing semantics off: an older number added
#   later would never run on databases that are already past it;
# - merged ones are immutable: a database that already ran a migration never
#   runs it again, so an edit only reaches new installs (#55);
# - every one has Up and Down sections.
set -euo pipefail
base=${1:-origin/main}
cd "$(dirname "$0")/.."
dir=internal/store/migrations
fail=0
# immutable <git status letter> <file> <where>
immutable() {
  local what=modified
  case $1 in D) what="deleted or renamed" ;; T) what="changed to another file type" ;; esac
  echo "$2: $what $3. Merged migrations are immutable: add a new migration instead." >&2; fail=1
}

latest=$(git ls-tree --name-only "$base" "$dir/" | sed -n 's#.*/\([0-9]\{5\}\)_.*#\1#p' | sort -n | tail -1)
latest=${latest:-0}
for f in $(git diff --name-only --diff-filter=A "$base"...HEAD -- "$dir"); do
  n=$(basename "$f" | cut -d_ -f1)
  if [ $((10#$n)) -le $((10#$latest)) ]; then
    echo "$f: number $n is not above the latest migration on $base ($latest)" >&2; fail=1
  fi
done
# Changed, deleted or renamed since the branch left the base.
while read -r status f _; do
  immutable "$status" "$f" "on this branch (against $base)"
done < <(git diff --name-status --no-renames --diff-filter=MDT "$base"...HEAD -- "$dir")

# Every migration of the latest release, byte for byte.
tag=$(git tag --list 'v*' --sort=-v:refname | head -1)
if [ -n "$tag" ]; then
  while read -r status f _; do
    immutable "$status" "$f" "since release $tag"
  done < <(git diff --name-status --no-renames --diff-filter=MDT "$tag" HEAD -- "$dir")
fi

for f in "$dir"/*.sql; do
  grep -q -- '-- +goose Up' "$f" && grep -q -- '-- +goose Down' "$f" || { echo "$f: missing goose Up/Down" >&2; fail=1; }
done
[ "$fail" = 0 ] && echo "migrations ok (latest on $base: $latest; release ${tag:-none} unchanged)"
exit $fail
