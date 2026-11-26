#!/usr/bin/env bash
# The files that make a change a security-model change, and the release rule
# for them (docs/development.md › Releases, #60): a final release whose
# commits since the previous final touch one of these ships an RC of the
# same version first, and every such commit is in its latest RC.
#
#   security-model-paths.sh --check <tag>   the rule, for the tag just pushed
#   security-model-paths.sh --files         file names on stdin; prints the
#                                           ones on the list, fails if none
# An entry is a directory (everything under it) or a single file (only it).
# Runs in the current directory's repository.
set -euo pipefail
paths=(
  docs/security-model.md
  proto
  internal/secrets
  internal/probe
  internal/agent
  internal/ingest
  internal/backup/engines/clickhouse/native_manifest.go
  internal/backup/engines/clickhouse/backupmeta.go
  internal/backup/engines/clickhouse/allowlist.go
  internal/backup/engines/clickhouse/sqllex.go
  internal/backup/engines/clickhouse/replicated.go
  internal/backup/engines/clickhouse/native.go
  internal/backup/engines/clickhouse/native_restore.go
  internal/backup/native.go
  internal/backup/native_chain.go
  internal/backup/native_restore.go
  internal/backup/restore_guide.go
  internal/restore/api.go
  internal/restore/native_execute.go
  internal/app/ingest.go
  internal/blob/fs.go
  deploy/helm/olympos-agent/templates/clusterrole.yaml
  deploy/helm/olympos-agent/templates/bench.yaml
)

case "${1:-}" in
--files)
  found=1
  while read -r f; do
    for p in "${paths[@]}"; do
      if [ "$f" = "$p" ] || [[ $f == "$p"/* ]]; then
        echo "$f"
        found=0
        break
      fi
    done
  done
  exit $found
  ;;
--check)
  tag=${2:?usage: $0 --check <tag>}
  if [[ $tag == *-* ]]; then
    echo "$tag is not a final tag; nothing to check"
    exit 0
  fi
  # The previous final release: the final tag just below this one.
  prev=$({ git tag --list 'v*' | grep -v -- -; echo "$tag"; } | sort -uV | grep -B1 -xF -- "$tag" | grep -vxF -- "$tag" || true)
  commits=$(git rev-list --abbrev-commit "${prev:+$prev..}$tag" -- "${paths[@]}")
  if [ -z "$commits" ]; then
    echo "$tag: no security-model change since ${prev:-the first commit}"
    exit 0
  fi
  rc=$(git tag --list "$tag-rc.*" --sort=-v:refname | head -1)
  missing=()
  for c in $commits; do
    if [ -z "$rc" ] || ! git merge-base --is-ancestor "$c" "$rc"; then
      missing+=("$c")
    fi
  done
  if [ ${#missing[@]} -eq 0 ]; then
    echo "$tag: every security-model change since ${prev:-the first commit} is in $rc"
    exit 0
  fi
  {
    echo "$tag changes the security model and needs a release candidate first (docs/development.md › Releases)."
    if [ -z "$rc" ]; then
      echo "There is no release candidate $tag-rc.N."
    else
      echo "These commits came after $rc:"
    fi
    for c in "${missing[@]}"; do git log -1 --format='  %h %s' "$c"; done
    echo "Nothing was published. Delete the tag $tag, tag $tag-rc.N on this commit, test it in the lab with a"
    echo "focused test plan, then tag $tag again."
  } >&2
  exit 1
  ;;
*)
  echo "usage: $0 --check <tag> | --files" >&2
  exit 2
  ;;
esac
