#!/usr/bin/env bash
# Release notes for a tag, from CHANGELOG.md (v0.1.0 final checklist A3):
# the "Upgrade notes" of the x.y.z section, then pointers to the changelog
# and to verification. Fails if the section or its upgrade notes are missing,
# so a release cannot go out without them.
#   scripts/release-notes.sh v0.1.0-rc.3 > notes.md
set -euo pipefail
tag=${1:?usage: release-notes.sh <tag>}
cd "$(dirname "$0")/.."
v=${tag#v}; base=${v%%-*}
section=$(awk -v h="## [$base]" 'index($0, h) == 1 {on = 1; next} on && /^## \[/ {exit} on' CHANGELOG.md)
[ -n "$section" ] || { echo "CHANGELOG.md has no ## [$base] section" >&2; exit 1; }
upgrade=$(printf '%s\n' "$section" | awk '/^### Upgrade notes/ {on = 1; next} on && /^### / {exit} on')
[ -n "$(printf '%s' "$upgrade" | tr -d '[:space:]')" ] || { echo "## [$base] has no ### Upgrade notes" >&2; exit 1; }
[ "$base" = "$v" ] || echo "Pre-release of v$base."$'\n'
echo "## Upgrade notes"
printf '%s\n' "$upgrade"
echo
echo "All changes: [CHANGELOG.md](https://github.com/Warewave-Technology/olympos/blob/$tag/CHANGELOG.md)."
echo "Verify before installing: [docs/install.md › Verifying releases](https://github.com/Warewave-Technology/olympos/blob/$tag/docs/install.md#verifying-releases)."
