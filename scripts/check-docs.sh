#!/usr/bin/env bash
# Documentation commands that can pass without checking anything (v0.1.0
# final checklist A1). sha256sum's skip-missing flag succeeds when no listed
# file is present, so a renamed download "verifies"; docs must name the file
# (docs/install.md "Verifying releases"). The pattern is split so this file
# does not match itself.
set -euo pipefail
cd "$(dirname "$0")/.."
flag='--ignore'"-missing"
if hits=$(grep -rnF -- "$flag" README.md docs .github 2>/dev/null); then
  echo "$hits"
  echo "error: $flag lets a checksum check pass with no file checked; name the file instead (docs/install.md)"
  exit 1
fi
echo "docs ok"
