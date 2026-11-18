#!/usr/bin/env bash
# The image and the packages must ship the same pinned tool versions.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/tools.env
fail=0
for v in TRIVY_VERSION KUBESCAPE_VERSION POLARIS_VERSION; do
  want=${!v}
  got=$(grep -E "^ARG $v=" deploy/docker/server.Dockerfile | cut -d= -f2)
  if [ "$want" != "$got" ]; then echo "$v: tools.env $want, Dockerfile $got" >&2; fail=1; fi
done
exit $fail
