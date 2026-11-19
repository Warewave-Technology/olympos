#!/usr/bin/env bash
# Upgrade test (F13): the lab runs the released chart of $1 (e.g.
# v0.1.0-rc.1) with a server image built from that tag, gets data (an
# enrolled cluster, a backup job and a run), then is upgraded to HEAD on the
# same bundled database; the M1/M2 smoke tests must pass and the data must
# still be there. The image is a dev build of the tag's source: the lab runs
# in devMode with the local key vault, which release binaries refuse (F6).
set -euo pipefail
from=${1:?usage: upgrade.sh <release tag>}
cd "$(dirname "$0")/../.."
export SETUP_ONLY=1
./test/e2e/run.sh   # lab + targets + HEAD images, Olympos reset
export KUBECONFIG=$PWD/test/e2e/.work/kubeconfig
v=${from#v}
src=$(mktemp -d)
git worktree add --detach "$src" "$from" >/dev/null
trap 'git worktree remove --force "$src"' EXIT
echo "==> building olympos-server $from (dev build)"
docker build -q -f "$src/deploy/docker/server.Dockerfile" -t "olympos-server:$v-dev" \
  --build-arg PG_VERSIONS="16 17" --build-arg GO_TAGS=dev --build-arg VERSION="$from" "$src" >/dev/null
kind load docker-image "olympos-server:$v-dev" --name olympos-lab >/dev/null
echo "==> installing the released chart of $from"
helm upgrade --install olympos oci://ghcr.io/warewave-technology/charts/olympos-server --version "$v" -n olympos \
  -f test/e2e/server-values.yaml --set image.tag="$v-dev" --wait --timeout 5m
OLYMPOS_E2E_KUBECONFIG=$KUBECONFIG OLYMPOS_E2E_URL=http://127.0.0.1:28080 \
  go test -tags e2e -count=1 -v -run 'TestM1EnrollInventoryDiscovery|TestM2BackupsPostgresAndClickHouse' ./test/e2e/
echo "==> upgrading to HEAD"
helm upgrade olympos deploy/helm/olympos-server -n olympos -f test/e2e/server-values.yaml --wait --timeout 5m
kubectl -n olympos rollout status deploy/olympos --timeout=180s
OLYMPOS_E2E_KUBECONFIG=$KUBECONFIG OLYMPOS_E2E_URL=http://127.0.0.1:28080 \
  go test -tags e2e -count=1 -v -run 'TestM1EnrollInventoryDiscovery|TestM2BackupsPostgresAndClickHouse' ./test/e2e/
echo "==> upgrade $from -> HEAD passed"
