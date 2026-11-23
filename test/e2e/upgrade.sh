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
# run.sh started HEAD, which migrated the bundled database. A release refuses
# a schema newer than its own (no downgrades), so the release under test
# starts on an empty database, as a real installation of it would.
WORK=$PWD/test/e2e/.work
source test/e2e/lib.sh
reset_olympos_db
v=${from#v}
src=$(mktemp -d)
git worktree add --detach "$src" "$from" >/dev/null
trap 'git worktree remove --force "$src"' EXIT
echo "==> building olympos-server $from (dev build)"
docker build -q -f "$src/deploy/docker/server.Dockerfile" -t "olympos-server:$v-dev" \
  --build-arg PG_VERSIONS="16 17" --build-arg GO_TAGS=dev --build-arg VERSION="$from" "$src" >/dev/null
kind load docker-image "olympos-server:$v-dev" --name olympos-lab >/dev/null
echo "==> installing the released chart of $from"
# A server from before the probe takes a probe enrollment for an agent one,
# which spends the token: the agent is installed without the probe here.
export OLYMPOS_E2E_PROBE=off
helm upgrade --install olympos oci://ghcr.io/warewave-technology/charts/olympos-server --version "$v" -n olympos \
  -f test/e2e/server-values.yaml --set image.tag="$v-dev" --wait --timeout 5m
OLYMPOS_E2E_KUBECONFIG=$KUBECONFIG OLYMPOS_E2E_URL=http://127.0.0.1:28080 \
  go test -tags e2e -count=1 -v -run 'TestM1EnrollInventoryDiscovery|TestM2BackupsPostgresAndClickHouse' ./test/e2e/
echo "==> upgrading to HEAD"
helm upgrade olympos deploy/helm/olympos-server -n olympos -f test/e2e/server-values.yaml --wait --timeout 5m
kubectl -n olympos rollout status deploy/olympos --timeout=180s
# The agents reconnect to the new server on their own schedule; tests that
# open a tunnel need the new session (a recent last_seen_at may still be the
# old one).
psql() { kubectl -n olympos exec statefulset/olympos-postgresql -- psql -U olympos -d olympos -Atc "$1"; }
since=$(psql "SELECT now()")
for i in $(seq 60); do
  [ "$(psql "SELECT coalesce(bool_and(last_seen_at > '$since'), false) FROM clusters WHERE status <> 'revoked'")" = t ] && break
  [ "$i" = 60 ] && { echo "agents did not reconnect after the upgrade"; exit 1; }
  sleep 3
done
OLYMPOS_E2E_KUBECONFIG=$KUBECONFIG OLYMPOS_E2E_URL=http://127.0.0.1:28080 \
  go test -tags e2e -count=1 -v -run 'TestM1EnrollInventoryDiscovery|TestM2BackupsPostgresAndClickHouse' ./test/e2e/
echo "==> upgrade $from -> HEAD passed"
