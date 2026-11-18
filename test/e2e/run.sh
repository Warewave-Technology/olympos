#!/usr/bin/env bash
# Olympos e2e lab on kind (SPEC §19): agent + server + Postgres + Vault +
# OpenBao + ClickHouse + Azurite. Uses its OWN kubeconfig; never touches the
# caller's current kube context.
#
#   ./test/e2e/run.sh            # create/reuse lab, build images, deploy, test
#   SKIP_BUILD=1 ./test/e2e/run.sh
#   ./test/e2e/run.sh down       # delete the lab cluster
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
WORK=$ROOT/test/e2e/.work
CLUSTER=olympos-lab
export KUBECONFIG=$WORK/kubeconfig
mkdir -p "$WORK"

if [ "${1:-}" = down ]; then
  kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
  exit 0
fi

log() { printf '\033[1;33m==> %s\033[0m\n' "$*"; }

if ! kind get clusters | grep -qx "$CLUSTER"; then
  log "creating kind cluster $CLUSTER"
  kind create cluster --config test/e2e/kind.yaml --kubeconfig "$KUBECONFIG"
fi
kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null

if [ -z "${SKIP_BUILD:-}" ]; then
  log "building images"
  docker build -q -f deploy/docker/agent.Dockerfile -t olympos-agent:e2e . >/dev/null
  docker build -q -f deploy/docker/server.Dockerfile -t olympos-server:e2e --build-arg PG_VERSIONS="16 17" . >/dev/null
fi
log "loading images into kind"
kind load docker-image olympos-agent:e2e olympos-server:e2e --name "$CLUSTER" >/dev/null

# Lab CA for target TLS (Postgres verify-full against orders-pg.lab.svc).
if [ ! -f "$WORK/lab-ca.crt" ]; then
  log "generating lab CA"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=Olympos Lab CA" -keyout "$WORK/lab-ca.key" -out "$WORK/lab-ca.crt" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=orders-pg.lab.svc" \
    -keyout "$WORK/pg.key" -out "$WORK/pg.csr" 2>/dev/null
  printf 'subjectAltName=DNS:orders-pg.lab.svc,DNS:orders-pg.lab.svc.cluster.local\n' > "$WORK/pg.ext"
  openssl x509 -req -in "$WORK/pg.csr" -CA "$WORK/lab-ca.crt" -CAkey "$WORK/lab-ca.key" -CAcreateserial \
    -days 30 -extfile "$WORK/pg.ext" -out "$WORK/pg.crt" 2>/dev/null
fi

log "deploying lab dependencies and targets"
kubectl apply -f test/e2e/manifests/olympos-deps.yaml >/dev/null
kubectl create namespace lab --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n lab create secret tls pg-tls --cert "$WORK/pg.crt" --key "$WORK/pg.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n olympos create configmap target-ca --from-file=ca.crt="$WORK/lab-ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f test/e2e/manifests/targets.yaml >/dev/null

log "deploying olympos-server (dev mode, local key vault)"
helm upgrade --install olympos deploy/helm/olympos-server --namespace olympos \
  -f test/e2e/server-values.yaml --wait --timeout 5m >/dev/null

kubectl -n lab rollout status statefulset/orders-pg --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/vault --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/openbao --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/metrics-ch --timeout=240s >/dev/null
kubectl -n olympos rollout status deploy/azurite --timeout=180s >/dev/null

log "running e2e tests"
OLYMPOS_E2E_KUBECONFIG=$KUBECONFIG OLYMPOS_E2E_URL=http://127.0.0.1:28080 \
  go test -tags e2e -count=1 -timeout 30m -v ./test/e2e/... 2>&1 | tee "$WORK/e2e.log"
