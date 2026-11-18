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
if [ ! -f "$WORK/vault.crt" ]; then
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=vault.lab.svc" \
    -keyout "$WORK/vault.key" -out "$WORK/vault.csr" 2>/dev/null
  printf 'subjectAltName=DNS:vault.lab.svc,DNS:vault.lab.svc.cluster.local,IP:127.0.0.1\n' > "$WORK/vault.ext"
  openssl x509 -req -in "$WORK/vault.csr" -CA "$WORK/lab-ca.crt" -CAkey "$WORK/lab-ca.key" -CAcreateserial \
    -days 30 -extfile "$WORK/vault.ext" -out "$WORK/vault.crt" 2>/dev/null
fi

log "deploying lab dependencies and targets"
kubectl apply -f test/e2e/manifests/olympos-deps.yaml >/dev/null
kubectl create namespace lab --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n lab create secret tls pg-tls --cert "$WORK/pg.crt" --key "$WORK/pg.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n lab create secret tls vault-tls --cert "$WORK/vault.crt" --key "$WORK/vault.key" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n olympos create configmap target-ca --from-file=ca.crt="$WORK/lab-ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f test/e2e/manifests/targets.yaml >/dev/null

# Kyverno 1.20 (chart 3.10) runs only policies.kyverno.io CEL policies.
# KYVERNO_CHART=3.9.2 (1.19) also runs the legacy kyverno.io ClusterPolicy.
KYVERNO_CHART=${KYVERNO_CHART:-3.10.0}
if ! helm -n kyverno list -o json 2>/dev/null | grep -q "kyverno-$KYVERNO_CHART"; then
  log "installing kyverno chart $KYVERNO_CHART"
  helm -n kyverno uninstall kyverno --wait >/dev/null 2>&1 || true
  helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
  helm repo update kyverno >/dev/null
  helm upgrade --install kyverno kyverno/kyverno --version "$KYVERNO_CHART" -n kyverno --create-namespace --wait --timeout 5m \
    --set admissionController.replicas=1 --set backgroundController.replicas=1 \
    --set cleanupController.enabled=false --set reportsController.replicas=1 >/dev/null
fi
kubectl apply -f test/e2e/manifests/kyverno-vpol.yaml >/dev/null
case "$KYVERNO_CHART" in
  3.10.*|3.1[1-9].*) kubectl delete -f test/e2e/manifests/kyverno-policy.yaml --ignore-not-found >/dev/null 2>&1 || true ;;
  *) kubectl apply -f test/e2e/manifests/kyverno-policy.yaml >/dev/null ;;
esac

log "deploying olympos-server (dev mode, local key vault)"
helm upgrade --install olympos deploy/helm/olympos-server --namespace olympos \
  -f test/e2e/server-values.yaml --wait --timeout 5m >/dev/null
# Same image tag on every build: restart so freshly loaded images are used.
kubectl -n olympos rollout restart deploy/olympos >/dev/null
kubectl -n olympos rollout status deploy/olympos --timeout=180s >/dev/null
if kubectl -n olympos-system get deploy olympos-agent >/dev/null 2>&1; then
  # Pick up chart changes (RBAC) and the freshly loaded image.
  helm upgrade olympos-agent deploy/helm/olympos-agent -n olympos-system --reuse-values --wait --timeout 3m >/dev/null
  kubectl -n olympos-system rollout restart deploy/olympos-agent >/dev/null
  kubectl -n olympos-system rollout status deploy/olympos-agent --timeout=180s >/dev/null
fi

kubectl -n lab rollout status statefulset/orders-pg --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/vault --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/openbao --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/metrics-ch --timeout=240s >/dev/null
kubectl -n olympos rollout status deploy/azurite --timeout=180s >/dev/null

# Vault runs on raft storage (snapshots need it): init + unseal once per pod.
vexec() { kubectl -n lab exec deploy/vault -- "$@"; }
for i in $(seq 1 30); do rc=0; vexec vault status -format=json >/dev/null 2>&1 || rc=$?; [ "$rc" -le 2 ] && break; sleep 2; done
if { vexec vault status -format=json 2>/dev/null || true; } | grep -q '"initialized": false'; then
  log "initializing lab vault"
  vexec vault operator init -key-shares=1 -key-threshold=1 -format=json > "$WORK/vault-init.json"
fi
if { vexec vault status -format=json 2>/dev/null || true; } | grep -q '"sealed": true'; then
  vexec vault operator unseal "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["unseal_keys_b64"][0])' "$WORK/vault-init.json")" >/dev/null
fi
ROOT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["root_token"])' "$WORK/vault-init.json")
for i in $(seq 1 30); do vexec env VAULT_TOKEN="$ROOT" vault secrets list >/dev/null 2>&1 && break; sleep 2; done
vexec env VAULT_TOKEN="$ROOT" vault secrets enable -path=secret kv-v2 >/dev/null 2>&1 || true
vexec env VAULT_TOKEN="$ROOT" vault secrets enable -path=legacy -version=1 kv >/dev/null 2>&1 || true

if [ -n "${SETUP_ONLY:-}" ]; then
  log "lab ready (SETUP_ONLY: tests skipped)"
  exit 0
fi

log "running e2e tests"
OLYMPOS_E2E_KUBECONFIG=$KUBECONFIG OLYMPOS_E2E_URL=http://127.0.0.1:28080 \
  go test -tags e2e -count=1 -timeout 30m -v ./test/e2e/... 2>&1 | tee "$WORK/e2e.log"
