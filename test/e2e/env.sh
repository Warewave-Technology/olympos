#!/usr/bin/env bash
# Browsable Olympos lab with two clusters and NO agents enrolled: you add the
# clusters yourself from the UI ("Add cluster") and run the generated command.
#
#   ./test/e2e/env.sh          # build/reuse everything, reset Olympos to empty
#   ./test/e2e/env.sh down     # delete both kind clusters
#
# Clusters (own kubeconfigs; your current kube context is never touched):
#   olympos-lab   server + Postgres/Vault/OpenBao/ClickHouse/Azurite targets
#   olympos-edge  shop workloads (TLS Postgres, old nginx/redis images)
set -euo pipefail
cd "$(dirname "$0")/../.."
WORK=$PWD/test/e2e/.work
LAB_KC=$WORK/kubeconfig
EDGE_KC=$WORK/kubeconfig-edge
ENV_KC=$WORK/kubeconfig-env
mkdir -p "$WORK"
log() { printf '\033[1;33m==> %s\033[0m\n' "$*"; }

if [ "${1:-}" = down ]; then
  kind delete cluster --name olympos-edge --kubeconfig "$EDGE_KC" || true
  kind delete cluster --name olympos-lab --kubeconfig "$LAB_KC" || true
  exit 0
fi

# 1. Lab cluster, images, dependencies and targets (no tests).
SETUP_ONLY=1 ./test/e2e/run.sh

# 2. Second cluster.
if ! kind get clusters | grep -qx olympos-edge; then
  log "creating kind cluster olympos-edge"
  kind create cluster --config test/e2e/kind-edge.yaml --kubeconfig "$EDGE_KC"
fi
KUBECONFIG=$EDGE_KC kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null
kind load docker-image olympos-agent:e2e --name olympos-edge >/dev/null
if [ ! -f "$WORK/payments-pg.crt" ]; then
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=payments-pg.shop.svc" \
    -keyout "$WORK/payments-pg.key" -out "$WORK/payments-pg.csr" 2>/dev/null
  printf 'subjectAltName=DNS:payments-pg.shop.svc,DNS:payments-pg.shop.svc.cluster.local\n' > "$WORK/payments-pg.ext"
  openssl x509 -req -in "$WORK/payments-pg.csr" -CA "$WORK/lab-ca.crt" -CAkey "$WORK/lab-ca.key" -CAcreateserial \
    -days 30 -extfile "$WORK/payments-pg.ext" -out "$WORK/payments-pg.crt" 2>/dev/null
fi
log "deploying edge workloads"
KUBECONFIG=$EDGE_KC kubectl create namespace shop --dry-run=client -o yaml | KUBECONFIG=$EDGE_KC kubectl apply -f - >/dev/null
KUBECONFIG=$EDGE_KC kubectl -n shop create secret tls payments-pg-tls --cert "$WORK/payments-pg.crt" --key "$WORK/payments-pg.key" \
  --dry-run=client -o yaml | KUBECONFIG=$EDGE_KC kubectl apply -f - >/dev/null
KUBECONFIG=$EDGE_KC kubectl apply -f test/e2e/manifests/edge-targets.yaml >/dev/null

# 3. Reset Olympos to an empty installation (no clusters, no history).
export KUBECONFIG=$LAB_KC
log "removing e2e agents"
helm -n olympos-system uninstall olympos-agent >/dev/null 2>&1 || true
helm -n olympos-e2e uninstall olympos-agent-e2e >/dev/null 2>&1 || true
kubectl delete namespace olympos-system olympos-e2e olympos-bench --ignore-not-found --wait=true --timeout=180s >/dev/null
for crb in $(kubectl get clusterrolebinding,clusterrole -o name | grep olympos-agent-); do kubectl delete "$crb" >/dev/null; done
KUBECONFIG=$EDGE_KC helm -n olympos-system uninstall olympos-agent >/dev/null 2>&1 || true

log "resetting the Olympos database, local key vault and lab Vault"
kubectl -n olympos scale deploy/olympos --replicas=0 >/dev/null
kubectl -n olympos wait --for=delete pod -l app.kubernetes.io/name=olympos-server --timeout=120s >/dev/null 2>&1 || true
kubectl -n olympos delete pod olympos-db-0 --wait=true >/dev/null   # no volume: data is gone
kubectl -n olympos delete pvc olympos-localkv --ignore-not-found >/dev/null
kubectl -n olympos rollout status statefulset/olympos-db --timeout=180s >/dev/null
kubectl -n lab rollout restart deploy/vault >/dev/null                # emptyDir: uninitialized again
kubectl -n lab rollout status deploy/vault --timeout=180s >/dev/null
rm -f "$WORK/vault-init.json"
vexec() { kubectl -n lab exec deploy/vault -- "$@"; }
for i in $(seq 1 30); do rc=0; vexec vault status -format=json >/dev/null 2>&1 || rc=$?; [ "$rc" -le 2 ] && break; sleep 2; done
vexec vault operator init -key-shares=1 -key-threshold=1 -format=json > "$WORK/vault-init.json"
UNSEAL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["unseal_keys_b64"][0])' "$WORK/vault-init.json")
ROOT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["root_token"])' "$WORK/vault-init.json")
vexec vault operator unseal "$UNSEAL" >/dev/null
for i in $(seq 1 30); do vexec env VAULT_TOKEN="$ROOT" vault secrets list >/dev/null 2>&1 && break; sleep 2; done
vexec env VAULT_TOKEN="$ROOT" vault secrets enable -path=secret kv-v2 >/dev/null
vexec env VAULT_TOKEN="$ROOT" vault secrets enable -path=legacy -version=1 kv >/dev/null
vexec env VAULT_TOKEN="$ROOT" vault kv put secret/shop/payments db_password=demo-only api_key=demo-only >/dev/null
vexec env VAULT_TOKEN="$ROOT" vault kv put secret/shop/storefront session_secret=demo-only >/dev/null

log "installing olympos-server for the browsable lab"
helm upgrade --install olympos deploy/helm/olympos-server --namespace olympos \
  -f test/e2e/server-values.yaml -f test/e2e/env-values.yaml --wait --timeout 5m >/dev/null
kubectl -n olympos scale deploy/olympos --replicas=1 >/dev/null
kubectl -n olympos rollout restart deploy/olympos >/dev/null
kubectl -n olympos rollout status deploy/olympos --timeout=180s >/dev/null

# 4. Backup destination helper: Azurite container + a container SAS (r c w t).
kubectl -n olympos port-forward svc/azurite 31000:10000 >/dev/null 2>&1 &
PF=$!
sleep 3
SAS=$(go run ./test/e2e/cmd/azurite-sas -url http://127.0.0.1:31000/devstoreaccount1 -container backups)
kill $PF 2>/dev/null || true

# 5. A kubeconfig with both contexts.
KUBECONFIG=$LAB_KC:$EDGE_KC kubectl config view --flatten > "$ENV_KC"

cat > "$WORK/ENV.md" <<EOF
# Olympos lab (local, not in git)

UI: http://127.0.0.1:28080

Sign in (dev mode, no Entra):
- Admin:    http://127.0.0.1:28080/auth/dev-login?oid=00000000-0000-0000-0000-00000000ad01&name=Lab%20Admin
- Maker:    http://127.0.0.1:28080/auth/dev-login?oid=00000000-0000-0000-0000-0000000000a1&name=Mia%20Maker
- Approver: http://127.0.0.1:28080/auth/dev-login?oid=00000000-0000-0000-0000-0000000000a2&name=Ali%20Approver
  (Maker/Approver first get "no access": sign in once, then grant them roles as Admin in Settings > Access,
  searching by name. Use a separate browser profile/private window per person.)

Clusters (kubeconfig with both contexts): $ENV_KC
- kind-olympos-lab   (2 nodes) namespaces lab, olympos
- kind-olympos-edge  (2 nodes) namespaces shop, secure

Add a cluster: Dashboard > Add cluster, copy the command, then run it from the repo root:
  export KUBECONFIG=$ENV_KC
  kubectl config use-context kind-olympos-edge     # or kind-olympos-lab
  <paste the command>

Backups: Settings > Destinations > SAS token, stored:
  account: devstoreaccount1   container: backups
  endpoint override: http://azurite.olympos.svc:10000/devstoreaccount1
  SAS: $SAS
Credentials: orders-pg (lab) backup / CANARY-lab-pg-password; payments-pg (edge) backup / edge-pg-password;
             metrics-ch (lab) backup / CANARY-lab-ch-password

Vault (lab/vault, TLS): root token for Vaults > Configure: $ROOT
  (mounts: secret/ = KV v2 with shop/payments and shop/storefront, legacy/ = KV v1)
EOF
log "ready"
cat "$WORK/ENV.md"
