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
# Both run synth-web, the synthetic monitoring target that CoreDNS answers
# every *.olympos-lab.test name with (docs/synthetic-monitoring.md).
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
kind load docker-image olympos-agent:e2e olympos-probe:e2e olympos-synth-web:e2e --name olympos-edge >/dev/null
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
KUBECONFIG=$EDGE_KC kubectl apply -f test/e2e/manifests/synthetic.yaml >/dev/null
(export KUBECONFIG=$EDGE_KC; source test/e2e/lib.sh; patch_coredns)
KUBECONFIG=$EDGE_KC kubectl -n lab rollout status deploy/synth-web --timeout=120s >/dev/null

# 3. Reset Olympos to an empty installation (no clusters, no history).
export KUBECONFIG=$LAB_KC
source test/e2e/lib.sh
reset_olympos
kubectl -n lab rollout status deploy/vault --timeout=180s >/dev/null
kubectl -n lab rollout status deploy/openbao --timeout=180s >/dev/null
for d in restore-pg restore-ch restore-vault; do kubectl -n lab rollout status "deploy/$d" --timeout=240s >/dev/null; done
init_vault vault vault
init_vault openbao bao
init_vault restore-vault vault
RESTORE_ROOT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["root_token"])' "$WORK/restore-vault-init.json")
ROOT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["root_token"])' "$WORK/vault-init.json")
BAO_ROOT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["root_token"])' "$WORK/openbao-init.json")
for t in vault:vault:$ROOT openbao:bao:$BAO_ROOT; do
  IFS=: read -r d b tok <<<"$t"
  kubectl -n lab exec "deploy/$d" -- env VAULT_TOKEN="$tok" BAO_TOKEN="$tok" "$b" kv put secret/shop/payments db_password=demo-only api_key=demo-only >/dev/null
  kubectl -n lab exec "deploy/$d" -- env VAULT_TOKEN="$tok" BAO_TOKEN="$tok" "$b" kv put secret/shop/storefront session_secret=demo-only >/dev/null
done

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

Backup destinations (Settings > Destinations > New destination):
- Azure Blob (Azurite): account devstoreaccount1, container backups, auth SAS token (stored),
    endpoint override http://azurite.olympos.svc:10000/devstoreaccount1
    SAS: $SAS
- S3 (MinIO, writer user WITHOUT delete): endpoint override http://minio.olympos.svc:9000, region us-east-1,
    bucket backups, path-style ON, access key id olympos-backup, secret key lab-backup-secret-key (stored)
    (MinIO root lab-root / lab-root-password can delete: use it to see the "can delete" warning)
- NFS: mount "lab" (a PVC standing in for an NFS export), path /var/lib/olympos/nfs/lab/olympos
Credentials: orders-pg (lab) backup / CANARY-lab-pg-password; payments-pg (edge) backup / edge-pg-password;
             metrics-ch (lab) backup / CANARY-lab-ch-password

Vaults (TLS, raft) — root tokens for Vaults > Configure (used once, not stored by Olympos):
  lab/vault   (HashiCorp): $ROOT
  lab/openbao (OpenBao):   $BAO_ROOT
  (mounts: secret/ = KV v2 with shop/payments and shop/storefront, legacy/ = KV v1)

Restore targets (new, empty servers in lab; Backups > a run > Restore…, docs/restore.md):
- restore-pg    PostgreSQL 16, TLS (lab CA): postgres / CANARY-lab-restore-pg-password (superuser)
- restore-ch    ClickHouse, no TLS (set the lab cluster's transfer mode to compressed): restore / CANARY-lab-restore-ch-password
- restore-vault Vault, raft, TLS, initialized and unsealed, NOT configured in Olympos; token for the restore:
  lab/restore-vault (HashiCorp, new Vault): $RESTORE_ROOT
  After a restore it holds lab/vault's data: unseal it with lab/vault's key ($WORK/vault-init.json):
    kubectl -n lab exec deploy/restore-vault -- vault operator unseal <unseal_keys_b64[0]>
  ./test/e2e/env.sh empties all three again (and resets Olympos).

Synthetic monitoring (Monitoring > Synthetic; docs/synthetic-monitoring.md):
- Settings > Synthetic monitoring: add the allowlist rule olympos-lab.test (suffix).
- In both clusters every *.olympos-lab.test name reaches synth-web (lab namespace, plain HTTP, port 80):
    /health, /api/items (any Authorization: Bearer token; echoes it and sets a cookie),
    /redirect?to=<url>; only the probes may call it (NetworkPolicy).
- Make one cluster fail, slow down or recover (in-memory, reset by env.sh):
    kubectl --context kind-olympos-edge -n lab exec deploy/synth-web -- /synth-web toggle 500   # or slow, ok
- metadata.olympos-lab.test resolves to 169.254.169.254: allowlisted by the rule above, still refused (ip_denied).
EOF
log "ready"
cat "$WORK/ENV.md"
