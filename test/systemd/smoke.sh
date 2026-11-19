#!/usr/bin/env bash
# systemd smoke test (F16): install the .deb on this host (a VM with
# systemd, e.g. a GitHub ubuntu-24.04 runner), run it on the local
# PostgreSQL over the Unix socket, connect a kind agent and back a
# PostgreSQL target up to an OS-managed NFS-style directory. Run as root:
#   sudo test/systemd/smoke.sh dist/olympos-server_<v>_amd64.deb
# The package must be a dev build (GO_TAGS=dev): CI has no Azure Key Vault.
set -euo pipefail
deb=${1:?usage: smoke.sh <olympos-server.deb>}
cd "$(dirname "$0")/../.."
log() { printf '\033[1;33m==> %s\033[0m\n' "$*"; }
ADMIN=00000000-0000-0000-0000-00000000ad01
URL=http://127.0.0.1:8080
JAR=$(mktemp)

log "local PostgreSQL 16"
apt-get update -qq && apt-get install -y -qq postgresql-16 postgresql-client-16 jq >/dev/null
# GitHub runners ship PostgreSQL preinstalled with the service disabled, so
# the install above neither creates nor starts a cluster there.
pg_lsclusters -h | grep -q '^16 main ' || pg_createcluster 16 main >/dev/null
systemctl enable --now postgresql >/dev/null
pg_ctlcluster 16 main start 2>/dev/null || true
for i in $(seq 30); do pg_isready -q -h /var/run/postgresql && break; sleep 1; done
pg_isready -h /var/run/postgresql

log "install $deb"
apt-get install -y -qq "./$deb" >/dev/null
id olympos
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'olympos'" | grep -q 1 || sudo -u postgres createuser olympos
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'olympos'" | grep -q 1 || sudo -u postgres createdb -O olympos olympos

log "kind cluster with a PostgreSQL target"
kind create cluster --name smoke --wait 2m >/dev/null
gw=$(docker network inspect kind -f '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)
kubectl create namespace shop >/dev/null
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: orders-pg, namespace: shop}
spec:
  selector: {matchLabels: {app: orders-pg}}
  template:
    metadata: {labels: {app: orders-pg}}
    spec:
      containers:
      - name: pg
        image: postgres:16-alpine
        env: [{name: POSTGRES_PASSWORD, value: smoke-pw}]
        ports: [{containerPort: 5432}]
---
apiVersion: v1
kind: Service
metadata:
  name: orders-pg
  namespace: shop
  annotations: {olympos.io/backup: postgresql}
spec:
  selector: {app: orders-pg}
  ports: [{name: postgres, port: 5432}]
YAML
docker build -q -f deploy/docker/agent.Dockerfile -t olympos-agent:smoke . >/dev/null
kind load docker-image olympos-agent:smoke --name smoke >/dev/null

log "configure and start the service (gateway reachable from kind at $gw:8443)"
cat > /etc/olympos/config.yaml <<YAML
olympos:
  devMode: true
  publicURL: $URL
  agentGatewayURL: $gw:8443
  bootstrapAdmins: ["$ADMIN"]
  listen: {http: ":8080", gateway: ":8443", metrics: "127.0.0.1:9090"}
  keyVault: {provider: local, name: smoke, localDir: /var/lib/olympos/localkv}
  database: {dsn: "postgres:///olympos?host=/var/run/postgresql"}
  backup: {pgDumpDir: "/usr/lib/postgresql", nfsRoot: /var/lib/olympos/nfs}
  audit: {kubescapeBin: /usr/lib/olympos/bin/kubescape, polarisBin: /usr/lib/olympos/bin/polaris}
  security: {trivyBin: /usr/lib/olympos/bin/trivy, trivyCacheDir: /var/lib/olympos/trivy-cache}
YAML
install -d -o olympos -g olympos -m 0750 /var/lib/olympos/nfs/smoke
sudo -u olympos olympos-server check-config -db
systemctl enable --now olympos-server
for i in $(seq 60); do curl -fsS http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:9090/readyz
systemd-analyze security olympos-server --threshold=30 | tail -1
olympos-server version

api() { # method path [json]
  local csrf; csrf=$(awk '$6=="olympos_csrf"{print $7}' "$JAR")
  curl -fsS -b "$JAR" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -X "$1" "$URL/api/v1$2" ${3:+-d "$3"}
}
curl -fsS -c "$JAR" -o /dev/null "$URL/auth/dev-login?oid=$ADMIN&name=Smoke"

log "enroll the kind agent"
resp=$(api POST /clusters '{"name":"smoke","labels":{"env":"smoke"}}')
cid=$(jq -r .cluster.id <<<"$resp")
cmd=$(jq -r .command <<<"$resp")
sets=$(grep -oE -- '--set [a-zA-Z.]+=[^ ]+' <<<"$cmd" | sed 's/--set //' | grep -E '^(server|bootstrapToken|serverCA|clusterName)=')
args=()
for s in $sets; do args+=(--set "$s"); done
helm upgrade --install olympos-agent deploy/helm/olympos-agent -n olympos-system --create-namespace \
  --set image.repository=olympos-agent --set image.tag=smoke --set image.pullPolicy=Never "${args[@]}" --wait --timeout 3m >/dev/null
for i in $(seq 90); do [ "$(api GET /clusters/"$cid" | jq -r .status)" = online ] && break; sleep 2; done
[ "$(api GET /clusters/"$cid" | jq -r .status)" = online ] || { echo "agent did not come online" >&2; exit 1; }
kubectl -n shop rollout status deploy/orders-pg --timeout=120s >/dev/null
tid=""
for i in $(seq 60); do
  tid=$(api GET /targets | jq -r --arg c "$cid" '.items[] | select(.cluster_id==$c and .service=="orders-pg" and .status!="gone") | .id' | head -1)
  [ -n "$tid" ] && break; sleep 2
done
[ -n "$tid" ] || { echo "orders-pg not discovered" >&2; exit 1; }

log "back orders-pg up to /var/lib/olympos/nfs/smoke"
did=$(api POST /destinations '{"name":"smoke-nfs","kind":"nfs","auth":"none","path":"/var/lib/olympos/nfs/smoke/olympos"}' | jq -r .id)
jid=$(api POST /backup/jobs "$(jq -n --arg t "$tid" --arg d "$did" '{target_id:$t, destination_id:$d, cron:"0 2 * * *", timezone:"UTC", enabled:false,
  credential:{source:"stored", username:"postgres", password:"smoke-pw"}}')" | jq -r .id)
api POST /backup/jobs/"$jid"/run '{"trigger":"manual"}' >/dev/null
st=""
for i in $(seq 90); do
  st=$(api GET "/backup/runs?job_id=$jid" | jq -r '.items[0].status // ""')
  case $st in succeeded|failed|missed) break ;; esac
  sleep 2
done
api GET "/backup/runs?job_id=$jid" | jq '.items[0] | {status, error, bytes, blob_path}'
[ "$st" = succeeded ] || exit 1
find /var/lib/olympos/nfs/smoke -name '*.zip' | grep -q . || { echo "no backup file on disk" >&2; exit 1; }
log "systemd smoke passed"
