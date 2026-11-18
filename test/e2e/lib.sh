# Shared helpers for run.sh and env.sh (sourced; expects $WORK and log()).

# init_vault <deployment> <cli>: init + unseal a raft Vault/OpenBao in the lab
# namespace once per pod, enable KV v2 at secret/ and KV v1 at legacy/.
# Keys are written to $WORK/<deployment>-init.json.
init_vault() { # deploy binary
  local d=$1 bin=$2 f="$WORK/$1-init.json" rc i
  vx() { kubectl -n lab exec "deploy/$d" -- "$@"; }
  for i in $(seq 1 30); do rc=0; vx "$bin" status -format=json >/dev/null 2>&1 || rc=$?; [ "$rc" -le 2 ] && break; sleep 2; done
  if { vx "$bin" status -format=json 2>/dev/null || true; } | grep -q '"initialized": false'; then
    log "initializing lab $d"
    vx "$bin" operator init -key-shares=1 -key-threshold=1 -format=json > "$f"
  fi
  if { vx "$bin" status -format=json 2>/dev/null || true; } | grep -q '"sealed": true'; then
    vx "$bin" operator unseal "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["unseal_keys_b64"][0])' "$f")" >/dev/null
  fi
  local root; root=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["root_token"])' "$f")
  for i in $(seq 1 30); do vx env VAULT_TOKEN="$root" BAO_TOKEN="$root" "$bin" secrets list >/dev/null 2>&1 && break; sleep 2; done
  vx env VAULT_TOKEN="$root" BAO_TOKEN="$root" "$bin" secrets enable -path=secret kv-v2 >/dev/null 2>&1 || true
  vx env VAULT_TOKEN="$root" BAO_TOKEN="$root" "$bin" secrets enable -path=legacy -version=1 kv >/dev/null 2>&1 || true
}

# reset_olympos: back to an empty installation — agents removed from both lab
# clusters, Olympos database and local key vault wiped, lab Vault/OpenBao
# uninitialized again (their data is an emptyDir). Expects $WORK and the lab
# kubeconfig in $KUBECONFIG. Safe to run when nothing is installed yet.
reset_olympos() {
  local edge="$WORK/kubeconfig-edge" crb
  log "resetting Olympos (agents, database, local key vault, lab vaults)"
  helm -n olympos-system uninstall olympos-agent >/dev/null 2>&1 || true
  helm -n olympos-e2e uninstall olympos-agent-e2e >/dev/null 2>&1 || true
  kubectl delete namespace olympos-system olympos-e2e olympos-bench --ignore-not-found --wait=true --timeout=180s >/dev/null
  for crb in $(kubectl get clusterrolebinding,clusterrole -o name | grep olympos-agent- || true); do kubectl delete "$crb" >/dev/null; done
  if [ -f "$edge" ]; then
    KUBECONFIG=$edge helm -n olympos-system uninstall olympos-agent >/dev/null 2>&1 || true
    KUBECONFIG=$edge kubectl delete namespace olympos-system olympos-bench --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1 || true
    for crb in $(KUBECONFIG=$edge kubectl get clusterrolebinding,clusterrole -o name 2>/dev/null | grep olympos-agent- || true); do KUBECONFIG=$edge kubectl delete "$crb" >/dev/null; done
  fi
  kubectl -n olympos scale deploy/olympos --replicas=0 >/dev/null 2>&1 || true
  kubectl -n olympos wait --for=delete pod -l app.kubernetes.io/name=olympos-server --timeout=120s >/dev/null 2>&1 || true
  kubectl -n olympos delete pod olympos-db-0 --ignore-not-found --wait=true >/dev/null   # no volume: data is gone
  kubectl -n olympos delete pvc olympos-localkv --ignore-not-found >/dev/null
  kubectl -n olympos rollout status statefulset/olympos-db --timeout=180s >/dev/null
  kubectl -n lab rollout restart deploy/vault deploy/openbao >/dev/null 2>&1 || true
  rm -f "$WORK/vault-init.json" "$WORK/openbao-init.json"
}
