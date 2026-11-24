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

# reset_olympos: back to an empty installation — agents (and probes) removed
# from both lab clusters, synth-web back to ok, Olympos database and local key vault wiped, lab Vault/OpenBao
# uninitialized again and the restore targets (restore-pg, restore-ch,
# restore-vault) empty again (their data is an emptyDir). Expects $WORK and the lab
# kubeconfig in $KUBECONFIG. Safe to run when nothing is installed yet.
# reset_olympos_db stops the server and drops its database and local key
# vault: the bundled PostgreSQL and both volumes go, helm upgrade recreates
# them (the password Secret is kept). Also drops the pre-F17 external lab DB.
reset_olympos_db() {
  kubectl -n olympos scale deploy/olympos --replicas=0 >/dev/null 2>&1 || true
  kubectl -n olympos wait --for=delete pod -l app.kubernetes.io/name=olympos-server --timeout=120s >/dev/null 2>&1 || true
  kubectl -n olympos delete statefulset olympos-postgresql olympos-db --ignore-not-found --wait=true >/dev/null
  kubectl -n olympos delete service olympos-db --ignore-not-found >/dev/null
  kubectl -n olympos wait --for=delete pod/olympos-postgresql-0 --timeout=120s >/dev/null 2>&1 || true
  kubectl -n olympos delete pvc data-olympos-postgresql-0 olympos-localkv --ignore-not-found --wait=true >/dev/null
}

reset_olympos() {
  local edge="$WORK/kubeconfig-edge" crb
  log "resetting Olympos (agents, database, local key vault, lab vaults)"
  helm -n olympos-system uninstall olympos-agent >/dev/null 2>&1 || true
  helm -n olympos-e2e uninstall olympos-agent-e2e >/dev/null 2>&1 || true
  helm -n olympos-b uninstall olympos-agent-b >/dev/null 2>&1 || true
  kubectl delete namespace olympos-system olympos-e2e olympos-b olympos-bench --ignore-not-found --wait=true --timeout=180s >/dev/null
  for crb in $(kubectl get clusterrolebinding,clusterrole -o name | grep olympos-agent- || true); do kubectl delete "$crb" >/dev/null; done
  if [ -f "$edge" ]; then
    KUBECONFIG=$edge helm -n olympos-system uninstall olympos-agent >/dev/null 2>&1 || true
    KUBECONFIG=$edge kubectl delete namespace olympos-system olympos-bench --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1 || true
    for crb in $(KUBECONFIG=$edge kubectl get clusterrolebinding,clusterrole -o name 2>/dev/null | grep olympos-agent- || true); do KUBECONFIG=$edge kubectl delete "$crb" >/dev/null; done
  fi
  reset_olympos_db
  kubectl -n lab rollout restart deploy/vault deploy/openbao >/dev/null 2>&1 || true
  kubectl -n lab rollout restart deploy/restore-pg deploy/restore-ch deploy/restore-vault >/dev/null 2>&1 || true
  # synth-web keeps its toggle (ok / 500 / slow) in memory: back to ok.
  kubectl -n lab rollout restart deploy/synth-web >/dev/null 2>&1 || true
  [ ! -f "$edge" ] || KUBECONFIG=$edge kubectl -n lab rollout restart deploy/synth-web >/dev/null 2>&1 || true
  rm -f "$WORK/vault-init.json" "$WORK/openbao-init.json" "$WORK/restore-vault-init.json"
}

# patch_coredns: in the cluster of $KUBECONFIG, CoreDNS answers every
# *.olympos-lab.test name with the lab's synth-web Service and
# metadata.olympos-lab.test with 169.254.169.254 (synthetic monitoring:
# docs/synthetic-monitoring.md, TestM9). The rewrite would catch the
# metadata name too, so that name gets a server block of its own (CoreDNS
# picks the most specific zone). Both edits sit between marker lines: a
# second run replaces them instead of adding more, an older version is
# replaced by this one, and removing the marked lines gives back the
# Corefile as kind wrote it. CoreDNS restarts only when the Corefile changed.
patch_coredns() {
  local cur new
  cur=$(kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')
  new=$(python3 - "$cur" <<'PY'
import sys
begin, end = "# olympos-lab synthetic begin (test/e2e/lib.sh)", "# olympos-lab synthetic end"
lines, kept, skip = sys.argv[1].split("\n"), [], False
for l in lines:  # drop an earlier version
    if l.strip() == begin:
        skip = True
    elif l.strip() == end and skip:
        skip = False
    elif not skip:
        kept.append(l)
out, done = [], False
for l in kept:
    out.append(l)
    if not done and l.strip() == ".:53 {":
        out += ["    " + begin,
                r"    rewrite name regex (.*)\.olympos-lab\.test synth-web.lab.svc.cluster.local answer auto",
                "    " + end]
        done = True
if not done:
    sys.exit("no .:53 server block in the Corefile")
while out and out[-1] == "":
    out.pop()
out += [begin, "metadata.olympos-lab.test:53 {", "    hosts {", "        169.254.169.254 metadata.olympos-lab.test", "    }", "}", end]
print("\n".join(out))
PY
)
  if [ "$cur" = "$new" ]; then return 0; fi
  log "patching CoreDNS for *.olympos-lab.test"
  kubectl -n kube-system patch configmap coredns --type merge \
    -p "$(python3 -c 'import json,sys; print(json.dumps({"data": {"Corefile": sys.argv[1] + "\n"}}))' "$new")" >/dev/null
  kubectl -n kube-system rollout restart deploy/coredns >/dev/null
  kubectl -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null
}
