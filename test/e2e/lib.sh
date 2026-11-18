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
