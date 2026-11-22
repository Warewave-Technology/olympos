#!/usr/bin/env bash
# The kube-bench image the agent runs is pinned by digest in
# internal/agent/bench.go (KubeBenchRepository, KubeBenchTag, KubeBenchDigest).
# Upstream images are not signed, so the release copies that exact index to
# ghcr.io/warewave-technology/kube-bench and signs it (release.yml).
#
#   scripts/kube-bench-pin.sh print          # repository, tag and digest of the pin
#   scripts/kube-bench-pin.sh check          # the upstream tag still points at the pinned digest
#   scripts/kube-bench-pin.sh mirror <repo>  # copy the pinned index to <repo>:<tag>, digest unchanged
#
# check and mirror need docker buildx and jq; mirror needs cosign and a login
# to the target registry.
set -euo pipefail
cd "$(dirname "$0")/.."
src=internal/agent/bench.go
pin() { sed -n "s/^[[:space:]]*$1[[:space:]]*= \"\(.*\)\"$/\1/p" "$src"; }
repo=$(pin KubeBenchRepository)
tag=$(pin KubeBenchTag)
digest=$(pin KubeBenchDigest)
[ -n "$repo" ] && [ -n "$tag" ] && [[ $digest == sha256:* ]] || { echo "cannot read the kube-bench pin from $src" >&2; exit 1; }
index() { docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r .digest; }

case "${1:-}" in
  print)
    echo "$repo:$tag@$digest"
    ;;
  check)
    got=$(index "$repo:$tag")
    if [ "$got" != "$digest" ]; then
      echo "$repo:$tag is now $got, the agent pins $digest: the tag was moved upstream." >&2
      echo "Check the release before changing the pin in $src." >&2
      exit 1
    fi
    echo "kube-bench pin ok: $repo:$tag@$digest"
    ;;
  mirror)
    dst=${2:?usage: kube-bench-pin.sh mirror <repository>}
    cosign copy --force "$repo@$digest" "$dst:$tag"
    got=$(index "$dst:$tag")
    [ "$got" = "$digest" ] || { echo "$dst:$tag has digest $got, want $digest" >&2; exit 1; }
    echo "mirrored $repo@$digest to $dst:$tag"
    ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
