#!/usr/bin/env bash
# Downloads trivy, kubescape, polaris and clickhouse (versions from deploy/tools.env) for
# linux/<arch> into dist/tools/linux_<arch>/, verified against the upstream
# checksum files. Used to build the .deb/.rpm/tarball (F16).
set -euo pipefail
arch=${1:?usage: fetch-tools.sh amd64|arm64}
cd "$(dirname "$0")/.."
. deploy/tools.env
out=dist/tools/linux_$arch
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
t=$([ "$arch" = arm64 ] && echo ARM64 || echo 64bit)
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz"
curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
grep " trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -
tar -xzf "trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz" trivy
curl -fsSLO "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_${arch}"
curl -fsSLO "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/checksums.sha256"
grep " kubescape_${KUBESCAPE_VERSION}_linux_${arch}$" checksums.sha256 | sha256sum -c -
mv "kubescape_${KUBESCAPE_VERSION}_linux_${arch}" kubescape
curl -fsSLO "https://github.com/FairwindsOps/polaris/releases/download/v${POLARIS_VERSION}/polaris_${POLARIS_VERSION}_linux_${arch}.tar.gz"
curl -fsSLO "https://github.com/FairwindsOps/polaris/releases/download/v${POLARIS_VERSION}/checksums.txt"
grep " polaris_${POLARIS_VERSION}_linux_${arch}.tar.gz$" checksums.txt | sha256sum -c -
tar -xzf "polaris_${POLARIS_VERSION}_linux_${arch}.tar.gz" polaris
ch="clickhouse-common-static-${CLICKHOUSE_VERSION}-${arch}.tgz"
curl -fsSLO "https://github.com/ClickHouse/ClickHouse/releases/download/v${CLICKHOUSE_VERSION}-lts/$ch"
curl -fsSLO "https://github.com/ClickHouse/ClickHouse/releases/download/v${CLICKHOUSE_VERSION}-lts/$ch.sha512"
sha512sum -c "$ch.sha512"
tar -xzf "$ch" --strip-components=3 "clickhouse-common-static-${CLICKHOUSE_VERSION}/usr/bin/clickhouse"
rm -f "$ch"
cd - >/dev/null
install -m 0755 "$tmp/trivy" "$tmp/kubescape" "$tmp/polaris" "$tmp/clickhouse" "$out/"
# kubescape artifacts (JSON, arch-independent; F14): downloaded with a
# kubescape for the build host.
art=dist/tools/kubescape-artifacts
if [ ! -s "$art/controls-inputs.json" ]; then
  host=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  ks="$out/kubescape"
  if [ "$host" != "$arch" ] || [ "$os" != linux ]; then
    ks="$tmp/kubescape-host"
    curl -fsSL -o "$ks" "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_${os}_${host}"
    grep " kubescape_${KUBESCAPE_VERSION}_${os}_${host}$" "$tmp/checksums.sha256" | awk '{print $1}' | sed "s#\$#  $ks#" | sha256sum -c -
    chmod +x "$ks"
  fi
  "$ks" download artifacts --output "$art" >/dev/null
fi
chmod -R u=rwX,go=rX "$art"
echo "tools for linux/$arch in $out, kubescape artifacts in $art"
