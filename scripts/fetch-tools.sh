#!/usr/bin/env bash
# Downloads trivy, kubescape and polaris (versions from deploy/tools.env) for
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
cd - >/dev/null
install -m 0755 "$tmp/trivy" "$tmp/kubescape" "$tmp/polaris" "$out/"
echo "tools for linux/$arch in $out"
