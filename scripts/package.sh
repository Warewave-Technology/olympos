#!/usr/bin/env bash
# Builds the release artifacts of olympos-server for linux/<arch> (F16):
# static binary, tarball, .deb and .rpm in dist/. Signing and SBOMs are done
# by the release workflow (cosign, syft).
#   scripts/package.sh 0.1.0 amd64
set -euo pipefail
version=${1:?version}; arch=${2:?arch}
cd "$(dirname "$0")/.."
mkdir -p "dist/linux_$arch"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
  -ldflags "-s -w -X github.com/Warewave-Technology/olympos/internal/version.Version=v$version" \
  -o "dist/linux_$arch/olympos-server" ./cmd/olympos-server
[ -x "dist/tools/linux_$arch/trivy" ] || scripts/fetch-tools.sh "$arch"
NFPM=${NFPM:-nfpm}
for p in deb rpm; do
  VERSION=$version ARCH=$arch $NFPM pkg -f deploy/systemd/nfpm.yaml -p "$p" -t dist/
done
name=olympos-server_${version}_linux_${arch}
stage=$(mktemp -d)
mkdir -p "$stage/$name/tools" "$stage/$name/systemd"
cp "dist/linux_$arch/olympos-server" "$stage/$name/"
cp "dist/tools/linux_$arch/"* "$stage/$name/tools/"
cp deploy/systemd/olympos-server.service deploy/systemd/config.yaml deploy/systemd/sysusers.conf deploy/systemd/tmpfiles.conf "$stage/$name/systemd/"
cp LICENSE docs/install-systemd.md docs/restore-olympos.md "$stage/$name/"
tar -C "$stage" -czf "dist/$name.tar.gz" "$name"
rm -rf "$stage"
ls -l dist/*"$version"* 2>/dev/null || ls -l dist
