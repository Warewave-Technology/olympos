# olympos-server: Go binary + pinned external tools on distroless (glibc).
# pg_dump/pg_dumpall 13–17 come from PGDG; their shared libraries are copied
# next to them. trivy, kubescape and polaris are static release binaries
# verified against the upstream checksum files. clickhouse is the official
# static binary (restore client).

ARG PG_VERSIONS="13 14 15 16 17"

FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS web
WORKDIR /web
RUN corepack enable
COPY web/ ./
RUN if [ -f package.json ]; then pnpm install --frozen-lockfile && pnpm build; else mkdir -p dist; fi

FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
# GO_TAGS=dev only for lab/e2e images: release images have no dev login and
# no local key vault (F6).
ARG GO_TAGS=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -tags "$GO_TAGS" -ldflags "-s -w -X github.com/Warewave-Technology/olympos/internal/version.Version=${VERSION}" \
    -o /out/olympos-server ./cmd/olympos-server && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" \
    -o /out/olympos-sh ./cmd/olympos-sh

FROM debian:bookworm-slim AS tools
ARG PG_VERSIONS TARGETARCH
ARG TRIVY_VERSION=0.76.2
ARG KUBESCAPE_VERSION=4.0.21
ARG POLARIS_VERSION=10.2.6
ARG CLICKHOUSE_VERSION=26.3.69.4
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg && \
    install -d /usr/share/postgresql-common/pgdg && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc && \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    for v in $PG_VERSIONS; do apt-get install -y --no-install-recommends postgresql-client-$v; done
# Collect pg_dump binaries and their shared libraries into /out.
RUN set -eu; mkdir -p /out/usr/lib/postgresql /out/lib; \
    for v in $PG_VERSIONS; do mkdir -p /out/usr/lib/postgresql/$v/bin; \
      cp /usr/lib/postgresql/$v/bin/pg_dump /usr/lib/postgresql/$v/bin/pg_dumpall /usr/lib/postgresql/$v/bin/pg_restore /out/usr/lib/postgresql/$v/bin/; \
      for b in pg_dump pg_dumpall pg_restore; do \
        ldd /usr/lib/postgresql/$v/bin/$b | awk '/=>/ {print $3}' | xargs -r -I{} cp -n {} /out/lib/; done; \
    done
RUN set -eu; arch=$([ "$TARGETARCH" = arm64 ] && echo ARM64 || echo 64bit); mkdir -p /out/usr/local/bin; cd /tmp; \
    curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz; \
    curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt; \
    grep " trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz$" trivy_${TRIVY_VERSION}_checksums.txt | sha256sum -c -; \
    tar -xzf trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz trivy && mv trivy /out/usr/local/bin/
RUN set -eu; cd /tmp; a=$([ "$TARGETARCH" = arm64 ] && echo arm64 || echo amd64); \
    curl -fsSLO https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_${a}; \
    curl -fsSLO https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/checksums.sha256; \
    grep " kubescape_${KUBESCAPE_VERSION}_linux_${a}$" checksums.sha256 | sha256sum -c -; \
    install -m 0755 kubescape_${KUBESCAPE_VERSION}_linux_${a} /out/usr/local/bin/kubescape
# Frameworks, controls, exceptions and control inputs at build time: scans
# need no egress to the ARMO API (F14, restricted networks).
# kubescape creates the tree 0700; COPY would carry that onto /usr/share and
# hide zoneinfo from the nonroot user.
RUN /out/usr/local/bin/kubescape download artifacts --output /out/usr/share/olympos/kubescape-artifacts && \
    test -s /out/usr/share/olympos/kubescape-artifacts/controls-inputs.json && \
    chmod -R u=rwX,go=rX /out/usr/share
RUN set -eu; cd /tmp; a=$([ "$TARGETARCH" = arm64 ] && echo arm64 || echo amd64); \
    curl -fsSLO https://github.com/FairwindsOps/polaris/releases/download/v${POLARIS_VERSION}/polaris_${POLARIS_VERSION}_linux_${a}.tar.gz; \
    curl -fsSLO https://github.com/FairwindsOps/polaris/releases/download/v${POLARIS_VERSION}/checksums.txt; \
    grep " polaris_${POLARIS_VERSION}_linux_${a}.tar.gz$" checksums.txt | sha256sum -c -; \
    tar -xzf polaris_${POLARIS_VERSION}_linux_${a}.tar.gz polaris && install -m 0755 polaris /out/usr/local/bin/polaris
# The official static ClickHouse binary (LTS): `clickhouse client` restores ClickHouse backups.
# clickhouse-client is the same binary under its other name.
RUN set -eu; cd /tmp; a=$([ "$TARGETARCH" = arm64 ] && echo arm64 || echo amd64); \
    f=clickhouse-common-static-${CLICKHOUSE_VERSION}-${a}.tgz; \
    curl -fsSLO https://github.com/ClickHouse/ClickHouse/releases/download/v${CLICKHOUSE_VERSION}-lts/$f; \
    curl -fsSLO https://github.com/ClickHouse/ClickHouse/releases/download/v${CLICKHOUSE_VERSION}-lts/$f.sha512; \
    sha512sum -c $f.sha512; \
    tar -xzf $f --strip-components=3 -C /out/usr/local/bin clickhouse-common-static-${CLICKHOUSE_VERSION}/usr/bin/clickhouse; \
    chmod 0755 /out/usr/local/bin/clickhouse; ln -s clickhouse /out/usr/local/bin/clickhouse-client; rm -f $f $f.sha512
# Every directory COPY lays over the base must stay readable for 65532.
RUN bad=$(find /out -type d ! -perm -0555); test -z "$bad" || { echo "not world-readable: $bad"; exit 1; }

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=tools /out/ /
COPY --from=build /out/olympos-server /olympos-server
# Not a shell: an exec-only shim so pg_dumpall can find pg_dump (popen).
COPY --from=build /out/olympos-sh /bin/sh
ENV LD_LIBRARY_PATH=/lib PATH=/usr/local/bin:/usr/bin:/bin
USER 65532:65532
EXPOSE 8080 8443 9090
ENTRYPOINT ["/olympos-server"]
