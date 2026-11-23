# olympos-probe: static binary on distroless, non-root, no shell. The image's
# CA bundle (distroless static ships ca-certificates) is the trust store for
# HTTPS and TLS steps.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/Warewave-Technology/olympos/internal/probe.Version=${VERSION}" \
    -o /out/olympos-probe ./cmd/olympos-probe

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/olympos-probe /olympos-probe
USER 65532:65532
ENTRYPOINT ["/olympos-probe"]
