# olympos-agent: static binary on distroless, non-root, no shell.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/Warewave-Technology/olympos/internal/agent.Version=${VERSION}" \
    -o /out/olympos-agent ./cmd/olympos-agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/olympos-agent /olympos-agent
USER 65532:65532
ENTRYPOINT ["/olympos-agent"]
