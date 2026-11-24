# synth-web: the lab's synthetic monitoring target (test/e2e/cmd/synth-web).
# Built from the repository root: docker build -f test/e2e/cmd/synth-web/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY test/e2e/cmd/synth-web ./test/e2e/cmd/synth-web
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/synth-web ./test/e2e/cmd/synth-web

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/synth-web /synth-web
USER 65532:65532
ENTRYPOINT ["/synth-web"]
