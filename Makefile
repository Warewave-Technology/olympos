GO ?= go
PROTO := proto/olympos/v1/gateway.proto

.PHONY: proto build test lint web images e2e

proto:
	protoc -I proto --go_out=internal/gen --go_opt=paths=source_relative \
	  --go-grpc_out=internal/gen --go-grpc_opt=paths=source_relative $(PROTO)

build:
	$(GO) build ./...

test:
	$(GO) test ./...

web:
	cd web && pnpm install --frozen-lockfile && pnpm build

images:
	docker build -f deploy/docker/server.Dockerfile -t olympos-server:dev .
	docker build -f deploy/docker/agent.Dockerfile -t olympos-agent:dev .

e2e:
	./test/e2e/run.sh

dev-db:
	docker run -d --name olympos-dev-pg -e POSTGRES_USER=olympos -e POSTGRES_PASSWORD=olympos \
	  -p 127.0.0.1:55432:5432 postgres:16-alpine
