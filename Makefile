version := "v3.1.2"

commit := $(shell git rev-parse --short HEAD)


build: dist/sso-auth dist/sso-proxy

dist/sso-auth:
	mkdir -p dist
	go generate ./...
	go build -mod=readonly -o dist/sso-auth ./cmd/sso-auth

dist/sso-proxy:
	mkdir -p dist
	go generate ./...
	go build -mod=readonly -o dist/sso-proxy ./cmd/sso-proxy

tools:
	go install golang.org/x/lint/golint@latest
	go install github.com/rakyll/statik@latest

test:
	./scripts/test

clean:
	rm -r dist

imagebuild-commit:
	docker build -t buzzfeed-sso-dev:$(commit) . --platform linux/amd64

releasepush: imagebuild-commit
	docker tag buzzfeed-sso-dev:$(commit) gcr.io/weave-lab/ops/buzzfeed-sso:$(version)
	docker push gcr.io/weave-lab/ops/buzzfeed-sso:$(version)

.PHONY: dist/sso-auth dist/sso-proxy tools
