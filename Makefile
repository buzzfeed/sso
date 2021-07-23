version := "v3.0.0"

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
	go get golang.org/x/lint/golint
	go get github.com/rakyll/statik 

test:
	./scripts/test

clean:
	rm -r dist

imagepush-commit:
	docker context create sso-dev
	docker buildx create sso-dev --name sso-dev
	docker buildx use sso-dev
	docker buildx build --tag buzzfeed/sso-dev:$(commit) . --platform linux/amd64,linux/arm64,linux/arm/v7 --push
	docker buildx rm sso-dev

imagepush-latest:
	docker context create sso-dev
	docker buildx create sso-dev --name sso-dev
	docker buildx use sso-dev
	docker buildx build --tag buzzfeed/sso-dev:latest . --platform linux/amd64,linux/arm64,linux/arm/v7 --push
	docker buildx rm sso-dev

releasepush:
	docker context create sso-dev
	docker buildx create sso-dev --name sso-dev
	docker buildx use sso-dev
	docker buildx build --tag buzzfeed/sso:$(version) . --platform linux/amd64,linux/arm64,linux/arm/v7 --push
	docker buildx build --tag buzzfeed/sso:latest . --platform linux/amd64,linux/arm64,linux/arm/v7 --push
	docker buildx rm sso-dev

.PHONY: dist/sso-auth dist/sso-proxy tools
