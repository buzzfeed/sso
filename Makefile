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
	go install golang.org/x/lint/golint@latest
	go install github.com/rakyll/statik@latest

test:
	./scripts/test

clean:
	rm -r dist

imagepush-commit:
	docker buildx create --name imagepush-commit
	docker buildx use imagepush-commit
	docker buildx build -t buzzfeed/sso-dev:$(commit) . --platform linux/amd64,linux/arm64 --push
	docker buildx rm imagepush-commit

imagepush-latest:
	docker buildx create --name imagepush-latest
	docker buildx use imagepush-latest
	docker buildx build -t buzzfeed/sso-dev:latest . --platform linux/amd64,linux/arm64 --push
	docker buildx rm imagepush-latest

releasepush:
	docker buildx create --name releasepush
	docker buildx use releasepush
	docker buildx build -t buzzfeed/sso:$(version) . --platform linux/amd64,linux/arm64 --push
	docker buildx build -t buzzfeed/sso:latest . --platform linux/amd64,linux/arm64 --push
	docker buildx rm releasepush

.PHONY: dist/sso-auth dist/sso-proxy tools
