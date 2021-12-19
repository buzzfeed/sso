version := "v3.0.0"

commit := $(shell git rev-parse --short HEAD)
gopath := $(shell go env GOPATH)


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
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(gopath)/bin v1.16.0
	go get github.com/rakyll/statik 

test:
	./scripts/test

clean:
	rm -r dist

imagepush-commit:
	docker build -t buzzfeed/sso-dev:$(commit) .
	docker push buzzfeed/sso-dev:$(commit)

imagepush-latest:
	docker build -t buzzfeed/sso-dev:latest .
	docker push buzzfeed/sso-dev:latest

releasepush:
	docker build -t buzzfeed/sso:$(version) -t buzzfeed/sso-dev:latest .
	docker push buzzfeed/sso:$(version)
	docker push buzzfeed/sso:latest

.PHONY: dist/sso-auth dist/sso-proxy tools
