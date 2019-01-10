version := "v1.1.0"

commit := $(shell git rev-parse --short HEAD)
version := $(shell go version)
ldflags := '-X "main.goVersion=$(version)"'

build: dist/sso-auth dist/sso-proxy

dist/sso-auth:
	mkdir -p dist
	go generate ./...
	go build -ldflags $(ldflags) -o dist/sso-auth ./cmd/sso-auth

dist/sso-proxy:
	mkdir -p dist
	go generate ./...
	go build -ldflags $(ldflags) -o dist/sso-proxy ./cmd/sso-proxy

test:
	./scripts/test

clean:
	rm -r dist

imagepush:
	docker build -t buzzfeed/sso-dev:$(commit) .
	docker push buzzfeed/sso-dev:$(commit)
