version := "v1.0.0"

commit := $(shell git rev-parse --short HEAD)

build: dist/sso-auth dist/sso-proxy

dist/sso-auth: 
	mkdir -p dist
	go build -o dist/sso-auth ./cmd/sso-auth

dist/sso-proxy: 
	mkdir -p dist
	go build -o dist/sso-proxy ./cmd/sso-proxy

test: 
	./scripts/test

clean:
	rm -r dist

imagepush: 
	docker build -t buzzfeed/sso-dev:$(commit) .
	docker login -u $(DOCKER_USER) -p $(DOCKER_PASS)
	docker push buzzfeed/sso-dev:$(commit)
