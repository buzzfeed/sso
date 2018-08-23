version := "v1.0.0"

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
