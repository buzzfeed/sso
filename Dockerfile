FROM golang:1.9.2

RUN apt-get update && apt-get install -y curl bash git jq gettext

# install gpm dependencies
COPY gpm /tmp/gpm
COPY Godeps /tmp/Godeps
RUN cd /tmp && ./gpm

COPY / /go/src/github.com/buzzfeed/sso/

RUN cd /go/src/github.com/buzzfeed/sso/cmd/sso-auth; go build -o /bin/sso-auth
RUN cd /go/src/github.com/buzzfeed/sso/cmd/sso-proxy; go build -o /bin/sso-proxy
