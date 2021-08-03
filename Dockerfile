# =============================================================================
# build stage
#
# install golang dependencies & build binaries
# =============================================================================
FROM golang:1.14 AS build

ENV GOFLAGS='-ldflags=-s -ldflags=-w'
ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /go/src/github.com/buzzfeed/sso

COPY ./go.mod ./go.sum ./
RUN go mod download
COPY . .
RUN cd cmd/sso-auth && go build -mod=readonly -o /bin/sso-auth
RUN cd cmd/sso-proxy && go build -mod=readonly -o /bin/sso-proxy
RUN cd cmd/sso-proxy/generate-request-signature && go build -mod=readonly -o /bin/sso-generate-request-signature

# =============================================================================
# final stage
#
# add static assets and copy binaries from build stage
# =============================================================================
FROM debian:stable-slim
RUN ln -s /usr/bin/dpkg-split /usr/sbin/dpkg-split
RUN ln -s /usr/bin/dpkg-deb /usr/sbin/dpkg-deb
RUN ln -s /bin/tar /usr/sbin/tar
RUN ln -s /bin/rm /usr/sbin/rm
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && groupadd -r sso && useradd -r -g sso sso
WORKDIR /sso
COPY --from=build /bin/sso-* /bin/
USER sso
