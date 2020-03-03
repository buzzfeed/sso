# =============================================================================
# build stage
#
# install golang dependencies & build binaries
# =============================================================================
FROM golang:1.12 AS build

ENV GOFLAGS='-ldflags=-s -ldflags=-w'
ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /go/src/github.com/buzzfeed/sso

COPY ./go.mod ./go.sum ./
RUN go mod download
COPY . .
RUN cd cmd/sso-auth && go build -mod=readonly -o /bin/sso-auth
RUN cd cmd/sso-proxy && go build -mod=readonly -o /bin/sso-proxy

# =============================================================================
# final stage
#
# add static assets and copy binaries from build stage
# =============================================================================
FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && groupadd -r sso && useradd -r -g sso sso
WORKDIR /sso
COPY --from=build /bin/sso-* /bin/
USER sso
