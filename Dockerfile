# =============================================================================
# build stage
#
# install golang dependencies & build binaries
# =============================================================================
FROM golang:1.10 AS build

ENV GOFLAGS='-ldflags="-s -w"'
ENV CGO_ENABLED=0

# use gpm to install dependencies
COPY Godeps gpm /tmp/
RUN cd /tmp && ./gpm install

WORKDIR /go/src/github.com/buzzfeed/sso

COPY cmd ./cmd
COPY internal ./internal
RUN cd cmd/sso-auth && go build -o /bin/sso-auth
RUN cd cmd/sso-proxy && go build -o /bin/sso-proxy


# =============================================================================
# final stage
#
# add static assets and copy binaries from build stage
# =============================================================================
FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /sso
COPY --from=build /bin/sso-* /bin/
