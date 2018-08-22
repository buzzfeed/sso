#!/usr/bin/env bash

# lets find out the host ip and then use that to connect the sso-proxy to the nginx-proxy
export host_ip=`docker run buzzfeed/cop:fix-dockerfile ping -c 1 host.docker.internal | grep icmp_seq | awk '{print $4}' | cut -d':' -f1`

#create cookies if they don't exist otherwise use the ones already created
test -f proxy_cookie_secret || openssl rand -base64 32 | head -c 32 | base64 > proxy_cookie_secret
test -f auth_cookie_secret || openssl rand -base64 32 | head -c 32 | base64 > auth_cookie_secret
test -f old_cookie_secret || openssl rand -base64 32 | head -c 32 | base64 > old_cookie_secret
export proxy_cookie_secret=`cat proxy_cookie_secret`
export auth_cookie_secret=`cat auth_cookie_secret`
export old_cookie_secret=`cat old_cookie_secret`

#start up the containers
docker-compose up

