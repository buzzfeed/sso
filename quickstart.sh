#!/usr/bin/env bash

function die {
    echo 1>&2 "${1:-}"
    exit 1
}

#test if the config files have been setup yet
test -f docker-compose.yml || die "Error: could not locate \`docker-compose.yml\` file
Copy and configure from \`docker-compose.yml.example\`"

test -f env || die "Error: could not locate \`env\` file
Copy and configure from \`env.example\`"

test -f config/google-service-account.json || die "Error: could not locate \`config/google-service-account.json\` file
Copy and configure from \`config/google-service-account.json.example\`"

test -f config/proxy_configs.yml || die "Error: could not locate \`config/proxy_configs.yml\` file
Copy and configure from \`config/proxy_configs.yml.example\`"

# lets find out the host ip and then use that to connect the sso-proxy to the nginx-proxy
export host_ip=`docker run buzzfeed/sso:latest ping -c 1 host.docker.internal | grep icmp_seq | awk '{print $4}' | cut -d':' -f1`

#create cookies if they don't exist otherwise use the ones already created
test -f proxy_cookie_secret || openssl rand -base64 32 | head -c 32 | base64 > proxy_cookie_secret
test -f auth_cookie_secret || openssl rand -base64 32 | head -c 32 | base64 > auth_cookie_secret
test -f old_cookie_secret || openssl rand -base64 32 | head -c 32 | base64 > old_cookie_secret
export proxy_cookie_secret=`cat proxy_cookie_secret`
export auth_cookie_secret=`cat auth_cookie_secret`
export old_cookie_secret=`cat old_cookie_secret`

#setup host side name resolution
ping -c 1 payload.sso.sso-test.io >/dev/null || echo "127.0.0.1 payload.sso.sso-test.io" >> /etc/hosts
ping -c 1 sso-auth.sso-test.io >/dev/null || echo "127.0.0.1 sso-auth.sso-test.io" >> /etc/hosts

#start up the containers
docker-compose up
