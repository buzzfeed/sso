# Quickstart

This quickstart guide will walk you through the process of creating a set of
Google OAuth credentials and using Docker Compose to run an example deployment
of **sso** protecting two upstream services.

To learn how to get started using SSO with Kubernetes, you can check out this [blog post](https://medium.com/@while1eq1/single-sign-on-for-internal-apps-in-kubernetes-using-google-oauth-sso-2386a34bc433) and [example](/quickstart/kubernetes), added and written by [Bill Broach](https://twitter.com/while1eq1), one our community contributors! 


## Prerequisites

Before proceeding, ensure that the following software is installed:
- [Git](https://help.github.com/articles/set-up-git/#setting-up-git)
- [Docker](https://docs.docker.com/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)


## 1. Clone this repo

    git clone https://github.com/buzzfeed/sso.git

The rest of this guide will assume you are in the `quickstart` subdirectory of
the repo:

    cd sso/quickstart

## 2. Create Google OAuth Credentials

Follow steps 1 and 2 of the [Google Provider Setup](google_provider_setup.md)
documentation.

**⚡️ Note:** Use `http://sso-auth.localtest.me/oauth2/callback` as the
**Authorized redirect URI** in Step 2.

At the end of step 2, you will have a client ID and client secret. Create a new
file called `env` with those values, like so:

    CLIENT_ID=<random id>.apps.googleusercontent.com
    CLIENT_SECRET=<secret value>

This file will be used to configure `sso-auth` in the example deployment to
allow you to log to **sso**.


## 3. Create example `sso` deployment

First, bring up all of the services:

    docker-compose up -d

Next, confirm that they are running as expected:

    docker-compose ps

You should see 5 services running, all in the "Up" state:

              Name                        Command               State         Ports
    --------------------------------------------------------------------------------------
    quickstart_hello-world_1   /bin/sh -c php-fpm -d vari ...   Up      80/tcp
    quickstart_httpbin_1       /bin/go-httpbin                  Up      8080/tcp
    quickstart_nginx-proxy_1   /app/docker-entrypoint.sh  ...   Up      0.0.0.0:80->80/tcp
    quickstart_sso-auth_1      /bin/sso-auth                    Up      4180/tcp
    quickstart_sso-proxy_1     /bin/sso-proxy                   Up      4180/tcp


## 4. Explore your newly secured services!

Visit http://hello-world.sso.localtest.me in your web browser.  Log in using
any Google account.

Now visit http://httpbin.sso.localtest.me, and see that you are automagically
logged in!  (To verify that **sso** is actually working here, feel free to
visit http://httpbin.sso.localtest.me in a private browsing window.)

Make sure to take a look at http://httpbin.sso.localtest.me/headers to see the
headers that **sso** provides to upstreams, like `X-Forwarded-User`,
`X-Forwarded-Groups`, etc!

**Note:** The `localtest.me` domain we use in this example deployment will always
resolve to `127.0.0.1`, so it's a convenient way to avoid needing `/etc/hosts`
hacks.  See [readme.localtest.me](http://readme.localtest.me/) for more info.


## Next Steps

Take a look at [upstream_configs.yml](/quickstart/upstream_configs.yml) to see
how `sso-proxy` is configured to protect these two upstream services, or check
out [docker-compose.yml](/quickstart/docker-compose.yml) to see how the whole
deployment is put together.
