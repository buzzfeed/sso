# Quickstart

This quickstart guide will walk you through the process of creating a set of
Google OAuth credentials and using Docker Compose to run an example deployment
of **sso** protecting two upstream services.

To learn how to get started using SSO with Kubernetes, you can check out this [blog post](https://medium.com/@while1eq1/single-sign-on-for-internal-apps-in-kubernetes-using-google-oauth-sso-2386a34bc433) and [example](/quickstart/kubernetes), added and written by [Bill Broach](https://twitter.com/while1eq1), one of our community contributors!


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

## 2. Configure Provider Credentials
Depending on which provider you would like to use SSO with (Google/Okta) follow the relevant
section below:

### Google

Follow steps 1 and 2 of the [Google Provider Setup](google_provider_setup.md)
documentation.

**⚡️ Note:** Use `http://sso-auth.localtest.me/google/callback` as the
**Authorized redirect URI** in step 2.

At the end of step 2, you will have a client ID and client secret. Create a new
file called `env` and input those values like so:

    PROVIDER_GOOGLEQUICKSTART_CLIENT_ID=<client id value>.apps.googleusercontent.com
    PROVIDER_GOOGLEQUICKSTART_CLIENT_SECRET=<client secret value>
    PROVIDER_GOOGLEQUICKSTART_TYPE=google
    PROVIDER_GOOGLEQUICKSTART_SLUG=google

Notes:

- Start by copying `env.google.example` to `env` (`cp env.google.example env`)

- `GOOGLEQUICKSTART` is a logical identifier that is used to group the
  configuration variables together for any one provider. This can be changed to
  an identifier that makes sense for your individual use case.

- `PROVIDER_*_TYPE` tells **sso** which provider type to use for a
  configuration identifier (`GOOGLEQUICKSTART` in this case)

- `PROVIDER_*_SLUG` controls the "slug" in the OAuth callback URL (i.e.,
  the `/google/` in `http://sso-auth.localtest.me/google/callback`).

This file will be used to configure `sso-auth` in the example deployment to
allow you to log to **sso**.

### Okta

Once you've completed the [Okta Provider Setup](okta_provider_setup.md) (alternatively, you
can skip to and complete Section 3 of the [Okta Provider Setup](okta_provider_setup.md) instead),
follow through the below steps:

**⚡️ Note:** Use `http://sso-auth.localtest.me/okta/callback` as the
**Authorized redirect URI** in step 3.

At the end of step 3 you will be given a client ID and client secret, which can
be found at the bottom of the settings page for the Application you've created.
Create a new file called `env` with those values, like so:

    PROVIDER_OKTAQUICKSTART_CLIENT_ID=<client id value>
    PROVIDER_OKTAQUICKSTART_CLIENT_SECRET=<client secret value>
    PROVIDER_OKTAQUICKSTART_OKTA_URL=<organisation url>
    PROVIDER_OKTAQUICKSTART_TYPE=okta
    PROVIDER_OKTAQUICKSTART_SLUG=okta
    DEFAULT_PROVIDER_SLUG=okta

Notes:

- Start by copying `env.okta.example` to `env` (`cp env.okta.example env`)

- `OKTAQUICKSTART` is a logical identifier that is used to group the
  configuration variables together for any one provider. This can be changed to
  an identifier that makes sense for your individual use case.

- `PROVIDER_*_TYPE` tells **sso** which provider type to use for a
  configuration identifier (`OKTAQUICKSTART` in this case)

- `PROVIDER_*_SLUG` controls the "slug" in the OAuth callback URL (i.e.,
  the `/okta/` in `http://sso-auth.localtest.me/okta/callback`).

- `PROVIDER_*_OKTA_URL` is configures the Okta provider with your Okta
  organization URL (e.g. `sso-test.okta.com`)

- `DEFAULT_PROVIDER_SLUG` tells **sso** to use the Okta provider by default

- **If you are not using the default Okta authorization server** you will also
  need to add `PROVIDER_OKTAQUICKSTART_SERVER_ID=<okta auth server ID>` to the
  above file.

This file will be used to configure `sso-auth` in the example deployment to
allow you to log in to **sso**.

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
any Google account. If you are using Okta as your SSO provider, log in using
any Okta account that has been correctly assigned to the Application (this
should have been done while setting up the Okta provider)

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
