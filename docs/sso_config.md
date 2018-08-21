## sso_proxy

### Proxy Config
All services using `sso_proxy` are configured in a `upstream_config.yml` file.
All config values can be templated from environmental variables with the prefix `BUZZFEED_SSO_CONFIG_`.
For example, the following config would have the following environment variables configed:, `BUZZFEED_SSO_CONFIG_CLUSTER`, `BUZZFEED_SSO_CONFIG_ROOT_DOMAIN`.


```json
- service: example_service
  default:
    from: example-service.sso.{{cluster}}.{{root_domain}}
    to: example-service.{{cluster}}.{{root_domain}}
    options:
      allowed_groups:
        - sso-test-group-1@example.com
        - sso-test-group-2@example.com
      skip_auth_regex:
        - ^\/github-webhook\/$
      header_overrides:
        X-Frame-Options: DENY
  prod:
    from: example-service.example.com
```


* **service** is the name of the service being protected
* **default** is the default specifier used to set cluster settings for all clusters
  * **from** is the domain that will be used to access the service
  * **to** is the cname of the proxied service (this tells sso proxy where to proxy requests that come in on the from field)
  * **type** declares the type of route to use, right now there is just *simple* and *rewrite*.
  * **options** are a set of options that can be added to your configuration.
    * **allowed groups** optional list of authorized google groups that can access the service. If not specified, anyone within an email domain is allowed to access the service.
    * **skip_auth_regex** skips authentication for paths matching these regular expressions. NOTE: Use with extreme caution.
    * **header_overrides** overrides any heads set either by SSO proxy itself or upstream applications. Useful for modifying browser security headers.
    * **timeout** sets the amount of time that SSO Proxy will wait for the upstream to complete its request.
    * **flush_interval** sets an interval to periodically flush the buffered response to the client. If specified, SSO Proxy will not timeout requests to this upstream and will stream the response to the client. NOTE: Use with extreme caution.
  * **extra_routes** allows services to specify multiple routes. These route can includes the *from*, *to*, *type*, and *options* fields defined above and inherit any configuration
from their parent routing config if not specified here (e.g. *options*).
* **cluster name <identifier>** are cluster-specific settings. Any configuration specified in the default field can be override here with cluster specific configuration.

### Route Types

There are currently two route types used by SSO to route requests, *simple* and *rewrite*.

#### Simple

*simple*, the default type, route using strict host string matching *from* the incoming request and proxies
that request to the *to* field.

For example:

```yaml
- service: example_service
  default:
    from: example-service.sso.{{cluster}}.{{root_domain}}
    to: example-service.{{cluster}}.{{root_domain}}
```

matches requests with the incoming host of `example-service.sso.{{cluster}}.{{root_domain}}`
and proxies those requests `example-service.{{cluster}}.{{root_domain}}`

#### Rewrite

*rewrite* routes allow for host regexp matching of incoming requests and then proxying that request
to an upstream using the `to` field which can be templated with replacements. Internally, this API
just uses [`Regexp.ReplaceAllString`](https://golang.org/pkg/regexp/#Regexp.ReplaceAllString)

For example:

```yaml
- service: example_service
  default:
    from: ^example-service--(.*).sso.{{cluster}}.{{root_domain}}$
    to: example-service--$1.{{cluster}}.{{root_domain}}
```

matches requests that using the above regex and then constructs an upstream uri by replacing any match groups
the templated replacements in the `to` field.

So, if sso received a request with the host header `example-service--janedoe.sso.{{cluster}}.{{root_domain}}`, it would
match the provided regex and have one match group. Using [`Regexp.ReplaceAllString`](https://golang.org/pkg/regexp/#Regexp.ReplaceAllString)
and the incoming request host header, we can construct the upstream uri using the `to` field, here `example-service--janedoe.cluster.root_domin`,
and proxy the request to that upstream.

### Request Signing
SSO Proxy can sign requests using an HMAC shared-secret signing key specified per upstream. This must be of the form `algorithm:secret_value`, where `sha256` is preferred for the algorithm.
To enable request signing, SSO Proxy looks for environment variables with the format `BUZZFEED_SSO_CONFIG_{{SERVICE}}_SIGNING_KEY` with the previous mentioned key.

For example:
```bash
export BUZZFEED_SSO_CONFIG_FOOBAR_SIGNING_KEY="sha256:shared-secret-value"
```
would be the signing key for the `foobar` upstream service, use the sha256 with the `shared-secret-value` as it's signing key value.

This signs the request using defined signature headers found in https://github.com/buzzfeed/sso/blob/master/sso_proxy/oauthproxy.go#L25.
Specific implementation details can be found at https://github.com/18F/hmacauth

### Headers

`sso_proxy` adds the following headers to each request it proxies to upstream services, so that upstream services may identify the authenticated user.

* `X-Forwarded-User`
  * This header contains user's username as a string:`user.name` for user `user.name@example.com`.
* `X-Forwarded-Email`
  * This header contains the user's email address as a string: `user.name@example.com`.
* `X-Forwarded-Groups`
  * This header contains the groups a user is a member of, as a comma-separated list. Only groups specified in an upstream's `allowed_groups` config option will be included. Upstream services may use this list to do finer-grained access control as necessary.
* `X-Forwarded-Host`
  * This header contains the original host header received by sso proxy for the request, which can be used to reconstruct the original request URL if an upstream needs to do so.

Optional:
* `Gap-Signature` if a `signing_key` for the upstream is specified

#### Security Headers

`sso_proxy` adds the following headers to every outgoing request, to ensure a baseline level of browser security for every service that it protects.  These headers _cannot_ be overridden by upstream services, but _can_ be overriden in the `HEADER_OVERRIDES` environment variable.

* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `X-XSS-Protection`


### Session Lifetime

Each SSO session lasts for 15 days and is re-validated with `sso_auth` every minute.  This means that any user should only need to sign into SSO once every 15 days, while still ensuring that revoking a user's access will take effect within 4 minutes.

#### Configuration

There are four configuration options that can be set as environment variables related to the behavior
of sso proxy when it authenticates with sso authenticator.


The **session_valid_ttl** option controls the amount of time it will take for
`sso_proxy` to pick up on authentication changes in the 3rd party provider
(e.g. revoked access, group membership updates).  Once expired, `sso_proxy`
will make an _internal request_ to `sso_auth` (i.e. invisible to the
end user) to revalidate & refresh the session.

The **session_lifetime_ttl** option controls the maximum lifetime of a
`sso_proxy` session, after which a user will be 301 redirected to
`sso_auth` to go through the 3rd party OAuth2 flow again.

The **cookie_expire** option controls the maximum lifetime of the `sso_proxy`
cookie stored by a user's web browser, after which a user will also be 301
redirected to `sso_auth` to go through the 3rd party OAuth2 flow
again.

The **grace_period_ttl** option controls the duration of the grace period that
`sso_proxy` grants to existing sessions in the event that `sso_auth`'s
upstream provider is unavailable. `sso_proxy` starts this grace period whenever
`sso_auth` returns either a `429 Too Many Requests` or `503 Service
Unavailable` response. During the grace period, existing session data is
honored as valid. The grace period ends either after the TTL expires or when
`sso_auth`'s upstream provider becomes available again.

##### Notes

* For now, the `cookie_expire` value should be greater than or equal to the
  `session_lifetime_ttl` value. In the future, we should remove the separate
  `cookie_expire` option altogether and just rely on `session_lifetime_ttl`.

* The value of `session_valid_ttl` has a direct impact on the number of
  requests we will make to the 3rd party authentication provider, as requests
  to re-validate a user's permissions will be made every time it expires. Tune
  this value to balance between responsiveness to permission changes and
  (over)use of 3rd party API quotas.

  See [Google service accounts](#google-service-accounts) below to
  check API usage and quotas.

* The grace period defined by `grace_period_ttl` is granted on a per-user basis,
  starting from the first failure to authenticate.


### `sso_proxy` Endpoints
* `/` - Begins the proxy process, attempting to authenticate the session cookie, redirecting to `sso-authenticator` if there is no cookie or an invalid one.
* `/oauth2/sign_out` - Clears the `sso_proxy` session cookie and redirects the user to sign out with `sso-authenticator`
* `/oauth2/callback` - The endpoint that `sso_auth` is redirected to after authenticating. This validates the redirect response and redirects to the service if the user is authenticated and authorized.
* `/oauth2/auth` - The endpoint that solely authenticates a user’s session cookie, returning a `401 Status Unauthorized` response if invalid and a `202 Status Accepted` response if valid.
* `/ping` - Health check endpoint. Can be used by load balancer to verify that service is still alive.

Please note that these endpoints will mask any endpoints exposed by upstream services which may
share the same paths.

