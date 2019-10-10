## sso_proxy

### Proxy Config
All services using `sso_proxy` are configured in a `upstream_config.yml` file.
All config values can be templated from environmental variables with the prefix `SSO_CONFIG_`.
For example, the following config would have the following environment variables configed:, `SSO_CONFIG_CLUSTER`, `SSO_CONFIG_ROOT_DOMAIN`.


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
      inject_request_headers:
        Authorization: Basic dXNlcjpwYXNzd29yZA==
  prod:
    from: example-service.example.com
```


* **service** is the name of the service being protected
* **default** is the default specifier used to set cluster settings for all clusters
  * **from** is the domain that will be used to access the service
  * **to** is the cname of the proxied service (this tells sso proxy where to proxy requests that come in on the from field)
  * **type** declares the type of route to use, right now there is just *simple* and *rewrite*.
  * **options** are a set of options that can be added to your configuration.
    * **allowed groups** optional list of authorized google groups that can access the service. If not specified, anyone within an email domain is allowed to access the service. *Note*: We do not support nested group authentication at this time. Groups must be made up of email addresses associated with individual's accounts. See [#133](https://github.com/buzzfeed/sso/issues/133).
    * **allowed_email_domains** optional list of authorized email domains that can access the service.
    * **allowed_email_addresses** optional list of authorized email addresses that can access the service.
    * **skip_auth_regex** skips authentication for paths matching these regular expressions. NOTE: Use with extreme caution.
    * **header_overrides** overrides any heads set either by SSO proxy itself or upstream applications. Useful for modifying browser security headers.
    * **inject_request_headers** adds headers to the request before the request is sent to the proxied service.  Useful for adding basic auth headers if needed.
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
To enable request signing, SSO Proxy looks for environment variables with the format `SSO_CONFIG_{{SERVICE}}_SIGNING_KEY` with the previous mentioned key.

For example:
```bash
export SSO_CONFIG_FOOBAR_SIGNING_KEY="sha256:shared-secret-value"
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

`sso_proxy` adds the following headers to every outgoing request, to ensure a baseline level of browser security for every service that it protects.  These headers _cannot_ be overridden by upstream services, but _can_ be overridden in the `HEADER_OVERRIDES` environment variable.

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

### Websockets
SSO supports upstreams that use websockets, providing the upstream has a positive flush interval (`flush_interval`) set.


### `sso_proxy` Endpoints
* `/` - Begins the proxy process, attempting to authenticate the session cookie, redirecting to `sso-authenticator` if there is no cookie or an invalid one.
* `/oauth2/sign_out` - Clears the `sso_proxy` session cookie and redirects the user to sign out with `sso-authenticator`
* `/oauth2/callback` - The endpoint that `sso_auth` is redirected to after authenticating. This validates the redirect response and redirects to the service if the user is authenticated and authorized.
* `/oauth2/auth` - The endpoint that solely authenticates a user’s session cookie, returning a `401 Status Unauthorized` response if invalid and a `202 Status Accepted` response if valid.
* `/ping` - Health check endpoint. Can be used by load balancer to verify that service is still alive.

Please note that these endpoints will mask any endpoints exposed by upstream services which may
share the same paths.

### diagram

![sso_request_flow](https://user-images.githubusercontent.com/10510566/44476373-8ae34e80-a605-11e8-93da-d876f7e48d84.png)


<!-- diagram source: http://sequencediagram.org/index.html#initialData=C4S2BsFMAIGVYPLQEqQI4FdIGdjQGLgD2A7gFBkB2RwMRAbpAE7QbbMA00AxAA4iUA1gC5oAFWYBbAUWIBzAJ4A6FdAA6lDQCotqbEQxMAxjAQlKzHeotK5S1uxYkAFkXbQAJgENgX6CGxoACNIATloLyMTbHYPa20tAGFwEEhKPABBXl4Uox8QIkorDUhbe0d6EBNoC0gPMIionEDgIgdmAHJA7194oq0MjGBXJhAAL3zCuGZGJmKbO2g5NOYfHAihkfHJymgjIg8YAAovSjjI6JaiQTSASj6dPQNjGFgZyy1rUsW0j14iAR4YY+aC8JgMECHQJsTrdHxeCjUWjQBjMdpMLjcABmOKCHg8wgAkrthjBgEwvPVQIUvOBoAhBsNoEx0FhcNAscQSNZSej-C1nDAAERPQzVMwWJhCpQaDRiQXQDos-RiyAdfwk5wBPZedwhMIaXkwpiBeQCfyHdJgZQUY0AWgAfDE2mCiAAPBTCADiAFExNBnMBgLxsMIAPRhrFEIhKZ1KSBurySHKlfaSMOImh0WbQZ2g8EezE4rF4gnymAszA4PDa2lcurBSB5GHQXnwJAVKrrLws0EYIK5cAKRqXEAD0qyyjE1sK8mUsAFSi0+mM5zM1nVjlcuCIaAABQLw+1vKFyVS6WgWRyVR20sn+CILHb0BIMGcXkY0AjwBIRAj0DPNJMmyXIdlDaAhTzV0PSFCIzggvMvE2ICb1aKV7DlLVAm1EJm3cdsuk8HAQDkXYYUCPwhQ8AxxxRJDhlgnsjC1WgjGAQxSgoKDDztR1uPdT1mKbQQOUffMBNzZpFz2aNBFSChaTwahxI9SSYmk-Zrnk6Bc30FSFD4vT6MFK08jQ70-QDIMQ3DMNnTtYz40TZMoCUNMMyoLMURzRDkNMnxHyLXF8WEcsdyQVcULMsScJoNdeQ0U8UiAy8QNQxdGPgk9V0fbZqV2N4mFmO9NEoB8n13V8Aw-GBv1-f9AIvK9QPyij4Lqv8w0vTZcomfLpiK5hAg0XCkPcMBumI0j+QiCDqP7KA6M2RjjBYpt2JZJQyB0nTtp23zSX8tDeKdIy-NAaKmGEISjBEqMWGMqKApYdh1KmTS5MgPbdp2lFeCUtpHqOsTXuwDTZO037dMB87UMfR0iGM8TKkOK7fX9QNg1DCNEc2JRXRR5g3KIdMvjKaAvWjORFoZTYACZ93BQmmG+nbWZ0pFszRXGmQJyFOB4YtS1EMKebXPnUZm04IJy0Y+ukwriusc1eTnKlF2XWmmUrNk8E5Ugtqh6B2b+gGlt5pn+ZeqTChNnSxeRq2TodiXmFEY1oHkbDKBNk2Xct1HnaR12rr2Fk1nN8WA7RUHwa0r6jbtyPHcDhHg+j0OPa8bIme7JoYnXKtcBN35faN-2IUD06YcOi7ntEFl6hZNjoAAakk+DjN6nYZMOCgjYOky6+Oh0K+ZhuN3ZC5mlba40msI42AaIxkvSAB9SEuBX89gDX9gjBZPB267uWe-2Q5bjLqHOe8mOztruGMUF4KCR0begI3jwrFOOI39X3f96H2-r2ZYko1hxA0C4ee0stZrkangbO14zLSSOAIBcdYFD3A0JIU4GAMHrjkAEWgJp-DAHYOALEL4wBrhgauRmlciaTh0NOYY2o8juF5CHGalMiDU1KDoK+v0x5OzTpsFObtoCzBAFiYcJ88rg0OBoH+SwVgUmRNPAurQbg+3LunBhTBDI1yHo-UQGirjaMEfte+xjLqOmVM8EwE8i54A9ocXwIBwDYEsRzLyqIWD2NVEFEsIUwoBJeDNE8opwmK2YLBDQKtZwUnVjSOksDC66y3AbScAARSAvBfgNCmLyJia02IcSImDUiHBDRYRkhgcAcQQgzhgNgJMMBdTNO6sMbu-UYlMBlKVZhmo2G6jJAqMJ1RjwKmNIRfmVpgDKAEYnI2EzICGI2A-S67tHBEXcZ47x0MNk2OeidQeT1zKSOYNI4cHt3yBH2EwZueBIA4I8REfEyphqUBAPGew5FZpBAwGMMYWJIB1GJpITwJMvACAOYpSRtJITolZmc4GBj1lA2Ho+a64d1Gw0umpMG70IYJyhpATxMABD0ERXEY0JtUVYoMdwRuDpjSiAACwAAYADMEFiTUpSHEDIUQDDpCFCXM4e1S6-RRdY858Nq76Qnk3dabcO7nB6qffq59SU-SsS6HiirMUmPSZuMxs9tELyXpQcI7916bz2P-PeTZD5qrkfLYlF8Dk3z8Yc6CCggnCz-jvT+394LBo-oAyAwBgEwFAasWgEDKBQN2LQsR8CIhpWQVMVB3zQAYKwZQHBlA8HgCHAQohQ1SHkMoSQahcEVxiIPPogZCQWG1PYWMmAXCpmvF3JFNFSgllQ3pXKtFpyx2MtEFImRRyekKMgEo+C8a1HtPzuYtIo6jHyoMYq-1pj10Ws3csqG-EPQYvxfXU17JXHRphfsk9v0fU+UnY-QNISFTPgHYyiJCoRQ4Aca8d4UplaajJEkhcKTG3a0nnrLkraypiWfFVd8n4Or-iidUPpXzRotgmhUkiuxaxzRootMWK1mJgHWhxBDuT8lnEKWBiIq0qNlN7FCQj1T0gKllvIqYfS4JxF5JhoDg0WAaDyLsIgWJaC7CabyVpkgxlhAQ2FLEIATR4FWZJMTGpOk603Prbkv56lxFQzAEIaQNA8L4dAI4KbOkMsftexNnSZnYUtKABZtxDYjoHq+2xe7DzbLRG4+9XjH36v0hOg1AlhAzpuTsyofgMiJAADLet8S+2LhZn7BIJJ01LaWKK9iCF4G4cRARtAU3pf1OnKjVCUfcwo6m5CGB7upqAAoQRpEIbUEhxbS3lowLwHonFIs6Xhe6uosqcsGXWfusOkAI51djsS+OJcKU1BoHOuWM3-NzbtMyuorLHAcp5XyygAqkXCv2BgMVmXkS+rPQGng-AhCiFYYEbAIw8BGA00YDA+HeRRjLaQBojcNPrV879UupcyAvcdICZgS46SdkceuFVLcPatHq12aAvx-iAkzE9nMyOmCo7xyYd9ZZxmwalmD18HguAdLANVL5aYYBYnBJCvw6OYB1tYUx0Y4QABqe5EgIYQKSJgdb3B+AM+yNMDQsd4A0NzkmbmdkmYaY2dcAArdadQgA -->
