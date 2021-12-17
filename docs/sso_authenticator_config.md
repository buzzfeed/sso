# Available Configuration Variables
We currently use environment variables to read configuration options, below is a list of environment variables and
their corresponding types that the sso authenticator will read.

Defaults for the below settings can be found here: https://github.com/buzzfeed/sso/blob/main/internal/auth/configuration.go#L66-L117


## Session and Server configuration

### Session
```
SESSION_COOKIE_NAME     - string - name associated with the session cookie
SESSION_COOKIE_SECRET   - string - seed string for secure cookies
SESSION_COOKIE_DOMAIN   - string - cookie domain (and subdomains) to force cookies to (ie: .yourcompany.com). If this is set,
cookies will be valid on subdomains too. To restrict to only the request's domain, leave this unset.
Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent
SESSION_KEY             - string - seed string for secure auth codes
SESSION_COOKIE_SECURE   - bool - set secure (HTTPS) cookie flag
SESSION_COOKIE_HTTPONLY - bool - set 'httponly' cookie flag
SESSION_COOKIE_REFRESH  - time.Duration - duration to refresh the cookie after
SESSION_COOKIE_EXPIRE   - time.Duration - duration that cookie is valid for
SESSION_LIFETIME        - time.Duration - the session TTL
```


### Client

```
CLIENT_PROXY_ID     - string - Client ID matching the SSO Proxy client ID
CLIENT_PROXY_SECRET - string - Client secret matching the SSO Proxy client secret
```


### Server
```
SERVER_SCHEME           - string - scheme the server will use, e.g. `https`
SERVER_HOST             - string - host header that's required on incoming requests
SERVER_PORT             - string - port the http server listens on
SERVER_TIMEOUT_REQUEST  - time.Duration - overall request timeout
SERVER_TIMEOUT_WRITE    - time.Duration - write request timeout
SERVER_TIMEOUT_READ     - time.Duration - read request timeout
SERVER_TIMEOUT_SHUTDOWN - time.Duration - time to allow in-flight requests to complete before server shutdown
```


### Authorization
```
AUTHORIZE_PROXY_DOMAINS   - []string - only redirect to the specified proxy domains.
AUTHORIZE_EMAIL_DOMAINS   - []string - authenticate emails with the specified domains. Use `*` to authenticate any email
AUTHORIZE_EMAIL_ADDRESSES - []string - authenticate emails with the specified email addresses. Use `*` to authenticate any email
```

## Logging and Monitoring Configuration
### StatsD
```
METRICS_STATSD_PORT - int - port that statsdclient listens on
METRICS_STATSD_HOST - string - hostname that statsd client uses
```

### Logging
```
LOGGING_ENABLE - bool - enable request logging
LOGGING_LEVEL  - string - level at which to log at, e.g. 'INFO'
```

## Provider configuration

`*` in the below variables acts as a logical idendifier to group configuration variables together for any one provider.
This should be changed to an identifier that makes sense for your use case.
```
PROVIDER_*_TYPE          - string - determines the type of provider (supported options: google, okta)
PROVIDER_*_SLUG          - string - unique provider 'slug' that is used to separate and create routes to individual providers.
PROVIDER_*_CLIENT_ID     - string - OAuth Client ID
PROVIDER_*_CLIENT_SECRET - string - OAuth Client secret
PROVIDER_*_SCOPE         - string - OAuth scopes the provider will use. Default standard set of scopes pre-set in individual provider
files; which this configuration variable overrides.
```

### Google provider specific
```
PROVIDER_*_GOOGLE_CREDENTIALS - string - the path to the Google account's json credential file
PROVIDER_*_GOOGLE_IMPERSONATE - string - the Google account to impersonate for API calls
```

### Okta provider specific
```
PROVIDER_*_OKTA_URL    - string - the URL for your Okta domain, e.g. `<company>.okta.com`
PROVIDER_*_OKTA_SERVER - string - the authorisation server ID
```

### Group refresh and caching
```
PROVIDER_*_GROUPCACHE_INTERVAL_REFRESH  - time.Duration - cache TTL for the groups fillcache mechanism used to preemptively fill group caches
PROVIDER_*_GROUPCACHE_INTERVAL_PROVIDER - time.Duration - cache TTL for the group cache provider used for on demand group caching
```
