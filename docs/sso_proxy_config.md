# Available Configuration Variables
We currently use environment variables to read configuration options, below is a list of environment variables and
their corresponding types that the sso proxy will read.

Defaults for the below settings can be found here: https://github.com/buzzfeed/sso/blob/main/internal/proxy/configuration.go#L61-L105


## Session and Server configuration

### Session
```
SESSION_COOKIE_NAME     - string - name associated with the session cookie
SESSION_COOKIE_SECRET   - string - seed string for secure cookies
SESSION_COOKIE_DOMAIN   - string - cookie domain (and subdomains) to force cookies to (ie: .yourcompany.com)*
SESSION_COOKIE_SECURE   - bool - set secure (HTTPS) cookie flag
SESSION_COOKIE_HTTPONLY - bool - set 'httponly' cookie flag
SESSION_TTL_LIFETIME    - time.Duration - 'time-to-live' of a session lifetime
SESSION_TTL_VALID       - time.Duration - 'time-to-live' of a valid session
SESSION_TTL_GRACEPERIOD - time.Duration - time period in which session data can be reused while the provider is unavailable.
```

### Server
```
SERVER_PORT             - string - port the http server listens on
SERVER_TIMEOUT_SHUTDOWN - time.Duration - time to allow in-flight requests to complete before server shutdown
SERVER_TIMEOUT_READ     - time.Duration - read request timeout
SERVER_TIMEOUT_WRITE    - time.Duration - write request timeout
```

### Client
```
CLIENT_ID     - string - the OAuth Client ID: ie: "123456.apps.googleusercontent.com"
CLIENT_SECRET - string - the OAuth Client secret
```

### Request Signer
```
REQUESTSIGNER_KEY - string - RSA private key used for digitally signing requests
```

## Upstream and Provider Configuration

### Upstream
For further upstream configuration, see https://github.com/buzzfeed/sso/blob/main/docs/sso_config.md.
```
UPSTREAM_DEFAULT_EMAIL_DOMAINS      - []string - default setting for upstream `allowed_email_domains` variable
UPSTREAM_DEFAULT_EMAIL_ADDRESSES    - []string - default setting for upstream `allowed_email_addresses` variable
UPSTREAM_DEFAULT_GROUPS             - []string - default setting for upstream `allowed groups` variable
UPSTREAM_DEFAULT_TIMEOUT            - time.Duration - default setting for upstream `timeout` variable
UPSTREAM_DEFAULT_TCP_RESET_DEADLINE - time.Duration - default time period to wait for a response from an upstream
UPSTREAM_DEFAULT_PROVIDER           - string - default setting for the upstream `provider_slug` variable
UPSTREAM_CONFIGS_FILE               - string - path to the file containing upstream configurations
UPSTREAM_SCHEME                     - string - the scheme used for upstreams (e.g. `https`)
UPSTREAM_CLUSTER                    - string - the cluster in which this is running, used within upstream configuration
```

## Provider
```
PROVIDER_TYPE - string - string - the 'type' of upstream provider to use (at this time, only a provider type of 'sso' is supported)
PROVIDER_URL_EXTERNAL  - string - the external URL for the upstream provider in this environment (e.g. "https://sso-auth.example.com")
PROVIDER_URL_INTERNAL  - string - the internal URL for the upstream provider in this environment (e.g.  "https://sso-auth-int.example.com")
PROVIDER_SCOPE         - string - OAuth `scope` sent with provider requests
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
```
