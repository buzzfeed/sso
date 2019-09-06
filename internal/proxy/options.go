package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/proxy/providers"

	"github.com/datadog/datadog-go/statsd"
)

// Options are configuration options that can be set by Environment Variables
// Port - int -  port to listen on for HTTP clients
// ProviderURLString - the URL for the provider in this environment: "https://sso-auth.example.com"
// ProxyProviderURLString - the internal URL for the provider in this environment: "https://sso-auth-int.example.com"
// UpstreamConfigsFile - the path to upstream configs file
// Cluster - the cluster in which this is running, used for upstream configs
// Scheme - the default scheme, used for upstream configs
// SkipAuthPreflight - will skip authentication for OPTIONS requests, default false
// EmailDomains - csv list of emails with the specified domain to authenticate. Use * to authenticate any email
// EmailAddresses - []string - authenticate emails with the specified email address (may be given multiple times). Use * to authenticate any email
// DefaultAllowedGroups - csv list of default allowed groups that are applied to authorize access to upstreams. Will be overridden by groups specified in upstream configs.
// ClientID - the OAuth Client ID: ie: "123456.apps.googleusercontent.com"
// ClientSecret - The OAuth Client Secret
// DefaultUpstreamTimeout - the default time period to wait for a response from an upstream
// DefaultUpstreamTCPResetDeadline - the default time period to wait for a response from an upstream
// TCPWriteTimeout - http server tcp write timeout - set to: max(default value specified, max(upstream timeouts))
// TCPReadTimeout - http server tcp read timeout
// CookieName - name of the cookie
// CookieSecret - the seed string for secure cookies (optionally base64 encoded)
// CookieDomain - an optional cookie domain to force cookies to (ie: .yourcompany.com)*
// CookieExpire - expire timeframe for cookie
// CookieSecure - set secure (HTTPS) cookie flag
// CookieHTTPOnly - set HttpOnly cookie flag
// PassAccessToken - send access token in the http headers
// Provider - OAuth provider
// DefaultProviderSlug - OAuth provider slug, used internally to identity a specific provider
// Scope - OAuth scope specification
// SessionLifetimeTTL - time to live for a session lifetime
// SessionValidTTL - time to live for a valid session
// GracePeriodTTL - time to reuse session data when provider unavailable
// RequestLoging - boolean whether or not to log requests
// StatsdHost - host addr for statsd client to listen on
// StatsdPort - port for statsdclient to listen on
type Options struct {
	Port int `envconfig:"PORT" default:"4180"`

	ProviderURLString         string `envconfig:"PROVIDER_URL"`
	ProviderURLInternalString string `envconfig:"PROVIDER_URL_INTERNAL"`
	UpstreamConfigsFile       string `envconfig:"UPSTREAM_CONFIGS"`
	Cluster                   string `envconfig:"CLUSTER"`
	Scheme                    string `envconfig:"SCHEME" default:"https"`

	SkipAuthPreflight bool `envconfig:"SKIP_AUTH_PREFLIGHT"`

	EmailDomains         []string `envconfig:"EMAIL_DOMAIN"`
	EmailAddresses       []string `envconfig:"EMAIL_ADDRESSES"`
	DefaultAllowedGroups []string `envconfig:"DEFAULT_ALLOWED_GROUPS"`

	ClientID     string `envconfig:"CLIENT_ID"`
	ClientSecret string `envconfig:"CLIENT_SECRET"`

	DefaultUpstreamTimeout          time.Duration `envconfig:"DEFAULT_UPSTREAM_TIMEOUT" default:"10s"`
	DefaultUpstreamTCPResetDeadline time.Duration `envconfig:"DEFAULT_UPSTREAM_TCP_RESET_DEADLINE" default:"60s"`

	TCPWriteTimeout time.Duration `envconfig:"TCP_WRITE_TIMEOUT" default:"30s"`
	TCPReadTimeout  time.Duration `envconfig:"TCP_READ_TIMEOUT" default:"30s"`

	CookieName     string        `envconfig:"COOKIE_NAME" default:"_sso_proxy"`
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE" default:"168h"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE" default:"true"`
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY"`

	RedisConnectionURL          string   `envconfig:"REDIS_CONNECTION_URL"`
	RedisUseSentinel            bool     `envconfig:"REDIS_USE_SENTINEL"`
	RedisSentinelMasterName     string   `envconfig:"REDIS_SENTINEL_MASTER_NAME"`
	RedisSentinelConnectionURLs []string `envconfig:"REDIS_SENTINEL_CONNECTION_URLS"`

	PassAccessToken bool `envconfig:"PASS_ACCESS_TOKEN" default:"false"`

	Provider            string `envconfig:"PROVIDER" default:"sso"`
	DefaultProviderSlug string `envconfig:"DEFAULT_PROVIDER_SLUG" default:"google"`
	Scope               string `envconfig:"SCOPE"`

	SessionLifetimeTTL time.Duration `envconfig:"SESSION_LIFETIME_TTL" default:"720h"`
	SessionValidTTL    time.Duration `envconfig:"SESSION_VALID_TTL" default:"1m"`
	GracePeriodTTL     time.Duration `envconfig:"GRACE_PERIOD_TTL" default:"3h"`

	RequestLogging bool `envconfig:"REQUEST_LOGGING" default:"true"`

	StatsdHost string `envconfig:"STATSD_HOST"`
	StatsdPort int    `envconfig:"STATSD_PORT"`

	RequestSigningKey string `envconfig:"REQUEST_SIGNATURE_KEY"`

	StatsdClient *statsd.Client

	// This is an override for supplying template vars at test time
	testTemplateVars map[string]string

	// internal values that are set after config validation
	upstreamConfigs     []*UpstreamConfig
	decodedCookieSecret []byte
}

// NewOptions returns a new options struct
func NewOptions() *Options {
	return &Options{
		CookieName:     "_sso_proxy",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieExpire:   time.Duration(168) * time.Hour,

		SkipAuthPreflight: false,
		RequestLogging:    true,

		DefaultUpstreamTimeout:          time.Duration(1) * time.Second,
		DefaultUpstreamTCPResetDeadline: time.Duration(1) * time.Minute,

		DefaultAllowedGroups: []string{},
		PassAccessToken:      false,
	}
}

// Validate validates options
func (o *Options) Validate() error {
	msgs := make([]string, 0)
	if o.Cluster == "" {
		msgs = append(msgs, "missing setting: cluster")
	}
	if o.ProviderURLString == "" {
		msgs = append(msgs, "missing setting: provider-url")
	}
	if o.UpstreamConfigsFile == "" {
		msgs = append(msgs, "missing setting: upstream-configs")
	}
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o.ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}
	if len(o.EmailDomains) == 0 && len(o.EmailAddresses) == 0 {
		msgs = append(msgs, "missing setting: email-domain or email-address")
	}

	if o.StatsdHost == "" {
		msgs = append(msgs, "missing setting: statsd-host")
	}

	if o.StatsdPort == 0 {
		msgs = append(msgs, "missing setting: statsd-port")
	}
	if o.StatsdHost != "" && o.StatsdPort != 0 {
		StatsdClient, err := newStatsdClient(o)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error creating statsd client error=%q", err))
		}
		o.StatsdClient = StatsdClient
	}

	if o.UpstreamConfigsFile != "" {
		rawBytes, err := ioutil.ReadFile(o.UpstreamConfigsFile)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error reading upstream configs file: %s", err))
		}

		templateVars := parseEnvironment(os.Environ())
		if o.testTemplateVars != nil {
			templateVars = o.testTemplateVars
		}

		defaultUpstreamOptionsConfig := &OptionsConfig{
			AllowedGroups: o.DefaultAllowedGroups,
			Timeout:       o.DefaultUpstreamTimeout,
			ResetDeadline: o.DefaultUpstreamTCPResetDeadline,
			ProviderSlug:  o.DefaultProviderSlug,
			CookieName:    o.CookieName,
		}

		o.upstreamConfigs, err = loadServiceConfigs(rawBytes, o.Cluster, o.Scheme, templateVars, defaultUpstreamOptionsConfig)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error parsing upstream configs file %s", err))
		}
	}

	if o.upstreamConfigs != nil {
		for _, uc := range o.upstreamConfigs {
			if uc.Timeout > o.TCPWriteTimeout {
				o.TCPWriteTimeout = uc.Timeout
			}
		}
	}

	if o.ProviderURLString != "" {
		err := parseProviderInfo(o)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("invalid value for provider-url: %s", err.Error()))
		}
	}

	decodedCookieSecret, err := base64.StdEncoding.DecodeString(o.CookieSecret)
	if err != nil {
		msgs = append(msgs, "Invalid value for COOKIE_SECRET; expected base64-encoded bytes, as from `openssl rand 32 -base64`")
	}
	validCookieSecretLength := false
	for _, i := range []int{32, 64} {
		if len(decodedCookieSecret) == i {
			validCookieSecretLength = true
		}
	}

	if !validCookieSecretLength {
		msgs = append(msgs, fmt.Sprintf("Invalid value for COOKIE_SECRET; must decode to 32 or 64 bytes, but decoded to %d bytes", len(decodedCookieSecret)))
	}

	o.decodedCookieSecret = decodedCookieSecret

	msgs = validateCookieName(o, msgs)

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseProviderInfo(o *Options) error {
	providerURL, err := url.Parse(o.ProviderURLString)
	if err != nil {
		return err
	}

	if providerURL.Scheme == "" || providerURL.Host == "" {
		return errors.New("provider-url must include scheme and host")
	}

	var providerURLInternal *url.URL
	if o.ProviderURLInternalString != "" {
		providerURLInternal, err = url.Parse(o.ProviderURLInternalString)
		if err != nil {
			return err
		}
		if providerURLInternal.Scheme == "" || providerURLInternal.Host == "" {
			return errors.New("proxy provider url must include scheme and host")
		}
	}

	return nil
}

func newProvider(opts *Options, upstreamConfig *UpstreamConfig) (providers.Provider, error) {
	providerURL, err := url.Parse(opts.ProviderURLString)
	if err != nil {
		return nil, err
	}

	var providerURLInternal *url.URL
	if opts.ProviderURLInternalString != "" {
		providerURLInternal, err = url.Parse(opts.ProviderURLInternalString)
		if err != nil {
			return nil, err
		}
	}

	providerData := &providers.ProviderData{
		ClientID:            opts.ClientID,
		ClientSecret:        opts.ClientSecret,
		ProviderURL:         providerURL,
		ProviderURLInternal: providerURLInternal,
		ProviderSlug:        upstreamConfig.ProviderSlug,
		Scope:               opts.Scope,
		SessionLifetimeTTL:  opts.SessionLifetimeTTL,
		SessionValidTTL:     opts.SessionValidTTL,
		GracePeriodTTL:      opts.GracePeriodTTL,
	}

	p := providers.New(opts.Provider, providerData, opts.StatsdClient)
	return providers.NewSingleFlightProvider(p, opts.StatsdClient), nil
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func parseEnvironment(environ []string) map[string]string {
	envPrefix := "SSO_CONFIG_"
	env := make(map[string]string)
	if len(environ) == 0 {
		return env
	}
	for _, e := range environ {
		// we only include env keys that have the SSO_CONFIG_ prefix
		if !strings.HasPrefix(e, envPrefix) {
			continue
		}

		split := strings.SplitN(e, "=", 2)
		key := strings.ToLower(strings.TrimPrefix(split[0], envPrefix))
		env[key] = split[1]
	}
	return env
}
