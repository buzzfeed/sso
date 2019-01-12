package auth

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/groups"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

// Options are config options that can be set by environment variables
// RedirectURL 	string - the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\
// ClientID - 	string - the OAuth ClientID ie "123456.apps.googleusercontent.com"
// ClientSecret string - the OAuth Client Secret
// ProxyClientID - string - the client id that matches the sso proxy client id
// ProxyClientSecret - string - the client secret that matches the sso proxy client secret
// Host - string - The host that is in the header that is required on incoming requests
// Port - string - Port to listen on
// EmailDomains - []string - authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email
// ProxyRootDomains - []string - only redirect to specified proxy domains (may be given multiple times)
// GoogleAdminEmail - string - the google admin to impersonate for api calls
// GoogleServiceAccountJSON - string - the path to the service account json credentials
// Footer - string custom footer string. Use \"-\" to disable default footer.
// CookieSecret - string - the seed string for secure cookies (optionally base64 encoded)
// CookieDomain - string - an optional cookie domain to force cookies to (ie: .yourcompany.com)*
// CookieExpire - duration - expire timeframe for cookie, defaults at 168 hours
// CookieRefresh - duration - refresh the cookie after this duration default 0
// CookieSecure - bool - set secure (HTTPS) cookie flag
// CookieHTTPOnly - bool - set httponly cookie flag
// RequestTimeout - duration - overall request timeout
// AuthCodeSecret - string - the seed string for secure auth codes (optionally base64 encoded)
// PassHostHeader - bool - pass the request Host Header to upstream (default true)
// SkipProviderButton - bool - if true, will skip sign-in-page to directly reach the next step: oauth/start
// PassUserHeaders - bool (default true) - pass X-Forwarded-User and X-Forwarded-Email information to upstream
// SetXAuthRequest - set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)
// Provider - provider name
// SignInURL - provider sign in endpoint
// RedeemURL - provider token redemption endpoint
// ProfileURL - provider profile access endpoint
// ValidateURL - access token validation endpoint
// Scope - Oauth scope specification
// ApprovalPrompt - OAuth approval prompt
// RequestLogging - bool to log requests
// StatsdPort - port where statsd client listens
// StatsdHost - host where statsd client listens
type Options struct {
	RedirectURL       string `envconfig:"REDIRECT_URL" `
	ClientID          string `envconfig:"CLIENT_ID"`
	ClientSecret      string `envconfig:"CLIENT_SECRET"`
	ProxyClientID     string `envconfig:"PROXY_CLIENT_ID"`
	ProxyClientSecret string `envconfig:"PROXY_CLIENT_SECRET"`

	Host string `envconfig:"HOST"`
	Port int    `envconfig:"PORT" default:"4180"`

	EmailDomains     []string `envconfig:"SSO_EMAIL_DOMAIN"`
	ProxyRootDomains []string `envconfig:"PROXY_ROOT_DOMAIN"`

	AzureTenant              string `envconfig:"AZURE_TENANT"`
	GoogleAdminEmail         string `envconfig:"GOOGLE_ADMIN_EMAIL"`
	GoogleServiceAccountJSON string `envconfig:"GOOGLE_SERVICE_ACCOUNT_JSON"`

	Footer string `envconfig:"FOOTER"`

	CookieName     string
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE" default:"168h"`
	CookieRefresh  time.Duration `envconfig:"COOKIE_REFRESH" default:"1h"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE" default:"true"`
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY" default:"true"`

	RequestTimeout  time.Duration `envconfig:"REQUEST_TIMEOUT" default:"2s"`
	TCPWriteTimeout time.Duration `envconfig:"TCP_WRITE_TIMEOUT" default:"30s"`
	TCPReadTimeout  time.Duration `envconfig:"TCP_READ_TIMEOUT" default:"30s"`

	AuthCodeSecret string `envconfig:"AUTH_CODE_SECRET"`

	GroupsCacheRefreshTTL time.Duration `envconfig:"GROUPS_CACHE_REFRESH_TTL" default:"10m"`
	SessionLifetimeTTL    time.Duration `envconfig:"SESSION_LIFETIME_TTL" default:"720h"`

	PassHostHeader     bool `envconfig:"PASS_HOST_HEADER" default:"true"`
	SkipProviderButton bool `envconfig:"SKIP_PROVIDER_BUTTON"`
	PassUserHeaders    bool `envconfig:"PASS_USER_HEADERS" default:"true"`
	SetXAuthRequest    bool `envconfig:"SET_XAUTHREQUEST" default:"false"`

	// These options allow for other providers besides Google, with potential overrides.
	Provider       string `envconfig:"PROVIDER" default:"google"`
	SignInURL      string `envconfig:"SIGNIN_URL"`
	RedeemURL      string `envconfig:"REDEEM_URL"`
	ProfileURL     string `envconfig:"PROFILE_URL"`
	ValidateURL    string `envconfig:"VALIDATE_URL"`
	Scope          string `envconfig:"SCOPE"`
	ApprovalPrompt string `envconfig:"APPROVAL_PROMPT" default:"force"`

	RequestLogging bool `envconfig:"REQUEST_LOGGING" default:"true"`

	StatsdPort int    `envconfig:"STATSD_PORT"`
	StatsdHost string `envconfig:"STATSD_HOST"`

	// internal values that are set after config validation
	redirectURL         *url.URL
	decodedCookieSecret []byte
	GroupsCacheStopFunc func()
}

// SignatureData represents the data associated with signatures
type SignatureData struct {
	hash crypto.Hash
	key  string
}

// NewOptions returns new options
func NewOptions() *Options {
	return &Options{
		Port:            4180,
		CookieName:      "_sso_auth",
		CookieSecure:    true,
		CookieHTTPOnly:  true,
		CookieExpire:    time.Duration(168) * time.Hour,
		CookieRefresh:   time.Duration(0),
		SetXAuthRequest: false,
		PassUserHeaders: true,
		PassHostHeader:  true,
		ApprovalPrompt:  "force",
		RequestLogging:  true,
	}
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}

// Validate validates options
func (o *Options) Validate() error {
	msgs := make([]string, 0)
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o.ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}
	if len(o.EmailDomains) == 0 {
		msgs = append(msgs, "missing setting for email validation: email-domain required.\n      use email-domain=* to authorize all email addresses")
	}
	if len(o.ProxyRootDomains) == 0 {
		msgs = append(msgs, "missing setting: proxy-root-domain")
	}
	if o.ProxyClientID == "" {
		msgs = append(msgs, "missing setting: proxy-client-id")
	}
	if o.ProxyClientSecret == "" {
		msgs = append(msgs, "missing setting: proxy-client-secret")
	}
	if o.Host == "" {
		msgs = append(msgs, "missing setting: required-host-header")
	}

	o.redirectURL, msgs = parseURL(o.RedirectURL, "redirect", msgs)

	msgs = validateEndpoints(o, msgs)

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

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	msgs = validateCookieName(o, msgs)

	if o.StatsdHost == "" {
		msgs = append(msgs, "missing setting: no host specified for statsd metrics collections")
	}

	if o.StatsdPort == 0 {
		msgs = append(msgs, "missing setting: no port specified for statsd metrics collections")
	}

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func validateEndpoints(o *Options, msgs []string) []string {
	_, msgs = parseURL(o.SignInURL, "signin", msgs)
	_, msgs = parseURL(o.RedeemURL, "redeem", msgs)
	_, msgs = parseURL(o.ProfileURL, "profile", msgs)
	_, msgs = parseURL(o.ValidateURL, "validate", msgs)

	return msgs
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func newProvider(o *Options) (providers.Provider, error) {
	p := &providers.ProviderData{
		Scope:              o.Scope,
		ClientID:           o.ClientID,
		ClientSecret:       o.ClientSecret,
		ApprovalPrompt:     o.ApprovalPrompt,
		SessionLifetimeTTL: o.SessionLifetimeTTL,
	}

	var err error
	if p.SignInURL, err = url.Parse(o.SignInURL); err != nil {
		return nil, err
	}
	if p.RedeemURL, err = url.Parse(o.RedeemURL); err != nil {
		return nil, err
	}
	p.RevokeURL = &url.URL{}
	if p.ProfileURL, err = url.Parse(o.ProfileURL); err != nil {
		return nil, err
	}
	if p.ValidateURL, err = url.Parse(o.ValidateURL); err != nil {
		return nil, err
	}

	var singleFlightProvider providers.Provider
	switch o.Provider {
	case providers.AzureProviderName:
		azureProvider, err := providers.NewAzureV2Provider(p)
		if err != nil {
			return nil, err
		}
		azureProvider.Configure(o.AzureTenant)
		singleFlightProvider = providers.NewSingleFlightProvider(azureProvider)
	case providers.GoogleProviderName:
		if o.GoogleServiceAccountJSON != "" {
			_, err := os.Open(o.GoogleServiceAccountJSON)
			if err != nil {
				return nil, fmt.Errorf("invalid Google credentials file: %s", o.GoogleServiceAccountJSON)
			}
		}
		googleProvider, err := providers.NewGoogleProvider(p, o.GoogleAdminEmail, o.GoogleServiceAccountJSON)
		if err != nil {
			return nil, err
		}
		cache := groups.NewFillCache(googleProvider.PopulateMembers, o.GroupsCacheRefreshTTL)
		googleProvider.GroupsCache = cache
		o.GroupsCacheStopFunc = cache.Stop
		singleFlightProvider = providers.NewSingleFlightProvider(googleProvider)
	default:
		return nil, fmt.Errorf("unimplemented provider: %q", o.Provider)
	}

	return singleFlightProvider, nil
}

// AssignProvider is a function that takes an Options struct and assigns the
// appropriate provider to the proxy. Should be called prior to
// AssignStatsdClient.
func AssignProvider(opts *Options) func(*Authenticator) error {
	return func(proxy *Authenticator) error {
		var err error
		proxy.provider, err = newProvider(opts)
		return err
	}
}

// AssignStatsdClient is function that takes in an Options struct and assigns a statsd client
// to the proxy and provider.
func AssignStatsdClient(opts *Options) func(*Authenticator) error {
	return func(proxy *Authenticator) error {
		logger := log.NewLogEntry()

		StatsdClient, err := newStatsdClient(opts.StatsdHost, opts.StatsdPort)
		if err != nil {
			return fmt.Errorf("error setting up statsd client error=%s", err)
		}
		logger.WithStatsdHost(opts.StatsdHost).WithStatsdPort(opts.StatsdPort).Info(
			"statsd client is running")

		proxy.StatsdClient = StatsdClient
		switch v := proxy.provider.(type) {
		case *providers.AzureV2Provider:
			v.SetStatsdClient(StatsdClient)
		case *providers.GoogleProvider:
			v.SetStatsdClient(StatsdClient)
		case *providers.SingleFlightProvider:
			v.AssignStatsdClient(StatsdClient)
		default:
			logger.Info("provider does not have statsd client")
		}
		return nil
	}
}
