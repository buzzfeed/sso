package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/groups"

	"github.com/datadog/datadog-go/statsd"
	"github.com/spf13/viper"
)

// Options are config options that can be set by environment variables
// RedirectURL - string - the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\
// ClientID - string - the OAuth ClientID ie "123456.apps.googleusercontent.com"
// ClientSecret string - the OAuth Client Secret
// OrgName - string - if using Okta as the provider, the Okta domain to use
// ProxyClientID - string - the client id that matches the sso proxy client id
// ProxyClientSecret - string - the client secret that matches the sso proxy client secret
// Host - string - The host that is in the header that is required on incoming requests
// Port - string - Port to listen on
// EmailDomains - []string - authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email
// EmailAddresses - []string - authenticate emails with the specified email address (may be given multiple times). Use * to authenticate any email
// ProxyRootDomains - []string - only redirect to specified proxy domains (may be given multiple times)
// GoogleAdminEmail - string - the google admin to impersonate for api calls
// GoogleServiceAccountJSON - string - the path to the service account json credentials
// CookieSecret - string - the seed string for secure cookies (optionally base64 encoded)
// CookieDomain - string - an optional cookie domain to force cookies to (ie: .yourcompany.com)*
// CookieExpire - duration - expire timeframe for cookie, defaults at 168 hours
// CookieRefresh - duration - refresh the cookie after this duration default 0
// CookieSecure - bool - set secure (HTTPS) cookie flag
// CookieHTTPOnly - bool - set httponly cookie flag
// RequestTimeout - duration - overall request timeout
// AuthCodeSecret - string - the seed string for secure auth codes (optionally base64 encoded)
// GroupCacheProviderTTL - time.Duration - cache TTL for the group-cache provider used for on-demand group caching
// GroupsCacheRefreshTTL - time.Duratoin - cache TTL for the groups fillcache mechanism used to preemptively fill group caches
// Provider - provider name
// ProviderSlug - string - client-side string used to uniquely identify a specific instantiation of an identity provider
// ProviderServerID - string - if using Okta as the provider, the authorisation server ID (defaults to 'default')
// Scope - Oauth scope specification
// ApprovalPrompt - OAuth approval prompt
// RequestLogging - bool to log requests
// StatsdPort - port where statsd client listens
// StatsdHost - host where statsd client listens
type Options struct {
	RedirectURL       string `mapstructure:"redirect_url" `
	ClientID          string `mapstructure:"client_id"`
	ClientSecret      string `mapstructure:"client_secret"`
	ProxyClientID     string `mapstructure:"proxy_client_id"`
	ProxyClientSecret string `mapstructure:"proxy_client_secret"`

	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`

	EmailDomains     []string `mapstructure:"sso_email_domain"`
	EmailAddresses   []string `mapstructure:"sso_email_addresses"`
	ProxyRootDomains []string `mapstructure:"proxy_root_domain"`

	GoogleAdminEmail         string `mapstructure:"google_admin_email"`
	GoogleServiceAccountJSON string `mapstructure:"google_service_account_json"`

	OrgURL string `mapstructure:"okta_org_url"`

	CookieName     string        `mapstructure:"cookie_name"`
	CookieSecret   string        `mapstructure:"cookie_secret"`
	CookieDomain   string        `mapstructure:"cookie_domain"`
	CookieExpire   time.Duration `mapstructure:"cookie_expire"`
	CookieRefresh  time.Duration `mapstructure:"cookie_refresh"`
	CookieSecure   bool          `mapstructure:"cookie_secure"`
	CookieHTTPOnly bool          `mapstructure:"cookie_http_only"`

	RequestTimeout  time.Duration `mapstructure:"request_timeout"`
	TCPWriteTimeout time.Duration `mapstructure:"tcp_write_timeout"`
	TCPReadTimeout  time.Duration `mapstructure:"tcp_read_timeout"`

	AuthCodeSecret string `mapstructure:"auth_code_secret"`

	GroupCacheProviderTTL time.Duration `mapstructure:"group_cache_provider_ttl"`
	GroupsCacheRefreshTTL time.Duration `mapstructure:"groups_cache_refresh_ttl"`
	SessionLifetimeTTL    time.Duration `mapstructure:"session_lifetime_ttl"`

	// These options allow for other providers besides Google, with potential overrides.
	Provider         string `mapstructure:"provider"`
	ProviderSlug     string `mapstructure:"provider_slug"`
	ProviderServerID string `mapstructure:"provider_server_id"`

	Scope          string `mapstructure:"scope"`
	ApprovalPrompt string `mapstructure:"approval_prompt"`

	RequestLogging bool `mapstructure:"request_logging"`

	StatsdPort int    `mapstructure:"statsd_port"`
	StatsdHost string `mapstructure:"statsd_host"`

	// internal values that are set after config validation
	redirectURL         *url.URL
	decodedCookieSecret []byte
	GroupsCacheStopFunc func()
}

// NewOptions returns new options with the below overrides
func NewOptions() (*Options, error) {
	v := viper.New()
	options, err := loadVars(v)
	if err != nil {
		return nil, err
	}
	return options, nil
}

// loadVars loads viper variables and returns a filled Options struct
func loadVars(v *viper.Viper) (*Options, error) {
	var opts Options

	bindAllOptVars(v, reflect.TypeOf(&opts).Elem(), "mapstructure")
	setDefaults(v)

	err := v.Unmarshal(&opts)
	if err != nil {
		return nil, fmt.Errorf("unable to decode env vars into options struct")
	}
	return &opts, nil
}

// bindAllOptVars takes in a struct with tags and uses the tag values to bind env vars
func bindAllOptVars(v *viper.Viper, t reflect.Type, tag string) error {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tagValue := field.Tag.Get(tag)
		err := v.BindEnv(tagValue)
		if err != nil {
			return fmt.Errorf("Unable to bind env var: %q", tagValue)
		}
	}
	return nil
}

// setDefaults sets config defaults for the default viper instance
func setDefaults(v *viper.Viper) {
	defaultVars := map[string]interface{}{
		"port":                     4180,
		"cookie_expire":            "168h",
		"cookie_name":              "_sso_auth",
		"cookie_refresh":           "1h",
		"cookie_secure":            true,
		"cookie_http_only":         true,
		"tcp_write_timeout":        "30s",
		"tcp_read_timeout":         "30s",
		"groups_cache_refresh_ttl": "10m",
		"group_cache_provider_ttl": "10m",
		"session_lifetime_ttl":     "720h",
		"provider":                 "google",
		"provider_slug":            "google",
		"provider_server_id":       "default",
		"approval_prompt":          "force",
		"request_logging":          true,
	}
	for key, value := range defaultVars {
		v.SetDefault(key, value)
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
	if len(o.EmailDomains) == 0 && len(o.EmailAddresses) == 0 {
		msgs = append(msgs, "missing setting for email validation: email-domain or email-address required.\n      use email-domain=* to authorize all email addresses")
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

	if len(o.OrgURL) > 0 {
		o.OrgURL = strings.Trim(o.OrgURL, `"`)
	}
	if len(o.ProviderServerID) > 0 {
		o.ProviderServerID = strings.Trim(o.ProviderServerID, `"`)
	}

	o.redirectURL, msgs = parseURL(o.RedirectURL, "redirect", msgs)

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

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func newProvider(o *Options) (providers.Provider, error) {
	p := &providers.ProviderData{
		ProviderSlug:       o.ProviderSlug,
		Scope:              o.Scope,
		ClientID:           o.ClientID,
		ClientSecret:       o.ClientSecret,
		ApprovalPrompt:     o.ApprovalPrompt,
		SessionLifetimeTTL: o.SessionLifetimeTTL,

		// set defaults so those aren't nil for future configuration
		SignInURL:   &url.URL{},
		RedeemURL:   &url.URL{},
		RevokeURL:   &url.URL{},
		ProfileURL:  &url.URL{},
		ValidateURL: &url.URL{},
	}

	var singleFlightProvider providers.Provider
	switch o.Provider {
	case providers.GoogleProviderName: // Google
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
	case providers.OktaProviderName:
		oktaProvider, err := providers.NewOktaProvider(p, o.OrgURL, o.ProviderServerID)
		if err != nil {
			return nil, err
		}
		tags := []string{"provider:okta"}

		groupsCache := providers.NewGroupCache(oktaProvider, o.GroupCacheProviderTTL, oktaProvider.StatsdClient, tags)
		singleFlightProvider = providers.NewSingleFlightProvider(groupsCache)
	default:
		return nil, fmt.Errorf("unimplemented provider: %q", o.Provider)
	}

	return singleFlightProvider, nil
}

// SetProvider is a function that takes a provider and assigns it to the authenticator.
func SetProvider(provider providers.Provider) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.provider = provider
		return nil
	}
}

// SetStatsdClient is function that takes in a statsd client and assigns it to the
// authenticator and provider.
func SetStatsdClient(statsdClient *statsd.Client) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.StatsdClient = statsdClient

		if a.provider != nil {
			a.provider.SetStatsdClient(statsdClient)
		}

		return nil
	}
}

// SetRedirectURL takes an options struct and identity provider slug to construct the
// url callback using the slug and configured redirect url.
func SetRedirectURL(opts *Options, slug string) func(*Authenticator) error {
	return func(a *Authenticator) error {
		redirectURL := new(url.URL)
		*redirectURL = *opts.redirectURL
		redirectURL.Path = path.Join(slug, "callback")
		a.redirectURL = redirectURL
		return nil
	}
}
