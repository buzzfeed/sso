package auth

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/groups"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
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
// Footer - string custom footer string. Use \"-\" to disable default footer.
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
// PassHostHeader - bool - pass the request Host Header to upstream (default true)
// SkipProviderButton - bool - if true, will skip sign-in-page to directly reach the next step: oauth/start
// PassUserHeaders - bool (default true) - pass X-Forwarded-User and X-Forwarded-Email information to upstream
// SetXAuthRequest - set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)
// Provider - provider name
// ProviderServerID - string - if using Okta as the provider, the authorisation server ID (defaults to 'default')
// SignInURL - provider sign in endpoint
// RedeemURL - provider token redemption endpoint
// RevokeURL - provider revoke token endpoint
// ProfileURL - provider profile access endpoint
// ValidateURL - access token validation endpoint
// Scope - Oauth scope specification
// ApprovalPrompt - OAuth approval prompt
// RequestLogging - bool to log requests
// StatsdPort - port where statsd client listens
// StatsdHost - host where statsd client listens

type Options struct {
	Port int `mapstructure:"handler_port"`

	EmailAddresses  []string      `mapstructure:"handler_sso_email_addresses"`
	RequestTimeout  time.Duration `mapstructure:"handler_request_timeout"`
	TCPWriteTimeout time.Duration `mapstructure:"handler_tcp_write_timeout"`
	TCPReadTimeout  time.Duration `mapstructure:"handler_tcp_read_timeout"`
	PassHostHeader  bool          `mapstructure:"handler_pass_host_header"`
	RequestLogging  bool          `mapstructure:"handler_request_logging"`

	ClientID                 string `mapstructure:"provider_client_id"`
	ClientSecret             string `mapstructure:"provider_client_secret"`
	GoogleAdminEmail         string `mapstructure:"provider_google_admin_email"`
	GoogleServiceAccountJSON string `mapstructure:"provider_google_service_account_json"`
	OrgURL                   string `mapstructure:"provider_okta_org_url"`
	Provider                 string `mapstructure:"provider_provider"`
	ProviderServerID         string `mapstructure:"provider_provider_server_id"`
	SignInURL                string `mapstructure:"provider_signin_url"`
	RedeemURL                string `mapstructure:"provider_redeem_url"`
	RedirectURL              string `mapstructure:"provider_redirect_url"`
	RevokeURL                string `mapstructure:"provider_revoke_url"`
	ProfileURL               string `mapstructure:"provider_profile_url"`
	ValidateURL              string `mapstructure:"provider_validate_url"`
	Scope                    string `mapstructure:"provider_scope"`
	ApprovalPrompt           string `mapstructure:"provider_approval_prompt"`

	GroupCacheProviderTTL time.Duration `mapstructure:"authenticator_group_cache_provider_ttl"`
	SkipProviderButton    bool          `mapstructure:"authenticator_skip_provider_button"`
	ProxyClientID         string        `mapstructure:"authenticator_proxy_client_id"`
	ProxyClientSecret     string        `mapstructure:"authenticator_proxy_client_secret"`
	Host                  string        `mapstructure:"authenticator_host"`
	EmailDomains          []string      `mapstructure:"authenticator_sso_email_domain"`
	ProxyRootDomains      []string      `mapstructure:"authenticator_proxy_root_domain"`
	Footer                string        `mapstructure:"authenticator_footer"`
	CookieName            string        `mapstructure:"authenticator_cookie_name"`
	CookieSecret          string        `mapstructure:"authenticator_cookie_secret"`
	CookieDomain          string        `mapstructure:"authenticator_cookie_domain"`
	CookieExpire          time.Duration `mapstructure:"authenticator_cookie_expire"`
	CookieRefresh         time.Duration `mapstructure:"authenticator_cookie_refresh"`
	CookieSecure          bool          `mapstructure:"authenticator_cookie_secure"`
	CookieHTTPOnly        bool          `mapstructure:"authenticator_cookie_http_only"`
	AuthCodeSecret        string        `mapstructure:"authenticator_auth_code_secret"`
	GroupsCacheRefreshTTL time.Duration `mapstructure:"authenticator_groups_cache_refresh_ttl"`
	PassUserHeaders       bool          `mapstructure:"authenticator_pass_user_headers"`
	SetXAuthRequest       bool          `mapstructure:"authenticator_set_xauthrequest"`
	redirectURL           *url.URL      `mapstructure:"authenticator_approval_prompt"`
	decodedCookieSecret   []byte        `mapstructure:"authenticator_set_xauthrequest"`

	SessionLifetimeTTL time.Duration `mapstructure:"global_session_lifetime_ttl"`
	StatsdPort         int           `mapstructure:"global_statsd_port"`
	StatsdHost         string        `mapstructure:"global_statsd_host"`

	GroupsCacheStopFunc func()
}

// SignatureData represents the data associated with signatures
type SignatureData struct {
	hash crypto.Hash
	key  string
}

// NewOptions returns new options with the below overrides
func NewOptions(prefix []string) (map[string]*Options, error) {
	v := viper.New()

	opts := make(map[string]*Options)
	for _, prefix := range prefix {
		options, err := loadVars(v, prefix)
		if err != nil {
			return nil, err
		}
		opts[prefix] = options
	}

	return opts, nil
}

// loadVars loads viper variables and returns a filled Options struct
func loadVars(v *viper.Viper, prefix string) (*Options, error) {
	var opts Options

	//v.SetEnvPrefix(prefix)
	bindAllOptVars(v, reflect.TypeOf(&opts).Elem(), "mapstructure", prefix)
	setDefaults(v)

	err := v.Unmarshal(&opts)
	if err != nil {
		return nil, fmt.Errorf("unable to decode env vars into options struct")
	}
	return &opts, nil
}

// bindAllOptVars takes in a struct with tags and uses the tag values to bind env vars
func bindAllOptVars(v *viper.Viper, t reflect.Type, tag, prefix string) error {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tagValue := field.Tag.Get(tag)
		// REVIEW: Explicitly set the env var for the key to bind to in BindEnv
		//         to get around needing to namespace the actual environment
		//         variables themselves. Instead, they are namespaced during
		//         the process of being pulled into the Viper config.

		//         This means we can't just pass []string{} to NewOptions though,
		//         as we we wouldn't know what namespace/prefix to search for.
		//         Viper would look for namespaced env vars e.g. 'provider_scope'
		//         and find nothing.
		envValue := strings.ToUpper(strings.TrimPrefix(tagValue, prefix+"_"))
		err := v.BindEnv(tagValue, envValue)
		if err != nil {
			return fmt.Errorf("Unable to bind env var: %q", tagValue)
		}
	}
	return nil
}

// setDefaults sets config defaults for the default viper instance
func setDefaults(v *viper.Viper) {
	defaultVars := map[string]interface{}{
		"authenticator_cookie_expire":            "168h",
		"authenticator_cookie_name":              "_sso_auth",
		"authenticator_cookie_refresh":           "1h",
		"authenticator_cookie_secure":            true,
		"authenticator_cookie_http_only":         true,
		"authenticator_groups_cache_refresh_ttl": "10m",
		"authenticator_group_cache_provider_ttl": "10m",
		"authenticator_pass_user_headers":        true,
		"authenticator_set_xauthrequest":         false,

		"provider_provider":           "google",
		"provider_provider_server_id": "default",
		"provider_approval_prompt":    "force",

		"handler_pass_host_header":  true,
		"handler_request_logging":   true,
		"handler_port":              4180,
		"handler_request_timeout":   "2s",
		"handler_tcp_write_timeout": "30s",
		"handler_tcp_read_timeout":  "30s",

		"global_session_lifetime_ttl": "720h",
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

// REVIEW: I wonder if we would like to separate out these tests into namespace specific test functions?
//         Preferred to keep one test function for all variables, or branch into separate provider/authenticator tests?

// Validate validates options
func Validate(o map[string]*Options) error {

	msgs := make([]string, 0)
	if o["authenticator"].CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o["provider"].ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o["provider"].ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}
	if len(o["authenticator"].EmailDomains) == 0 && len(o["authenticator"].EmailAddresses) == 0 {
		msgs = append(msgs, "missing setting for email validation: email-domain or email-address required.\n      use email-domain=* to authorize all email addresses")
	}
	if len(o["authenticator"].ProxyRootDomains) == 0 {
		msgs = append(msgs, "missing setting: proxy-root-domain")
	}
	if o["authenticator"].ProxyClientID == "" {
		msgs = append(msgs, "missing setting: proxy-client-id")
	}
	if o["authenticator"].ProxyClientSecret == "" {
		msgs = append(msgs, "missing setting: proxy-client-secret")
	}
	if o["authenticator"].Host == "" {
		msgs = append(msgs, "missing setting: required-host-header")
	}

	if len(o["provider"].OrgURL) > 0 {
		o["provider"].OrgURL = strings.Trim(o["provider"].OrgURL, `"`)
	}
	if len(o["provider"].ProviderServerID) > 0 {
		o["provider"].ProviderServerID = strings.Trim(o["provider"].ProviderServerID, `"`)
	}

	o["authenticator"].redirectURL, msgs = parseURL(o["provider"].RedirectURL, "redirect", msgs)

	msgs = validateEndpoints(o["provider"], msgs)

	decodedCookieSecret, err := base64.StdEncoding.DecodeString(o["authenticator"].CookieSecret)
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

	o["authenticator"].decodedCookieSecret = decodedCookieSecret

	if o["authenticator"].CookieRefresh >= o["authenticator"].CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o["authenticator"].CookieRefresh.String(),
			o["authenticator"].CookieExpire.String()))
	}

	msgs = validateCookieName(o["authenticator"], msgs)

	if o["global"].StatsdHost == "" {
		msgs = append(msgs, "missing setting: no host specified for statsd metrics collections")
	}

	if o["global"].StatsdPort == 0 {
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
	_, msgs = parseURL(o.RevokeURL, "revoke", msgs)
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
	if p.RevokeURL, err = url.Parse(o.RevokeURL); err != nil {
		return nil, err
	}
	if p.ProfileURL, err = url.Parse(o.ProfileURL); err != nil {
		return nil, err
	}
	if p.ValidateURL, err = url.Parse(o.ValidateURL); err != nil {
		return nil, err
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
		proxy.provider.SetStatsdClient(StatsdClient)
		return nil
	}
}
