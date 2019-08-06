package auth

import (
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/micro/go-micro/config"
	"github.com/micro/go-micro/config/source/env"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/xerrors"
)

// DefaultAuthConfig specifies all the defaults used to configure sso-auth
// All configuration can be set using environment variables. Below is a list of
// configuration variables via their envivronment configuration
//
// SESSION COOKIE_NAME
// SESSION_COOKIE_SECRET
// SESSION_COOKIE_EXPIRE
// SESSION_COOKIE_DOMAIN
// SESSION_COOKIE_REFRESH
// SESSION_COOKIE_SECURE
// SESSION_COOKIE_HTTPONLY
// SESSION_LIFETIME
// SESSION_KEY
//
// CLIENT_PROXY_ID
// CLIENT_PROXY_SECRET
//
// PROVIDER_*_TYPE
// PROVIDER_*_SLUG
// PROVIDER_*_CLIENT_ID
// PROVIDER_*_CLIENT_SECRET
// PROVIDER_*_SCOPE
//
// PROVIDER_*_GOOGLE_CREDENTIALS
// PROVIDER_*_GOOGLE_IMPERSONATE
// PROVIDER_*_GOOGLE_PROMPT
// PROVIDER_*_GOOGLE_DOMAIN
//
// PROVIDER_*_OKTA_URL
// PROVIDER_*_OKTA_SERVER
//
// PROVIDER_*_GROUPCACHE_INTERVAL_REFRESH
// PROVIDER_*_GROUPCACHE_INTERVAL_PROVIDER
//
// SERVER_SCHEME
// SERVER_HOST
// SERVER_PORT
// SERVER_TIMEOUT_REQUEST
// SERVER_TIMEOUT_WRITE
// SERVER_TIMEOUT_READ
//
// AUTHORIZE_PROXY_DOMAINS
// AUTHORIZE_EMAIL_DOMAINS
// AUTHORIZE_EMAIL_ADDRESSES
//
// METRICS_STATSD_PORT
// METRICS_STATSD_HOST
//
// LOGGING_ENABLE
// LOGGING_LEVEL

func DefaultAuthConfig() Configuration {
	return Configuration{
		ProviderConfigs: map[string]ProviderConfig{},
		ClientConfigs: map[string]ClientConfig{
			"proxy": ClientConfig{},
		},
		ServerConfig: ServerConfig{
			Port:   4180,
			Scheme: "https",
			TimeoutConfig: TimeoutConfig{
				Write:   30 * time.Second,
				Read:    30 * time.Second,
				Request: 45 * time.Second,
			},
		},
		SessionConfig: SessionConfig{
			SessionLifetimeTTL: (30 * 24) * time.Hour,
			CookieConfig: CookieConfig{
				Expire:   (7 * 24) * time.Hour,
				Name:     "_sso_auth",
				Secure:   true,
				HTTPOnly: true,
			},
		},
		LoggingConfig: LoggingConfig{
			Enable: true,
			Level:  "info",
		},
		MetricsConfig: MetricsConfig{
			StatsdConfig: StatsdConfig{
				Port: 8125,
				Host: "localhost",
			},
		},
		// we provide no defaults for these right now
		AuthorizeConfig: AuthorizeConfig{
			ProxyConfig: ProxyConfig{
				Domains: []string{},
			},
		},
	}
}

// Validator interface ensures all config structs implement Validate()
type Validator interface {
	Validate() error
}

var (
	_ Validator = Configuration{}
	_ Validator = ProviderConfig{}
	_ Validator = ClientConfig{}
	_ Validator = AuthorizeConfig{}
	_ Validator = ProxyConfig{}
	_ Validator = ServerConfig{}
	_ Validator = MetricsConfig{}
	_ Validator = GoogleProviderConfig{}
	_ Validator = OktaProviderConfig{}
	_ Validator = CookieConfig{}
	_ Validator = TimeoutConfig{}
	_ Validator = StatsdConfig{}
	_ Validator = LoggingConfig{}
)

// Configuration is the parent struct that holds all the configuration
type Configuration struct {
	ProviderConfigs map[string]ProviderConfig `mapstructure:"provider"`
	ClientConfigs   map[string]ClientConfig   `mapstructure:"client"`
	AuthorizeConfig AuthorizeConfig           `mapstructure:"authorize"`
	SessionConfig   SessionConfig             `mapstructure:"session"`
	ServerConfig    ServerConfig              `mapstructure:"server"`
	MetricsConfig   MetricsConfig             `mapstructrue:"metrics"`
	LoggingConfig   LoggingConfig             `mapstructure:"logging"`
}

func (c Configuration) Validate() error {
	for slug, providerConfig := range c.ProviderConfigs {
		if err := providerConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid provider.%s config: %w", slug, err)
		}
	}

	for slug, clientConfig := range c.ClientConfigs {
		if err := clientConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid client.%s config: %w", slug, err)
		}
	}

	if err := c.SessionConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session config: %w", err)
	}

	if err := c.ServerConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid server config: %w", err)
	}

	if err := c.AuthorizeConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid authorize config: %w", err)
	}

	if err := c.MetricsConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics config: %w", err)
	}

	return nil
}

type ProviderConfig struct {
	ProviderType string       `mapstructure:"type"`
	ProviderSlug string       `mapstructure:"slug"`
	ClientConfig ClientConfig `mapstructure:"client"`
	Scope        string       `mapstructure:"scope"`

	// provider specific
	GoogleProviderConfig GoogleProviderConfig `mapstructure:"google"`
	OktaProviderConfig   OktaProviderConfig   `mapstructure:"okta"`

	// caching
	GroupCacheConfig GroupCacheConfig `mapstructure:"groupcache"`
}

func (pc ProviderConfig) Validate() error {
	if pc.ProviderType == "" {
		return xerrors.Errorf("invalid provider.type: %q", pc.ProviderType)
	}

	// TODO: more validation of provider slug, should conform to simple character space
	if pc.ProviderSlug == "" {
		return xerrors.Errorf("invalid provider.slug: %q", pc.ProviderSlug)
	}

	if err := pc.ClientConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid provider.client: %w", err)
	}

	switch pc.ProviderType {
	case "google":
		if err := pc.GoogleProviderConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid provider.google config: %w", err)
		}
	case "okta":
		if err := pc.OktaProviderConfig.Validate(); err != nil {
			return xerrors.Errorf("invalid provider.okta config: %w", err)
		}
	case "test":
		break
	default:
		return xerrors.Errorf("unknown provider.type: %q", pc.ProviderType)
	}

	if err := pc.GroupCacheConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid provider.groupcache config: %w", err)
	}

	return nil
}

type GoogleProviderConfig struct {
	Credentials    string `mapstructure:"credentials"`
	Impersonate    string `mapstructure:"impersonate"`
	ApprovalPrompt string `mapstructure:"prompt"`
	HostedDomain   string `mapstructure:"domain"`
}

func (gpc GoogleProviderConfig) Validate() error {
	// must specify both credentials and impersonate or neither
	if (len(gpc.Credentials) > 0) != (len(gpc.Impersonate) > 0) {
		return xerrors.New("must specify both google.credentials and google.impersonate")
	}

	// verify the credentials file can be opened
	if gpc.Credentials != "" {
		r, err := os.Open(gpc.Credentials)
		if err != nil {
			return xerrors.Errorf("invalid google.credentials filepath: %w", err)
		}
		r.Close()
	}

	return nil
}

type OktaProviderConfig struct {
	ServerID string `mapstructure:"server"`
	OrgURL   string `mapstructure:"url"`
}

func (opc OktaProviderConfig) Validate() error {
	if opc.OrgURL == "" {
		return xerrors.New("no okta.url is configured")
	}

	if opc.ServerID == "" {
		return xerrors.New("no okta.server is configured")
	}

	return nil
}

type GroupCacheConfig struct {
	Interval struct {
		Provider time.Duration `mapstructure:"provider"`
		Refresh  time.Duration `mapstructure:"refresh"`
	} `mapstructure:"interval"`
}

func (gcc GroupCacheConfig) Validate() error {
	return nil
}

type SessionConfig struct {
	CookieConfig CookieConfig `mapstructure:"cookie"`

	SessionLifetimeTTL time.Duration `mapstructure:"lifetime"`
	Key                string        `mapstructure:"key"`
}

func (sc SessionConfig) Validate() error {
	if sc.Key == "" {
		return xerrors.New("no session.key configured")
	}

	if err := validateCipherKeyValue(sc.Key); err != nil {
		return xerrors.Errorf("invalid session.key: %w", err)
	}

	if sc.SessionLifetimeTTL >= (365*24)*time.Hour || sc.SessionLifetimeTTL <= 1*time.Minute {
		return xerrors.Errorf("session.lifetime must be between 1 minute and 1 year but is: %v", sc.SessionLifetimeTTL)
	}

	if err := sc.CookieConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid session.cookie config: %w", err)
	}

	return nil
}

func validateCipherKeyValue(val string) error {
	s, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return xerrors.Errorf("expected base64-encoded bytes, as from `openssl rand 32 -base64`: %w", err)
	}

	slen := len(s)
	if slen != 32 && slen != 64 {
		return xerrors.Errorf("expected to decode 32 or 64 base64-encoded bytes, but decoded %d", slen)
	}

	return nil
}

type CookieConfig struct {
	Name     string        `mapstructure:"name"`
	Secret   string        `mapstructure:"secret"`
	Domain   string        `mapstructure:"domain"`
	Expire   time.Duration `mapstructure:"expire"`
	Secure   bool          `mapstructure:"secure"`
	HTTPOnly bool          `mapstructure:"httponly"`
}

func (cc CookieConfig) Validate() error {
	// TODO: Validate cookie secret:
	if cc.Name == "" {
		return xerrors.New("no cookie.name configured")
	}

	cookie := &http.Cookie{Name: cc.Name}
	if cookie.String() == "" {
		return xerrors.Errorf("invalid cookie.name: %q", cc.Name)
	}

	if cc.Secret == "" {
		return xerrors.New("no cookie.secret configured")
	}

	if err := validateCipherKeyValue(cc.Secret); err != nil {
		return xerrors.Errorf("invalid cookie.secret: %w", err)
	}

	return nil
}

type ServerConfig struct {
	Host   string `mapstructure:"host"`
	Port   int    `mapstructure:"port"`
	Scheme string `mapstructure:"scheme"`

	TimeoutConfig TimeoutConfig `mapstructure:"timeout"`
}

func (sc ServerConfig) Validate() error {
	if sc.Host == "" {
		return xerrors.New("no server.host configured")
	}

	if sc.Port == 0 {
		return xerrors.New("no server.port configured")
	}

	if err := sc.TimeoutConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid server.tcp config: %w", err)
	}

	return nil
}

type TimeoutConfig struct {
	Write   time.Duration `mapstructure:"write"`
	Read    time.Duration `mapstructure:"read"`
	Request time.Duration `mapstructure:"request"`
}

func (tc TimeoutConfig) Validate() error {
	return nil
}

type ClientConfig struct {
	ID     string `mapstructure:"id"`
	Secret string `mapstructure:"secret"`
}

func (cc ClientConfig) Validate() error {
	if cc.ID == "" {
		return xerrors.New("no client.id configured")
	}

	if cc.Secret == "" {
		return xerrors.New("no client.secret configured")
	}

	return nil
}

type AuthorizeConfig struct {
	ProxyConfig ProxyConfig `mapstructure:"proxy"`
}

func (ac AuthorizeConfig) Validate() error {
	if err := ac.ProxyConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid authorize.proxy config: %w", err)
	}

	return nil
}

type ProxyConfig struct {
	Domains []string `mapstructure:"domains"`
}

func (pc ProxyConfig) Validate() error {
	if len(pc.Domains) == 0 {
		return xerrors.New("no proxy.domains configured")
	}

	return nil
}

type MetricsConfig struct {
	StatsdConfig StatsdConfig `mapstructure:"statsd"`
}

func (mc MetricsConfig) Validate() error {
	if err := mc.StatsdConfig.Validate(); err != nil {
		return xerrors.Errorf("invalid metrics.statsd config: %w", err)
	}

	return nil
}

type LoggingConfig struct {
	Enable bool   `mapstructure:"enable"`
	Level  string `mapstructure:"level"`
}

func (lc LoggingConfig) Validate() error {
	return nil
}

type StatsdConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

func (sc StatsdConfig) Validate() error {
	if sc.Host == "" {
		return xerrors.New("no statsd.host configured")
	}

	if sc.Port == 0 {
		return xerrors.New(" no statsd.port configured")
	}

	return nil
}

// LoadConfig loads all the configuration from env and defaults
func LoadConfig() (Configuration, error) {
	c := DefaultAuthConfig()

	conf := config.NewConfig()
	err := conf.Load(env.NewSource())
	if err != nil {
		return c, err
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
		Result: &c,
	})
	if err != nil {
		return c, err
	}

	err = decoder.Decode(conf.Map())
	if err != nil {
		return c, err
	}

	return c, nil
}
