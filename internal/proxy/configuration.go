package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/micro/go-micro/config"
	"github.com/micro/go-micro/config/source/env"
	"github.com/mitchellh/mapstructure"
)

// DefaultProxyCongig specifies all the defaults used to configure sso-proxy
// All configuration can be set using environment variables. Below is a list of
// configuration variables via their environment configuraiton
//
// SESSION_COOKIE_NAME
// SESSION_COOKIE_SECRET
// SESSION_COOKIE_EXPIRE
// SESSION_COOKIE_DOMAIN
// SESSION_COOKIE_HTTPONLY
// SESSION_TTL_LIFETIME
// SESSION_TTL_VALID
// SESSION_TTL_GRACEPERIOD
//
// REQUESTSIGNER_KEY
//
// CLIENT_ID
// CLIENT_SECRET
//
// SERVER_PORT
// SERVER_TIMEOUT_SHUTDOWN
// SERVER_TIMEOUT_READ
// SERVER_TIMEOUT_WRITE
//
// METRICS_STATSD_HOST
// METRICS_STATSD_PORT
//
// LOGGING_ENABLE
//
// UPSTREAM_DEFAULT_EMAIL_DOMAINS
// UPSTREAM_DEFAULT_EMAIL_ADDRESSES
// UPSTREAM_DEFAULT_GROUPS
// UPSTREAM_DEFAULT_TIMEOUT
// UPSTREAM_DEFAULT_TCP_RESET_DEADLINE
// UPSTREAM_DEFAULT_PROVIDER
// UPSTREAM_CONFIGS_FILE
// UPSTREAM_SCHEME
// UPSTREAM_CLUSTER
//
// PROVIDER_TYPE
// PROVIDER_URL_EXTERNAL
// PROVIDER_URL_INTERNAL
// PROVIDER_SCOPE

func DefaultProxyConfig() Configuration {
	return Configuration{
		ServerConfig: ServerConfig{
			Port: 4180,
			TimeoutConfig: &TimeoutConfig{
				Write:    30 * time.Second,
				Read:     30 * time.Second,
				Shutdown: 30 * time.Second,
			},
		},
		ProviderConfig: ProviderConfig{
			ProviderType: "sso",
		},
		SessionConfig: SessionConfig{
			CookieConfig: CookieConfig{
				Name:     "_sso_proxy",
				Expire:   168 * time.Hour,
				Secure:   true,
				HTTPOnly: true,
			},
			TTLConfig: TTLConfig{
				Lifetime:    720 * time.Hour,
				Valid:       60 * time.Second,
				GracePeriod: 3 * time.Hour,
			},
		},
		UpstreamConfigs: UpstreamConfigs{
			DefaultConfig: DefaultConfig{
				Timeout:       10 * time.Second,
				ResetDeadline: 60 * time.Second,
				ProviderSlug:  "google",
			},
			Scheme: "https",
		},
		LoggingConfig: LoggingConfig{
			Enable: true,
		},
		MetricsConfig: MetricsConfig{
			StatsdConfig: StatsdConfig{
				Port: 8125,
				Host: "localhost",
			},
		},
	}
}

type Validator interface {
	Validate() error
}

var (
	_ Validator = Configuration{}
	_ Validator = ProviderConfig{}
	_ Validator = SessionConfig{}
	_ Validator = CookieConfig{}
	_ Validator = TTLConfig{}
	_ Validator = ClientConfig{}
	_ Validator = ServerConfig{}
	_ Validator = TimeoutConfig{}
	_ Validator = MetricsConfig{}
	_ Validator = StatsdConfig{}
	_ Validator = LoggingConfig{}
	_ Validator = UpstreamConfigs{}
	_ Validator = DefaultConfig{}
	_ Validator = EmailConfig{}
	_ Validator = RequestSignerConfig{}
)

type Configuration struct {
	ServerConfig        ServerConfig        `mapstructure:"server"`
	ProviderConfig      ProviderConfig      `mapstructure:"provider"`
	ClientConfig        ClientConfig        `mapstructure:"client"`
	SessionConfig       SessionConfig       `mapstructure:"session"`
	UpstreamConfigs     UpstreamConfigs     `mapstructure:"upstream"`
	MetricsConfig       MetricsConfig       `mapstructrue:"metrics"`
	LoggingConfig       LoggingConfig       `mapstructure:"logging"`
	RequestSignerConfig RequestSignerConfig `mapstructure:"requestsigner"`
}

func (c Configuration) Validate() error {
	var validationErrors []string

	if err := c.ServerConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid server config: %s", err))
	}

	if err := c.ProviderConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid provider config: %s", err))
	}

	if err := c.SessionConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid session config: %s", err))
	}

	if err := c.ClientConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid client config: %s", err))
	}

	if err := c.UpstreamConfigs.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid upstream config: %s", err))
	}

	if err := c.MetricsConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid metrics config: %s", err))
	}

	if err := c.LoggingConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid metrics config: %s", err))
	}

	if err := c.RequestSignerConfig.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Sprintf("invalid metrics config: %s", err))
	}

	if len(validationErrors) != 0 {
		return fmt.Errorf(strings.Join(validationErrors, "\n"))
	}

	return nil
}

type ProviderConfig struct {
	ProviderType      string            `mapstructure:"type"`
	Scope             string            `mapstructure:"scope"`
	ProviderURLConfig ProviderURLConfig `mapstructure:"url"`
}

func (pc ProviderConfig) Validate() error {
	if err := pc.ProviderURLConfig.Validate(); err != nil {
		return fmt.Errorf("invalid provider.providerurl config: %w", err)
	}

	if pc.ProviderType == "" {
		return fmt.Errorf("no provider.type configured")
	}

	return nil
}

type ProviderURLConfig struct {
	External string `mapstructure:"external"`
	Internal string `mapstructure:"internal"`
}

func (puc ProviderURLConfig) Validate() error {
	if puc.External == "" {
		return errors.New("no providerurl.external configured")
	} else {
		providerURLExternal, err := url.Parse(puc.External)
		if err != nil {
			return err
		}
		if providerURLExternal.Scheme == "" || providerURLExternal.Host == "" {
			return errors.New("providerurl.external must include scheme and host")
		}
	}

	if puc.Internal != "" {
		providerURLInternal, err := url.Parse(puc.Internal)
		if err != nil {
			return err
		}
		if providerURLInternal.Scheme == "" || providerURLInternal.Host == "" {
			return errors.New("providerurl.internal must include scheme and host")
		}
	}
	return nil
}

type SessionConfig struct {
	CookieConfig CookieConfig `mapstructure:"cookie"`
	TTLConfig    TTLConfig    `mapstructure:"ttl"`
}

func (sc SessionConfig) Validate() error {
	if err := sc.CookieConfig.Validate(); err != nil {
		return fmt.Errorf("invalid session.cookie config: %w", err)
	}

	if err := sc.TTLConfig.Validate(); err != nil {
		return fmt.Errorf("invalid session.ttl config: %w", err)
	}
	return nil
}

type CookieConfig struct {
	Name     string        `mapstructure:"name"`
	Secret   string        `mapstructure:"secret"`
	Expire   time.Duration `mapstructure:"expire"`
	Domain   string        `mapstructure:"domain"`
	Secure   bool          `mapstructure:"secure"`
	HTTPOnly bool          `mapstructure:"httponly"`
}

func (cc CookieConfig) Validate() error {
	if cc.Secret == "" {
		return fmt.Errorf("no cookie.secret configured")
	}
	decodedCookieSecret, err := base64.StdEncoding.DecodeString(cc.Secret)
	if err != nil {
		return fmt.Errorf("invalid cookie.secret configured; expected base64-encoded bytes, as from `openssl rand 32 -base64`: %q", err)
	}

	validCookieSecretLength := false
	for _, i := range []int{32, 64} {
		if len(decodedCookieSecret) == i {
			validCookieSecretLength = true
		}
	}
	if !validCookieSecretLength {
		return fmt.Errorf("invalid value for cookie.secret; must decode to 32 or 64 bytes, but decoded to %d bytes", len(decodedCookieSecret))
	}

	cookie := &http.Cookie{Name: cc.Name}
	if cookie.String() == "" {
		return fmt.Errorf("invalid cc.name: %q", cc.Name)
	}
	return nil
}

type TTLConfig struct {
	Lifetime    time.Duration `mapstructure:"lifetime"`
	Valid       time.Duration `mapstructure:"valid"`
	GracePeriod time.Duration `mapstructre:"grace_period"`
}

func (ttlc TTLConfig) Validate() error {
	return nil
}

type ClientConfig struct {
	ID     string `mapstructure:"id"`
	Secret string `mapstructure:"secret"`
}

func (cc ClientConfig) Validate() error {
	if cc.ID == "" {
		return fmt.Errorf("no client.id configured")
	}
	if cc.Secret == "" {
		return fmt.Errorf("no client.secret configured")
	}
	return nil
}

type ServerConfig struct {
	Port          int            `mapstructure:"port"`
	TimeoutConfig *TimeoutConfig `mapstructure:"timeout"`
}

func (sc ServerConfig) Validate() error {
	if sc.Port == 0 {
		return errors.New("no server.port configured")
	}

	if err := sc.TimeoutConfig.Validate(); err != nil {
		return fmt.Errorf("invalid server.timeout config: %w", err)
	}
	return nil
}

type TimeoutConfig struct {
	Write    time.Duration `mapstructure:"write"`
	Read     time.Duration `mapstructure:"read"`
	Shutdown time.Duration `mapstructure:"shutdown"`
}

func (tc TimeoutConfig) Validate() error {
	return nil
}

type MetricsConfig struct {
	StatsdConfig StatsdConfig `mapstructure:"statsd"`
}

func (mc MetricsConfig) Validate() error {
	if err := mc.StatsdConfig.Validate(); err != nil {
		return fmt.Errorf("invalid metrics.statsd config: %w", err)
	}

	return nil
}

type StatsdConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

func (sc StatsdConfig) Validate() error {
	if sc.Host == "" {
		return errors.New("no statsd.host configured")
	}

	if sc.Port == 0 {
		return errors.New("no statsd.port configured")
	}

	return nil
}

type LoggingConfig struct {
	Enable bool `mapstructure:"enable"`
}

func (lc LoggingConfig) Validate() error {
	return nil
}

type UpstreamConfigs struct {
	DefaultConfig    DefaultConfig `mapstructure:"default"`
	ConfigsFile      string        `mapstructure:"configfile"`
	testTemplateVars map[string]string
	upstreamConfigs  []*UpstreamConfig
	Cluster          string `mapstructure:"cluster"`
	Scheme           string `mapstructure:"scheme"`
}

func (uc UpstreamConfigs) Validate() error {
	if err := uc.DefaultConfig.Validate(); err != nil {
		return fmt.Errorf("invalid upstream.defaultconfig: %w", err)
	}

	if uc.ConfigsFile != "" {
		r, err := os.Open(uc.ConfigsFile)
		if err != nil {
			return fmt.Errorf("invalid upstream.configfile: %w", err)
		}
		r.Close()
	}

	if uc.Cluster == "" {
		return errors.New("no upstream.cluster configured")
	}
	return nil
}

type DefaultConfig struct {
	EmailConfig   EmailConfig   `mapstructure:"email"`
	AllowedGroups []string      `mapstructure:"groups"`
	ProviderSlug  string        `mapstructure:"provider"`
	Timeout       time.Duration `mapstructure:"timeout"`
	ResetDeadline time.Duration `mapstructure:"resetdeadline"`
}

func (dc DefaultConfig) Validate() error {
	if err := dc.EmailConfig.Validate(); err != nil {
		return fmt.Errorf("invalid default.emailconfig: %w", err)
	}

	if dc.ProviderSlug == "" {
		return fmt.Errorf("no defaultconfig.provider configured")
	}

	return nil
	//TODO tests here - timeout and reset deadline?
}

type EmailConfig struct {
	AllowedDomains   []string `mapstructure:"domains"`
	AllowedAddresses []string `mapstructure:"addresses"`
}

func (ec EmailConfig) Validate() error {
	return nil
}

type RequestSignerConfig struct {
	Key string `mapstructure:"key"`
}

func (rsc RequestSignerConfig) Validate() error {
	return nil
}

// LoadConfig loads all the configuration from env and defaults
func LoadConfig() (Configuration, error) {
	c := DefaultProxyConfig()

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
