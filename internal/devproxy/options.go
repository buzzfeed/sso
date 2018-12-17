package devproxy

import (
	// "encoding/base64"
	// "errors"
	"fmt"
	"io/ioutil"

	// "net/http"
	"net/url"
	"os"
	"strings"
	"time"
	// "github.com/datadog/datadog-go/statsd"
)

// Options are configuration options that can be set by Environment Variables
// Port - int -  port to listen on for HTTP clients
// ProviderURLString - the URL for the provider in this environment: "https://sso-auth.example.com"
// UpstreamConfigsFile - the path to upstream configs file
// Cluster - the cluster in which this is running, used for upstream configs
// Scheme - the default scheme, used for upstream configs
// DefaultUpstreamTimeout - the default time period to wait for a response from an upstream
// TCPWriteTimeout - http server tcp write timeout
// TCPReadTimeout - http server tcp read timeout
// SessionLifetimeTTL - time to live for a session lifetime
// SessionValidTTL - time to live for a valid session
// GracePeriodTTL - time to reuse session data when provider unavailable
// RequestLoging - boolean whether or not to log requests
// StatsdHost - host addr for statsd client to listen on
// StatsdPort - port for statsdclient to listen on
type Options struct {
	Port int `envconfig:"PORT" default:"4180"`

	UpstreamConfigsFile string `envconfig:"UPSTREAM_CONFIGS"`
	Cluster             string `envconfig:"CLUSTER"`
	Scheme              string `envconfig:"SCHEME" default:"https"`

	Host string `envconfig:"HOST"`

	DefaultUpstreamTimeout time.Duration `envconfig:"DEFAULT_UPSTREAM_TIMEOUT" default:"10s"`

	TCPWriteTimeout time.Duration `envconfig:"TCP_WRITE_TIMEOUT" default:"30s"`
	TCPReadTimeout  time.Duration `envconfig:"TCP_READ_TIMEOUT" default:"30s"`

	RequestLogging bool `envconfig:"REQUEST_LOGGING" default:"true"`

	// StatsdHost string `envconfig:"STATSD_HOST"`
	// StatsdPort int    `envconfig:"STATSD_PORT"`

	// StatsdClient *statsd.Client

	// This is an override for supplying template vars at test time
	testTemplateVars map[string]string

	// internal values that are set after config validation
	upstreamConfigs []*UpstreamConfig
}

// NewOptions returns a new options struct
func NewOptions() *Options {
	return &Options{
		RequestLogging:         true,
		DefaultUpstreamTimeout: time.Duration(1) * time.Second,
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
	if o.Cluster == "" {
		msgs = append(msgs, "missing setting: cluster")
	}
	if o.UpstreamConfigsFile == "" {
		msgs = append(msgs, "missing setting: upstream-configs")
	}

	// if o.StatsdHost == "" {
	// 	msgs = append(msgs, "missing setting: statsd-host")
	// }

	// if o.StatsdPort == 0 {
	// 	msgs = append(msgs, "missing setting: statsd-port")
	// }
	// if o.StatsdHost != "" && o.StatsdPort != 0 {
	// 	StatsdClient, err := newStatsdClient(o)
	// 	if err != nil {
	// 		msgs = append(msgs, fmt.Sprintf("error creating statsd client error=%q", err))
	// 	}
	// 	o.StatsdClient = StatsdClient
	// }

	if o.UpstreamConfigsFile != "" {
		rawBytes, err := ioutil.ReadFile(o.UpstreamConfigsFile)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error reading upstream configs file: %s", err))
		}

		templateVars := parseEnvironment(os.Environ())
		if o.testTemplateVars != nil {
			templateVars = o.testTemplateVars
		}

		o.upstreamConfigs, err = loadServiceConfigs(rawBytes, o.Cluster, o.Scheme, templateVars)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error parsing upstream configs file %s", err))
		}
	}

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseEnvironment(environ []string) map[string]string {
	envPrefix := "DEV_CONFIG_"
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
