package devproxy

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"
)

// Options are configuration options that can be set by Environment Variables
// Port - int -  port to listen on for HTTP clients
// UpstreamConfigsFile - the path to upstream configs file
// Cluster - the cluster in which this is running, used for upstream configs
// Scheme - the default scheme, used for upstream configs
// DefaultUpstreamTimeout - the default time period to wait for a response from an upstream
// TCPWriteTimeout - http server tcp write timeout
// TCPReadTimeout - http server tcp read timeout
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
