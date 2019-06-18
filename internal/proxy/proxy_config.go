package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/18F/hmacauth"
	"github.com/imdario/mergo"
	"gopkg.in/yaml.v2"
)

const (
	simple  = "simple"
	rewrite = "rewrite"
)

var (
	space = regexp.MustCompile(`\s+`)
)

// ServiceConfig represents the configuration for a given service
type ServiceConfig struct {
	Service        string                     `yaml:"service"`
	ClusterConfigs map[string]*UpstreamConfig `yaml:",inline"`
}

// SimpleRoute contains a FromURL and ToURL used to construct simple routes in the reverse proxy.
type SimpleRoute struct {
	FromURL *url.URL
	ToURL   *url.URL
}

// RewriteRoute contains a FromRegex and ToTemplate used to construct rewrite routes in the reverse proxy.
type RewriteRoute struct {
	FromRegex  *regexp.Regexp
	ToTemplate *url.URL
}

// UpstreamConfig represents the configuration for a given cluster in a given service
type UpstreamConfig struct {
	Service string

	RouteConfig RouteConfig `yaml:",inline"`

	ExtraRoutes []*RouteConfig `yaml:"extra_routes"`

	// Generated at Parse Time
	Route interface{} // note: :/

	SkipAuthCompiledRegex []*regexp.Regexp
	AllowedGroups         []string
	TLSSkipVerify         bool
	PreserveHost          bool
	HMACAuth              hmacauth.HmacAuth
	Timeout               time.Duration
	ResetDeadline         time.Duration
	FlushInterval         time.Duration
	HeaderOverrides       map[string]string
	SkipRequestSigning    bool
	CookieName            string
	ProviderSlug          string
}

// RouteConfig maps to the yaml config fields,
// * "from" - the domain that will be used to access the service
// * "to" -  the cname of the proxied service (this tells sso proxy where to proxy requests that come in on the from field)
type RouteConfig struct {
	From    string         `yaml:"from"`
	To      string         `yaml:"to"`
	Type    string         `yaml:"type"`
	Options *OptionsConfig `yaml:"options"`
}

// OptionsConfig maps to the yaml config fields:
// * header_overrides - overrides any heads set either by sso proxy itself or upstream applications.
//   This can be useful for modifying browser security headers.
// * skip_auth_regex - skips authentication for paths matching these regular expressions.
// * allowed_groups - optional list of authorized google groups that can access the service.
// * tls_skip_verify - a bool to skip certification verification of upstreams
// * preserve_host - preserve the host named based in up the client request rather than re-writing for the upstream host
// * timeout - duration before timing out request.
// * reset_deadline - a duration to trigger resets of tcp connections to upstreams. This is useful in dynamic dns environments.
// * flush_interval - interval at which the proxy should flush data to the browser
// * skip_request_signing - skip request signing if this behavior is problematic or undesired. For requests with large http bodies
//   this maybe useful to unset as http bodies are read into memory in order to sign.
type OptionsConfig struct {
	HeaderOverrides    map[string]string `yaml:"header_overrides"`
	SkipAuthRegex      []string          `yaml:"skip_auth_regex"`
	AllowedGroups      []string          `yaml:"allowed_groups"`
	TLSSkipVerify      bool              `yaml:"tls_skip_verify"`
	PreserveHost       bool              `yaml:"preserve_host"`
	Timeout            time.Duration     `yaml:"timeout"`
	ResetDeadline      time.Duration     `yaml:"reset_deadline"`
	FlushInterval      time.Duration     `yaml:"flush_interval"`
	SkipRequestSigning bool              `yaml:"skip_request_signing"`
	ProviderSlug       string            `yaml:"provider_slug"`

	// CookieName is still set globally, so we do not provide override behavior
	CookieName string
}

// ErrParsingConfig is an error specific to config parsing.
type ErrParsingConfig struct {
	Message string
	Err     error
}

// Error() implements the error interface, returning a string representation of the error.
func (e *ErrParsingConfig) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s error=%s", e.Message, e.Err)
	}
	return e.Message
}

func loadServiceConfigs(raw []byte, cluster, scheme string, configVars map[string]string, defaultOpts *OptionsConfig) ([]*UpstreamConfig, error) {
	// We fill in all templated values and resolve overrides
	rawTemplated := resolveTemplates(raw, configVars)

	serviceConfigs, err := parseServiceConfigs(rawTemplated)
	if err != nil {
		return nil, err
	}

	// we don't set this to the len(serviceConfig) since not all service configs
	// are configured for all clusters, leaving nil tail pointers in the slice.
	configs := make([]*UpstreamConfig, 0)
	// resolve overrides
	for _, service := range serviceConfigs {
		proxy, err := resolveUpstreamConfig(service, cluster)
		if err != nil {
			return nil, err
		}

		// if we don't resolve a upstream config, this cluster is not configured for this upstream
		// so the proxy struct will be nil and we skip adding it to our running config
		if proxy != nil {
			configs = append(configs, proxy)
		}
	}

	extraRoutes := make([]*UpstreamConfig, 0)
	for _, proxy := range configs {
		if len(proxy.ExtraRoutes) == 0 {
			continue
		}

		for _, extra := range proxy.ExtraRoutes {
			resolvedProxy, err := resolveExtraRoute(extra, proxy)
			if err != nil {
				return nil, err
			}
			extraRoutes = append(extraRoutes, resolvedProxy)
		}
		// for completeness, we set this to nil now that we've processed extra routes
		proxy.ExtraRoutes = nil
	}

	configs = append(configs, extraRoutes...)

	// We verify the config has necessary values
	for _, proxy := range configs {
		err := validateUpstreamConfig(proxy)
		if err != nil {
			return nil, err
		}
	}

	// We compose the URLs for all our finalized domains
	for _, proxy := range configs {
		switch proxy.RouteConfig.Type {
		case simple, "":
			route, err := simpleRoute(scheme, proxy.RouteConfig)
			if err != nil {
				return nil, err
			}
			proxy.Route = route
		case rewrite:
			route, err := rewriteRoute(scheme, proxy.RouteConfig)
			if err != nil {
				return nil, err
			}
			proxy.Route = route
		default:
			return nil, &ErrParsingConfig{
				Message: fmt.Sprintf("unknown routing config type %q", proxy.RouteConfig.Type),
				Err:     nil,
			}
		}
	}

	// We validate OptionsConfig
	for _, proxy := range configs {
		err := parseOptionsConfig(proxy, defaultOpts)
		if err != nil {
			return nil, err
		}
	}

	for _, proxy := range configs {
		key := fmt.Sprintf("%s_signing_key", proxy.Service)
		signingKey, ok := configVars[key]
		if !ok {
			continue
		}
		auth, err := generateHmacAuth(signingKey)
		if err != nil {
			return nil, &ErrParsingConfig{
				Message: fmt.Sprintf("unable to generate hmac auth for %s", proxy.Service),
				Err:     err,
			}
		}
		proxy.HMACAuth = auth

	}

	return configs, nil
}

func rewriteRoute(scheme string, routeConfig RouteConfig) (*RewriteRoute, error) {
	compiled, err := regexp.Compile(routeConfig.From)
	if err != nil {
		return nil, &ErrParsingConfig{
			Message: "unable to compile rewrite from regex",
			Err:     err,
		}
	}

	toURL := &url.URL{
		Scheme: scheme,
		Opaque: routeConfig.To, // we use opaque since the template value may not be a parsable URL
	}

	return &RewriteRoute{
		FromRegex:  compiled,
		ToTemplate: toURL,
	}, nil
}

func simpleRoute(scheme string, routeConfig RouteConfig) (*SimpleRoute, error) {
	// url parse domain
	fromURL, err := urlParse(scheme, routeConfig.From)
	if err != nil {
		return nil, &ErrParsingConfig{
			Message: "unable to url parse `from` parameter",
			Err:     err,
		}
	}

	// url parse to url
	toURL, err := urlParse(scheme, routeConfig.To)
	if err != nil {
		return nil, &ErrParsingConfig{
			Message: "unable to url parse `to` parameter",
			Err:     err,
		}
	}

	return &SimpleRoute{
		FromURL: fromURL,
		ToURL:   toURL,
	}, nil
}

func urlParse(scheme, uri string) (*url.URL, error) {
	// NOTE: This is done intentionally to add a scheme so it is valid to parse.
	//
	// From https://golang.org/pkg/net/url/#Parse
	// > Trying to parse a hostname and path without a scheme is invalid
	// > but may not necessarily return an error, due to parsing ambiguities.
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("%s://%s", scheme, uri)
	}
	return url.Parse(uri)
}

func parseServiceConfigs(data []byte) ([]*ServiceConfig, error) {
	serviceConfigs := make([]*ServiceConfig, 0)
	err := yaml.Unmarshal(data, &serviceConfigs)
	if err != nil {
		return nil, &ErrParsingConfig{
			Message: "failed to parse yaml",
			Err:     err,
		}
	}

	return serviceConfigs, err
}

func resolveExtraRoute(routeConfig *RouteConfig, src *UpstreamConfig) (*UpstreamConfig, error) {
	dst := &UpstreamConfig{RouteConfig: *routeConfig}

	err := mergo.Merge(dst, *src)
	if err != nil {
		return nil, err
	}

	dst.ExtraRoutes = nil

	return dst, nil
}

func resolveUpstreamConfig(service *ServiceConfig, override string) (*UpstreamConfig, error) {
	dst, dstOk := service.ClusterConfigs["default"]
	src, srcOk := service.ClusterConfigs[override]

	if !(dstOk || srcOk) {
		// no default or cluster is configured, which we allow
		return nil, nil
	}

	if dst == nil {
		dst = &UpstreamConfig{}
	}

	if src == nil {
		src = &UpstreamConfig{}
	}

	err := mergo.Merge(dst, *src, mergo.WithOverride)
	if err != nil {
		return nil, err
	}

	dst.Service = cleanWhiteSpace(service.Service)
	return dst, nil
}

func validateUpstreamConfig(proxy *UpstreamConfig) error {
	if proxy.Service == "" {
		return &ErrParsingConfig{
			Message: "missing `service` parameter",
		}
	}

	if proxy.RouteConfig.From == "" {
		return &ErrParsingConfig{
			Message: "missing `from` parameter",
		}
	}

	if proxy.RouteConfig.To == "" {
		return &ErrParsingConfig{
			Message: "missing `to` parameter",
		}
	}

	return nil
}

func resolveTemplates(raw []byte, templateVars map[string]string) []byte {
	rawString := string(raw)
	for k, v := range templateVars {
		templated := fmt.Sprintf("{{%s}}", k)
		rawString = strings.Replace(rawString, templated, v, -1)
	}
	return []byte(rawString)
}

func parseOptionsConfig(proxy *UpstreamConfig, defaultOpts *OptionsConfig) error {
	dst := &OptionsConfig{}

	if defaultOpts == nil {
		defaultOpts = &OptionsConfig{}
	}

	// Override empty with defaults
	err := mergo.Merge(dst, *defaultOpts, mergo.WithOverride)
	if err != nil {
		return err
	}

	// Override defaults with specified
	if proxy.RouteConfig.Options != nil {
		err := mergo.Merge(dst, proxy.RouteConfig.Options, mergo.WithOverride)
		if err != nil {
			return err
		}
	}

	// We compile all the regexes in SkipAuth Regex
	for _, uncompiled := range dst.SkipAuthRegex {
		compiled, err := regexp.Compile(uncompiled)
		if err != nil {
			return &ErrParsingConfig{
				Message: "unable to compile skip auth regex",
				Err:     err,
			}
		}
		proxy.SkipAuthCompiledRegex = append(proxy.SkipAuthCompiledRegex, compiled)
	}

	proxy.AllowedGroups = dst.AllowedGroups
	proxy.Timeout = dst.Timeout
	proxy.ResetDeadline = dst.ResetDeadline
	proxy.FlushInterval = dst.FlushInterval
	proxy.HeaderOverrides = dst.HeaderOverrides
	proxy.TLSSkipVerify = dst.TLSSkipVerify
	proxy.PreserveHost = dst.PreserveHost
	proxy.SkipRequestSigning = dst.SkipRequestSigning
	proxy.CookieName = dst.CookieName
	proxy.ProviderSlug = dst.ProviderSlug

	proxy.RouteConfig.Options = nil

	return nil
}

func cleanWhiteSpace(s string) string {
	// This trims all white space from a service name and collapses all remaining space to `_`
	return space.ReplaceAllString(strings.TrimSpace(s), "_") //
}

func generateHmacAuth(signatureKey string) (hmacauth.HmacAuth, error) {
	components := strings.Split(signatureKey, ":")
	if len(components) != 2 {
		return nil, fmt.Errorf("invalid signature hash:key spec")
	}

	algorithm, secret := components[0], components[1]
	hash, err := hmacauth.DigestNameToCryptoHash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported signature hash algorithm: %s", algorithm)
	}
	auth := hmacauth.NewHmacAuth(hash, []byte(secret), HMACSignatureHeader, SignatureHeaders)
	return auth, nil
}
