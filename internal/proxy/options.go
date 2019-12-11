package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/proxy/providers"

	"github.com/datadog/datadog-go/statsd"
)

// SetCookieStore sets the session and csrf stores as a functional option
func SetCookieStore(cc CookieConfig) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {

		decodedCookieSecret, err := base64.StdEncoding.DecodeString(cc.Secret)
		if err != nil {
			return err
		}

		cookieStore, err := sessions.NewCookieStore(cc.Name,
			sessions.CreateMiscreantCookieCipher(decodedCookieSecret),
			func(c *sessions.CookieStore) error {
				c.CookieDomain = cc.Domain
				c.CookieHTTPOnly = cc.HTTPOnly
				c.CookieExpire = cc.Expire
				c.CookieSecure = cc.Secure
				return nil
			})

		if err != nil {
			return err
		}

		op.csrfStore = cookieStore
		op.sessionStore = cookieStore
		op.cookieCipher = cookieStore.CookieCipher
		return nil
	}
}

// SetRequestSigner sets the request signer  as a functional option
func SetRequestSigner(signer *RequestSigner) func(*OAuthProxy) error {
	logger := log.NewLogEntry()
	return func(op *OAuthProxy) error {
		if signer == nil {
			logger.Warn("Running OAuthProxy without signing key. Requests will not be signed.")
			return nil
		}

		// Configure the RequestSigner (used to sign requests with `Sso-Signature` header).
		// Also build the `certs` static JSON-string which will be served from a public endpoint.
		// The key published at this endpoint allows upstreams to decrypt the `Sso-Signature`
		// header, and validate the integrity and authenticity of a request.

		certs := make(map[string]string)
		id, key := signer.PublicKey()
		certs[id] = key

		certsAsStr, err := json.MarshalIndent(certs, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal public certs as JSON: %s", err)
		}

		op.requestSigner = signer
		op.publicCertsJSON = certsAsStr

		return nil
	}
}

// SetUpstreamConfig sets the upstream config as a functional option
func SetUpstreamConfig(upstreamConfig *UpstreamConfig) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.upstreamConfig = upstreamConfig
		return nil
	}
}

// SetProxyHandler sets the proxy handler as a functional option
func SetProxyHandler(handler http.Handler) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.handler = handler
		return nil
	}
}

// SetValidator sets the email validator as a functional option
func SetValidators(validators []options.Validator) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.Validators = validators
		return nil
	}
}

// SetProvider sets the provider as a functional option
func SetProvider(provider providers.Provider) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.provider = provider
		return nil
	}
}

func SetUpstreamConfigs(uc *UpstreamConfigs, cc CookieConfig, svc ServerConfig) error {
	if uc.ConfigsFile != "" {
		rawBytes, err := ioutil.ReadFile(uc.ConfigsFile)
		if err != nil {
			return fmt.Errorf("error reading upstream configs file: %s", err)
		}

		templateVars := parseEnvironment(os.Environ())
		if uc.testTemplateVars != nil {
			templateVars = uc.testTemplateVars
		}

		defaultUpstreamOptionsConfig := &OptionsConfig{
			AllowedEmailAddresses: uc.DefaultConfig.EmailConfig.AllowedAddresses,
			AllowedEmailDomains:   uc.DefaultConfig.EmailConfig.AllowedDomains,
			AllowedGroups:         uc.DefaultConfig.AllowedGroups,
			Timeout:               uc.DefaultConfig.Timeout,
			ResetDeadline:         uc.DefaultConfig.ResetDeadline,
			ProviderSlug:          uc.DefaultConfig.ProviderSlug,
			CookieName:            cc.Name,
		}

		uc.upstreamConfigs, err = loadServiceConfigs(rawBytes, uc.Cluster, uc.Scheme, templateVars, defaultUpstreamOptionsConfig)
		if err != nil {
			return fmt.Errorf("error parsing upstream configs file %s", err)
		}
	}

	if uc.upstreamConfigs != nil {
		invalidUpstreams := []string{}
		for _, c := range uc.upstreamConfigs {
			if c.Timeout > svc.TimeoutConfig.Write {
				svc.TimeoutConfig.Write = c.Timeout
			}

			if len(c.AllowedEmailDomains) == 0 && len(c.AllowedEmailAddresses) == 0 && len(c.AllowedGroups) == 0 {
				invalidUpstreams = append(invalidUpstreams, c.Service)
			}
		}
		if len(invalidUpstreams) != 0 {
			return fmt.Errorf(
				"missing setting: ALLOWED_EMAIL_DOMAINS, ALLOWED_EMAIL_ADDRESSES, ALLOWED_GROUPS default in environment or override in upstream config in the following upstreams: %v",
				invalidUpstreams)
		}
	}

	return nil
}

func newProvider(cc ClientConfig, pc ProviderConfig, sc SessionConfig, uc UpstreamConfigs, statsdClient *statsd.Client) (providers.Provider, error) {
	providerURL, err := url.Parse(pc.ProviderURLConfig.External)
	if err != nil {
		return nil, err
	}

	var providerURLInternal *url.URL
	if pc.ProviderURLConfig.Internal != "" {
		//TODO: sort out this providerURLInternal/External stuff
		providerURLInternal, err = url.Parse(pc.ProviderURLConfig.Internal)
		if err != nil {
			return nil, err
		}
	}

	providerData := &providers.ProviderData{
		ClientID:     cc.ID,
		ClientSecret: cc.Secret,

		ProviderURL:         providerURL,
		ProviderURLInternal: providerURLInternal,
		ProviderSlug:        uc.DefaultConfig.ProviderSlug,
		Scope:               pc.Scope,

		SessionLifetimeTTL: sc.TTLConfig.Lifetime,
		SessionValidTTL:    sc.TTLConfig.Valid,
		GracePeriodTTL:     sc.TTLConfig.GracePeriod,
	}

	p := providers.New(pc.ProviderType, providerData, statsdClient)
	return providers.NewSingleFlightProvider(p, statsdClient), nil
}

// SetStatsdClient sets the statsd client as a functional option
func SetStatsdClient(statsdClient *statsd.Client) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.StatsdClient = statsdClient
		return nil
	}
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
