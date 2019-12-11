package proxy

import (
	"fmt"
	"net/http"

	"github.com/buzzfeed/sso/internal/pkg/hostmux"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/datadog/datadog-go/statsd"
)

type SSOProxy struct {
	http.Handler
}

func New(config Configuration, statsdClient *statsd.Client) (*SSOProxy, error) {
	optFuncs := []func(*OAuthProxy) error{}

	var requestSigner *RequestSigner
	var err error

	if config.RequestSignerConfig.Key != "" {
		requestSigner, err = NewRequestSigner(config.RequestSignerConfig.Key)
		if err != nil {
			return nil, err
		}
		optFuncs = append(optFuncs, SetRequestSigner(requestSigner))
	}

	hostRouter := hostmux.NewRouter()
	for _, upstreamConfig := range config.UpstreamConfigs.upstreamConfigs {
		provider, err := newProvider(
			config.ClientConfig,
			config.ProviderConfig,
			config.SessionConfig,
			config.UpstreamConfigs,
			statsdClient,
		)
		if err != nil {
			return nil, err
		}

		handler, err := NewUpstreamReverseProxy(upstreamConfig, requestSigner)
		if err != nil {
			return nil, err
		}

		validators := []options.Validator{}
		if len(upstreamConfig.AllowedEmailAddresses) != 0 {
			validators = append(validators, options.NewEmailAddressValidator(upstreamConfig.AllowedEmailAddresses))
		}

		if len(upstreamConfig.AllowedEmailDomains) != 0 {
			validators = append(validators, options.NewEmailDomainValidator(upstreamConfig.AllowedEmailDomains))
		}

		if len(upstreamConfig.AllowedGroups) != 0 {
			validators = append(validators, options.NewEmailGroupValidator(provider, upstreamConfig.AllowedGroups))
		}

		optFuncs = append(optFuncs,
			SetProvider(provider),
			SetCookieStore(config.SessionConfig.CookieConfig),
			SetUpstreamConfig(upstreamConfig),
			SetProxyHandler(handler),
			SetStatsdClient(statsdClient),
			SetValidators(validators),
		)

		oauthproxy, err := NewOAuthProxy(config.SessionConfig, optFuncs...)
		if err != nil {
			return nil, err
		}

		switch route := upstreamConfig.Route.(type) {
		case *SimpleRoute:
			hostRouter.HandleStatic(route.FromURL.Host, oauthproxy.Handler())
		case *RewriteRoute:
			hostRouter.HandleRegexp(route.FromRegex, oauthproxy.Handler())
		default:
			return nil, fmt.Errorf("unknown route type")
		}
	}

	healthcheckHandler := setHealthCheck("/ping", hostRouter)

	return &SSOProxy{
		healthcheckHandler,
	}, nil
}
