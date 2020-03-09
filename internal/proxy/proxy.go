package proxy

import (
	"fmt"
	"net/http"

	"github.com/buzzfeed/sso/internal/pkg/hostmux"
	"github.com/buzzfeed/sso/internal/pkg/validators"
)

type SSOProxy struct {
	http.Handler
}

func New(opts *Options) (*SSOProxy, error) {
	optFuncs := []func(*OAuthProxy) error{}

	var requestSigner *RequestSigner
	var err error

	if opts.RequestSigningKey != "" {
		requestSigner, err = NewRequestSigner(opts.RequestSigningKey)
		if err != nil {
			return nil, err
		}
		optFuncs = append(optFuncs, SetRequestSigner(requestSigner))
	}

	hostRouter := hostmux.NewRouter()
	for _, upstreamConfig := range opts.upstreamConfigs {
		provider, err := newProvider(opts, upstreamConfig)
		if err != nil {
			return nil, err
		}

		handler, err := NewUpstreamReverseProxy(upstreamConfig, requestSigner)
		if err != nil {
			return nil, err
		}

		v := []validators.Validator{}
		if len(upstreamConfig.AllowedEmailAddresses) != 0 {
			v = append(v, validators.NewEmailAddressValidator(upstreamConfig.AllowedEmailAddresses))
		}

		if len(upstreamConfig.AllowedEmailDomains) != 0 {
			v = append(v, validators.NewEmailDomainValidator(upstreamConfig.AllowedEmailDomains))
		}

		if len(upstreamConfig.AllowedGroups) != 0 {
			v = append(v, validators.NewEmailGroupValidator(provider, upstreamConfig.AllowedGroups))
		}

		optFuncs = append(optFuncs,
			SetProvider(provider),
			SetCookieStore(opts),
			SetUpstreamConfig(upstreamConfig),
			SetProxyHandler(handler),
			SetValidators(v),
		)

		oauthproxy, err := NewOAuthProxy(opts, optFuncs...)
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
