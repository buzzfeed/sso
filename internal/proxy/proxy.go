package proxy

import (
	"fmt"
	"net/http"
	"os"

	"github.com/buzzfeed/sso/internal/pkg/hostmux"
	"github.com/buzzfeed/sso/internal/pkg/ping"
)

type SSOProxy struct {
	http.Handler
}

func New(opts *Options) (*SSOProxy, error) {
	signer, err := NewRequestSigner(opts.RequestSigningKey)
	if err != nil {
		return nil, err
	}

	hostRouter := hostmux.NewRouter()
	for _, upstreamConfig := range opts.UpstreamConfigs {
		handler, err := NewUpstreamReverseProxy(upstreamConfig, signer)
		if err != nil {
			return nil, err
		}

		oauthproxy, err := NewOAuthProxy(opts,
			SetValidator(opts),
			SetCookieStore(opts),
			SetUpstreamConfig(upstreamConfig),
			SetProxyHandler(handler),
			SetRequestSigner(signer),
		)
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

	// ping handler
	pingHandler := &ping.PingHandler{
		Handler: hostRouter,
	}

	// logging handler
	loggingHandler := NewLoggingHandler(os.Stdout, pingHandler, opts.RequestLogging, opts.StatsdClient)

	return &SSOProxy{
		loggingHandler,
	}, nil
}
