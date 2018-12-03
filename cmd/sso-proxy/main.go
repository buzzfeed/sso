package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/buzzfeed/sso/internal/proxy"
	"github.com/kelseyhightower/envconfig"
)

func init() {
	log.SetServiceName("sso-proxy")
}

func main() {
	logger := log.NewLogEntry()

	opts := proxy.NewOptions()
	err := envconfig.Process("", opts)
	if err != nil {
		logger.Error(err, "error parsing env vars into options")
		os.Exit(1)
	}

	err = opts.Validate()
	if err != nil {
		logger.Error(err, "error validing options")
		os.Exit(1)
	}

	validator := func(p *proxy.OAuthProxy) error {
		p.EmailValidator = options.NewEmailValidator(opts.EmailDomains)
		return nil
	}

	oauthproxy, err := proxy.NewOAuthProxy(opts, validator, proxy.SetCookieStore(opts))
	if err != nil {
		logger.Error(err, "error creating oauthproxy")
		os.Exit(1)
	}

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", opts.Port),
		ReadTimeout:  opts.TCPReadTimeout,
		WriteTimeout: opts.TCPWriteTimeout,
		Handler:      proxy.NewLoggingHandler(os.Stdout, oauthproxy.Handler(), opts.RequestLogging, oauthproxy.StatsdClient),
	}
	logger.Fatal(s.ListenAndServe())
}
