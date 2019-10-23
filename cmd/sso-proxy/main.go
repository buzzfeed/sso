package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/buzzfeed/sso/internal/pkg/httpserver"
	"github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/proxy"
	"github.com/buzzfeed/sso/internal/proxy/collector"
)

func init() {
	logging.SetServiceName("sso-proxy")
}

func main() {
	logger := logging.NewLogEntry()

	opts := proxy.NewOptions()
	err := envconfig.Process("", opts)
	if err != nil {
		logger.Error(err, "error parsing env vars into options")
		os.Exit(1)
	}

	err = opts.Validate()
	if err != nil {
		logger.Error(err, "error validating options")
		os.Exit(1)
	}

	// we setup a runtime collector to emit stats
	go func() {
		c := collector.New(opts.StatsdClient, 30*time.Second)
		c.Run()
	}()

	ssoProxy, err := proxy.New(opts)
	if err != nil {
		logger.Error(err, "error creating sso proxy")
		os.Exit(1)
	}

	loggingHandler := proxy.NewLoggingHandler(os.Stdout,
		ssoProxy,
		opts.RequestLogging,
		opts.StatsdClient,
	)

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", opts.Port),
		ReadTimeout:  opts.TCPReadTimeout,
		WriteTimeout: opts.TCPWriteTimeout,
		Handler:      loggingHandler,
	}

	if err := httpserver.Run(s, opts.ShutdownTimeout, logger); err != nil {
		logger.WithError(err).Fatal("error running server")
	}
}
