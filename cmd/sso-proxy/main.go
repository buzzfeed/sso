package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

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

	config, err := proxy.LoadConfig()
	if err != nil {
		logger.Error(err, "error loading in config from env vars")
		os.Exit(1)
	}

	err = config.Validate()
	if err != nil {
		logger.Error(err, "error validating config")
		os.Exit(1)
	}

	sc := config.MetricsConfig.StatsdConfig
	statsdClient, err := proxy.NewStatsdClient(sc.Host, sc.Port)
	if err != nil {
		logger.Error(err, "error creating statsd client")
		os.Exit(1)
	}

	// we setup a runtime collector to emit stats
	go func() {
		c := collector.New(statsdClient, 30*time.Second)
		c.Run()
	}()

	err = proxy.SetUpstreamConfigs(
		&config.UpstreamConfigs,
		config.SessionConfig.CookieConfig,
		config.ServerConfig,
	)
	if err != nil {
		logger.Error(err, "error setting upstream configs")
		os.Exit(1)
	}

	ssoProxy, err := proxy.New(config, statsdClient)
	if err != nil {
		logger.Error(err, "error creating sso proxy")
		os.Exit(1)
	}

	loggingHandler := proxy.NewLoggingHandler(os.Stdout,
		ssoProxy,
		config.LoggingConfig,
		statsdClient,
	)

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.ServerConfig.Port),
		ReadTimeout:  config.ServerConfig.TimeoutConfig.Read,
		WriteTimeout: config.ServerConfig.TimeoutConfig.Write,
		Handler:      loggingHandler,
	}

	if err := httpserver.Run(s, config.ServerConfig.TimeoutConfig.Shutdown, logger); err != nil {
		logger.WithError(err).Fatal("error running server")
	}
}
