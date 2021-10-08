package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/buzzfeed/sso/internal/auth"
	"github.com/buzzfeed/sso/internal/pkg/httpserver"
	"github.com/buzzfeed/sso/internal/pkg/logging"
)

func init() {
	flag.Bool("version", false, "provides application version and go version")
	logging.SetServiceName("sso-authenticator")
}

func main() {
	logger := logging.NewLogEntry()
	flag.Parse()

	if flagPassed("version") {
		version, err := os.ReadFile("./dist/.version.txt")
		if err != nil {
			logger.Fatal(err)
		}
		fmt.Printf("%sBuilt with %s\n", string(version), runtime.Version())
		os.Exit(0)
	}

	config, err := auth.LoadConfig()
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
	statsdClient, err := auth.NewStatsdClient(sc.Host, sc.Port)
	if err != nil {
		logger.Error(err, "error creating statsd client")
		os.Exit(1)
	}

	authMux, err := auth.NewAuthenticatorMux(config, statsdClient)
	if err != nil {
		logger.Error(err, "error creating new AuthenticatorMux")
		os.Exit(1)
	}
	defer authMux.Stop()

	// we leave the message field blank, which will inherit the stdlib timeout page which is sufficient
	// and better than other naive messages we would currently place here
	timeoutHandler := http.TimeoutHandler(authMux, config.ServerConfig.TimeoutConfig.Request, "")

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.ServerConfig.Port),
		ReadTimeout:  config.ServerConfig.TimeoutConfig.Read,
		WriteTimeout: config.ServerConfig.TimeoutConfig.Write,
		Handler:      auth.NewLoggingHandler(os.Stdout, timeoutHandler, config.LoggingConfig.Enable, statsdClient),
	}

	if err := httpserver.Run(s, config.ServerConfig.TimeoutConfig.Shutdown, logger); err != nil {
		logger.WithError(err).Fatal("error running server")
	}
}

func flagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
