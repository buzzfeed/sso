package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/buzzfeed/sso/internal/auth"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

var goVersion string

func init() {
	log.SetServiceName("sso-authenticator")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(auth.VERSION)
		fmt.Println(goVersion)
		os.Exit(1)
	}

	logger := log.NewLogEntry()

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

	logger.Fatal(s.ListenAndServe())
}
