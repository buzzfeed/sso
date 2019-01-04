package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/buzzfeed/sso/internal/devproxy"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/kelseyhightower/envconfig"
)

func init() {
	log.SetServiceName("sso-dev-proxy")
}

func main() {
	logger := log.NewLogEntry()

	opts := devproxy.NewOptions()

	err := envconfig.Process("", opts)
	if err != nil {
		logger.Error(err, "error loading in env vars")
		os.Exit(1)
	}

	err = opts.Validate()
	if err != nil {
		logger.Error(err, "error validing options")
		os.Exit(1)
	}

	proxy, err := devproxy.NewDevProxy(opts)
	if err != nil {
		logger.Error(err, "error creating devproxy")
		os.Exit(1)
	}

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", opts.Port),
		ReadTimeout:  opts.TCPReadTimeout,
		WriteTimeout: opts.TCPWriteTimeout,
		Handler:      devproxy.NewLoggingHandler(os.Stdout, proxy.Handler(), opts.RequestLogging),
	}
	logger.Fatal(s.ListenAndServe())
}
