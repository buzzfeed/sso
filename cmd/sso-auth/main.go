package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/buzzfeed/sso/internal/auth"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/kelseyhightower/envconfig"
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

	opts := auth.NewOptions()

	err := envconfig.Process("", opts)
	if err != nil {
		logger.Error(err, "error loading in env vars")
		os.Exit(1)
	}

	err = opts.Validate()
	if err != nil {
		logger.Error(err, "error validating opts")
		os.Exit(1)
	}

	emailValidator := func(p *auth.Authenticator) error {
		p.Validator = options.NewEmailValidator(opts.EmailDomains)
		return nil
	}

	authenticator, err := auth.NewAuthenticator(opts, emailValidator, auth.AssignProvider(opts), auth.SetCookieStore(opts), auth.AssignStatsdClient(opts))
	if err != nil {
		logger.Error(err, "error creating new Authenticator")
		os.Exit(1)
	}
	defer authenticator.Stop()

	// we leave the message field blank, which will inherit the stdlib timeout page which is sufficient
	// and better than other naive messages we would currently place here
	timeoutHandler := http.TimeoutHandler(authenticator.ServeMux, opts.RequestTimeout, "")

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", opts.Port),
		ReadTimeout:  opts.TCPReadTimeout,
		WriteTimeout: opts.TCPWriteTimeout,
		Handler:      auth.NewLoggingHandler(os.Stdout, timeoutHandler, opts.RequestLogging, authenticator.StatsdClient),
	}

	logger.Fatal(s.ListenAndServe())
}
