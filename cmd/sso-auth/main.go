package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/buzzfeed/sso/internal/auth"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
)

func init() {
	log.SetServiceName("sso-authenticator")
}

func main() {
	logger := log.NewLogEntry()
	// TODO: if relevant struct is not referenced below an invalid memory address or nil pointer dereference will occur at runtime
	opts, err := auth.NewOptions([]string{"global", "authenticator", "provider", "handler"})
	if err != nil {
		logger.Error(err, "error loading in env vars")
		os.Exit(1)
	}

	err = auth.Validate(opts)
	if err != nil {
		logger.Error(err, "error validating opts")
		os.Exit(1)
	}

	emailValidator := func(p *auth.Authenticator) error {
		//if len(opts.Authenticator.EmailAddresses) != 0 {
		if len(opts["authenticator"].EmailAddresses) != 0 {
			p.Validator = options.NewEmailAddressValidator(opts["authenticator"].EmailAddresses)
		} else {
			p.Validator = options.NewEmailDomainValidator(opts["authenticator"].EmailDomains)
		}
		return nil
	}

	authenticator, err := auth.NewAuthenticator(opts["authenticator"], emailValidator, auth.AssignProvider(opts["provider"]), auth.SetCookieStore(opts["authenticator"]), auth.AssignStatsdClient(opts["global"]))
	if err != nil {
		logger.Error(err, "error creating new Authenticator")
		os.Exit(1)
	}
	defer authenticator.Stop()

	// we leave the message field blank, which will inherit the stdlib timeout page which is sufficient
	// and better than other naive messages we would currently place here
	timeoutHandler := http.TimeoutHandler(authenticator.ServeMux, opts["global"].RequestTimeout, "")

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", opts["handler"].Port),
		ReadTimeout:  opts["handler"].TCPReadTimeout,
		WriteTimeout: opts["handler"].TCPWriteTimeout,
		Handler:      auth.NewLoggingHandler(os.Stdout, timeoutHandler, opts["handler"].RequestLogging, authenticator.StatsdClient),
	}

	logger.Fatal(s.ListenAndServe())
}
