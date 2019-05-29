package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/buzzfeed/sso/internal/auth/providers"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"

	"github.com/datadog/datadog-go/statsd"
)

type AuthenticatorMux struct {
	mux            *http.ServeMux
	authenticators []*Authenticator
}

func NewAuthenticatorMux(opts *Options, statsdClient *statsd.Client) (*AuthenticatorMux, error) {
	logger := log.NewLogEntry()

	emailValidator := func(p *Authenticator) error {
		if len(opts.EmailAddresses) != 0 {
			p.Validator = options.NewEmailAddressValidator(opts.EmailAddresses)
		} else {
			p.Validator = options.NewEmailDomainValidator(opts.EmailDomains)
		}
		return nil
	}

	// one day, we will contruct more providers here
	idp, err := newProvider(opts)
	if err != nil {
		logger.Error(err, "error creating new Identity Provider")
		return nil, err
	}
	identityProviders := []providers.Provider{idp}
	authenticators := []*Authenticator{}

	idpMux := http.NewServeMux()
	for _, idp := range identityProviders {
		idpSlug := idp.Data().ProviderSlug
		authenticator, err := NewAuthenticator(opts,
			emailValidator,
			SetProvider(idp),
			SetCookieStore(opts, idpSlug),
			SetStatsdClient(statsdClient),
			SetRedirectURL(opts, idpSlug),
		)
		if err != nil {
			logger.Error(err, "error creating new Authenticator")
			return nil, err
		}

		authenticators = append(authenticators, authenticator)

		// setup our mux with the idpslug as the first part of the path
		idpMux.Handle(
			fmt.Sprintf("/%s/", idpSlug),
			http.StripPrefix(fmt.Sprintf("/%s", idpSlug), authenticator.ServeMux),
		)
	}

	// load static files
	fsHandler, err := loadFSHandler()
	if err != nil {
		logger.Fatal(err)
	}
	idpMux.Handle("/static/", http.StripPrefix("/static/", fsHandler))

	// NOTE: we have to include trailing slash for the router to match the host header
	host := opts.Host
	if !strings.HasSuffix(host, "/") {
		host = fmt.Sprintf("%s/", host)
	}

	mux := http.NewServeMux()
	// We setup our IPD Mux only on our declared host header
	mux.Handle(host, idpMux) // setup our service mux to only handle our required host header
	// Ping should respond to all requests
	mux.HandleFunc("/ping", PingHandler)

	return &AuthenticatorMux{
		mux:            mux,
		authenticators: authenticators,
	}, nil
}

func (a *AuthenticatorMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *AuthenticatorMux) Stop() {
	for _, authenticator := range a.authenticators {
		authenticator.Stop()
	}
}

// PingHandler handles the /ping route
func PingHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, http.StatusText(http.StatusOK))
}
