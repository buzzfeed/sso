package auth

import (
	"fmt"
	"net/http"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/hostmux"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"

	"github.com/datadog/datadog-go/statsd"
)

type AuthenticatorMux struct {
	handler        http.Handler
	authenticators []*Authenticator
}

func NewAuthenticatorMux(opts *Options, statsdClient *statsd.Client) (*AuthenticatorMux, error) {
	logger := log.NewLogEntry()

	var validator func(string) bool
	if len(opts.EmailAddresses) != 0 {
		validator = options.NewEmailAddressValidator(opts.EmailAddresses)
	} else {
		validator = options.NewEmailDomainValidator(opts.EmailDomains)
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
			SetValidator(validator),
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

		// TODO: This should be removed once we feel confident clients have been moved over to the new
		// style /slug/ paths. This is kept around to allow graceful migrations/upgrades.
		if idpSlug == opts.DefaultProviderSlug {
			// setup our mux with the idpslug as the first part of the path
			authenticator, err := NewAuthenticator(opts,
				SetValidator(validator),
				SetProvider(idp),
				SetCookieStore(opts, idpSlug),
				SetStatsdClient(statsdClient),
				SetDefaultRedirectURL(opts),
			)
			if err != nil {
				logger.Error(err, "error creating new Authenticator")
				return nil, err
			}

			authenticators = append(authenticators, authenticator)

			idpMux.Handle("/", authenticator.ServeMux)
		}
	}

	// load static files
	fsHandler, err := loadFSHandler()
	if err != nil {
		logger.Fatal(err)
	}
	idpMux.Handle("/static/", http.StripPrefix("/static/", fsHandler))
	idpMux.HandleFunc("/robots.txt", RobotsTxt)

	hostRouter := hostmux.NewRouter()
	hostRouter.HandleStatic(opts.Host, idpMux)

	healthcheckHandler := setHealthCheck("/ping", hostRouter)

	return &AuthenticatorMux{
		handler:        healthcheckHandler,
		authenticators: authenticators,
	}, nil
}

func (a *AuthenticatorMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.handler.ServeHTTP(w, r)
}

func (a *AuthenticatorMux) Stop() {
	for _, authenticator := range a.authenticators {
		authenticator.Stop()
	}
}

func setHealthCheck(healthcheckPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthcheckPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RobotsTxt handles the /robots.txt route
func RobotsTxt(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}
