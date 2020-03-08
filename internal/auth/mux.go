package auth

import (
	"fmt"
	"net/http"

	"github.com/buzzfeed/sso/internal/pkg/hostmux"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"

	"github.com/datadog/datadog-go/statsd"
	"github.com/gorilla/mux"
)

type AuthenticatorMux struct {
	handler        http.Handler
	authenticators []*Authenticator
}

func NewAuthenticatorMux(config Configuration, statsdClient *statsd.Client) (*AuthenticatorMux, error) {
	logger := log.NewLogEntry()
	validators := []options.Validator{}
	if len(config.AuthorizeConfig.EmailConfig.Addresses) != 0 {
		validators = append(validators, options.NewEmailAddressValidator(config.AuthorizeConfig.EmailConfig.Addresses))
	} else {
		validators = append(validators, options.NewEmailDomainValidator(config.AuthorizeConfig.EmailConfig.Domains))
	}

	authenticators := []*Authenticator{}
	idpMux := mux.NewRouter()
	idpMux.UseEncodedPath()

	for slug, providerConfig := range config.ProviderConfigs {
		idp, err := newProvider(providerConfig, config.SessionConfig)
		if err != nil {
			logger.Error(err, fmt.Sprintf("error creating provider.%s", slug))
			return nil, err
		}

		idpSlug := idp.Data().ProviderSlug
		authenticator, err := NewAuthenticator(config,
			SetValidators(validators),
			SetProvider(idp),
			SetCookieStore(config.SessionConfig, idpSlug),
			SetStatsdClient(statsdClient),
			SetRedirectURL(config.ServerConfig, idpSlug),
		)
		if err != nil {
			logger.Error(err, "error creating new Authenticator")
			return nil, err
		}

		authenticators = append(authenticators, authenticator)

		// setup our mux with the idpslug as the first part of the path
		providerPath := fmt.Sprintf("/%s", idpSlug)
		idpMux.PathPrefix(providerPath).Handler(http.StripPrefix(providerPath, authenticator.ServeMux))
	}

	// load static files
	fsHandler, err := loadFSHandler()
	if err != nil {
		logger.Fatal(err)
	}
	idpMux.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fsHandler))
	idpMux.HandleFunc("/robots.txt", RobotsTxt)

	hostRouter := hostmux.NewRouter()
	hostRouter.HandleStatic(config.ServerConfig.Host, idpMux)

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
