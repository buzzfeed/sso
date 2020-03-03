package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/aead"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/templates"

	"github.com/datadog/datadog-go/statsd"
	"github.com/gorilla/mux"
)

// Authenticator stores all the information associated with proxying the request.
type Authenticator struct {
	Validators       []options.Validator
	EmailDomains     []string
	ProxyRootDomains []string
	Host             string
	Scheme           string

	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore

	redirectURL *url.URL // the url to receive requests at
	provider    providers.Provider
	ServeMux    http.Handler

	AuthCodeCipher aead.Cipher

	ProxyClientID     string
	ProxyClientSecret string

	StatsdClient *statsd.Client

	CacheRefreshTTL    time.Duration
	SessionLifetimeTTL time.Duration

	templates templates.Template
}

type redeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Email        string `json:"email"`
}

type refreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type getProfileResponse struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

// NewAuthenticator creates a Authenticator struct and applies the optional functions slice to the struct.
func NewAuthenticator(config Configuration, optionFuncs ...func(*Authenticator) error) (*Authenticator, error) {
	logger := log.NewLogEntry()

	templates := templates.NewHTMLTemplate()

	proxyRootDomains := []string{}
	for _, domain := range config.AuthorizeConfig.ProxyConfig.Domains {
		if !strings.HasPrefix(domain, ".") {
			domain = fmt.Sprintf(".%s", domain)
		}
		proxyRootDomains = append(proxyRootDomains, domain)
	}

	p := &Authenticator{
		ProxyClientID:     config.ClientConfigs["proxy"].ID,
		ProxyClientSecret: config.ClientConfigs["proxy"].Secret,
		EmailDomains:      config.AuthorizeConfig.EmailConfig.Domains,
		Host:              config.ServerConfig.Host,
		Scheme:            config.ServerConfig.Scheme,

		ProxyRootDomains: proxyRootDomains,
		templates:        templates,
	}

	p.ServeMux = p.newMux()

	// apply the option functions
	for _, optFunc := range optionFuncs {
		err := optFunc(p)
		if err != nil {
			logger.Error(err)
			return nil, err
		}
	}

	return p, nil
}

func (p *Authenticator) newMux() http.Handler {
	// we setup our service mux to handle service routes that use the required host header
	serviceMux := mux.NewRouter()
	serviceMux.UseEncodedPath()
	serviceMux.HandleFunc("/start", p.withMethods(p.OAuthStart, "GET"))
	serviceMux.HandleFunc("/sign_in", p.withMethods(p.validateClientID(p.validateRedirectURI(p.validateSignature(p.SignIn))), "GET"))
	serviceMux.HandleFunc("/sign_out", p.withMethods(p.validateRedirectURI(p.validateSignature(p.SignOut)), "GET", "POST"))
	serviceMux.HandleFunc("/callback", p.withMethods(p.OAuthCallback, "GET"))
	serviceMux.HandleFunc("/profile", p.withMethods(p.validateClientID(p.validateClientSecret(p.GetProfile)), "GET"))
	serviceMux.HandleFunc("/validate", p.withMethods(p.validateClientID(p.validateClientSecret(p.ValidateToken)), "GET"))
	serviceMux.HandleFunc("/redeem", p.withMethods(p.validateClientID(p.validateClientSecret(p.Redeem)), "POST"))
	serviceMux.HandleFunc("/refresh", p.withMethods(p.validateClientID(p.validateClientSecret(p.Refresh)), "POST"))

	return setHeaders(serviceMux)
}

// GetRedirectURI returns the redirect url for a given OAuthProxy,
func (p *Authenticator) GetRedirectURI(host string) string {
	// default to the request Host if not set
	return p.redirectURL.String()

}

type signInResp struct {
	ProviderSlug string
	ProviderName string
	EmailDomains []string
	Redirect     string
	Destination  string
	Version      string
}

// SignInPage directs the user to the sign in page
func (p *Authenticator) SignInPage(rw http.ResponseWriter, req *http.Request, code int) {
	rw.WriteHeader(code)

	// We construct this URL based on the known callback URL that we send to Google.
	// We don't want to rely on req.Host, as that can be attacked via Host header injection
	// This ends up looking like:
	// https://sso-auth.example.com/sign_in?client_id=...&redirect_uri=...
	path := strings.TrimPrefix(req.URL.Path, "/")
	redirectURL := p.redirectURL.ResolveReference(
		&url.URL{
			Path:     path,
			RawQuery: req.URL.RawQuery,
		},
	)

	// validateRedirectURI middleware already ensures that this is a valid URL
	destinationURL, _ := url.Parse(redirectURL.Query().Get("redirect_uri"))

	t := signInResp{
		ProviderName: p.provider.Data().ProviderName,
		ProviderSlug: p.provider.Data().ProviderSlug,
		EmailDomains: p.EmailDomains,
		Redirect:     redirectURL.String(),
		Destination:  destinationURL.Host,
		Version:      VERSION,
	}
	p.templates.ExecuteTemplate(rw, "sign_in.html", t)
}

func (p *Authenticator) authenticate(rw http.ResponseWriter, req *http.Request) (*sessions.SessionState, error) {
	logger := log.NewLogEntry()
	remoteAddr := getRemoteAddr(req)
	// TODO remove refresh cookie bool when we remove payloads cipher logic
	session, err := p.sessionStore.LoadSession(req)
	if err != nil {
		logger.WithRemoteAddress(remoteAddr).Error(err, "error loading session")
		p.sessionStore.ClearSession(rw, req)
		return nil, err
	}

	if session.LifetimePeriodExpired() {
		logger.WithUser(session.Email).Info("lifetime has expired, restarting authentication")
		p.sessionStore.ClearSession(rw, req)
		return nil, sessions.ErrLifetimeExpired
	}

	if session.RefreshPeriodExpired() {
		ok, err := p.provider.RefreshSessionIfNeeded(session)
		// We failed to refresh the session successfully
		// clear the cookie and reject the request
		if err != nil {
			logger.WithUser(session.Email).Error(err, "refreshing session failed")
			p.sessionStore.ClearSession(rw, req)
			return nil, err
		}

		if !ok {
			// User is not authorized after refresh
			// clear the cookie and reject the request
			logger.WithUser(session.Email).Error("not authorized after refreshing the session")
			p.sessionStore.ClearSession(rw, req)
			return nil, ErrUserNotAuthorized
		}

		err = p.sessionStore.SaveSession(rw, req, session)
		if err != nil {
			// We refreshed the session successfully, but failed to save it.
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request
			logger.WithUser(session.Email).Error(err, "could not save refreshed session")
			p.sessionStore.ClearSession(rw, req)
			return nil, err
		}
	} else {
		ok := p.provider.ValidateSessionState(session)
		if !ok {
			logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Error("invalid session state")
			p.sessionStore.ClearSession(rw, req)
			return nil, ErrUserNotAuthorized
		}
		err = p.sessionStore.SaveSession(rw, req, session)
		if err != nil {
			// We validated the session successfully, but failed to save it.
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request!
			logger.WithUser(session.Email).Error(err, "could not save validated session")
			p.sessionStore.ClearSession(rw, req)
			return nil, err
		}
	}

	errors := options.RunValidators(p.Validators, session)
	if len(errors) == len(p.Validators) {
		logger.WithUser(session.Email).Info(
			fmt.Sprintf("permission denied: unauthorized: %q", errors))
		return nil, ErrUserNotAuthorized
	}

	logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
		fmt.Sprintf("authentication: user passed validation"))

	return session, nil
}

// SignIn handles the /sign_in endpoint. It attempts to authenticate the user, and if the user is not authenticated, it renders
// a sign in page.
func (p *Authenticator) SignIn(rw http.ResponseWriter, req *http.Request) {
	// We attempt to authenticate the user. If they cannot be authenticated, we render a sign-in
	// page.
	//
	// If the user is authenticated, we redirect back to the proxy application
	// at the `redirect_uri`, with a temporary token.
	//
	// TODO: It is possible for a user to visit this page without a redirect destination.
	// Should we allow the user to authenticate? If not, what should be the proposed workflow?

	// statsd client tags
	proxyHost := getProxyHost(req)
	tags := []string{
		"action:sign_in",
		fmt.Sprintf("proxy_host:%s", proxyHost),
	}
	session, err := p.authenticate(rw, req)
	switch err {
	case nil:
		// User is authenticated, redirect back to the proxy application
		// with the necessary state
		p.ProxyOAuthRedirect(rw, req, session, tags)
	case http.ErrNoCookie:
		p.SignInPage(rw, req, http.StatusOK)
	case providers.ErrTokenRevoked:
		p.sessionStore.ClearSession(rw, req)
		p.SignInPage(rw, req, http.StatusOK)
	case sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
		p.sessionStore.ClearSession(rw, req)
		p.SignInPage(rw, req, http.StatusOK)
	default:
		tags = append(tags, "error:sign_in_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, err.Error(), codeForError(err))
	}
}

// ProxyOAuthRedirect redirects the user back to sso proxy's redirection endpoint.
func (p *Authenticator) ProxyOAuthRedirect(rw http.ResponseWriter, req *http.Request, session *sessions.SessionState, tags []string) {
	// This workflow corresponds to Section 3.1.2 of the OAuth2 RFC.
	// See https://tools.ietf.org/html/rfc6749#section-3.1.2 for more specific information.
	//
	// We redirect the user back to the proxy application's redirection endpoint; in the
	// sso proxy, this is the `/oauth/callback` endpoint.
	//
	// We must provide the proxy with a temporary authorization code via the `code` parameter,
	// which they can use to redeem an access token for subsequent API calls.
	//
	// We must also include the original `state` parameter received from the proxy application.

	err := req.ParseForm()
	if err != nil {
		p.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
		return
	}

	state := req.Form.Get("state")
	if state == "" {
		tags = append(tags, "error:empty_state")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, "no state parameter supplied", http.StatusForbidden)
		return
	}

	redirectURI := req.Form.Get("redirect_uri")
	if redirectURI == "" {
		tags = append(tags, "error:empty_redirect_uri")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, "no redirect_uri parameter supplied", http.StatusForbidden)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		tags = append(tags, "error:invalid_redirect_uri")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, "malformed redirect_uri parameter passed", http.StatusBadRequest)
		return
	}

	encrypted, err := sessions.MarshalSession(session, p.AuthCodeCipher)
	if err != nil {
		tags = append(tags, "error:invalid_auth_code")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
		return
	}

	authCodeRedirect, err := getAuthCodeRedirectURL(redirectURL, state, string(encrypted), p.Scheme)
	if err != nil {
		tags = append(tags, "error:invalid_auth_redirect")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(rw, req, authCodeRedirect, http.StatusFound)
}

func getAuthCodeRedirectURL(redirectURL *url.URL, state, authCode, scheme string) (string, error) {
	u, err := url.Parse(redirectURL.String())
	if err != nil {
		return "", err
	}

	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", err
	}

	params.Set("code", authCode)
	params.Set("state", state)

	u.RawQuery = params.Encode()
	u.Scheme = scheme

	return u.String(), nil
}

// SignOut signs the user out.
func (p *Authenticator) SignOut(rw http.ResponseWriter, req *http.Request) {
	logger := log.NewLogEntry()

	redirectURI := req.Form.Get("redirect_uri")

	// statsd client tags
	proxyHost := getProxyHost(req)
	tags := []string{
		"action:sign_out",
		fmt.Sprintf("proxy_host:%s", proxyHost),
	}

	if req.Method == "GET" {
		p.SignOutPage(rw, req, "")
		return
	}

	session, err := p.sessionStore.LoadSession(req)
	switch err {
	case nil:
		break
	// if there's no cookie in the session we can just redirect
	case http.ErrNoCookie:
		http.Redirect(rw, req, redirectURI, http.StatusFound)
		return
	default:
		// a different error, clear the session cookie and redirect
		logger.Error(err, "error loading cookie session")
		p.sessionStore.ClearSession(rw, req)
		http.Redirect(rw, req, redirectURI, http.StatusFound)
		return
	}

	err = p.provider.Revoke(session)
	if err != nil {
		tags = append(tags, "error:revoke_session")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		logger.Error(err, "error revoking session")
		p.SignOutPage(rw, req, "An error occurred during sign out. Please try again.")
		return
	}

	p.sessionStore.ClearSession(rw, req)
	http.Redirect(rw, req, redirectURI, http.StatusFound)
}

type signOutResp struct {
	ProviderSlug string
	Version      string
	Redirect     string
	Signature    string
	Timestamp    string
	Message      string
	Destination  string
	Email        string
}

// SignOutPage renders a sign out page with a message
func (p *Authenticator) SignOutPage(rw http.ResponseWriter, req *http.Request, message string) {
	// validateRedirectURI middleware already ensures that this is a valid URL
	redirectURI := req.Form.Get("redirect_uri")

	session, err := p.sessionStore.LoadSession(req)
	if err != nil {
		http.Redirect(rw, req, redirectURI, http.StatusFound)
		return
	}

	signature := req.Form.Get("sig")
	timestamp := req.Form.Get("ts")
	destinationURL, _ := url.Parse(redirectURI)

	// An error message indicates that an internal server error occurred
	if message != "" {
		rw.WriteHeader(http.StatusInternalServerError)
	}

	t := signOutResp{
		ProviderSlug: p.provider.Data().ProviderSlug,
		Version:      VERSION,
		Redirect:     redirectURI,
		Signature:    signature,
		Timestamp:    timestamp,
		Message:      message,
		Destination:  destinationURL.Host,
		Email:        session.Email,
	}
	p.templates.ExecuteTemplate(rw, "sign_out.html", t)
	return
}

// OAuthStart starts the authentication process by redirecting to the provider. It provides a
// `redirectURI`, allowing the provider to redirect back to the sso proxy after authentication.
func (p *Authenticator) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	tags := []string{"action:start"}

	nonce := fmt.Sprintf("%x", aead.GenerateKey())
	p.csrfStore.SetCSRF(rw, req, nonce)
	authRedirectURL, err := url.Parse(req.URL.Query().Get("redirect_uri"))
	if err != nil || !validRedirectURI(authRedirectURL.String(), p.ProxyRootDomains) {
		tags = append(tags, "error:invalid_redirect_parameter")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	// Here we validate the redirect that is nested within the redirect_uri.
	// `authRedirectURL` points to step D, `proxyRedirectURL` points to step E.
	//
	//    A*       B             C               D              E
	// /start -> Google -> auth /callback -> /sign_in -> proxy /callback
	//
	// * you are here
	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !validRedirectURI(proxyRedirectURL.String(), p.ProxyRootDomains) {
		tags = append(tags, "error:invalid_redirect_parameter")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !validSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, p.ProxyClientSecret) {
		p.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	redirectURI := p.GetRedirectURI(req.Host)
	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))
	signInURL := p.provider.GetSignInURL(redirectURI, state)
	http.Redirect(rw, req, signInURL, http.StatusFound)
}

func (p *Authenticator) redeemCode(host, code string) (*sessions.SessionState, error) {
	// The authenticator redeems `code` for an access token, and uses the token to request user
	// info from the provider (Google).

	redirectURI := p.GetRedirectURI(host)
	// see providers/google.go#Redeem for more info
	session, err := p.provider.Redeem(redirectURI, code)
	if err != nil {
		return nil, err
	}

	if session.Email == "" {
		return nil, fmt.Errorf("no email included in session")
	}
	return session, nil
}

func (p *Authenticator) getOAuthCallback(rw http.ResponseWriter, req *http.Request) (string, error) {
	// After the provider (Google) redirects back to the sso proxy, the proxy uses this
	// endpoint to set up auth cookies.
	logger := log.NewLogEntry()

	remoteAddr := getRemoteAddr(req)

	tags := []string{
		"action:callback",
	}

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		return "", HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		tags = append(tags, "error:error_in_callback")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		return "", HTTPError{Code: http.StatusForbidden, Message: errorString}
	}

	code := req.Form.Get("code")
	if code == "" {
		return "", HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"}
	}
	session, err := p.redeemCode(req.Host, code)
	if err != nil {
		tags = append(tags, "error:redeem_code")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(
			err, "error redeeming authentication code")
		return "", err
	}

	bytes, err := base64.URLEncoding.DecodeString(req.Form.Get("state"))
	if err != nil {
		return "", HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"}
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		tags = append(tags, "error:invalid_state")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		return "", HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"}
	}
	nonce := s[0]
	redirect := s[1]
	c, err := p.csrfStore.GetCSRF(req)
	if err != nil {
		tags = append(tags, "error:missing_csrf_cookie")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		return "", HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"}
	}
	p.csrfStore.ClearCSRF(rw, req)
	if c.Value != nonce {
		tags = append(tags, "error:csrf_token_mismatch")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(
			"csrf_token_mismatch", "POTENTIAL ATTACK: CSRF token mismatch")
		return "", HTTPError{Code: http.StatusForbidden, Message: "csrf failed"}
	}

	if !validRedirectURI(redirect, p.ProxyRootDomains) {
		tags = append(tags, "error:invalid_redirect_parameter")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		return "", HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI"}
	}

	// Set cookie, or deny: The authenticator validates the session email and group
	// - for p.Validator see validator.go#newValidatorImpl for more info
	// - for p.provider.ValidateGroup see providers/google.go#ValidateGroup for more info

	errors := options.RunValidators(p.Validators, session)
	if len(errors) == len(p.Validators) {
		tags := append(tags, "error:invalid_email")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
			fmt.Sprintf("oauth callback: unauthorized: %q", errors))

		formattedErrors := make([]string, 0, len(errors))
		for _, err := range errors {
			formattedErrors = append(formattedErrors, err.Error())
		}
		errorMsg := fmt.Sprintf("We ran into some issues while validating your account: \"%s\"",
			strings.Join(formattedErrors, ", "))
		return "", HTTPError{Code: http.StatusForbidden, Message: errorMsg}
	}
	logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
		fmt.Sprintf("oauth callback: user passed validation"))

	logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info("authentication complete")
	err = p.sessionStore.SaveSession(rw, req, session)
	if err != nil {
		tags = append(tags, "error:save_session_failed")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(err, "internal error")
		return "", HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"}
	}
	return redirect, nil
}

// OAuthCallback handles the callback from the provider, and returns an error response if there is an error.
// If there is no error it will redirect to the redirect url.
func (p *Authenticator) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.getOAuthCallback(rw, req)
	switch h := err.(type) {
	case nil:
		break
	case HTTPError:
		p.ErrorResponse(rw, req, h.Message, h.Code)
		return
	default:
		p.ErrorResponse(rw, req, "Internal Error", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, req, redirect, http.StatusFound)
}

// Redeem has a signed access token, and provides the user information associated with the access token.
func (p *Authenticator) Redeem(rw http.ResponseWriter, req *http.Request) {
	// The auth code is redeemed by the sso proxy for an access token, refresh token,
	// expiration, and email.
	logger := log.NewLogEntry()

	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("Bad Request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	tags := []string{
		"action:redeem",
	}

	session, err := sessions.UnmarshalSession(req.Form.Get("code"), p.AuthCodeCipher)
	if err != nil {
		tags = append(tags, "error:invalid_auth_code")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithHTTPStatus(http.StatusUnauthorized).Error(err, "invalid auth code")
		http.Error(rw, fmt.Sprintf("invalid auth code: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	if session == nil {
		tags = append(tags, "error:invalid_session")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithHTTPStatus(http.StatusUnauthorized).Error("invalid session")
		http.Error(rw, fmt.Sprintf("invalid session: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	if session != nil && (session.RefreshPeriodExpired() || session.LifetimePeriodExpired()) {
		tags = append(tags, "error:expired_session")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithUser(session.Email).WithRefreshDeadline(session.RefreshDeadline).WithLifetimeDeadline(session.LifetimeDeadline).Error("expired session")
		p.sessionStore.ClearSession(rw, req)

		http.Error(rw, fmt.Sprintf("expired session"), http.StatusUnauthorized)
		return
	}

	response := redeemResponse{
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		ExpiresIn:    int64(session.RefreshDeadline.Sub(time.Now()).Seconds()),
		Email:        session.Email,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.Header().Set("GAP-Auth", session.Email)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonBytes)
}

// Refresh takes a refresh token and returns a new access token
func (p *Authenticator) Refresh(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, fmt.Sprintf("Bad Request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	refreshToken := req.Form.Get("refresh_token")
	if refreshToken == "" {
		http.Error(rw, "Bad Request: No Refresh Token", http.StatusBadRequest)
		return
	}

	accessToken, expiresIn, err := p.provider.RefreshAccessToken(refreshToken)
	if err != nil {
		p.ErrorResponse(rw, req, err.Error(), codeForError(err))
		return
	}

	response := refreshResponse{
		AccessToken: accessToken,
		ExpiresIn:   int64(expiresIn.Seconds()),
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusCreated)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(bytes)
}

// GetProfile gets a list of groups of which a user is a member.
func (p *Authenticator) GetProfile(rw http.ResponseWriter, req *http.Request) {
	// The sso proxy sends the user's email to this endpoint to get a list of Google groups that
	// the email is a member of. The proxy will compare these groups to the list of allowed
	// groups for the upstream service the user is trying to access.
	logger := log.NewLogEntry()

	tags := []string{
		"action:profile",
	}

	email := req.FormValue("email")
	if email == "" {
		tags = append(tags, "error:empty_email")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		http.Error(rw, "no email address included", http.StatusBadRequest)
		return
	}

	accessToken := req.Header.Get("X-Access-Token")
	if accessToken == "" {
		// TODO: This should be an error in the future, but is OK to be missing for now
		// we track an error to see observe how often this occurs
		p.StatsdClient.Incr("application_error", append(tags, "error:missing_access_token"), 1.0)
	}

	groupsFormValue := req.FormValue("groups")
	allowedGroups := []string{}
	if groupsFormValue != "" {
		allowedGroups = strings.Split(groupsFormValue, ",")
	}

	groups, err := p.provider.ValidateGroupMembership(email, allowedGroups, accessToken)
	if err != nil {
		tags = append(tags, "error:groups_resource")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		logger.Error(err, "error retrieving groups")
		p.ErrorResponse(rw, req, err.Error(), codeForError(err))
		return
	}

	response := getProfileResponse{
		Email:  email,
		Groups: groups,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("error marshaling response: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("GAP-Auth", email)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(jsonBytes)
}

// ValidateToken validates the X-Access-Token from the header and returns an error response
// if it's invalid
func (p *Authenticator) ValidateToken(rw http.ResponseWriter, req *http.Request) {
	accessToken := req.Header.Get("X-Access-Token")

	tags := []string{
		"action:validate",
	}

	if accessToken == "" {
		tags = append(tags, "error:empty_access_token")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	ok := p.provider.ValidateSessionState(&sessions.SessionState{
		AccessToken: accessToken,
	})

	if !ok {
		tags = append(tags, "error:invalid_access_token")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	rw.WriteHeader(http.StatusOK)
	return
}

// Stop calls the provider's stop function
func (p *Authenticator) Stop() {
	p.provider.Stop()
}
