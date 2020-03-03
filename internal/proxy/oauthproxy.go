package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/proxy/providers"

	"github.com/datadog/datadog-go/statsd"
	"github.com/gorilla/mux"
)

// HMACSignatureHeader is the header name where the signed request header is stored.
const HMACSignatureHeader = "Gap-Signature"

// SignatureHeaders are the headers that are valid in the request.
var SignatureHeaders = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Groups",
	"X-Forwarded-Access-Token",
	"Cookie",
}

// Errors
var (
	ErrLifetimeExpired       = errors.New("user lifetime expired")
	ErrUserNotAuthorized     = errors.New("user not authorized")
	ErrWrongIdentityProvider = errors.New("user authenticated with wrong identity provider")
)

type ErrOAuthProxyMisconfigured struct {
	Missing string
}

func (e *ErrOAuthProxyMisconfigured) Error() string {
	return fmt.Sprintf("OAuthProxy is misconfigured: missing required component: %s", e.Missing)
}

const statusInvalidHost = 421

// OAuthProxy stores all the information associated with proxying the request.
type OAuthProxy struct {
	cookieSecure bool
	Validators   []options.Validator
	redirectURL  *url.URL // the url to receive requests at
	templates    *template.Template

	skipAuthPreflight bool
	passAccessToken   bool

	StatsdClient *statsd.Client

	requestSigner   *RequestSigner
	publicCertsJSON []byte

	// these are required
	provider       providers.Provider
	cookieCipher   aead.Cipher
	upstreamConfig *UpstreamConfig
	handler        http.Handler
	csrfStore      sessions.CSRFStore
	sessionStore   sessions.SessionStore
}

// SetCookieStore sets the session and csrf stores as a functional option
func SetCookieStore(opts *Options) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		cookieStore, err := sessions.NewCookieStore(opts.CookieName,
			sessions.CreateMiscreantCookieCipher(opts.decodedCookieSecret),
			func(c *sessions.CookieStore) error {
				c.CookieDomain = opts.CookieDomain
				c.CookieHTTPOnly = opts.CookieHTTPOnly
				c.CookieExpire = opts.CookieExpire
				c.CookieSecure = opts.CookieSecure
				return nil
			})

		if err != nil {
			return err
		}

		op.csrfStore = cookieStore
		op.sessionStore = cookieStore
		op.cookieCipher = cookieStore.CookieCipher
		return nil
	}
}

// SetRequestSigner sets the request signer  as a functional option
// SetRequestSigner sets a request signer
func SetRequestSigner(signer *RequestSigner) func(*OAuthProxy) error {
	logger := log.NewLogEntry()
	return func(op *OAuthProxy) error {
		if signer == nil {
			logger.Warn("Running OAuthProxy without signing key. Requests will not be signed.")
			return nil
		}

		// Configure the RequestSigner (used to sign requests with `Sso-Signature` header).
		// Also build the `certs` static JSON-string which will be served from a public endpoint.
		// The key published at this endpoint allows upstreams to decrypt the `Sso-Signature`
		// header, and validate the integrity and authenticity of a request.

		certs := make(map[string]string)
		id, key := signer.PublicKey()
		certs[id] = key

		certsAsStr, err := json.MarshalIndent(certs, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal public certs as JSON: %s", err)
		}

		op.requestSigner = signer
		op.publicCertsJSON = certsAsStr

		return nil
	}
}

// SetUpstreamConfig sets the upstream config as a functional option
func SetUpstreamConfig(upstreamConfig *UpstreamConfig) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.upstreamConfig = upstreamConfig
		return nil
	}
}

// SetProxyHandler sets the proxy handler as a functional option
func SetProxyHandler(handler http.Handler) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.handler = handler
		return nil
	}
}

// SetValidator sets the email validator as a functional option
func SetValidators(validators []options.Validator) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.Validators = validators
		return nil
	}
}

// SetProvider sets the provider as a functional option
func SetProvider(provider providers.Provider) func(*OAuthProxy) error {
	return func(op *OAuthProxy) error {
		op.provider = provider
		return nil
	}
}

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// NewOAuthProxy creates a new OAuthProxy struct.
func NewOAuthProxy(opts *Options, optFuncs ...func(*OAuthProxy) error) (*OAuthProxy, error) {
	p := &OAuthProxy{
		cookieSecure: opts.CookieSecure,
		StatsdClient: opts.StatsdClient,
		Validators:   []options.Validator{},

		redirectURL: &url.URL{Path: "/oauth2/callback"},
		templates:   getTemplates(),

		skipAuthPreflight: opts.SkipAuthPreflight,
		passAccessToken:   opts.PassAccessToken,
	}

	for _, optFunc := range optFuncs {
		err := optFunc(p)
		if err != nil {
			return nil, err
		}
	}

	// these are required by the oauth proxy
	if p.provider == nil {
		return nil, &ErrOAuthProxyMisconfigured{
			Missing: "Identity Provider",
		}
	}
	if p.cookieCipher == nil {
		return nil, &ErrOAuthProxyMisconfigured{
			Missing: "Cookie Cipher",
		}
	}
	if p.upstreamConfig == nil {
		return nil, &ErrOAuthProxyMisconfigured{
			Missing: "Upstream Config",
		}
	}
	if p.handler == nil {
		return nil, &ErrOAuthProxyMisconfigured{
			Missing: "http.Handler",
		}
	}
	if p.csrfStore == nil {
		return nil, &ErrOAuthProxyMisconfigured{
			Missing: "CSRF Store",
		}
	}
	if p.sessionStore == nil {
		return nil, &ErrOAuthProxyMisconfigured{
			Missing: "Session Store",
		}
	}

	return p, nil
}

// Handler returns a http handler for an OAuthProxy
func (p *OAuthProxy) Handler() http.Handler {
	mux := mux.NewRouter()
	mux.UseEncodedPath()
	mux.HandleFunc("/favicon.ico", p.Favicon)
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/oauth2/v1/certs", p.Certs)
	mux.HandleFunc("/oauth2/sign_out", p.SignOut)
	mux.HandleFunc("/oauth2/callback", p.OAuthCallback)
	mux.HandleFunc("/oauth2/auth", p.AuthenticateOnly)
	mux.PathPrefix("/").HandlerFunc(p.Proxy)

	// Global middleware, which will be applied to each request in reverse
	// order as applied here (i.e., we want to validate the host _first_ when
	// processing a request)
	var handler http.Handler = mux
	if p.cookieSecure {
		handler = requireHTTPS(handler)
	}
	handler = p.setResponseHeaderOverrides(p.upstreamConfig, handler)
	handler = setSecurityHeaders(handler)

	return handler
}

// GetRedirectURL returns the redirect url for a given OAuthProxy,
// setting the scheme to be https if CookieSecure is true.
func (p *OAuthProxy) GetRedirectURL(host string) *url.URL {
	// TODO: Ensure that we only allow valid upstream hosts in redirect URIs
	var u url.URL
	u = *p.redirectURL

	// Build redirect URI from request host
	if u.Scheme == "" {
		if p.cookieSecure {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	u.Host = host
	return &u
}

func (p *OAuthProxy) redeemCode(host, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	redirectURL := p.GetRedirectURL(host)
	s, err := p.provider.Redeem(redirectURL.String(), code)
	if err != nil {
		return s, err
	}

	if s.Email == "" {
		return s, errors.New("invalid email address")
	}
	return s, nil
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *OAuthProxy) RobotsTxt(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}

// Certs publishes the public key necessary for upstream services to validate the digital signature
// used to sign each request.
func (p *OAuthProxy) Certs(rw http.ResponseWriter, _ *http.Request) {
	rw.Write(p.publicCertsJSON)
}

// Favicon will proxy the request as usual if the user is already authenticated
// but responds with a 404 otherwise, to avoid spurious and confusing
// authentication attempts when a browser automatically requests the favicon on
// an error page.
func (p *OAuthProxy) Favicon(rw http.ResponseWriter, req *http.Request) {
	err := p.Authenticate(rw, req)
	if err != nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	p.Proxy(rw, req)
}

// XHRError returns a simple error response with an error message to the application if the request is an XML request
func (p *OAuthProxy) XHRError(rw http.ResponseWriter, req *http.Request, code int, err error) {
	remoteAddr := getRemoteAddr(req)
	logger := log.NewLogEntry().WithRemoteAddress(remoteAddr)

	jsonError := struct {
		Error error `json:"error"`
	}{
		Error: err,
	}

	jsonBytes, err := json.Marshal(jsonError)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	logger.WithHTTPStatus(code).WithRequestURI(req.URL.String()).Error(err, "error serving XHR")
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write(jsonBytes)
}

// ErrorPage renders an error page with a given status code, title, and message.
func (p *OAuthProxy) ErrorPage(rw http.ResponseWriter, req *http.Request, code int, title string, message string) {
	if p.isXHR(req) {
		p.XHRError(rw, req, code, errors.New(message))
		return
	}

	remoteAddr := getRemoteAddr(req)
	logger := log.NewLogEntry().WithRemoteAddress(remoteAddr)

	logger.WithHTTPStatus(code).WithPageTitle(title).WithPageMessage(message).Info(
		"error page")
	rw.WriteHeader(code)
	t := struct {
		Code    int
		Title   string
		Message string
	}{
		Code:    code,
		Title:   title,
		Message: message,
	}
	p.templates.ExecuteTemplate(rw, "error.html", t)
}

// IsWhitelistedRequest cheks that proxy host exists and checks the SkipAuthRegex
func (p *OAuthProxy) IsWhitelistedRequest(req *http.Request) bool {
	if p.skipAuthPreflight && req.Method == "OPTIONS" {
		return true
	}

	for _, re := range p.upstreamConfig.SkipAuthCompiledRegex {
		if re.MatchString(req.URL.Path) {
			// This upstream has a matching skip auth regex
			return true
		}
	}

	return false
}

func (p *OAuthProxy) isXHR(req *http.Request) bool {
	return req.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// SignOut redirects the request to the provider's sign out url.
func (p *OAuthProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	p.sessionStore.ClearSession(rw, req)

	var scheme string

	// Build redirect URI from request host
	if req.URL.Scheme == "" {
		if p.cookieSecure {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	redirectURL := &url.URL{
		Scheme: scheme,
		Host:   req.Host,
		Path:   "/",
	}
	fullURL := p.provider.GetSignOutURL(redirectURL)
	http.Redirect(rw, req, fullURL.String(), http.StatusFound)
}

// OAuthStart begins the authentication flow, encrypting the redirect url in a request to the provider's sign in endpoint.
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request, tags []string) {
	// The proxy redirects to the authenticator, and provides it with redirectURI (which points
	// back to the sso proxy).
	logger := log.NewLogEntry()
	remoteAddr := getRemoteAddr(req)

	if p.isXHR(req) {
		logger.WithRemoteAddress(remoteAddr).Error("aborting start of oauth flow on XHR")
		p.XHRError(rw, req, http.StatusUnauthorized, errors.New("cannot continue oauth flow on xhr"))
		return
	}

	requestURI := req.URL.String()
	callbackURL := p.GetRedirectURL(req.Host)

	// We redirect the browser to the authenticator with a 302 status code. The target URL is
	// constructed using the GetSignInURL() method, which encodes the following data:
	//
	// * client_id: Defined by the OAuth2 RFC https://tools.ietf.org/html/rfc6749.
	//              Identifies the application requesting authentication information,
	//              from our perspective this will always be static since the client
	//              will always be sso proxy
	//
	// * redirect_uri: Defined by the OAuth2 RFC https://tools.ietf.org/html/rfc6749.
	//                 Informs the authenticator _where_ to redirect the user back to once
	//                 they have authenticated with the auth provider and given us permission
	//                 to access their auth information
	//
	// * response_type: Defined by the OAuth2 RFC https://tools.ietf.org/html/rfc6749.
	//                  Required by the spec and must be set to "code"
	//
	// * scope: Defined by the OAuth2 RFC https://tools.ietf.org/html/rfc6749.
	//          Used to offer different auth scopes, but will be unnecessary in the context of SSO.
	//
	// * state: Defined by the OAuth2 RFC https://tools.ietf.org/html/rfc6749.
	//          Used to prevent cross site forgery and maintain state across the client and server.

	key := aead.GenerateKey()

	state := &StateParameter{
		SessionID:   fmt.Sprintf("%x", key),
		RedirectURI: requestURI,
	}

	// we encrypt this value to be opaque the browser cookie
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedCSRF, err := p.cookieCipher.Marshal(state)
	if err != nil {
		tags = append(tags, "csrf_token_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.Error(err, "failed to marshal state parameter for CSRF token")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}
	p.csrfStore.SetCSRF(rw, req, encryptedCSRF)

	// we encrypt this value to be opaque the uri query value
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedState, err := p.cookieCipher.Marshal(state)
	if err != nil {
		tags = append(tags, "error:marshaling_state_parameter")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.Error(err, "failed to marshal state parameter for state query parameter")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}

	signinURL := p.provider.GetSignInURL(callbackURL, encryptedState)
	logger.WithSignInURL(signinURL).Info("starting OAuth flow")
	http.Redirect(rw, req, signinURL.String(), http.StatusFound)
}

// OAuthCallback validates the cookie sent back from the provider, then validates
// the user information, and if authorized, redirects the user back to the original
// application.
func (p *OAuthProxy) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	// We receive the callback from the SSO Authenticator. This request will either contain an
	// error, or it will contain a `code`; the code can be used to fetch an access token, and
	// other metadata, from the authenticator.
	logger := log.NewLogEntry()

	remoteAddr := getRemoteAddr(req)
	tags := []string{"action:callback"}

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		tags = append(tags, "error:callback_error_exists")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorPage(rw, req, http.StatusForbidden, "Permission Denied", errorString)
		return
	}

	// We begin the process of redeeming the code for an access token.
	session, err := p.redeemCode(req.Host, req.Form.Get("code"))
	if err != nil {
		tags = append(tags, "error:redeem_code_error")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(
			err, "error redeeming authorization code")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	encryptedState := req.Form.Get("state")
	stateParameter := &StateParameter{}
	err = p.cookieCipher.Unmarshal(encryptedState, stateParameter)
	if err != nil {
		tags = append(tags, "error:state_parameter_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(
			err, "could not unmarshal state parameter value")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	c, err := p.csrfStore.GetCSRF(req)
	if err != nil {
		tags = append(tags, "error:csrf_cookie_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		p.ErrorPage(rw, req, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}

	encryptedCSRF := c.Value
	csrfParameter := &StateParameter{}
	err = p.cookieCipher.Unmarshal(encryptedCSRF, csrfParameter)
	if err != nil {
		tags = append(tags, "error:csrf_parameter_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(
			err, "couldn't unmarshal CSRF parameter value")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	if encryptedState == encryptedCSRF {
		tags = append(tags, "error:equal_encrypted_state_and_csrf")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Info(
			"encrypted state value and encrypted CSRF value are unexpectedly equal")
		p.ErrorPage(rw, req, http.StatusBadRequest, "Bad Request", "Bad Request")
		return
	}

	if !reflect.DeepEqual(stateParameter, csrfParameter) {
		tags = append(tags, "error:state_csrf_mismatch")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Info(
			"state parameter and CSRF parameters are unexpectedly not equal")
		p.ErrorPage(rw, req, http.StatusBadRequest, "Bad Request", "Bad Request")
		return
	}

	// We validate the user information, and check that this user has proper authorization
	// for the resources requested.
	//
	// set cookie, or deny

	errors := options.RunValidators(p.Validators, session)
	if len(errors) == len(p.Validators) {
		tags = append(tags, "error:validation_failed")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
			fmt.Sprintf("permission denied: unauthorized: %q", errors))

		formattedErrors := make([]string, 0, len(errors))
		for _, err := range errors {
			formattedErrors = append(formattedErrors, err.Error())
		}
		errorMsg := fmt.Sprintf("We ran into some issues while validating your account: \"%s\"",
			strings.Join(formattedErrors, ", "))
		p.ErrorPage(rw, req, http.StatusForbidden, "Permission Denied", errorMsg)
		return
	}

	logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).WithInGroups(session.Groups).Info(
		fmt.Sprintf("oauth callback: user validated "))

	// We store the session in a cookie and redirect the user back to the application
	err = p.sessionStore.SaveSession(rw, req, session)
	if err != nil {
		tags = append(tags, "error:save_session_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(err, "error saving session")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	// Now that we know the request and user is valid, clear the CSRF token
	p.csrfStore.ClearCSRF(rw, req)

	// This is the redirect back to the original requested application
	http.Redirect(rw, req, stateParameter.RedirectURI, http.StatusFound)
}

// AuthenticateOnly calls the Authenticate handler.
func (p *OAuthProxy) AuthenticateOnly(rw http.ResponseWriter, req *http.Request) {
	logger := log.NewLogEntry()
	err := p.Authenticate(rw, req)
	if err != nil {
		p.StatsdClient.Incr("application_error", []string{"action:auth", "error:unauthorized_request"}, 1.0)
		logger.Error(err, "error authenticating")
		http.Error(rw, "unauthorized request", http.StatusUnauthorized)
	}
	rw.WriteHeader(http.StatusAccepted)
}

// Proxy authenticates a request, either proxying the request if it is authenticated, or starting the authentication process if not.
func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	// Attempts to validate the user and their cookie.
	logger := log.NewLogEntry()
	start := time.Now()
	tags := []string{"action:proxy"}
	var err error

	// If the request is explicitly whitelisted, we skip authentication
	if p.IsWhitelistedRequest(req) {
		tags = append(tags, "auth_type:whitelisted")
	} else {
		tags = append(tags, "auth_type:authenticated")
		err = p.Authenticate(rw, req)
	}

	// If the authentication is not successful we proceed to start the OAuth Flow with
	// OAuthStart. If authentication is successful, we proceed to proxy to the configured
	// upstream.
	if err != nil {
		switch err {
		case http.ErrNoCookie:
			// No cookie is set, start the oauth flow
			p.OAuthStart(rw, req, tags)
			return
		case ErrLifetimeExpired:
			// User's lifetime expired, we trigger the start of the oauth flow
			p.OAuthStart(rw, req, tags)
			return
		case ErrWrongIdentityProvider:
			// User is authenticated with the incorrect provider. This most common non-malicious
			// case occurs when an upstream has been transitioned to a different provider but
			// the user has a stale sesssion.
			p.OAuthStart(rw, req, tags)
			return
		case sessions.ErrInvalidSession:
			// The user session is invalid and we can't decode it.
			// This can happen for a variety of reasons but the most common non-malicious
			// case occurs when the session encoding schema changes. We manage this ux
			// by triggering the start of the oauth flow.
			p.OAuthStart(rw, req, tags)
			return
		case ErrUserNotAuthorized:
			tags = append(tags, "error:user_unauthorized")
			p.StatsdClient.Incr("application_error", tags, 1.0)
			// We know the user is not authorized for the request, we show them a forbidden page
			p.ErrorPage(rw, req, http.StatusForbidden, "Forbidden", "You're not authorized to view this page")
			return
		case providers.ErrTokenRevoked:
			p.ErrorPage(rw, req, http.StatusUnauthorized, "Unauthorized", "Token Expired or Revoked")
			return
		default:
			logger.Error(err, "unknown error authenticating user")
			tags = append(tags, "error:internal_error")
			p.StatsdClient.Incr("application_error", tags, 1.0)
			// We don't know exactly what happened, but authenticating the user failed, show an error
			p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "An unexpected error occurred")
			return
		}
	}

	overhead := time.Now().Sub(start)
	p.StatsdClient.Timing("request_overhead", overhead, tags, 1.0)

	p.handler.ServeHTTP(rw, req)
}

// Authenticate authenticates a request by checking for a session cookie, and validating its expiration,
// clearing the session cookie if it's invalid and returning an error if necessary..
func (p *OAuthProxy) Authenticate(rw http.ResponseWriter, req *http.Request) (err error) {
	logger := log.NewLogEntry().WithRemoteAddress(getRemoteAddr(req))

	remoteAddr := getRemoteAddr(req)
	tags := []string{"action:authenticate"}

	allowedGroups := p.upstreamConfig.AllowedGroups

	// Clear the session cookie if anything goes wrong.
	defer func() {
		if err != nil {
			p.sessionStore.ClearSession(rw, req)
		}
	}()

	session, err := p.sessionStore.LoadSession(req)
	if err != nil {
		// We loaded a cookie but it wasn't valid, clear it, and reject the request
		logger.Error(err, "error authenticating user")
		return err
	}

	// check if this session belongs to the correct identity provider application.
	// this case exists primarly to allow us to gracefully manage a clean ux during
	// transitions from one provider to another by gracefully restarting the authentication process.
	if session.ProviderSlug != p.provider.Data().ProviderSlug {
		logger.WithUser(session.Email).Info(
			"authenticated with incorrect identity provider; restarting authentication")
		return ErrWrongIdentityProvider
	}

	// Lifetime period is the entire duration in which the session is valid.
	// This should be set to something like 14 to 30 days.
	if session.LifetimePeriodExpired() {
		// session lifetime has expired, we reject the request and clear the cookie
		logger.WithUser(session.Email).Info(
			"lifetime has expired; restarting authentication")
		return ErrLifetimeExpired
	} else if session.RefreshPeriodExpired() {
		// Refresh period is the period in which the access token is valid. This is ultimately
		// controlled by the upstream provider and tends to be around 1 hour.
		ok, err := p.provider.RefreshSession(session, allowedGroups)
		// We failed to refresh the session successfully
		// clear the cookie and reject the request
		if err != nil {
			logger.WithUser(session.Email).Error(err, "refreshing session failed")
			return err
		}

		if !ok {
			// User is not authorized after refresh
			// clear the cookie and reject the request
			logger.WithUser(session.Email).Info(
				"not authorized after refreshing session")
			return ErrUserNotAuthorized
		}

		err = p.sessionStore.SaveSession(rw, req, session)
		if err != nil {
			// We refreshed the session successfully, but failed to save it.
			//
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request!
			logger.WithUser(session.Email).Error(
				err, "could not save refreshed session")
			return err
		}
	} else if session.ValidationPeriodExpired() {
		// Validation period has expired, this is the shortest interval we use to
		// check for valid requests. This should be set to something like a minute.
		// This calls up the provider chain to validate this user is still active
		// and hasn't been de-authorized.
		ok := p.provider.ValidateSessionState(session, allowedGroups)
		if !ok {
			// This user is now no longer authorized, or we failed to
			// validate the user.
			// Clear the cookie and reject the request
			logger.WithUser(session.Email).Error(
				err, "no longer authorized after validation period")
			return ErrUserNotAuthorized
		}

		err = p.sessionStore.SaveSession(rw, req, session)
		if err != nil {
			// We validated the session successfully, but failed to save it.

			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request!
			logger.WithUser(session.Email).Error(
				err, "could not save validated session")
			return err
		}
	}

	// We revalidate group membership whenever the session is refreshed or revalidated
	// just above in the call to ValidateSessionState and RefreshSession.
	// To reduce strain on upstream identity providers we only revalidate email domains and
	// addresses on each request here.
	for _, v := range p.Validators {
		_, EmailGroupValidator := v.(options.EmailGroupValidator)

		if !EmailGroupValidator {
			err := v.Validate(session)
			if err != nil {
				tags = append(tags, "error:validation_failed")
				p.StatsdClient.Incr("application_error", tags, 1.0)
				logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
					fmt.Sprintf("permission denied: unauthorized: %q", err))
				return ErrUserNotAuthorized
			}
		}
	}

	logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
		fmt.Sprintf("authentication: user validated"))

	for key, val := range p.upstreamConfig.InjectRequestHeaders {
		req.Header.Set(key, val)
	}

	req.Header.Set("X-Forwarded-User", session.User)

	if p.passAccessToken && session.AccessToken != "" {
		req.Header.Set("X-Forwarded-Access-Token", session.AccessToken)
	}

	req.Header.Set("X-Forwarded-Email", session.Email)
	req.Header.Set("X-Forwarded-Groups", strings.Join(session.Groups, ","))

	// stash authenticated user so that it can be logged later (see func logRequest)
	rw.Header().Set(loggingUserHeader, session.Email)

	// This user has been OK'd. Allow the request!
	return nil
}
