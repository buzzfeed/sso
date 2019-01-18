package proxy

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/proxy/collector"
	"github.com/buzzfeed/sso/internal/proxy/providers"

	"github.com/18F/hmacauth"
	"github.com/datadog/datadog-go/statsd"
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
	"Cookie",
}

// Errors
var (
	ErrLifetimeExpired   = errors.New("user lifetime expired")
	ErrUserNotAuthorized = errors.New("user not authorized")
	ErrUnknownHost       = errors.New("unknown host")
)

const statusInvalidHost = 421

// EmailValidatorFn function type for validating email addresses.
type EmailValidatorFn func(string) bool

// OAuthProxy stores all the information associated with proxying the request.
type OAuthProxy struct {
	CookieSecure bool
	CookieCipher aead.Cipher

	EmailValidator EmailValidatorFn

	redirectURL       *url.URL // the url to receive requests at
	provider          providers.Provider
	skipAuthPreflight bool
	templates         *template.Template

	PassAccessToken bool

	StatsdClient *statsd.Client

	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore

	mux         map[string]*route
	regexRoutes []*route

	requestSigner   *RequestSigner
	publicCertsJSON []byte
}

type route struct {
	upstreamConfig *UpstreamConfig
	handler        http.Handler
	tags           []string

	// only used for ones that have regex
	regex *regexp.Regexp
}

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// UpstreamProxy stores information necessary for proxying the request back to the upstream.
type UpstreamProxy struct {
	name          string
	cookieName    string
	handler       http.Handler
	auth          hmacauth.HmacAuth
	requestSigner *RequestSigner
	statsdClient  *statsd.Client
}

// deleteSSOCookieHeader deletes the session cookie from the request header string.
func deleteSSOCookieHeader(req *http.Request, cookieName string) {
	headers := []string{}
	for _, cookie := range req.Cookies() {
		if cookie.Name != cookieName {
			headers = append(headers, cookie.String())
		}
	}
	req.Header.Set("Cookie", strings.Join(headers, ";"))
}

// ServeHTTP signs the http request and deletes cookie headers
// before calling the upstream's ServeHTTP function.
func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deleteSSOCookieHeader(r, u.cookieName)
	if u.auth != nil {
		u.auth.SignRequest(r)
	}
	if u.requestSigner != nil {
		u.requestSigner.Sign(r)
	}

	start := time.Now()
	u.handler.ServeHTTP(w, r)
	duration := time.Now().Sub(start)

	tags := []string{
		fmt.Sprintf("service_name:%s", u.name),
	}
	u.statsdClient.Timing("proxy_request", duration, tags, 1.0)
}

// upstreamTransport is used to ensure that upstreams cannot override the
// security headers applied by sso_proxy
type upstreamTransport struct {
	transport *http.Transport
}

// RoundTrip round trips the request and deletes security headers before returning the response.
func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		logger := log.NewLogEntry()
		logger.Error(err, "error in upstreamTransport RoundTrip")
		return nil, err
	}
	for key := range securityHeaders {
		resp.Header.Del(key)
	}
	return resp, err
}

func newUpstreamTransport(insecureSkipVerify bool) *upstreamTransport {
	return &upstreamTransport{
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// NewReverseProxy creates a reverse proxy to a specified url.
// It adds an X-Forwarded-Host header that is the request's host.
func NewReverseProxy(to *url.URL, config *UpstreamConfig) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(to)
	proxy.Transport = newUpstreamTransport(config.TLSSkipVerify)
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		director(req)
		if !config.PreserveHost {
			req.Host = to.Host
		}
	}
	return proxy
}

// NewRewriteReverseProxy creates a reverse proxy that is capable of creating upstream
// urls on the fly based on a from regex and a templated to field.
// It adds an X-Forwarded-Host header to the the upstream's request.
func NewRewriteReverseProxy(route *RewriteRoute, config *UpstreamConfig) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}
	proxy.Transport = newUpstreamTransport(config.TLSSkipVerify)
	proxy.Director = func(req *http.Request) {
		// we do this to rewrite requests
		rewritten := route.FromRegex.ReplaceAllString(req.Host, route.ToTemplate.Opaque)

		// we use to favor scheme's used in the regex, else we use the default passed in via the template
		target, err := urlParse(route.ToTemplate.Scheme, rewritten)
		if err != nil {
			logger := log.NewLogEntry()
			// we aren't in an error handling context so we have to fake it(thanks stdlib!)
			logger.WithRequestHost(req.Host).WithRewriteRoute(route).Error(
				err, "unable to parse and replace rewrite url")
			req.URL = nil // this will raise an error in http.RoundTripper
			return
		}
		director := httputil.NewSingleHostReverseProxy(target).Director

		req.Header.Add("X-Forwarded-Host", req.Host)
		director(req)
		if !config.PreserveHost {
			req.Host = target.Host
		}
	}
	return proxy
}

// NewReverseProxyHandler creates a new http.Handler given a httputil.ReverseProxy
func NewReverseProxyHandler(reverseProxy *httputil.ReverseProxy, opts *Options, config *UpstreamConfig, signer *RequestSigner) (http.Handler, []string) {
	upstreamProxy := &UpstreamProxy{
		name:          config.Service,
		handler:       reverseProxy,
		auth:          config.HMACAuth,
		cookieName:    opts.CookieName,
		statsdClient:  opts.StatsdClient,
		requestSigner: signer,
	}
	if config.SkipRequestSigning {
		upstreamProxy.requestSigner = nil
	}
	if config.FlushInterval != 0 {
		return NewStreamingHandler(upstreamProxy, opts, config), []string{"handler:streaming"}
	}
	return NewTimeoutHandler(upstreamProxy, opts, config), []string{"handler:timeout"}
}

// NewTimeoutHandler creates a new handler with a configure timeout.
func NewTimeoutHandler(handler http.Handler, opts *Options, config *UpstreamConfig) http.Handler {
	timeout := opts.DefaultUpstreamTimeout
	if config.Timeout != 0 {
		timeout = config.Timeout
	}
	timeoutMsg := fmt.Sprintf(
		"%s failed to respond within the %s timeout period", config.Service, timeout)
	return http.TimeoutHandler(handler, timeout, timeoutMsg)
}

// NewStreamingHandler creates a new handler capable of proxying a stream
func NewStreamingHandler(handler http.Handler, opts *Options, config *UpstreamConfig) http.Handler {
	upstreamProxy := handler.(*UpstreamProxy)
	reverseProxy := upstreamProxy.handler.(*httputil.ReverseProxy)
	reverseProxy.FlushInterval = config.FlushInterval
	return upstreamProxy
}

func generateHmacAuth(signatureKey string) (hmacauth.HmacAuth, error) {
	components := strings.Split(signatureKey, ":")
	if len(components) != 2 {
		return nil, fmt.Errorf("invalid signature hash:key spec")
	}

	algorithm, secret := components[0], components[1]
	hash, err := hmacauth.DigestNameToCryptoHash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported signature hash algorithm: %s", algorithm)
	}
	auth := hmacauth.NewHmacAuth(hash, []byte(secret), HMACSignatureHeader, SignatureHeaders)
	return auth, nil
}

// NewOAuthProxy creates a new OAuthProxy struct.
func NewOAuthProxy(opts *Options, optFuncs ...func(*OAuthProxy) error) (*OAuthProxy, error) {
	logger := log.NewLogEntry()
	logger.WithProvider(opts.provider.Data().ProviderName).WithClientID(opts.ClientID).Info(
		"OAuthProxy configured")
	domain := opts.CookieDomain
	if domain == "" {
		domain = "<default>"
	}

	// we setup a runtime collector to emit stats to datadog
	go func() {
		c := collector.New(opts.StatsdClient, 30*time.Second)
		c.Run()
	}()

	// Configure the RequestSigner (used to sign requests with `Sso-Signature` header).
	// Also build the `certs` static JSON-string which will be served from a public endpoint.
	// The key published at this endpoint allows upstreams to decrypt the `Sso-Signature`
	// header, and validate the integrity and authenticity of a request.
	certs := make(map[string]string)
	var requestSigner *RequestSigner
	var err error
	if len(opts.RequestSigningKey) > 0 {
		if requestSigner, err = NewRequestSigner(opts.RequestSigningKey); err != nil {
			return nil, fmt.Errorf("could not build RequestSigner: %s", err)
		}
		id, key := requestSigner.PublicKey()
		certs[id] = key
	} else {
		logger.Warn("Running OAuthProxy without signing key. Requests will not be signed.")
	}
	certsAsStr, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("could not marshal public certs as JSON: %s", err)
	}

	p := &OAuthProxy{

		CookieSecure: opts.CookieSecure,
		StatsdClient: opts.StatsdClient,

		// these fields make up the routing mechanism
		mux:         make(map[string]*route),
		regexRoutes: make([]*route, 0),

		provider:          opts.provider,
		redirectURL:       &url.URL{Path: "/oauth2/callback"},
		skipAuthPreflight: opts.SkipAuthPreflight,
		templates:         getTemplates(),
		PassAccessToken:   opts.PassAccessToken,

		requestSigner:   requestSigner,
		publicCertsJSON: certsAsStr,
	}

	for _, optFunc := range optFuncs {
		err := optFunc(p)
		if err != nil {
			return nil, err
		}
	}

	for _, upstreamConfig := range opts.upstreamConfigs {
		switch route := upstreamConfig.Route.(type) {
		case *SimpleRoute:
			reverseProxy := NewReverseProxy(route.ToURL, upstreamConfig)
			handler, tags := NewReverseProxyHandler(
				reverseProxy, opts, upstreamConfig, requestSigner)
			p.Handle(route.FromURL.Host, handler, tags, upstreamConfig)
		case *RewriteRoute:
			reverseProxy := NewRewriteReverseProxy(route, upstreamConfig)
			handler, tags := NewReverseProxyHandler(
				reverseProxy, opts, upstreamConfig, requestSigner)
			p.HandleRegex(route.FromRegex, handler, tags, upstreamConfig)
		default:
			return nil, fmt.Errorf("unknown route type")
		}
	}

	return p, nil
}

// Handler returns a http handler for an OAuthProxy
func (p *OAuthProxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", p.Favicon)
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/oauth2/v1/certs", p.Certs)
	mux.HandleFunc("/oauth2/sign_out", p.SignOut)
	mux.HandleFunc("/oauth2/callback", p.OAuthCallback)
	mux.HandleFunc("/oauth2/auth", p.AuthenticateOnly)
	mux.HandleFunc("/", p.Proxy)

	// Global middleware, which will be applied to each request in reverse
	// order as applied here (i.e., we want to validate the host _first_ when
	// processing a request)
	var handler http.Handler = mux
	if p.CookieSecure {
		handler = requireHTTPS(handler)
	}
	handler = p.setResponseHeaderOverrides(handler)
	handler = setSecurityHeaders(handler)
	handler = p.validateHost(handler)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Skip host validation for /ping requests because they hit the LB directly.
		if req.URL.Path == "/ping" {
			p.PingPage(rw, req)
			return
		}
		handler.ServeHTTP(rw, req)
	})
}

// UnknownHost returns an http error for unknown or invalid hosts
func (p *OAuthProxy) UnknownHost(rw http.ResponseWriter, req *http.Request) {
	logger := log.NewLogEntry()

	tags := []string{
		fmt.Sprintf("action:%s", GetActionTag(req)),
		"error:unknown_host",
	}
	p.StatsdClient.Incr("application_error", tags, 1.0)
	logger.WithRequestHost(req.Host).Error("unknown host")
	http.Error(rw, "", statusInvalidHost)
}

// Handle constructs a route from the given host string and matches it to the provided http.Handler and UpstreamConfig
func (p *OAuthProxy) Handle(host string, handler http.Handler, tags []string, upstreamConfig *UpstreamConfig) {
	tags = append(tags, "route:simple")
	p.mux[host] = &route{handler: handler, upstreamConfig: upstreamConfig, tags: tags}
}

// HandleRegex constructs a route from the given regexp and matches it to the provided http.Handler and UpstreamConfig
func (p *OAuthProxy) HandleRegex(regex *regexp.Regexp, handler http.Handler, tags []string, upstreamConfig *UpstreamConfig) {
	tags = append(tags, "route:rewrite")
	p.regexRoutes = append(p.regexRoutes, &route{regex: regex, handler: handler, upstreamConfig: upstreamConfig, tags: tags})
}

// router attempts to find a route for a equest. If a route is successfully matched,
// it returns the route information and a bool value of `true`. If a route can not be matched,
//a nil value for the route and false bool value is returned.
func (p *OAuthProxy) router(req *http.Request) (*route, bool) {
	route, ok := p.mux[req.Host]
	if ok {
		return route, true
	}

	for _, route := range p.regexRoutes {
		if route.regex.MatchString(req.Host) {
			return route, true
		}
	}

	return nil, false
}

// GetRedirectURL returns the redirect url for a given OAuthProxy,
// setting the scheme to be https if CookieSecure is true.
func (p *OAuthProxy) GetRedirectURL(host string) *url.URL {
	// TODO: Ensure that we only allow valid upstream hosts in redirect URIs
	var u url.URL
	u = *p.redirectURL

	// Build redirect URI from request host
	if u.Scheme == "" {
		if p.CookieSecure {
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

// PingPage send back a 200 OK response.
func (p *OAuthProxy) PingPage(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "OK")
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

	route, ok := p.router(req)
	if !ok {
		// This proxy host doesn't exist, so not allowed
		return false
	}

	upstreamConfig := route.upstreamConfig
	for _, re := range upstreamConfig.SkipAuthCompiledRegex {
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
		if p.CookieSecure {
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
	//              from our prespective this will always be static since the client
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
	encryptedCSRF, err := p.CookieCipher.Marshal(state)
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
	encryptedState, err := p.CookieCipher.Marshal(state)
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
	err = p.CookieCipher.Unmarshal(encryptedState, stateParameter)
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
	p.csrfStore.ClearCSRF(rw, req)

	encryptedCSRF := c.Value
	csrfParameter := &StateParameter{}
	err = p.CookieCipher.Unmarshal(encryptedCSRF, csrfParameter)
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
	// for the resources requested. This can be set via the email address or any groups.
	//
	// set cookie, or deny
	if !p.EmailValidator(session.Email) {
		tags = append(tags, "error:invalid_email")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
			"permission denied: unauthorized")
		p.ErrorPage(rw, req, http.StatusForbidden, "Permission Denied", "Invalid Account")
		return
	}

	route, ok := p.router(req)
	if !ok {
		// this shouldn't happen since we've already matched the host once on this request
		tags = append(tags, "error:unknown_host")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
			"couldn't resolve route from host name for membership check")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Error looking up route for group membership")
		return
	}
	allowedGroups := route.upstreamConfig.AllowedGroups

	inGroups, validGroup, err := p.provider.ValidateGroup(session.Email, allowedGroups)
	if err != nil {
		tags = append(tags, "error:user_group_failed")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).Info(
			"couldn't fetch user groups")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Error validating group membership, please try again")
		return
	}
	if !validGroup {
		tags = append(tags, "error:unauthorized_email")
		p.StatsdClient.Incr("provider_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).WithAllowedGroups(
			allowedGroups).Info("permission denied: unauthorized")
		p.ErrorPage(rw, req, http.StatusForbidden, "Permission Denied", "Group membership required")
		return
	}
	logger.WithRemoteAddress(remoteAddr).WithUser(session.Email).WithInGroups(inGroups).Info(
		"authentication complete")
	session.Groups = inGroups

	// We store the session in a cookie and redirect the user back to the application
	err = p.sessionStore.SaveSession(rw, req, session)
	if err != nil {
		tags = append(tags, "error:save_session_error")
		p.StatsdClient.Incr("application_error", tags, 1.0)
		logger.WithRemoteAddress(remoteAddr).Error(err, "error saving session")
		p.ErrorPage(rw, req, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

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
		case ErrUserNotAuthorized:
			tags = append(tags, "error:user_unauthorized")
			p.StatsdClient.Incr("application_error", tags, 1.0)
			// We know the user is not authorized for the request, we show them a forbidden page
			p.ErrorPage(rw, req, http.StatusForbidden, "Forbidden", "You're not authorized to view this page")
			return
		case ErrLifetimeExpired:
			// User's lifetime expired, we trigger the start of the oauth flow
			p.OAuthStart(rw, req, tags)
			return
		case sessions.ErrInvalidSession:
			// The user session is invalid and we can't decode it.
			// This can happen for a variety of reasons but the most common non-malicious
			// case occurs when the session encoding schema changes. We manage this ux
			// by triggering the start of the oauth flow.
			p.OAuthStart(rw, req, tags)
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

	// We have validated the users request and now proxy their request to the provided upstream.
	route, ok := p.router(req)
	if !ok {
		p.UnknownHost(rw, req)
		return
	}
	if route.tags != nil {
		tags = append(tags, route.tags...)
	}

	overhead := time.Now().Sub(start)
	p.StatsdClient.Timing("request_overhead", overhead, tags, 1.0)

	route.handler.ServeHTTP(rw, req)
}

// Authenticate authenticates a request by checking for a session cookie, and validating its expiration,
// clearing the session cookie if it's invalid and returning an error if necessary..
func (p *OAuthProxy) Authenticate(rw http.ResponseWriter, req *http.Request) (err error) {
	logger := log.NewLogEntry().WithRemoteAddress(getRemoteAddr(req))

	route, ok := p.router(req)
	if !ok {
		logger.WithRequestHost(req.Host).Info(
			"error looking up route by host to validate user groups")
		return ErrUnknownHost
	}
	allowedGroups := route.upstreamConfig.AllowedGroups

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

	if !p.EmailValidator(session.Email) {
		logger.WithUser(session.Email).Error("not authorized")
		return ErrUserNotAuthorized
	}

	req.Header.Set("X-Forwarded-User", session.User)

	if p.PassAccessToken && session.AccessToken != "" {
		req.Header.Set("X-Forwarded-Access-Token", session.AccessToken)
	}

	req.Header.Set("X-Forwarded-Email", session.Email)
	req.Header.Set("X-Forwarded-Groups", strings.Join(session.Groups, ","))

	// stash authenticated user so that it can be logged later (see func logRequest)
	rw.Header().Set(loggingUserHeader, session.Email)

	// This user has been OK'd. Allow the request!
	return nil
}
