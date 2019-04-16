package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

// upstreamTransport is used to ensure that upstreams cannot override the
// security headers applied by sso_proxy. Also includes functionality to rotate
// http.Transport objects to ensure tcp connection reset deadlines are not exceeded
type upstreamTransport struct {
	mux sync.Mutex

	deadAfter     time.Time
	resetDeadline time.Duration

	transport          *http.Transport
	insecureSkipVerify bool
}

// RoundTrip round trips the request and deletes security headers before returning the response.
func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.getTransport().RoundTrip(req)
	if err != nil {
		log.Error(err, "error in upstreamTransport RoundTrip")
		return nil, err
	}
	return resp, err
}

// getTransport gets either a cached http transport or allocates a new one
// We proactively rotate tcp connects by re-cycling the http.Transport every
// resetDeadline period.
func (t *upstreamTransport) getTransport() *http.Transport {
	t.mux.Lock()
	defer t.mux.Unlock()

	if t.transport == nil || time.Now().After(t.deadAfter) {
		t.deadAfter = time.Now().Add(t.resetDeadline)
		t.transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: t.insecureSkipVerify},
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	return t.transport
}

func NewUpstreamReverseProxy(config *UpstreamConfig, signer *RequestSigner) (http.Handler, error) {
	baseDirector := &Director{
		config: config,
		signer: signer,
	}

	var directorFunc func(*http.Request)
	switch route := config.Route.(type) {
	case *SimpleRoute:
		directorFunc = baseDirector.StaticDirectorFunc(route)
	case *RewriteRoute:
		directorFunc = baseDirector.RewriteDirectorFunc(route)
	default:
		return nil, fmt.Errorf("unknown route type")
	}

	reverseProxy := &httputil.ReverseProxy{
		Director: directorFunc,
		Transport: &upstreamTransport{
			resetDeadline:      config.ResetDeadline,
			insecureSkipVerify: config.TLSSkipVerify,
		},
		ModifyResponse: func(resp *http.Response) error {
			// DRAGONS: This helps implement special behavior regarding security headers
			// We do not allow upstreams to override security headers and this is logic
			// is required to delete the headers from the response before we add new headers in
			// the response writer for all requests. If we add them here, they will only be added
			// to authenicated requests.
			for key := range securityHeaders {
				resp.Header.Del(key)
			}
			return nil
		},
	}

	if config.FlushInterval != 0 {
		reverseProxy.FlushInterval = config.FlushInterval
	}
	if config.Timeout != 0 {
		return newTimeoutHandler(reverseProxy, config), nil
	}

	return reverseProxy, nil
}

type Director struct {
	config *UpstreamConfig
	signer *RequestSigner
}

func (d *Director) DirectorFunc(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		targetQuery := target.RawQuery

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		// add x-forwarded-host
		req.Header.Add("X-Forwarded-Host", req.Host)
		if !d.config.PreserveHost {
			req.Host = target.Host
		}

		// delete session cookie
		deleteCookie(req, d.config.CookieName)

		// sign request
		if d.signer != nil && !d.config.SkipRequestSigning {
			d.signer.Sign(req)
		}
		if d.config.HMACAuth != nil && !d.config.SkipRequestSigning {
			d.config.HMACAuth.SignRequest(req)
		}
	}
}

func (d *Director) StaticDirectorFunc(route *SimpleRoute) func(*http.Request) {
	return d.DirectorFunc(route.ToURL)
}

func (d *Director) RewriteDirectorFunc(route *RewriteRoute) func(*http.Request) {
	return func(req *http.Request) {
		// we do this to rewrite requests
		logger := log.NewLogEntry()

		rewritten := route.FromRegex.ReplaceAllString(req.Host, route.ToTemplate.Opaque)

		// we use to favor scheme's used in the regex, else we use the default passed in via the template
		target, err := urlParse(route.ToTemplate.Scheme, rewritten)
		if err != nil {
			// we aren't in an error handling context so we have to fake it(thanks stdlib!)
			logger.WithRequestHost(req.Host).WithRewriteRoute(route).Error(
				err, "unable to parse and replace rewrite url")
			req.URL = nil // this will raise an error in http.RoundTripper
			return
		}

		d.DirectorFunc(target)(req)
	}
}

func newTimeoutHandler(handler http.Handler, config *UpstreamConfig) http.Handler {
	timeoutMsg := fmt.Sprintf("%s failed to respond within the %s timeout period", config.Service, config.Timeout)
	return http.TimeoutHandler(handler, config.Timeout, timeoutMsg)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// deleteCookie deletes the named cookie from the request header string.
func deleteCookie(req *http.Request, cookieName string) {
	headers := []string{}
	for _, cookie := range req.Cookies() {
		if cookie.Name != cookieName {
			headers = append(headers, cookie.String())
		}
	}

	if len(headers) == 0 {
		// there are no cookies other then session cookie so we delete the header entirely
		req.Header.Del("Cookie")
		return
	}

	// if there are other headers to keep, we set them minus the session cookie
	req.Header.Set("Cookie", strings.Join(headers, ";"))
}
