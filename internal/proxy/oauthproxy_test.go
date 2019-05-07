package proxy

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/18F/hmacauth"
	"github.com/mccutchen/go-httpbin/httpbin"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
	"github.com/buzzfeed/sso/internal/proxy/providers"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

}

func testValidatorFunc(valid bool) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.emailValidator = func(string) bool {
			return valid
		}
		return nil
	}
}

func setValidator(f func(string) bool) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.emailValidator = f
		return nil
	}
}

func setCSRFStore(s sessions.CSRFStore) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.csrfStore = s
		return nil
	}
}

func setSessionStore(s sessions.SessionStore) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.sessionStore = s
		return nil
	}
}

func setSkipAuthPreflight(skip bool) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.skipAuthPreflight = skip
		return nil
	}
}

// setCookieCipher is specifically for testing marshaling outside of the cookie store
func setCookieCipher(a aead.Cipher) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		if a != nil {
			p.cookieCipher = a
		}
		return nil
	}
}

func setCookieSecure(cookieSecure bool) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.cookieSecure = cookieSecure
		return nil
	}
}

func testSession() *sessions.SessionState {
	theFuture := time.Now().AddDate(100, 100, 100)

	return &sessions.SessionState{
		Email:       "michael.bland@gsa.gov",
		AccessToken: "my_access_token",
		Groups:      []string{"foo", "bar"},

		RefreshDeadline:  theFuture,
		LifetimeDeadline: theFuture,
		ValidDeadline:    theFuture,
	}
}

func testHTTPBin(t *testing.T) (*url.URL, func()) {
	h := httpbin.NewHTTPBin()

	backend := httptest.NewServer(h.Handler())
	backendURL, err := url.Parse(backend.URL)
	testutil.Assert(t, err == nil, "could not parse ural from httptest server: %v", err)
	return backendURL, backend.Close
}

func testNewOAuthProxy(t *testing.T, optFuncs ...func(*OAuthProxy) error) (*OAuthProxy, func()) {
	backendURL, close := testHTTPBin(t)

	opts := NewOptions()
	providerURL, _ := url.Parse("http://localhost/")
	provider := providers.NewTestProvider(providerURL, "")

	requestSigningKey, err := ioutil.ReadFile("testdata/private_key.pem")
	if err != nil {
		t.Fatalf("could not read private key from testdata: %s", err)
	}

	requestSigner, err := NewRequestSigner(string(requestSigningKey))
	if err != nil {
		t.Fatalf("could not create request signer from testdata: %s", err)
	}

	if requestSigner == nil {
		t.Fatalf("request signer is nil")
	}

	session := testSession()

	upstreamConfig := &UpstreamConfig{
		Route: &SimpleRoute{
			ToURL: backendURL,
		},
		AllowedGroups: session.Groups,
	}

	reverseProxy := NewReverseProxy(backendURL, upstreamConfig)
	handler := NewReverseProxyHandler(reverseProxy, opts, upstreamConfig, requestSigner)

	if requestSigner == nil {
		t.Fatalf("request signer is nil")
	}

	standardOptFuncs := []func(*OAuthProxy) error{
		testValidatorFunc(true),
		SetProvider(provider),
		setSessionStore(&sessions.MockSessionStore{Session: testSession()}),
		SetUpstreamConfig(upstreamConfig),
		SetProxyHandler(handler),
		SetRequestSigner(requestSigner),
		setCSRFStore(&sessions.MockCSRFStore{}),
		setCookieCipher(&aead.MockCipher{}),
	}

	if requestSigner == nil {
		t.Fatalf("request signer is nil")
	}

	standardOptFuncs = append(standardOptFuncs, optFuncs...)

	proxy, err := NewOAuthProxy(opts, standardOptFuncs...)
	testutil.Assert(t, err == nil, "could not create upstream reverse proxy: %v", err)

	if requestSigner == nil {
		t.Fatalf("request signer is nil")
	}

	return proxy, close
}

func TestNewReverseProxy(t *testing.T) {
	type respStruct struct {
		Host           string `json:"host"`
		XForwardedHost string `json:"x-forwarded-host"`
	}

	testCases := []struct {
		name           string
		useTLS         bool
		skipVerify     bool
		preserveHost   bool
		expectedStatus int
	}{
		{
			name:           "tls true skip verify false preserve host false",
			useTLS:         true,
			skipVerify:     false,
			preserveHost:   false,
			expectedStatus: 502,
		},
		{
			name:           "tls true skip verify true preserve host false",
			useTLS:         true,
			skipVerify:     true,
			preserveHost:   false,
			expectedStatus: 200,
		},
		{
			name:           "tls true skip verify false preserve host true",
			useTLS:         true,
			skipVerify:     false,
			preserveHost:   true,
			expectedStatus: 502,
		},
		{
			name:           "tls true skip verify true preserve host true",
			useTLS:         true,
			skipVerify:     true,
			preserveHost:   true,
			expectedStatus: 200,
		},

		{
			name:           "tls false skip verify false preserve host false",
			useTLS:         false,
			skipVerify:     false,
			preserveHost:   false,
			expectedStatus: 200,
		},
		{
			name:           "tls false skip verify true preserve host false",
			useTLS:         false,
			skipVerify:     true,
			preserveHost:   false,
			expectedStatus: 200,
		},
		{
			name:           "tls false skip verify false preserve host true",
			useTLS:         false,
			skipVerify:     false,
			preserveHost:   true,
			expectedStatus: 200,
		},
		{
			name:           "tls false skip verify true preserve host true",
			useTLS:         false,
			skipVerify:     true,
			preserveHost:   true,
			expectedStatus: 200,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var newServer func(http.Handler) *httptest.Server
			if tc.useTLS {
				newServer = httptest.NewTLSServer
			} else {
				newServer = httptest.NewServer
			}
			to := newServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				body, err := json.Marshal(
					&respStruct{
						Host:           r.Host,
						XForwardedHost: r.Header.Get("X-Forwarded-Host"),
					},
				)
				if err != nil {
					t.Fatalf("expected to marshal json: %s", err)
				}
				rw.Write(body)
			}))
			defer to.Close()

			toURL, err := url.Parse(to.URL)
			if err != nil {
				t.Fatalf("expected to parse to url: %s", err)
			}

			reverseProxy := NewReverseProxy(toURL, &UpstreamConfig{TLSSkipVerify: tc.skipVerify, PreserveHost: tc.preserveHost})
			from := httptest.NewServer(reverseProxy)
			defer from.Close()

			fromURL, err := url.Parse(from.URL)
			if err != nil {
				t.Fatalf("expected to parse from url: %s", err)
			}

			want := &respStruct{
				Host:           toURL.Host,
				XForwardedHost: fromURL.Host,
			}
			if tc.preserveHost {
				want.Host = fromURL.Host
			}

			res, err := http.Get(from.URL)
			if err != nil {
				t.Fatalf("expected to be able to make req: %s", err)
			}

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("expected to read body: %s", err)
			}

			if res.StatusCode != tc.expectedStatus {
				t.Logf(" got status code: %v", res.StatusCode)
				t.Logf("want status code: %d", tc.expectedStatus)

				t.Errorf("got unexpected response code for tls failure")
			}

			if res.StatusCode >= 200 && res.StatusCode < 300 {
				got := &respStruct{}
				err = json.Unmarshal(body, got)
				if err != nil {
					t.Fatalf("expected to decode json: %s", err)
				}

				if !reflect.DeepEqual(want, got) {
					t.Logf(" got host: %v", got.Host)
					t.Logf("want host: %v", want.Host)

					t.Logf(" got X-Forwarded-Host: %v", got.XForwardedHost)
					t.Logf("want X-Forwarded-Host: %v", want.XForwardedHost)

					t.Errorf("got unexpected response for Host or X-Forwarded-Host header")
				}
				if res.Header.Get("Cookie") != "" {
					t.Errorf("expected Cookie header to be empty but was %s", res.Header.Get("Cookie"))
				}
			}
		})
	}
}

func TestNewRewriteReverseProxy(t *testing.T) {
	type respStruct struct {
		Host           string `json:"host"`
		XForwardedHost string `json:"x-forwarded-host"`
	}

	testCases := []struct {
		name           string
		useTLS         bool
		skipVerify     bool
		preserveHost   bool
		expectedStatus int
	}{
		{
			name:           "tls true skip verify false preserve host false",
			useTLS:         true,
			skipVerify:     false,
			preserveHost:   false,
			expectedStatus: 502,
		},
		{
			name:           "tls true skip verify true preserve host false",
			useTLS:         true,
			skipVerify:     true,
			preserveHost:   false,
			expectedStatus: 200,
		},
		{
			name:           "tls true skip verify false preserve host true",
			useTLS:         true,
			skipVerify:     false,
			preserveHost:   true,
			expectedStatus: 502,
		},
		{
			name:           "tls true skip verify true preserve host true",
			useTLS:         true,
			skipVerify:     true,
			preserveHost:   true,
			expectedStatus: 200,
		},

		{
			name:           "tls false skip verify false preserve host false",
			useTLS:         false,
			skipVerify:     false,
			preserveHost:   false,
			expectedStatus: 200,
		},
		{
			name:           "tls false skip verify true preserve host false",
			useTLS:         false,
			skipVerify:     true,
			preserveHost:   false,
			expectedStatus: 200,
		},
		{
			name:           "tls false skip verify false preserve host true",
			useTLS:         false,
			skipVerify:     false,
			preserveHost:   true,
			expectedStatus: 200,
		},
		{
			name:           "tls false skip verify true preserve host true",
			useTLS:         false,
			skipVerify:     true,
			preserveHost:   true,
			expectedStatus: 200,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var newServer func(http.Handler) *httptest.Server
			if tc.useTLS {
				newServer = httptest.NewTLSServer
			} else {
				newServer = httptest.NewServer
			}
			upstream := newServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(200)
				rw.Write([]byte(req.Host))
			}))
			defer upstream.Close()

			parsedUpstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("expected to parse upstream URL err:%q", err)
			}

			route := &RewriteRoute{
				FromRegex: regexp.MustCompile("(.*)"),
				ToTemplate: &url.URL{
					Scheme: parsedUpstreamURL.Scheme,
					Opaque: parsedUpstreamURL.Host,
				},
			}

			rewriteProxy := NewRewriteReverseProxy(route, &UpstreamConfig{TLSSkipVerify: tc.skipVerify, PreserveHost: tc.preserveHost})

			frontend := httptest.NewServer(rewriteProxy)
			defer frontend.Close()

			frontendURL, err := url.Parse(frontend.URL)
			if err != nil {
				t.Fatalf("expected to parse frontend url: %s", err)
			}

			res, err := http.Get(frontend.URL)
			if err != nil {
				t.Fatalf("expected to make successful request err:%q", err)
			}

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("expected to read body err:%q", err)
			}

			if res.StatusCode != tc.expectedStatus {
				t.Logf(" got status code: %v", res.StatusCode)
				t.Logf("want status code: %d", tc.expectedStatus)

				t.Errorf("got unexpected response code for tls failure")
			}

			if res.StatusCode >= 200 && res.StatusCode < 300 {
				if tc.preserveHost {
					if string(body) != frontendURL.Host {
						t.Logf("got  %v", string(body))
						t.Logf("want %v", frontendURL.Host)
						t.Fatalf("got unexpected response from upstream")
					}
				} else {
					if string(body) != parsedUpstreamURL.Host {
						t.Logf("got  %v", string(body))
						t.Logf("want %v", parsedUpstreamURL.Host)
						t.Fatalf("got unexpected response from upstream")
					}
				}

				if res.Header.Get("Cookie") != "" {
					t.Errorf("expected Cookie header to be empty but was %s", res.Header.Get("Cookie"))
				}
			}
		})
	}
}

func TestDeleteSSOHeader(t *testing.T) {
	testCases := []struct {
		name                 string
		cookies              []*http.Cookie
		expectedCookieString string
	}{
		{
			name:                 "no cookies",
			cookies:              []*http.Cookie{},
			expectedCookieString: "",
		},

		{
			name: "no sso proxy cookie",
			cookies: []*http.Cookie{
				{Name: "cookie", Value: "something"},
				{Name: "another", Value: "cookie"},
			},
			expectedCookieString: "cookie=something;another=cookie",
		},
		{
			name: "just sso proxy cookie",
			cookies: []*http.Cookie{
				{Name: "_sso_proxy", Value: "something"},
			},
			expectedCookieString: "",
		},
		{
			name: "sso proxy cookie mixed in",
			cookies: []*http.Cookie{
				{Name: "something", Value: "else"},
				{Name: "_sso_proxy", Value: "something"},
				{Name: "another", Value: "cookie"},
			},
			expectedCookieString: "something=else;another=cookie",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for _, c := range tc.cookies {
				req.AddCookie(c)
			}
			deleteSSOCookieHeader(req, "_sso_proxy")
			if req.Header.Get("Cookie") != tc.expectedCookieString {
				t.Errorf("expected cookie string to be %s, but was %s", tc.expectedCookieString, req.Header.Get("Cookie"))
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	testCases := []struct {
		name          string
		url           string
		expectedError bool
	}{
		{
			name: "no error",
			url:  "http://www.example.com/",
		},
		{
			name:          "with error",
			url:           "/",
			expectedError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.url, nil)
			ut := &upstreamTransport{
				insecureSkipVerify: false,
				resetDeadline:      time.Duration(1) * time.Minute,
			}
			resp, err := ut.RoundTrip(req)
			if err == nil && tc.expectedError {
				t.Errorf("expected error but error was nil")
			}
			if err != nil && !tc.expectedError {
				t.Errorf("unexpected error %s", err.Error())
			}
			if err != nil {
				return
			}
			for key := range securityHeaders {
				if resp.Header.Get(key) != "" {
					t.Errorf("security header %s expected to be deleted but was %s", key, resp.Header.Get(key))
				}
			}
		})
	}
}

func TestEncodedSlashes(t *testing.T) {
	var seen string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		seen = r.RequestURI
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("unexpected err parsing backend url: %v", err)
	}
	proxyHandler := NewReverseProxy(backendURL, &UpstreamConfig{TLSSkipVerify: false, PreserveHost: false})
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	frontendURL, err := url.Parse(frontend.URL)
	if err != nil {
		t.Fatalf("unexpected err parsing frontend url: %v", err)
	}

	encodedPath := "/a%2Fb/?c=1"
	getReq := &http.Request{
		URL: &url.URL{
			Scheme: "http",
			Host:   frontendURL.Host,
			Opaque: encodedPath,
		},
	}

	_, err = http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	if seen != encodedPath {
		t.Errorf("got bad request %q expected %q", seen, encodedPath)
	}
}

func TestRobotsTxt(t *testing.T) {
	proxy, close := testNewOAuthProxy(t)
	defer close()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://localhost/robots.txt", nil)
	proxy.Handler().ServeHTTP(rw, req)
	testutil.Equal(t, 200, rw.Code)
	testutil.Equal(t, "User-agent: *\nDisallow: /", rw.Body.String())
}

func TestCerts(t *testing.T) {
	expectedPublicKey, err := ioutil.ReadFile("testdata/public_key.pub")
	testutil.Assert(t, err == nil, "could not read public key from testdata: %s", err)

	hasher := sha256.New()
	_, _ = hasher.Write(expectedPublicKey)

	var keyHash []byte
	keyHash = hasher.Sum(keyHash)

	proxy, close := testNewOAuthProxy(t)
	defer close()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://localhost/oauth2/v1/certs", nil)

	proxy.Handler().ServeHTTP(rw, req)
	testutil.Equal(t, 200, rw.Code)

	body := rw.Body.String()

	var certs map[string]string
	err = json.Unmarshal([]byte(body), &certs)

	testutil.Assert(t, err == nil, "could not unmarshal body: %s err:%v", body, err)
	testutil.Equal(t, string(expectedPublicKey), certs[hex.EncodeToString(keyHash)])
}

func TestFavicon(t *testing.T) {
	proxy, close := testNewOAuthProxy(t)
	defer close()

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://localhost/favicon.ico", nil)

	proxy.Handler().ServeHTTP(rw, req)

	testutil.Equal(t, http.StatusNotFound, rw.Code)
}

func TestAuthOnlyEndpoint(t *testing.T) {
	testCases := []struct {
		name         string
		validEmail   bool
		sessionStore *sessions.MockSessionStore
		expectedBody string
		expectedCode int
	}{
		{
			name: "accepted",
			sessionStore: &sessions.MockSessionStore{
				Session: testSession(),
			},
			validEmail:   true,
			expectedBody: "",
			expectedCode: http.StatusAccepted,
		},
		{
			name:         "unauthorized on no cookie set",
			expectedBody: "unauthorized request\n",
			sessionStore: &sessions.MockSessionStore{},
			validEmail:   true,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name: "unauthorized on expiration",
			sessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					LifetimeDeadline: time.Now().Add(-1 * time.Hour),
				},
			},
			validEmail:   true,
			expectedBody: "unauthorized request\n",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name: "unauthorized on email validation failure",
			sessionStore: &sessions.MockSessionStore{
				Session: testSession(),
			},
			expectedBody: "unauthorized request\n",
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, close := testNewOAuthProxy(t,
				setSessionStore(tc.sessionStore),
				setValidator(func(_ string) bool { return tc.validEmail }),
				SetProvider(&providers.TestProvider{
					RefreshSessionFunc:  func(*sessions.SessionState, []string) (bool, error) { return true, nil },
					ValidateSessionFunc: func(*sessions.SessionState, []string) bool { return true },
				}),
			)
			defer close()

			req := httptest.NewRequest("GET", "https://localhost/oauth2/auth", nil)
			resp := httptest.NewRecorder()

			proxy.AuthenticateOnly(resp, req)
			testutil.Equal(t, tc.expectedCode, resp.Code)
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			testutil.Equal(t, tc.expectedBody, string(bodyBytes))
		})

	}
}

func TestSkipAuthRequest(t *testing.T) {
	// start an upstream server
	testCases := []struct {
		name         string
		method       string
		url          string
		expectedCode int
	}{
		{
			name:   "rejected request",
			method: "GET",
			url:    "https://localhost/rejected",
			// We get a 302 here, status found, and attempt to authenticate
			expectedCode: http.StatusFound,
		},
		{
			name:         "skip auth on preflight requests",
			method:       "OPTIONS",
			url:          "https://localhost/preflight-request",
			expectedCode: http.StatusOK,
		},
		{
			name:         "allowed request",
			method:       "GET",
			url:          "https://localhost/allow",
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			config := &UpstreamConfig{
				SkipAuthCompiledRegex: []*regexp.Regexp{
					regexp.MustCompile(`^\/allow$`),
				},
			}

			proxy, close := testNewOAuthProxy(t,
				setSkipAuthPreflight(true),
				SetProxyHandler(backend),
				SetUpstreamConfig(config),
				setSessionStore(&sessions.MockSessionStore{LoadError: http.ErrNoCookie}),
			)
			defer close()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.url, nil)

			proxy.Handler().ServeHTTP(rw, req)

			testutil.Equal(t, tc.expectedCode, rw.Code)
		})
	}
}

func TestHMACSignatures(t *testing.T) {
	testCases := map[string]struct {
		signatureKey string
		method       string
		body         io.Reader
		signer       hmacauth.HmacAuth
	}{
		"Test Get Request": {
			signatureKey: "sha1:foobar",
			method:       "GET",
			signer: hmacauth.NewHmacAuth(crypto.SHA1,
				[]byte(`foobar`),
				HMACSignatureHeader,
				SignatureHeaders,
			),
		},
		"Test POST Request": {
			signatureKey: "sha1:foobar",
			method:       "POST",
			body:         bytes.NewBufferString(`{ "hello": "world!" }`),
			signer: hmacauth.NewHmacAuth(crypto.SHA1,
				[]byte(`foobar`),
				HMACSignatureHeader,
				SignatureHeaders,
			),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// this signer acts as an upstream attempting to authenticate the request
				result, have, want := tc.signer.AuthenticateRequest(r)
				switch result {
				case hmacauth.ResultNoSignature:
					t.Fatalf("no signature received: %v", result)
				case hmacauth.ResultMismatch:
					t.Logf("have: %v", have)
					t.Logf("want: %v", want)
					t.Fatalf("expected hmac signature to match")
				case hmacauth.ResultMatch:
					break
				default:
					t.Fatalf("unexpected result: %v", result)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("unexpected err parsing upstream url: %v", err)
			}

			hmacSigner, err := generateHmacAuth(tc.signatureKey)
			if err != nil {
				t.Fatalf("unexpected err creating hmac auth: %v", err)
			}

			upstreamConfig := &UpstreamConfig{
				HMACAuth: hmacSigner,
			}

			opts := NewOptions()
			reverseProxy := NewReverseProxy(upstreamURL, upstreamConfig)
			handler := NewReverseProxyHandler(reverseProxy, opts, upstreamConfig, nil)

			proxy, close := testNewOAuthProxy(t,
				SetUpstreamConfig(upstreamConfig),
				SetProxyHandler(handler),
				setCookieSecure(false),
			)
			defer close()

			proxyServer := httptest.NewServer(proxy.Handler())
			defer proxyServer.Close()

			req, err := http.NewRequest(tc.method, proxyServer.URL, tc.body)
			if err != nil {
				t.Fatalf("got unexpected error creating http request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("got unexpected error doing http request: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Logf("have: %v", resp.StatusCode)
				t.Logf("want: %v", http.StatusOK)
				t.Fatalf("got unexpected status code")
			}
		})
	}
}

func TestHeadersSentToUpstreams(t *testing.T) {
	testCases := []struct {
		name                 string
		otherCookies         []*http.Cookie
		expectedCookieHeader string
	}{
		{
			name:                 "only cookie is _sso_proxy cookie",
			otherCookies:         []*http.Cookie{},
			expectedCookieHeader: "",
		},
		{
			name: "other cookies added as well",
			otherCookies: []*http.Cookie{
				{Name: "something", Value: "else", Expires: time.Now().Add(time.Hour)},
			},
			expectedCookieHeader: "something=else",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, close := testNewOAuthProxy(t)
			defer close()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "https://localhost/headers", nil)

			for _, c := range tc.otherCookies {
				req.AddCookie(c)
			}

			proxy.Handler().ServeHTTP(rw, req)

			if rw.Code != http.StatusOK {
				t.Errorf("expected status = 200, got %d", rw.Code)
			}

			type headersResponse struct {
				Headers http.Header `json:"headers"`
			}

			resp := &headersResponse{}
			err := json.Unmarshal(rw.Body.Bytes(), resp)
			if err != nil {
				t.Errorf("error unmarshaling response: %s", err)
			}

			session := testSession()
			expectedHeaders := map[string]string{
				"X-Forwarded-Email":  session.Email,
				"X-Forwarded-User":   session.User,
				"X-Forwarded-Groups": strings.Join(session.Groups, ","),
				"Cookie":             tc.expectedCookieHeader,
			}

			for key, val := range expectedHeaders {
				if resp.Headers.Get(key) != val {
					t.Errorf("expected header %s=%q, got %s=%q", key, val, key, resp.Headers.Get(key))
				}
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	// Constants to represent possible cookie behaviors.
	const (
		NewCookie = iota
		ClearCookie
		KeepCookie
	)

	var (
		ErrRefreshFailed = errors.New("refresh failed")
		LoadCookieFailed = errors.New("load cookie fail")
		SaveCookieFailed = errors.New("save cookie fail")
	)
	testCases := []struct {
		Name string

		SessionStore        *sessions.MockSessionStore
		ExpectedErr         error
		CookieExpectation   int // One of: {NewCookie, ClearCookie, KeepCookie}
		RefreshSessionFunc  func(*sessions.SessionState, []string) (bool, error)
		ValidateSessionFunc func(*sessions.SessionState, []string) bool
	}{
		{
			Name: "redirect if deadlines are blank",
			SessionStore: &sessions.MockSessionStore{

				Session: &sessions.SessionState{
					Email:       "email1@example.com",
					AccessToken: "my_access_token",
				},
			},
			ExpectedErr:       ErrLifetimeExpired,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "session unmarshaling fails, get error",
			SessionStore: &sessions.MockSessionStore{
				Session:   &sessions.SessionState{},
				LoadError: LoadCookieFailed,
			},
			ExpectedErr:       LoadCookieFailed,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "authenticate successfully",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:       nil,
			CookieExpectation: KeepCookie,
		},
		{
			Name: "lifetime expired, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:       ErrLifetimeExpired,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "refresh expired, refresh fails, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:        ErrRefreshFailed,
			CookieExpectation:  ClearCookie,
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return false, ErrRefreshFailed },
		},
		{
			Name: "refresh expired, user not OK, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:        ErrUserNotAuthorized,
			CookieExpectation:  ClearCookie,
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return false, nil },
		},
		{
			Name: "refresh expired, user OK, authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:        nil,
			CookieExpectation:  NewCookie,
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return true, nil },
		},
		{
			Name: "refresh expired, refresh and user OK, error saving session",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
				},
				SaveError: SaveCookieFailed,
			},
			ExpectedErr:        SaveCookieFailed,
			CookieExpectation:  ClearCookie,
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return true, nil },
		},
		{
			Name: "validation expired, user not OK, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(-1) * time.Minute),
				},
			},
			ExpectedErr:         ErrUserNotAuthorized,
			CookieExpectation:   ClearCookie,
			ValidateSessionFunc: func(s *sessions.SessionState, g []string) bool { return false },
		},
		{
			Name: "validation expired, user OK, authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email1@example.com",
					AccessToken:      "my_access_token",
					LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:    time.Now().Add(time.Duration(-1) * time.Minute),
				},
			},
			ExpectedErr:         nil,
			CookieExpectation:   NewCookie,
			ValidateSessionFunc: func(s *sessions.SessionState, g []string) bool { return true },
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			provider := &providers.TestProvider{
				RefreshSessionFunc:  tc.RefreshSessionFunc,
				ValidateSessionFunc: tc.ValidateSessionFunc,
			}

			proxy, close := testNewOAuthProxy(t,
				SetProvider(provider),
				setSessionStore(tc.SessionStore),
			)
			defer close()

			req := httptest.NewRequest("GET", "https://localhost", nil)
			rw := httptest.NewRecorder()

			err := proxy.Authenticate(rw, req)

			switch tc.CookieExpectation {
			case ClearCookie:
				testutil.Equal(t, tc.SessionStore.ResponseSession, "")
			case NewCookie:
				testutil.NotEqual(t, tc.SessionStore.ResponseSession, "")
			case KeepCookie:
				testutil.Equal(t, tc.SessionStore.ResponseSession, "")
			}

			if err != tc.ExpectedErr {
				t.Logf(" got error: %#v", err)
				t.Logf("want error: %#v", tc.ExpectedErr)
				t.Error("unexpected error value for authenticate")
			}
		})
	}
}

func TestProxyXHRErrorHandling(t *testing.T) {
	testCases := []struct {
		Name         string
		Session      *sessions.SessionState
		Method       string
		ExpectedCode int
		Header       map[string]string
	}{
		{
			Name: "expired session should redirect on normal request (GET)",
			Session: &sessions.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
			},
			Method:       "GET",
			ExpectedCode: http.StatusFound,
		},
		{
			Name: "expired session should proxy preflight request (OPTIONS)",
			Session: &sessions.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
			},
			Method:       "OPTIONS",
			ExpectedCode: http.StatusFound,
		},
		{
			Name: "expired session should return error code when XMLHttpRequest",
			Session: &sessions.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
			},
			Method: "GET",
			Header: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
			},
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			Name:    "no session should return error code when XMLHttpRequest",
			Session: nil,
			Method:  "GET",
			Header: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
			},
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			Name: "valid session should proxy as normal when XMLHttpRequest",
			Session: &sessions.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(1) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
			},
			Method: "GET",
			Header: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
			},
			ExpectedCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			proxy, close := testNewOAuthProxy(t,
				setSessionStore(&sessions.MockSessionStore{Session: tc.Session}),
			)
			defer close()

			req := httptest.NewRequest(tc.Method, "https://localhost/", nil)
			for k, v := range tc.Header {
				req.Header.Set(k, v)
			}
			rw := httptest.NewRecorder()

			proxy.Handler().ServeHTTP(rw, req)

			if tc.ExpectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.ExpectedCode, rw.Code)
			}
		})
	}
}

func TestOAuthStart(t *testing.T) {
	testCases := []struct {
		name               string
		isXHR              bool
		expectedStatusCode int
	}{
		{
			name:               "OAuthStart returns successfully",
			expectedStatusCode: http.StatusFound,
		},
		{

			name:               "XHR request returns an error",
			isXHR:              true,
			expectedStatusCode: http.StatusUnauthorized,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup deafults
			csrfStore := &sessions.MockCSRFStore{}

			s := &StateParameter{
				SessionID:   "abcdefg123",
				RedirectURI: "example.com/redirect",
			}

			marshaled, err := json.Marshal(s)
			testutil.Ok(t, err)

			cookieCipher := &aead.MockCipher{
				MarshalString:  string(marshaled),
				UnmarshalBytes: marshaled,
			}

			proxy, close := testNewOAuthProxy(t,
				setSessionStore(&sessions.MockSessionStore{}),
				setCSRFStore(csrfStore),
				setCookieCipher(cookieCipher),
			)
			defer close()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "https://localhost/", nil)
			if tc.isXHR {
				req.Header.Add("X-Requested-With", "XMLHttpRequest")
			}

			proxy.OAuthStart(rw, req, []string{})
			res := rw.Result()

			if res.StatusCode != tc.expectedStatusCode {
				t.Fatalf("unexpected status code response")
			}

			if tc.expectedStatusCode != http.StatusFound {
				return
			}

			location, err := res.Location()
			if err != nil {
				t.Fatalf("expected req to succeeded err:%v", err)
			}

			state := location.Query().Get("state")

			cookieParameter := &StateParameter{}
			err = json.Unmarshal([]byte(csrfStore.ResponseCSRF), cookieParameter)
			if err != nil {
				t.Errorf("response csrf: %v", csrfStore.ResponseCSRF)
				t.Fatalf("unexpected err during unmarshal: %v", err)
			}

			stateParameter := &StateParameter{}
			err = json.Unmarshal([]byte(state), stateParameter)
			if err != nil {
				t.Errorf("location: %v", location)
				t.Errorf("state: %v", state)
				t.Fatalf("unexpected err during unmarshal: %v", err)
			}

			if !reflect.DeepEqual(cookieParameter, stateParameter) {
				t.Logf("cookie parameter: %#v", cookieParameter)
				t.Logf(" state parameter: %#v", stateParameter)
				t.Fatalf("expected structs to be equal")
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	testCases := []struct {
		name            string
		path            string
		authenticated   bool
		expectedCode    int
		expectedHeaders map[string]string
	}{
		{
			name:            "security headers are added to authenticated requests",
			path:            "/",
			authenticated:   true,
			expectedCode:    http.StatusOK,
			expectedHeaders: securityHeaders,
		},
		{
			name:            "security headers are added to unauthenticated requests",
			path:            "/",
			authenticated:   false,
			expectedCode:    http.StatusFound,
			expectedHeaders: securityHeaders,
		},
		{
			name:          "additional headers set by upstream are proxied",
			path:          "/add-header",
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Test-Header": "true",
			},
		},
		{
			name:          "security headers may NOT be overridden by upstream",
			path:          "/override-security-header",
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Frame-Options": "SAMEORIGIN",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/add-header":
					w.Header().Set("X-Test-Header", "true")
				case "/override-security-header":
					w.Header().Set("X-Frame-Options", "OVERRIDE")
				}
				w.WriteHeader(200)
				w.Write([]byte(r.URL.RequestURI()))
			}))
			defer backend.Close()
			backendURL, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatalf("unexpected err parsing backend url: %v", err)
			}

			upstreamConfig := &UpstreamConfig{
				Route: &SimpleRoute{
					ToURL: backendURL,
				},
			}
			opts := NewOptions()

			// NOTE: This logic particularly hard to test as it requires *our* special reverse proxy
			// to behavior to delete the security headers passed by the upstream *before* we set
			// them on our response.
			//
			// We do this to ensure *every* response, either originating from the upstream or
			// from the sso proxy itself contains these security headers.
			//
			// * If we just specified this behavior in the reverse proxy itself, responses
			//   that originate from the sso proxy would not have security headers.
			// * If we just specified this beahvior in sso proxy w/out deleting headers,
			//   we wouldn't be able to override the headers as they sent upstream, we'd just
			//   send multiple headers
			reverseProxy := NewReverseProxy(backendURL, upstreamConfig)
			handler := NewReverseProxyHandler(reverseProxy, opts, upstreamConfig, nil)

			sessionStore := &sessions.MockSessionStore{}
			if tc.authenticated {
				sessionStore = &sessions.MockSessionStore{Session: testSession()}
			}
			proxy, close := testNewOAuthProxy(t,
				setSessionStore(sessionStore),
				SetUpstreamConfig(upstreamConfig),
				SetProxyHandler(handler),
			)
			defer close()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("https://localhost%s", tc.path), nil)

			proxy.Handler().ServeHTTP(rw, req)
			resp := rw.Result()

			if tc.expectedCode != resp.StatusCode {
				t.Fatalf("expected code %d, got %d", tc.expectedCode, resp.StatusCode)
			}

			if tc.expectedCode == http.StatusOK {
				body, err := ioutil.ReadAll(resp.Body)
				defer resp.Body.Close()
				testutil.Assert(t, err == nil, "could not read http response body: %v", err)
				if string(body) != tc.path {
					t.Errorf("expected body = %q, got %q", tc.path, string(body))
				}
			}

			for key, val := range tc.expectedHeaders {
				vals, found := resp.Header[http.CanonicalHeaderKey(key)]
				if !found {
					t.Errorf("expected header %s but not found in headers: %v", key, resp.Header)
				} else if len(vals) > 1 {
					t.Errorf("got duplicate values for headers %s: %v", key, vals)
				} else if vals[0] != val {
					t.Errorf("expected header %s=%q, got %s=%q\n", key, val, key, vals[0])
				}
			}
		})
	}
}

func TestHeaderOverrides(t *testing.T) {
	testCases := []struct {
		name            string
		overrides       map[string]string
		expectedHeaders map[string]string
	}{
		{
			name:            "security headers are added to requests",
			overrides:       nil,
			expectedHeaders: securityHeaders,
		},
		{
			name: "security headers are overridden by config",
			overrides: map[string]string{
				"X-Frame-Options": "ALLOW-FROM nsa.gov",
			},
			expectedHeaders: map[string]string{
				"X-Frame-Options": "ALLOW-FROM nsa.gov",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			config := &UpstreamConfig{
				HeaderOverrides: tc.overrides,
			}

			proxy, close := testNewOAuthProxy(t,
				SetUpstreamConfig(config),
				SetProxyHandler(backend),
			)
			defer close()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://localhost/", nil)

			proxy.Handler().ServeHTTP(rw, req)

			for key, val := range tc.expectedHeaders {
				vals, found := rw.HeaderMap[http.CanonicalHeaderKey(key)]
				if !found {
					t.Errorf("expected header %s not found", key)
				} else if len(vals) > 1 {
					t.Errorf("got duplicate values for headers %s: %v", key, vals)
				} else if vals[0] != val {
					t.Errorf("expected header %s=%q, got %s=%q\n", key, val, key, vals[0])
				}
			}
		})
	}
}

func TestHTTPSRedirect(t *testing.T) {
	testCases := []struct {
		name                 string
		url                  string
		host                 string
		cookieSecure         bool
		authenticated        bool
		requestHeaders       map[string]string
		expectedCode         int
		expectedLocation     string // must match entire Location header
		expectedLocationHost string // just match hostname of Location header
		expectSTS            bool   // should we get a Strict-Transport-Security header?
	}{
		{
			name:          "no https redirect with http and cookie_secure=false and authenticated=true",
			url:           "http://localhost/",
			cookieSecure:  false,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     false,
		},
		{
			name:                 "no https redirect with http cookie_secure=false and authenticated=false",
			url:                  "http://localhost/",
			cookieSecure:         false,
			authenticated:        false,
			expectedCode:         http.StatusFound,
			expectedLocationHost: "localhost",
			expectSTS:            false,
		},
		{
			name:          "no https redirect with https and cookie_secure=false and authenticated=true",
			url:           "https://localhost/",
			cookieSecure:  false,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     false,
		},
		{
			name:                 "no https redirect with https and cookie_secure=false and authenticated=false",
			url:                  "https://localhost/",
			cookieSecure:         false,
			authenticated:        false,
			expectedCode:         http.StatusFound,
			expectedLocationHost: "localhost",
			expectSTS:            false,
		},
		{
			name:             "https redirect with cookie_secure=true and authenticated=false",
			url:              "http://localhost/",
			cookieSecure:     true,
			authenticated:    false,
			expectedCode:     http.StatusMovedPermanently,
			expectedLocation: "https://localhost/",
			expectSTS:        true,
		},
		{
			name:             "https redirect with cookie_secure=true and authenticated=true",
			url:              "http://localhost/",
			cookieSecure:     true,
			authenticated:    true,
			expectedCode:     http.StatusMovedPermanently,
			expectedLocation: "https://localhost/",
			expectSTS:        true,
		},
		{
			name:          "no https redirect with https and cookie_secure=true and authenticated=true",
			url:           "https://localhost/",
			cookieSecure:  true,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     true,
		},
		{
			name:          "no https redirect with https and cookie_secure=true and authenticated=false",
			url:           "https://localhost/",
			cookieSecure:  true,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     true,
		},
		{
			name:             "request path and query are preserved in redirect",
			url:              "http://localhost/foo/bar.html?a=1&b=2&c=3",
			cookieSecure:     true,
			authenticated:    true,
			expectedCode:     http.StatusMovedPermanently,
			expectedLocation: "https://localhost/foo/bar.html?a=1&b=2&c=3",
			expectSTS:        true,
		},
		{
			name:           "no https redirect with http and X-Forwarded-Proto=https",
			url:            "http://localhost/",
			cookieSecure:   true,
			authenticated:  true,
			requestHeaders: map[string]string{"X-Forwarded-Proto": "https"},
			expectedCode:   http.StatusOK,
			expectSTS:      true,
		},
		{
			name:             "correct host name with relative URL",
			url:              "/",
			host:             "localhost",
			cookieSecure:     true,
			authenticated:    false,
			expectedLocation: "https://localhost/",
			expectedCode:     http.StatusMovedPermanently,
			expectSTS:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sessionStore := &sessions.MockSessionStore{}
			if tc.authenticated {
				sessionStore = &sessions.MockSessionStore{Session: testSession()}
			}

			proxy, close := testNewOAuthProxy(t,
				setSessionStore(sessionStore),
				setCookieSecure(tc.cookieSecure),
			)
			defer close()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.url, nil)

			for key, val := range tc.requestHeaders {
				req.Header.Set(key, val)
			}

			if tc.host != "" {
				req.Host = tc.host
			}

			proxy.Handler().ServeHTTP(rw, req)

			if tc.expectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.expectedCode, rw.Code)
			}

			location := rw.Header().Get("Location")
			locationURL, err := url.Parse(location)
			if err != nil {
				t.Errorf("error parsing location %q: %s", location, err)
			}
			if tc.expectedLocation != "" && location != tc.expectedLocation {
				t.Errorf("expected Location=%q, got Location=%q", tc.expectedLocation, location)
			}
			if tc.expectedLocationHost != "" && locationURL.Hostname() != tc.expectedLocationHost {
				t.Errorf("expected location host = %q, got %q", tc.expectedLocationHost, locationURL.Hostname())
			}

			stsKey := http.CanonicalHeaderKey("Strict-Transport-Security")
			if tc.expectSTS {
				val := rw.Header().Get(stsKey)
				expectedVal := "max-age=31536000"
				if val != expectedVal {
					t.Errorf("expected %s=%q, got %q", stsKey, expectedVal, val)
				}
			} else {
				_, found := rw.HeaderMap[stsKey]
				if found {
					t.Errorf("%s header should not be present, got %q", stsKey, rw.Header().Get(stsKey))
				}
			}
		})
	}
}

func TestTimeoutHandler(t *testing.T) {
	testCases := []struct {
		name               string
		config             *UpstreamConfig
		globalTimeout      time.Duration
		ExpectedStatusCode int
		ExpectedBody       string
		ExpectedErr        error
	}{
		{
			name: "does not timeout",
			config: &UpstreamConfig{
				Timeout: time.Duration(100) * time.Millisecond,
			},
			globalTimeout:      time.Duration(100) * time.Millisecond,
			ExpectedStatusCode: 200,
			ExpectedBody:       "OK",
		},
		{
			name: "times out using upstream config timeout",
			config: &UpstreamConfig{
				Service: "service-test",
				Timeout: time.Duration(10) * time.Millisecond,
			},
			globalTimeout:      time.Duration(100) * time.Millisecond,
			ExpectedStatusCode: 503,
			ExpectedBody:       fmt.Sprintf("service-test failed to respond within the 10ms timeout period"),
		},
		{
			name: "times out using global write timeout",
			config: &UpstreamConfig{
				Service: "service-test",
				Timeout: time.Duration(100) * time.Millisecond,
			},
			globalTimeout: time.Duration(10) * time.Millisecond,
			ExpectedErr: &url.Error{
				Err: io.EOF,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				timer := time.NewTimer(time.Duration(50) * time.Millisecond)
				<-timer.C
				w.Write([]byte("OK"))
			})
			timeoutHandler := NewTimeoutHandler(baseHandler, tc.config)

			srv := httptest.NewUnstartedServer(timeoutHandler)
			srv.Config.WriteTimeout = tc.globalTimeout
			srv.Start()
			defer srv.Close()

			res, err := http.Get(srv.URL)
			if err != nil {
				if tc.ExpectedErr == nil {
					t.Fatalf("got unexpected err=%v", err)
				}
				urlErr, ok := err.(*url.Error)
				if !ok {
					t.Fatalf("got unexpected err=%v", err)
				}
				if urlErr.Err != io.EOF {
					t.Fatalf("got unexpected err=%v", err)
				}
				// We got the error we expected, exit
				return
			}

			if res.StatusCode != tc.ExpectedStatusCode {
				t.Errorf(" got=%v", res.StatusCode)
				t.Errorf("want=%v", tc.ExpectedStatusCode)
				t.Fatalf("got unexpcted status code")
			}

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("got unexpected err=%q", err)
			}

			if string(body) != tc.ExpectedBody {
				t.Errorf(" got=%q", body)
				t.Errorf("want=%q", tc.ExpectedBody)
				t.Fatalf("got unexpcted body")
			}
		})
	}
}

func TestRewriteRoutingHandling(t *testing.T) {
	type response struct {
		Host           string `json:"host"`
		XForwardedHost string `json:"x-forwarded-host"`
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(
			&response{
				Host:           r.Host,
				XForwardedHost: r.Header.Get("X-Forwarded-Host"),
			},
		)
		if err != nil {
			t.Fatalf("expected to marshal json: %s", err)
		}
		rw.Write(body)
	}))
	defer upstream.Close()

	parsedUpstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("expected to parse upstream URL err:%q", err)
	}

	upstreamHost, upstreamPort, err := net.SplitHostPort(parsedUpstreamURL.Host)
	if err != nil {
		t.Fatalf("expected to split host/hort err:%q", err)
	}

	testCases := []struct {
		Name             string
		TestHost         string
		RewriteRoute     *RewriteRoute
		ExpectedCode     int
		ExpectedResponse *response
	}{
		{
			Name:     "everything should work in the normal case",
			TestHost: "localhost",
			RewriteRoute: &RewriteRoute{
				FromRegex: regexp.MustCompile("(.*)"),
				ToTemplate: &url.URL{
					Scheme: parsedUpstreamURL.Scheme,
					Opaque: parsedUpstreamURL.Host,
				},
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: &response{
				Host:           parsedUpstreamURL.Host,
				XForwardedHost: "localhost",
			},
		},
		{
			Name:     "it should match and replace using regex/template to find port in embeded domain",
			TestHost: fmt.Sprintf("somedomain--%s", upstreamPort),
			RewriteRoute: &RewriteRoute{
				FromRegex: regexp.MustCompile("somedomain--(.*)"),
				ToTemplate: &url.URL{
					Scheme: "http",
					Opaque: fmt.Sprintf("%s:$1", upstreamHost), // add port to dest
				},
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: &response{
				Host:           parsedUpstreamURL.Host,
				XForwardedHost: fmt.Sprintf("somedomain--%s", upstreamPort),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			opts := NewOptions()

			upstreamConfig := &UpstreamConfig{
				Route: tc.RewriteRoute,
			}

			reverseProxy := NewRewriteReverseProxy(tc.RewriteRoute, upstreamConfig)
			handler := NewReverseProxyHandler(reverseProxy, opts, upstreamConfig, nil)

			proxy, close := testNewOAuthProxy(t,
				SetUpstreamConfig(upstreamConfig),
				SetProxyHandler(handler),
			)
			defer close()

			requestURL := fmt.Sprintf("https://%s/", tc.TestHost)
			t.Logf("requestURL: %v", requestURL)

			req := httptest.NewRequest("GET", requestURL, nil)
			rw := httptest.NewRecorder()

			proxy.Handler().ServeHTTP(rw, req)

			if tc.ExpectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.ExpectedCode, rw.Code)
			}

			if tc.ExpectedResponse == nil {
				// we've passed our test, we didn't expect a body, exit early
				return
			}

			body, err := ioutil.ReadAll(rw.Body)
			if err != nil {
				t.Fatalf("expected to read body: %s", err)
			}

			got := &response{}
			err = json.Unmarshal(body, got)
			if err != nil {
				t.Fatalf("expected to decode json: %s", err)
			}

			if !reflect.DeepEqual(tc.ExpectedResponse, got) {
				t.Logf(" got host: %v", got.Host)
				t.Logf("want host: %v", tc.ExpectedResponse.Host)

				t.Logf(" got X-Forwarded-Host: %v", got.XForwardedHost)
				t.Logf("want X-Forwarded-Host: %v", tc.ExpectedResponse.XForwardedHost)

				t.Errorf("got unexpected response for Host or X-Forwarded-Host header")
			}
		})
	}
}
