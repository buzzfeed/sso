package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/datadog/datadog-go/statsd"
	"github.com/mccutchen/go-httpbin/httpbin"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
	"github.com/buzzfeed/sso/internal/proxy/providers"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

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
		Email:              "michael.bland@gsa.gov",
		AccessToken:        "my_access_token",
		Groups:             []string{"foo", "bar"},
		AuthorizedUpstream: "localhost",

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

	config := DefaultProxyConfig()
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

	session := testSession()

	upstreamConfig := &UpstreamConfig{
		Route: &SimpleRoute{
			ToURL: backendURL,
		},
		AllowedGroups: session.Groups,
	}

	reverseProxy, err := NewUpstreamReverseProxy(upstreamConfig, requestSigner)
	if err != nil {
		t.Fatalf("unexpected error creating upstream reverse proxy: %v", err)
	}

	statsdClient, _ := statsd.New("127.0.0.1:8125")

	standardOptFuncs := []func(*OAuthProxy) error{
		SetValidators([]options.Validator{options.NewMockValidator(true)}),
		SetProvider(provider),
		setSessionStore(&sessions.MockSessionStore{Session: testSession()}),
		SetUpstreamConfig(upstreamConfig),
		SetProxyHandler(reverseProxy),
		SetRequestSigner(requestSigner),
		setCSRFStore(&sessions.MockCSRFStore{}),
		setCookieCipher(&aead.MockCipher{}),
		SetStatsdClient(statsdClient),
	}

	if requestSigner == nil {
		t.Fatalf("request signer is nil")
	}

	standardOptFuncs = append(standardOptFuncs, optFuncs...)

	proxy, err := NewOAuthProxy(config.SessionConfig, standardOptFuncs...)
	testutil.Assert(t, err == nil, "could not create upstream reverse proxy: %v", err)

	if requestSigner == nil {
		t.Fatalf("request signer is nil")
	}

	return proxy, close
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

func TestSetCookieStore(t *testing.T) {
	config := DefaultProxyConfig()
	secret := "W0KcDGnkIxqgDuue/Xx5BejqD7QFX0TTtiubse9tfwA="
	config.SessionConfig.CookieConfig.Secret = secret
	err := config.SessionConfig.CookieConfig.Validate()
	if err != nil {
		t.Errorf("error validating cookieconfig: %s", err)
	}

	proxy, close := testNewOAuthProxy(t, SetCookieStore(config.SessionConfig.CookieConfig))
	defer close()

	_, ok := proxy.sessionStore.(*sessions.CookieStore)
	if !ok {
		t.Error("Unexpected object type")
	}
	_, ok = proxy.csrfStore.(*sessions.CookieStore)
	if !ok {
		t.Error("Unexpected object type")
	}
	_, ok = proxy.cookieCipher.(*aead.MiscreantCipher)
	if !ok {
		t.Error("Unexpected object type")
	}
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
			providerURL, _ := url.Parse("http://localhost/")
			tp := providers.NewTestProvider(providerURL, "")
			tp.RefreshSessionFunc = func(*sessions.SessionState, []string) (bool, error) { return true, nil }
			tp.ValidateSessionFunc = func(*sessions.SessionState, []string) bool { return true }

			proxy, close := testNewOAuthProxy(t,
				setSessionStore(tc.sessionStore),
				SetValidators([]options.Validator{options.NewMockValidator(tc.validEmail)}),
				SetProvider(tp),
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
				SkipAuthPreflight: true,
				SkipAuthCompiledRegex: []*regexp.Regexp{
					regexp.MustCompile(`^\/allow$`),
				},
			}

			proxy, close := testNewOAuthProxy(t,
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

func TestEncodedPath(t *testing.T) {
	t.Run("encoded path-component is perfectly forwarded", func(t *testing.T) {
		var seen string
		backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.RequestURI
			w.WriteHeader(http.StatusOK)
		})

		config := &UpstreamConfig{
			SkipAuthPreflight: true,
			SkipAuthCompiledRegex: []*regexp.Regexp{
				regexp.MustCompile(`^\/allow/.*$`),
			},
		}

		proxy, close := testNewOAuthProxy(t,
			SetProxyHandler(backend),
			SetUpstreamConfig(config),
			setSessionStore(&sessions.MockSessionStore{LoadError: http.ErrNoCookie}),
		)
		defer close()

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://localhost/allow/http:%2F%2Fexample.com%2F/", nil)

		proxy.Handler().ServeHTTP(rw, req)

		// If path-components are not perfectly-forwarded, this will be a 301 instead of a 200.
		testutil.Equal(t, http.StatusOK, rw.Code)
		testutil.Equal(t, "https://localhost/allow/http:%2F%2Fexample.com%2F/", seen)
	})
}

func TestHeadersSentToUpstreams(t *testing.T) {
	testCases := []struct {
		name                      string
		otherCookies              []*http.Cookie
		expectedCookieHeader      string
		passAccessToken           bool
		additionalExpectedHeaders map[string]string
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
		{
			name:            "pass access token set to true",
			passAccessToken: true,
			additionalExpectedHeaders: map[string]string{
				"X-Forwarded-Access-Token": "my_access_token",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backendURL, close := testHTTPBin(t)
			upstreamConfig := &UpstreamConfig{
				Route: &SimpleRoute{
					ToURL: backendURL,
				},
				PassAccessToken: tc.passAccessToken,
			}
			proxy, close := testNewOAuthProxy(t, SetUpstreamConfig(upstreamConfig))
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
			for key, val := range tc.additionalExpectedHeaders {
				// don't overwrite standard expected headers. we might *need* to overwrite and test them at some point
				// but right now, we don't and so we can actively combat against that behaviour
				if _, ok := expectedHeaders[key]; ok {
					continue
				}
				expectedHeaders[key] = val
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:       nil,
			CookieExpectation: KeepCookie,
		},
		{
			Name: "lifetime expired, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(-24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:       ErrLifetimeExpired,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "refresh expired, refresh fails, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(-1) * time.Minute),
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
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(-1) * time.Minute),
				},
			},
			ExpectedErr:         nil,
			CookieExpectation:   NewCookie,
			ValidateSessionFunc: func(s *sessions.SessionState, g []string) bool { return true },
		},
		{
			Name: "wrong identity provider, user OK, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					ProviderSlug:       "example",
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:       ErrWrongIdentityProvider,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "authorized against different upstream, user OK, do not authenticate",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "foo",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectedErr:       ErrUnauthorizedUpstreamRequested,
			CookieExpectation: ClearCookie,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			providerURL, _ := url.Parse("http://localhost/")
			tp := providers.NewTestProvider(providerURL, "")
			tp.RefreshSessionFunc = tc.RefreshSessionFunc
			tp.ValidateSessionFunc = tc.ValidateSessionFunc

			proxy, close := testNewOAuthProxy(t,
				SetProvider(tp),
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

func TestAuthenticationUXFlows(t *testing.T) {
	var (
		ErrRefreshFailed = errors.New("refresh failed")
		LoadCookieFailed = errors.New("load cookie fail")
		SaveCookieFailed = errors.New("save cookie fail")
	)
	testCases := []struct {
		Name string

		SessionStore        *sessions.MockSessionStore
		RefreshSessionFunc  func(*sessions.SessionState, []string) (bool, error)
		ValidateSessionFunc func(*sessions.SessionState, []string) bool

		ExpectStatusCode int
	}{
		{
			Name: "missing deadlines, redirect to sign-in",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
				},
			},
			ExpectStatusCode: http.StatusFound,
		},
		{
			Name: "session unmarshaling fails, show error",
			SessionStore: &sessions.MockSessionStore{
				Session:   &sessions.SessionState{},
				LoadError: LoadCookieFailed,
			},
			ExpectStatusCode: http.StatusInternalServerError,
		},
		{
			Name: "authenticate successfully, expect ok",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectStatusCode: http.StatusOK,
		},
		{
			Name: "lifetime expired, redirect to sign-in",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(-24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectStatusCode: http.StatusFound,
		},
		{
			Name: "refresh expired, refresh fails, show error",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return false, ErrRefreshFailed },
			ExpectStatusCode:   http.StatusInternalServerError,
		},
		{
			Name: "refresh expired, user not OK, deny",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return false, nil },
			ExpectStatusCode:   http.StatusForbidden,
		},
		{
			Name: "refresh expired, user OK, expect ok",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return true, nil },
			ExpectStatusCode:   http.StatusOK,
		},
		{
			Name: "refresh expired, refresh and user OK, error saving session, show error",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(-1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
				SaveError: SaveCookieFailed,
			},
			RefreshSessionFunc: func(s *sessions.SessionState, g []string) (bool, error) { return true, nil },
			ExpectStatusCode:   http.StatusInternalServerError,
		},
		{
			Name: "validation expired, user not OK, deny",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(-1) * time.Minute),
				},
			},
			ValidateSessionFunc: func(s *sessions.SessionState, g []string) bool { return false },
			ExpectStatusCode:    http.StatusForbidden,
		},
		{
			Name: "validation expired, user OK, expect ok",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(-1) * time.Minute),
				},
			},
			ValidateSessionFunc: func(s *sessions.SessionState, g []string) bool { return true },
			ExpectStatusCode:    http.StatusOK,
		},
		{
			Name: "wrong identity provider, redirect to sign-in",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					ProviderSlug:       "example",
					Email:              "email1@example.com",
					AuthorizedUpstream: "localhost",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectStatusCode: http.StatusFound,
		},
		{
			Name: "authorized against different upstream, redirect to sign-in",
			SessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:              "email1@example.com",
					AuthorizedUpstream: "foo",
					AccessToken:        "my_access_token",
					LifetimeDeadline:   time.Now().Add(time.Duration(24) * time.Hour),
					RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
					ValidDeadline:      time.Now().Add(time.Duration(1) * time.Minute),
				},
			},
			ExpectStatusCode: http.StatusFound,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			providerURL, _ := url.Parse("http://localhost/")
			tp := providers.NewTestProvider(providerURL, "")
			tp.RefreshSessionFunc = tc.RefreshSessionFunc
			tp.ValidateSessionFunc = tc.ValidateSessionFunc

			proxy, close := testNewOAuthProxy(t,
				SetProvider(tp),
				setSessionStore(tc.SessionStore),
			)
			defer close()

			req := httptest.NewRequest("GET", "https://localhost", nil)
			rw := httptest.NewRecorder()

			proxy.Proxy(rw, req)

			res := rw.Result()

			if tc.ExpectStatusCode != res.StatusCode {
				t.Errorf("have: %v", res.StatusCode)
				t.Errorf("want: %v", tc.ExpectStatusCode)
				t.Fatalf("expected status codes to be equal")
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
				LifetimeDeadline:   time.Now().Add(time.Duration(-24) * time.Hour),
				AuthorizedUpstream: "localhost",
			},
			Method:       "GET",
			ExpectedCode: http.StatusFound,
		},
		{
			Name: "expired session should proxy preflight request (OPTIONS)",
			Session: &sessions.SessionState{
				LifetimeDeadline:   time.Now().Add(time.Duration(-24) * time.Hour),
				AuthorizedUpstream: "localhost",
			},
			Method:       "OPTIONS",
			ExpectedCode: http.StatusFound,
		},
		{
			Name: "expired session should return error code when XMLHttpRequest",
			Session: &sessions.SessionState{
				LifetimeDeadline:   time.Now().Add(time.Duration(-24) * time.Hour),
				AuthorizedUpstream: "localhost",
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
				LifetimeDeadline:   time.Now().Add(time.Duration(1) * time.Hour),
				RefreshDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:      time.Now().Add(time.Duration(1) * time.Hour),
				AuthorizedUpstream: "localhost",
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
			// setup defaults
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
			handler, err := NewUpstreamReverseProxy(upstreamConfig, nil)
			if err != nil {
				t.Fatalf("unepxected err creating upstream reverse proxy: %v", err)
			}

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
