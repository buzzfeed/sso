package proxy

import (
	"crypto"
	"encoding/base64"
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

	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/proxy/providers"

	"github.com/18F/hmacauth"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

var testEncodedCookieSecret = base64.URLEncoding.EncodeToString([]byte("574b776a7c934d6b9fc42ec63a389f79"))

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

}

func testValidatorFunc(valid bool) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		p.EmailValidator = func(string) bool {
			return valid
		}
		return nil
	}
}

func testCookieCipher(a aead.Cipher) func(*OAuthProxy) error {
	return func(p *OAuthProxy) error {
		if a != nil {
			p.CookieCipher = a
		}
		return nil
	}
}

func testSession() *providers.SessionState {
	theFuture := time.Now().AddDate(100, 0, 0)

	return &providers.SessionState{
		Email:       "michael.bland@gsa.gov",
		AccessToken: "my_access_token",

		RefreshDeadline:  theFuture,
		LifetimeDeadline: theFuture,
		ValidDeadline:    theFuture,
	}
}

func TestNewReverseProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		hostname, _, _ := net.SplitHostPort(r.Host)
		w.Write([]byte(hostname))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	backendHost := net.JoinHostPort(backendHostname, backendPort)
	proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")

	proxyHandler := NewReverseProxy(proxyURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func TestNewRewriteReverseProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
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

	rewriteProxy := NewRewriteReverseProxy(route)

	frontend := httptest.NewServer(rewriteProxy)
	defer frontend.Close()

	resp, err := http.Get(frontend.URL)
	if err != nil {
		t.Fatalf("expected to make successful request err:%q", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("expected to read body err:%q", err)
	}

	if string(body) != parsedUpstreamURL.Host {
		t.Logf("got  %v", string(body))
		t.Logf("want %v", parsedUpstreamURL.Host)
		t.Fatalf("got unexpected response from upstream")
	}
}

func TestNewReverseProxyHostname(t *testing.T) {
	type respStruct struct {
		Host           string `json:"host"`
		XForwardedHost string `json:"x-forwarded-host"`
	}

	to := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
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

	reverseProxy := NewReverseProxy(toURL)
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

	res, err := http.Get(from.URL)
	if err != nil {
		t.Fatalf("expected to be able to make req: %s", err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("expected to read body: %s", err)
	}

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
			url:  "https://www.example.com/",
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
			ut := upstreamTransport{}
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

	b, _ := url.Parse(backend.URL)
	proxyHandler := NewReverseProxy(b)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	f, _ := url.Parse(frontend.URL)
	encodedPath := "/a%2Fb/?c=1"
	getReq := &http.Request{URL: &url.URL{Scheme: "http", Host: f.Host, Opaque: encodedPath}}
	_, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	if seen != encodedPath {
		t.Errorf("got bad request %q expected %q", seen, encodedPath)
	}
}

func generateTestUpstreamConfigs(to string) []*UpstreamConfig {
	if !strings.Contains(to, "://") {
		to = fmt.Sprintf("%s://%s", "http", to)
	}
	parsed, err := url.Parse(to)
	if err != nil {
		panic(err)
	}
	templateVars := map[string]string{
		"root_domain": "dev",
		"cluster":     "sso",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(fmt.Sprintf(`
- service: foo
  default:
    from: foo.sso.dev
    to: %s
`, parsed)), "sso", "http", templateVars)
	if err != nil {
		panic(err)
	}
	return upstreamConfigs
}

func TestRobotsTxt(t *testing.T) {
	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.ProviderURLString = "https://auth.sso.dev"
	opts.upstreamConfigs = generateTestUpstreamConfigs("foo-internal.sso.dev")
	opts.Validate()

	proxy, err := NewOAuthProxy(opts)
	if err != nil {
		t.Errorf("unexpected error %s", err)
	}
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "https://foo.sso.dev/robots.txt", nil)
	proxy.Handler().ServeHTTP(rw, req)
	testutil.Equal(t, 200, rw.Code)
	testutil.Equal(t, "User-agent: *\nDisallow: /", rw.Body.String())
}

func TestFavicon(t *testing.T) {
	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.ProviderURLString = "https://auth.sso.dev"
	opts.upstreamConfigs = generateTestUpstreamConfigs("foo-internal.sso.dev")
	opts.Validate()

	proxy, _ := NewOAuthProxy(opts)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "https://foo.sso.dev/favicon.ico", nil)
	proxy.Handler().ServeHTTP(rw, req)
	testutil.Equal(t, http.StatusNotFound, rw.Code)
}

type TestProvider struct {
	*providers.ProviderData
	EmailAddress string
	ValidToken   bool
}

func NewTestProvider(providerURL *url.URL, emailAddress string) *TestProvider {
	return &TestProvider{
		ProviderData: &providers.ProviderData{
			ProviderName: "Test Provider",
			SignInURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/api/v1/profile",
			},
			Scope: "profile.email",
		},
		EmailAddress: emailAddress,
	}
}

func (tp *TestProvider) GetEmailAddress(session *providers.SessionState) (string, error) {
	return tp.EmailAddress, nil
}

func (tp *TestProvider) ValidateSessionState(session *providers.SessionState, g []string) bool {
	return tp.ValidToken
}

type ProcessCookieTest struct {
	opts         *Options
	proxy        *OAuthProxy
	rw           *httptest.ResponseRecorder
	req          *http.Request
	provider     TestProvider
	responseCode int
	validateUser bool
}

type ProcessCookieTestOpts struct {
	providerValidateCookieResponse bool
}

func NewProcessCookieTest(opts ProcessCookieTestOpts) *ProcessCookieTest {
	var pcTest ProcessCookieTest

	pcTest.opts = NewOptions()
	pcTest.opts.ClientID = "bazquux"
	pcTest.opts.ClientSecret = "xyzzyplugh"
	pcTest.opts.CookieSecret = testEncodedCookieSecret
	pcTest.opts.ProviderURLString = "https://auth.sso.dev"
	pcTest.opts.upstreamConfigs = generateTestUpstreamConfigs("foo-internal.sso.dev")
	pcTest.opts.Validate()
	pcTest.proxy, _ = NewOAuthProxy(pcTest.opts, func(p *OAuthProxy) error {
		p.EmailValidator = func(string) bool {
			return pcTest.validateUser
		}
		return nil
	})

	pcTest.proxy.provider = &TestProvider{
		ValidToken: opts.providerValidateCookieResponse,
	}

	pcTest.rw = httptest.NewRecorder()
	pcTest.req, _ = http.NewRequest("GET", "https://foo.sso.dev/", strings.NewReader(""))
	pcTest.validateUser = true
	return &pcTest
}

func NewProcessCookieTestWithDefaults() *ProcessCookieTest {
	return NewProcessCookieTest(ProcessCookieTestOpts{
		providerValidateCookieResponse: true,
	})
}

func (p *ProcessCookieTest) SaveSession(s *providers.SessionState, ref time.Time) error {
	value, err := providers.MarshalSession(s, p.proxy.CookieCipher)
	if err != nil {
		return err
	}
	c := p.proxy.MakeSessionCookie(p.req, value, p.proxy.CookieExpire, ref)
	p.req.AddCookie(c)
	return nil
}

func (p *ProcessCookieTest) MakeCookie(value string, ref time.Time) *http.Cookie {
	return p.proxy.MakeSessionCookie(p.req, value, p.proxy.CookieExpire, ref)
}

func (p *ProcessCookieTest) LoadCookiedSession() (*providers.SessionState, error) {
	return p.proxy.LoadCookiedSession(p.req)
}

func TestLoadCookiedSession(t *testing.T) {

	testCases := []struct {
		name          string
		want          *providers.SessionState
		expectedError error
	}{
		{
			name: "normal load with new cookie cipher",
			want: testSession(),
		},
		{
			name:          "no cookie in session",
			expectedError: http.ErrNoCookie,
			want:          nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pcTest := NewProcessCookieTestWithDefaults()

			value, err := providers.MarshalSession(tc.want, pcTest.proxy.CookieCipher)
			if err != nil {
				t.Errorf("error marshaling session, value=%s error=%s", value, err)
			}

			c := pcTest.proxy.MakeSessionCookie(pcTest.req, value, pcTest.proxy.CookieExpire, time.Now().Add(24*time.Hour))
			if tc.want != nil {
				pcTest.req.AddCookie(c)
			}
			got, err := pcTest.proxy.LoadCookiedSession(pcTest.req)

			if tc.expectedError != err {
				t.Logf("want error %s", tc.expectedError)
				t.Logf("got error %s", err)
				t.Errorf("unexpected error for LoadCookiedSession")
			}

			if tc.expectedError != nil && tc.want == nil {
				return
			}

			if tc.want.Email != got.Email {
				t.Logf(" got: %v", got.Email)
				t.Logf("want: %v", tc.want.Email)
				t.Errorf("got unexpected value for Email")
			}

			if tc.want.AccessToken != got.AccessToken {
				t.Logf("got: %v", got.AccessToken)
				t.Logf("want: %v", tc.want.AccessToken)
				t.Errorf("got unexpected value for AccessToken")
			}

			if !tc.want.RefreshDeadline.Equal(got.RefreshDeadline) {
				t.Logf(" got: %v", got.RefreshDeadline)
				t.Logf("want: %v", tc.want.RefreshDeadline)
				t.Errorf("got unexpected value for RefreshDeadline")
			}

			if !tc.want.LifetimeDeadline.Equal(got.LifetimeDeadline) {
				t.Logf(" got: %v", got.LifetimeDeadline)
				t.Logf("want: %v", tc.want.LifetimeDeadline)
				t.Errorf("got unexpected value for LifetimeDeadline")
			}

			if !tc.want.ValidDeadline.Equal(got.ValidDeadline) {
				t.Logf(" got: %v", got.ValidDeadline)
				t.Logf("want: %v", tc.want.ValidDeadline)
				t.Errorf("got unexpected value for ValidDeadline")
			}
		})
	}
}

func TestProcessCookieNoCookieError(t *testing.T) {
	pcTest := NewProcessCookieTestWithDefaults()

	session, err := pcTest.LoadCookiedSession()
	testutil.Equal(t, "http: named cookie not present", err.Error())
	if session != nil {
		t.Errorf("expected nil session. got %#v", session)
	}
}

func NewAuthOnlyEndpointTest() *ProcessCookieTest {
	pcTest := NewProcessCookieTestWithDefaults()
	pcTest.req, _ = http.NewRequest("GET", "https://foo.sso.dev/oauth2/auth", nil)
	return pcTest
}

func TestAuthOnlyEndpointAccepted(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := testSession()
	test.SaveSession(startSession, time.Now())

	test.proxy.Handler().ServeHTTP(test.rw, test.req)
	testutil.Equal(t, http.StatusAccepted, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	testutil.Equal(t, "", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnNoCookieSetError(t *testing.T) {
	test := NewAuthOnlyEndpointTest()

	test.proxy.Handler().ServeHTTP(test.rw, test.req)
	testutil.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	testutil.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnExpiration(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	test.proxy.CookieExpire = time.Duration(24) * time.Hour
	reference := time.Now().Add(time.Duration(25) * time.Hour * -1)
	startSession := testSession()
	startSession.LifetimeDeadline = reference
	test.SaveSession(startSession, reference)

	test.proxy.Handler().ServeHTTP(test.rw, test.req)
	testutil.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	testutil.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthOnlyEndpointUnauthorizedOnEmailValidationFailure(t *testing.T) {
	test := NewAuthOnlyEndpointTest()
	startSession := testSession()
	test.SaveSession(startSession, time.Now())
	test.validateUser = false

	test.proxy.Handler().ServeHTTP(test.rw, test.req)
	testutil.Equal(t, http.StatusUnauthorized, test.rw.Code)
	bodyBytes, _ := ioutil.ReadAll(test.rw.Body)
	testutil.Equal(t, "unauthorized request\n", string(bodyBytes))
}

func TestAuthSkippedForPreflightRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()

	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.SkipAuthPreflight = true
	opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
	opts.Validate()

	upstreamURL, _ := url.Parse(upstream.URL)
	opts.provider = NewTestProvider(upstreamURL, "")

	proxy, _ := NewOAuthProxy(opts)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "https://foo.sso.dev/preflight-request", nil)
	proxy.Handler().ServeHTTP(rw, req)

	testutil.Equal(t, 200, rw.Code)
	testutil.Equal(t, "response", rw.Body.String())
}

func generateTestAuthSkipConfigs(to string) []*UpstreamConfig {
	if !strings.Contains(to, "://") {
		to = fmt.Sprintf("%s://%s", "http", to)
	}
	parsed, err := url.Parse(to)
	if err != nil {
		panic(err)
	}
	templateVars := map[string]string{
		"root_domain": "dev",
		"cluster":     "sso",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(fmt.Sprintf(`
- service: foo
  default:
    from: foo.sso.dev
    to: %s
    options:
      skip_auth_regex:
        - ^\/allow$
`, parsed)), "sso", "http", templateVars)
	if err != nil {
		panic(err)
	}
	return upstreamConfigs
}

func TestAuthSkipRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("response"))
	}))
	defer upstream.Close()

	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.SkipAuthPreflight = true
	opts.upstreamConfigs = generateTestAuthSkipConfigs(upstream.URL)
	opts.Validate()

	upstreamURL, _ := url.Parse(upstream.URL)
	opts.provider = NewTestProvider(upstreamURL, "")

	proxy, _ := NewOAuthProxy(opts)

	// expect to get rejected
	rejectedRW := httptest.NewRecorder()
	rejectedReq, _ := http.NewRequest("GET", "https://foo.sso.dev/rejected", nil)
	proxy.Handler().ServeHTTP(rejectedRW, rejectedReq)
	// We get a 302 here, status found, and attempt to authenticate
	testutil.Equal(t, http.StatusFound, rejectedRW.Code)

	// Expect OK
	allowRW := httptest.NewRecorder()
	allowReq, _ := http.NewRequest("GET", "https://foo.sso.dev/allow", nil)
	proxy.Handler().ServeHTTP(allowRW, allowReq)
	testutil.Equal(t, http.StatusOK, allowRW.Code)
	testutil.Equal(t, "response", allowRW.Body.String())
}

func generateMultiTestAuthSkipConfigs(toFoo, toBar string) []*UpstreamConfig {
	if !strings.Contains(toFoo, "://") {
		toFoo = fmt.Sprintf("%s://%s", "http", toFoo)
	}
	parsedFoo, err := url.Parse(toFoo)
	if err != nil {
		panic(err)
	}

	if !strings.Contains(toBar, "://") {
		toBar = fmt.Sprintf("%s://%s", "http", toBar)
	}
	parsedBar, err := url.Parse(toBar)
	if err != nil {
		panic(err)
	}
	templateVars := map[string]string{
		"root_domain": "dev",
		"cluster":     "sso",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(fmt.Sprintf(`
- service: foo
  default:
    from: foo.sso.dev
    to: %s
    options:
      skip_auth_regex:
        - ^\/allow$
- service: bar
  default:
    from: bar.sso.dev
    to: %s
`, parsedFoo, parsedBar)), "sso", "http", templateVars)
	if err != nil {
		panic(err)
	}
	return upstreamConfigs
}

func TestMultiAuthSkipRequests(t *testing.T) {
	upstreamFoo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("foo"))
	}))
	defer upstreamFoo.Close()

	upstreamBar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("bar"))
	}))
	defer upstreamBar.Close()

	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.SkipAuthPreflight = true
	opts.upstreamConfigs = generateMultiTestAuthSkipConfigs(upstreamFoo.URL, upstreamBar.URL)
	opts.Validate()

	upstreamFooURL, _ := url.Parse(upstreamFoo.URL)
	opts.provider = NewTestProvider(upstreamFooURL, "")

	proxy, _ := NewOAuthProxy(opts)

	// expect to get rejected
	rejectedRW := httptest.NewRecorder()
	rejectedReq, _ := http.NewRequest("GET", "https://bar.sso.dev/allow", nil)
	proxy.Handler().ServeHTTP(rejectedRW, rejectedReq)
	// We get a 302 here, status found, and attempt to authenticate
	testutil.Equal(t, http.StatusFound, rejectedRW.Code)

	// Expect OK
	allowRW := httptest.NewRecorder()
	allowReq, _ := http.NewRequest("GET", "https://foo.sso.dev/allow", nil)
	proxy.Handler().ServeHTTP(allowRW, allowReq)
	testutil.Equal(t, http.StatusOK, allowRW.Code)
	testutil.Equal(t, "foo", allowRW.Body.String())
}

type SignatureAuthenticator struct {
	auth hmacauth.HmacAuth
}

func (v *SignatureAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) {
	result, headerSig, computedSig := v.auth.AuthenticateRequest(r)
	if result == hmacauth.ResultNoSignature {
		w.Write([]byte("no signature received"))
	} else if result == hmacauth.ResultMatch {
		w.Write([]byte("signatures match"))
	} else if result == hmacauth.ResultMismatch {
		w.Write([]byte("signatures do not match:" +
			"\n  received: " + headerSig +
			"\n  computed: " + computedSig))
	} else {
		panic("Unknown result value: " + result.String())
	}
}

type SignatureTest struct {
	opts          *Options
	upstream      *httptest.Server
	upstreamHost  string
	provider      *httptest.Server
	header        http.Header
	rw            *httptest.ResponseRecorder
	authenticator *SignatureAuthenticator
}

func generateSignatureTestUpstreamConfigs(key, to string) []*UpstreamConfig {

	if !strings.Contains(to, "://") {
		to = fmt.Sprintf("%s://%s", "http", to)
	}
	parsed, err := url.Parse(to)
	if err != nil {
		panic(err)
	}
	templateVars := map[string]string{
		"root_domain":     "dev",
		"cluster":         "sso",
		"foo_signing_key": key,
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(fmt.Sprintf(`
- service: foo
  default:
    from: foo.{{cluster}}.{{root_domain}}
    to: %s
`, parsed)), "sso", "http", templateVars)
	if err != nil {
		panic(err)
	}

	return upstreamConfigs
}

func NewSignatureTest(key string) *SignatureTest {
	opts := NewOptions()
	opts.CookieSecret = testEncodedCookieSecret
	opts.ClientID = "client ID"
	opts.ClientSecret = "client secret"
	opts.EmailDomains = []string{"example.com"}

	authenticator := &SignatureAuthenticator{}
	upstream := httptest.NewServer(
		http.HandlerFunc(authenticator.Authenticate))
	upstreamURL, _ := url.Parse(upstream.URL)

	providerHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token": "my_auth_token"}`))
	}
	provider := httptest.NewServer(http.HandlerFunc(providerHandler))
	providerURL, _ := url.Parse(provider.URL)
	opts.provider = NewTestProvider(providerURL, "email1@example.com")
	opts.upstreamConfigs = generateSignatureTestUpstreamConfigs(key, upstream.URL)
	opts.Validate()

	return &SignatureTest{
		opts,
		upstream,
		upstreamURL.Host,
		provider,
		make(http.Header),
		httptest.NewRecorder(),
		authenticator,
	}
}

func (st *SignatureTest) Close() {
	st.provider.Close()
	st.upstream.Close()
}

// fakeNetConn simulates an http.Request.Body buffer that will be consumed
// when it is read by the hmacauth.HmacAuth if not handled properly. See:
//   https://github.com/18F/hmacauth/pull/4
type fakeNetConn struct {
	reqBody string
}

func (fnc *fakeNetConn) Read(p []byte) (n int, err error) {
	if bodyLen := len(fnc.reqBody); bodyLen != 0 {
		copy(p, fnc.reqBody)
		fnc.reqBody = ""
		return bodyLen, io.EOF
	}
	return 0, io.EOF
}

func (st *SignatureTest) MakeRequestWithExpectedKey(method, body, key string) {
	proxy, _ := NewOAuthProxy(st.opts, testValidatorFunc(true))
	var bodyBuf io.ReadCloser
	if body != "" {
		bodyBuf = ioutil.NopCloser(&fakeNetConn{reqBody: body})
	}
	req := httptest.NewRequest(method, "https://foo.sso.dev/foo/bar", bodyBuf)
	req.Header = st.header

	state := testSession()
	value, err := providers.MarshalSession(state, proxy.CookieCipher)
	if err != nil {
		panic(err)
	}
	cookie := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
	req.AddCookie(cookie)
	// This is used by the upstream to validate the signature.
	st.authenticator.auth = hmacauth.NewHmacAuth(
		crypto.SHA1, []byte(key), SignatureHeader, SignatureHeaders)
	proxy.Handler().ServeHTTP(st.rw, req)
}

func TestRequestSignatureGetRequest(t *testing.T) {
	st := NewSignatureTest("sha1:foobar")
	defer st.Close()
	st.MakeRequestWithExpectedKey("GET", "", "foobar")
	testutil.Equal(t, 200, st.rw.Code)
	testutil.Equal(t, st.rw.Body.String(), "signatures match")
}

func TestRequestSignaturePostRequest(t *testing.T) {
	st := NewSignatureTest("sha1:foobar")
	defer st.Close()
	payload := `{ "hello": "world!" }`
	st.MakeRequestWithExpectedKey("POST", payload, "foobar")
	testutil.Equal(t, 200, st.rw.Code)
	testutil.Equal(t, st.rw.Body.String(), "signatures match")
}

func TestHeadersSentToUpstreams(t *testing.T) {
	type headersResponse struct {
		Headers http.Header `json:"headers"`
	}

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

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(&headersResponse{
			Headers: r.Header,
		})
		if err != nil {
			t.Errorf("error marshaling headersResponse: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	}))
	defer upstream.Close()

	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.CookieSecure = false
	opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
	opts.Validate()
	providerURL, _ := url.Parse("http://sso-auth.example.com/")
	opts.provider = NewTestProvider(providerURL, "")

	state := testSession()
	state.Email = "foo@example.com"
	state.User = "foo"
	state.Groups = []string{"fooGroup"}
	proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "http://foo.sso.dev/bar", nil)

			value, err := providers.MarshalSession(state, proxy.CookieCipher)
			if err != nil {
				panic(err)
			}

			cookie := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
			req.AddCookie(cookie)

			for _, c := range tc.otherCookies {
				req.AddCookie(c)
			}

			proxy.Handler().ServeHTTP(rw, req)

			if rw.Code != http.StatusOK {
				t.Errorf("expected status = 200, got %d", rw.Code)
			}

			resp := &headersResponse{}
			err = json.Unmarshal(rw.Body.Bytes(), resp)
			if err != nil {
				t.Errorf("error unmarshaling response: %s", err)
			}

			expectedHeaders := map[string]string{
				"X-Forwarded-Email":  "foo@example.com",
				"X-Forwarded-User":   "foo",
				"X-Forwarded-Groups": "fooGroup",
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

type testAuthenticateProvider struct {
	*providers.ProviderData
	refreshSessionFunc  func(*providers.SessionState, []string) (bool, error)
	validateSessionFunc func(*providers.SessionState, []string) bool
}

func (tap *testAuthenticateProvider) RefreshSession(s *providers.SessionState, g []string) (bool, error) {
	return tap.refreshSessionFunc(s, g)
}

func (tap *testAuthenticateProvider) ValidateSessionState(s *providers.SessionState, g []string) bool {
	return tap.validateSessionFunc(s, g)
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
	)
	testCases := []struct {
		Name                string
		Session             *providers.SessionState
		ExpectedErr         error
		CookieExpectation   int // One of: {NewCookie, ClearCookie, KeepCookie}
		RefreshSessionFunc  func(*providers.SessionState, []string) (bool, error)
		ValidateSessionFunc func(*providers.SessionState, []string) bool
		Cipher              aead.Cipher
	}{
		{
			Name: "redirect if deadlines are blank",
			Session: &providers.SessionState{
				Email:       "email1@example.com",
				AccessToken: "my_access_token",
			},
			ExpectedErr:       ErrLifetimeExpired,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "session unmarshaling fails, get ErrInvalidSession",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
			},
			ExpectedErr:       ErrInvalidSession,
			CookieExpectation: ClearCookie,
			Cipher: &aead.MockCipher{
				MarshalString:  "randomstring",
				UnmarshalError: errors.New("siv: authentication failed"),
			},
		},
		{
			Name: "authenticate successfully",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
			},
			ExpectedErr:       nil,
			CookieExpectation: KeepCookie,
		},
		{
			Name: "lifetime expired, do not authenticate",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
			},
			ExpectedErr:       ErrLifetimeExpired,
			CookieExpectation: ClearCookie,
		},
		{
			Name: "refresh expired, refresh fails, do not authenticate",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
			},
			ExpectedErr:        ErrRefreshFailed,
			CookieExpectation:  ClearCookie,
			RefreshSessionFunc: func(s *providers.SessionState, g []string) (bool, error) { return false, ErrRefreshFailed },
		},
		{
			Name: "refresh expired, user not OK, do not authenticate",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
			},
			ExpectedErr:        ErrUserNotAuthorized,
			CookieExpectation:  ClearCookie,
			RefreshSessionFunc: func(s *providers.SessionState, g []string) (bool, error) { return false, nil },
		},
		{
			Name: "refresh expired, user OK, authenticate",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(-1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Minute),
			},
			ExpectedErr:        nil,
			CookieExpectation:  NewCookie,
			RefreshSessionFunc: func(s *providers.SessionState, g []string) (bool, error) { return true, nil },
		},
		{
			Name: "validation expired, user not OK, do not authenticate",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(-1) * time.Minute),
			},
			ExpectedErr:         ErrUserNotAuthorized,
			CookieExpectation:   ClearCookie,
			ValidateSessionFunc: func(s *providers.SessionState, g []string) bool { return false },
		},
		{
			Name: "validation expired, user OK, authenticate",
			Session: &providers.SessionState{
				Email:            "email1@example.com",
				AccessToken:      "my_access_token",
				LifetimeDeadline: time.Now().Add(time.Duration(24) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(-1) * time.Minute),
			},
			ExpectedErr:         nil,
			CookieExpectation:   NewCookie,
			ValidateSessionFunc: func(s *providers.SessionState, g []string) bool { return true },
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// setup deafults
			opts := NewOptions()
			opts.CookieSecret = testEncodedCookieSecret
			opts.CookieExpire = time.Duration(72) * time.Hour
			opts.ClientID = "client ID"
			opts.ClientSecret = "client secret"
			opts.EmailDomains = []string{"example.com"}
			opts.ProviderURLString = "https://auth.sso.dev"
			opts.GracePeriodTTL = time.Duration(3) * time.Hour
			opts.upstreamConfigs = generateTestUpstreamConfigs("foo-internal.sso.dev")
			opts.Validate()
			proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true), testCookieCipher(tc.Cipher))
			proxy.provider = &testAuthenticateProvider{
				refreshSessionFunc:  tc.RefreshSessionFunc,
				validateSessionFunc: tc.ValidateSessionFunc,
			}

			value, err := providers.MarshalSession(tc.Session, proxy.CookieCipher)
			if err != nil {
				t.Fatalf("unexpected err encoding session err:%s", err)
			}

			req, err := http.NewRequest("GET", "https://foo.sso.dev/", strings.NewReader(""))
			if err != nil {
				t.Fatalf("unexpected err creating request err:%s", err)
			}
			c := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
			req.AddCookie(c)

			rw := httptest.NewRecorder()

			gotErr := proxy.Authenticate(rw, req)

			// Extract cookie from response.
			cookieBehavior := func() int {
				cookies := strings.Split(rw.Header().Get("Set-Cookie"), ";")
				for _, cookie := range cookies {
					if strings.HasPrefix(cookie, "_sso_proxy=") {
						if len(cookie) == len("_sso_proxy=") {
							// Empty value for "_sso_proxy" in header.
							// Clear the session cookie on the client.
							return ClearCookie
						}
						// Non-empty value given to "_sso_proxy" in header.
						// Assign new value to session cookie on client.
						return NewCookie
					}
				}
				// No "_sso_proxy" in Set-Cookie header. Keep cookie as is.
				return KeepCookie
			}()

			if gotErr != tc.ExpectedErr {
				t.Logf(" got error: %#v", gotErr)
				t.Logf("want error: %#v", tc.ExpectedErr)
				t.Error("unexpected error value for authenticate")
			}
			if cookieBehavior != tc.CookieExpectation {
				t.Logf(" got cookie behavior: %d", cookieBehavior)
				t.Logf("want cookie behavior: %d", tc.CookieExpectation)
				t.Error("unexpected session cookie behavior for authenticate")
			}
		})
	}
}

func TestProxyXHRErrorHandling(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("upstream"))
	}))

	defer upstream.Close()
	testCases := []struct {
		Name         string
		Session      *providers.SessionState
		Method       string
		ExpectedCode int
		Header       map[string]string
	}{
		{
			Name: "expired session should redirect on normal request (GET)",
			Session: &providers.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
			},
			Method:       "GET",
			ExpectedCode: http.StatusFound,
		},
		{
			Name: "expired session should proxy preflight request (OPTIONS)",
			Session: &providers.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
			},
			Method:       "OPTIONS",
			ExpectedCode: http.StatusOK,
		},
		{
			Name: "expired session should return error code when XMLHttpRequest",
			Session: &providers.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(-24) * time.Hour),
			},
			Method: "GET",
			Header: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
			},
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			Name: "valid session should proxy as normal when XMLHttpRequest",
			Session: &providers.SessionState{
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
			// setup deafults
			opts := NewOptions()
			opts.SkipAuthPreflight = true
			opts.CookieSecret = testEncodedCookieSecret
			opts.CookieExpire = time.Duration(72) * time.Hour
			opts.ClientID = "client ID"
			opts.ClientSecret = "client secret"
			opts.EmailDomains = []string{"example.com"}
			opts.ProviderURLString = "https://auth.sso.dev"
			opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
			opts.Validate()
			proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true))

			// save our session
			value, err := providers.MarshalSession(tc.Session, proxy.CookieCipher)
			if err != nil {
				t.Fatalf("unexpected err encoding session err:%s", err)
			}

			req, err := http.NewRequest(tc.Method, "https://foo.sso.dev/", strings.NewReader(""))
			if err != nil {
				t.Fatalf("unexpected err creating request err:%s", err)
			}
			c := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
			req.AddCookie(c)

			for k, v := range tc.Header {
				req.Header.Set(k, v)
			}

			rw := httptest.NewRecorder()

			proxy.Proxy(rw, req)

			if tc.ExpectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.ExpectedCode, rw.Code)
			}
		})
	}
}

func TestOAuthStart(t *testing.T) {
	testCases := []struct {
		Name string
	}{
		{
			Name: "OAuthStart returns successfully",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// setup deafults
			opts := NewOptions()
			opts.CookieSecret = testEncodedCookieSecret
			opts.CookieExpire = time.Duration(72) * time.Hour
			opts.ClientID = "client ID"
			opts.ClientSecret = "client secret"
			opts.EmailDomains = []string{"example.com"}
			opts.ProviderURLString = "https://auth.sso.dev"
			opts.upstreamConfigs = generateTestUpstreamConfigs("foo-internal.sso.dev")
			opts.Validate()
			proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true))

			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				proxy.OAuthStart(rw, r, []string{})
			}))
			defer srv.Close()

			req, err := http.NewRequest("GET", srv.URL, nil)
			if err != nil {
				t.Fatalf("expected req to succeeded err:%v", err)
			}

			client := &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatalf("expected req to succeeded err:%v", err)
			}

			if res.StatusCode != http.StatusFound {
				t.Fatalf("unexpected status code response")
			}

			location, err := res.Location()
			if err != nil {
				t.Fatalf("expected req to succeeded err:%v", err)
			}

			cookies := res.Cookies()
			if len(cookies) != 1 {
				t.Fatalf("unexpected number of cookies")
			}
			c := cookies[0]

			state := location.Query().Get("state")
			if state == c.Value {
				t.Fatalf("expected state to not be equal to cookie value")
			}

			cookieParameter := &StateParameter{}
			err = proxy.CookieCipher.Unmarshal(c.Value, cookieParameter)
			if err != nil {
				t.Fatalf("unexpected err during unmarshal: %v", err)
			}

			stateParameter := &StateParameter{}
			err = proxy.CookieCipher.Unmarshal(state, stateParameter)
			if err != nil {
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

func TestPing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
	opts.Validate()

	providerURL, _ := url.Parse("http://sso-auth.example.com/")
	opts.provider = NewTestProvider(providerURL, "")

	proxy, _ := NewOAuthProxy(opts)
	state := testSession()

	testCases := []struct {
		name          string
		url           string
		host          string
		authenticated bool
		expectedCode  int
	}{
		{
			name:          "ping never reaches upstream",
			url:           "http://foo.sso.dev/ping",
			authenticated: true,
			expectedCode:  http.StatusOK,
		},
		{
			name:         "ping skips host check with no host set",
			url:          "/ping",
			expectedCode: http.StatusOK,
		},
		{
			name:         "ping skips host check with unknown host set",
			url:          "/ping",
			host:         "example.com",
			expectedCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", tc.url, nil)

			if tc.authenticated {
				value, err := providers.MarshalSession(state, proxy.CookieCipher)
				if err != nil {
					t.Fatalf("unexpected err encoding session err:%s", err)
				}
				cookie := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
				req.AddCookie(cookie)
			}

			proxy.Handler().ServeHTTP(rw, req)

			if tc.expectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.expectedCode, rw.Code)
			}
			if rw.Body.String() != "OK" {
				t.Errorf("expected body = %q, got %q", "OK", rw.Body.String())
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/add-header":
			w.Header().Set("X-Test-Header", "true")
		case "/override-security-header":
			w.Header().Set("X-Frame-Options", "OVERRIDE")
		}
		w.WriteHeader(200)
		w.Write([]byte(r.URL.RequestURI()))
	}))
	defer upstream.Close()

	opts := NewOptions()
	opts.ClientID = "bazquux"
	opts.ClientSecret = "foobar"
	opts.CookieSecret = testEncodedCookieSecret
	opts.CookieSecure = false
	opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
	opts.Validate()

	providerURL, _ := url.Parse("http://sso-auth.example.com/")
	opts.provider = NewTestProvider(providerURL, "")

	proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true))

	state := testSession()

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
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://foo.sso.dev%s", tc.path), nil)

			if tc.authenticated {
				value, err := providers.MarshalSession(state, proxy.CookieCipher)
				if err != nil {
					t.Fatalf("unexpected err encoding session err:%s", err)
				}
				cookie := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
				req.AddCookie(cookie)
			}

			proxy.Handler().ServeHTTP(rw, req)

			if tc.expectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.expectedCode, rw.Code)
			}
			if tc.expectedCode == http.StatusOK {
				if rw.Body.String() != tc.path {
					t.Errorf("expected body = %q, got %q", tc.path, rw.Body.String())
				}
			}
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

func makeUpstreamConfigWithHeaderOverrides(overrides map[string]string) []*UpstreamConfig {
	templateVars := map[string]string{
		"root_domain": "dev",
		"cluster":     "sso",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(fmt.Sprintf(`
- service: foo
  default:
    from: foo.sso.dev
    to: foo-internal.sso.dev

- service: bar
  default:
    from: bar.sso.dev
    to: bar-internal.sso.dev
`)), "sso", "http", templateVars)
	if err != nil {
		panic(err)
	}
	upstreamConfigs[0].HeaderOverrides = overrides // we override foo and not bar
	return upstreamConfigs
}

func TestHeaderOverrides(t *testing.T) {
	testCases := []struct {
		name            string
		overrides       map[string]string
		expectedCode    int
		expectedHeaders map[string]string
	}{
		{
			name:            "security headers are added to requests",
			overrides:       nil,
			expectedCode:    http.StatusOK,
			expectedHeaders: securityHeaders,
		},
		{
			name: "security headers are overridden by config",
			overrides: map[string]string{
				"X-Frame-Options": "ALLOW-FROM nsa.gov",
			},
			expectedCode: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Frame-Options": "ALLOW-FROM nsa.gov",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewOptions()
			opts.ClientID = "bazquux"
			opts.ClientSecret = "foobar"
			opts.CookieSecret = testEncodedCookieSecret
			opts.CookieSecure = false
			opts.upstreamConfigs = makeUpstreamConfigWithHeaderOverrides(tc.overrides)
			opts.Validate()

			providerURL, _ := url.Parse("http://sso-auth.example.com/")
			opts.provider = NewTestProvider(providerURL, "")

			proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true))

			// Check Foo
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "http://foo.sso.dev/", nil)
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

			// Check Bar
			rwBar := httptest.NewRecorder()
			reqBar, _ := http.NewRequest("GET", "http://bar.sso.dev/", nil)
			proxy.Handler().ServeHTTP(rwBar, reqBar)
			for key, val := range securityHeaders {
				vals, found := rwBar.HeaderMap[http.CanonicalHeaderKey(key)]
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.String()))
	}))
	defer upstream.Close()

	providerURL, _ := url.Parse("http://sso-auth.example.com/")
	provider := NewTestProvider(providerURL, "")
	state := testSession()

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
			url:           "http://foo.sso.dev/",
			cookieSecure:  false,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     false,
		},
		{
			name:                 "no https redirect with http cookie_secure=false and authenticated=false",
			url:                  "http://foo.sso.dev/",
			cookieSecure:         false,
			authenticated:        false,
			expectedCode:         http.StatusFound,
			expectedLocationHost: "sso-auth.example.com",
			expectSTS:            false,
		},
		{
			name:          "no https redirect with https and cookie_secure=false and authenticated=true",
			url:           "https://foo.sso.dev/",
			cookieSecure:  false,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     false,
		},
		{
			name:                 "no https redirect with https and cookie_secure=false and authenticated=false",
			url:                  "https://foo.sso.dev/",
			cookieSecure:         false,
			authenticated:        false,
			expectedCode:         http.StatusFound,
			expectedLocationHost: "sso-auth.example.com",
			expectSTS:            false,
		},
		{
			name:             "https redirect with cookie_secure=true and authenticated=false",
			url:              "http://foo.sso.dev/",
			cookieSecure:     true,
			authenticated:    false,
			expectedCode:     http.StatusMovedPermanently,
			expectedLocation: "https://foo.sso.dev/",
			expectSTS:        true,
		},
		{
			name:             "https redirect with cookie_secure=true and authenticated=true",
			url:              "http://foo.sso.dev/",
			cookieSecure:     true,
			authenticated:    true,
			expectedCode:     http.StatusMovedPermanently,
			expectedLocation: "https://foo.sso.dev/",
			expectSTS:        true,
		},
		{
			name:          "no https redirect with https and cookie_secure=true and authenticated=true",
			url:           "https://foo.sso.dev/",
			cookieSecure:  true,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     true,
		},
		{
			name:          "no https redirect with https and cookie_secure=true and authenticated=false",
			url:           "https://foo.sso.dev/",
			cookieSecure:  true,
			authenticated: true,
			expectedCode:  http.StatusOK,
			expectSTS:     true,
		},
		{
			name:             "request path and query are preserved in redirect",
			url:              "http://foo.sso.dev/foo/bar.html?a=1&b=2&c=3",
			cookieSecure:     true,
			authenticated:    true,
			expectedCode:     http.StatusMovedPermanently,
			expectedLocation: "https://foo.sso.dev/foo/bar.html?a=1&b=2&c=3",
			expectSTS:        true,
		},
		{
			name:           "no https redirect with http and X-Forwarded-Proto=https",
			url:            "http://foo.sso.dev/",
			cookieSecure:   true,
			authenticated:  true,
			requestHeaders: map[string]string{"X-Forwarded-Proto": "https"},
			expectedCode:   http.StatusOK,
			expectSTS:      true,
		},
		{
			name:             "correct host name with relative URL",
			url:              "/",
			host:             "foo.sso.dev",
			cookieSecure:     true,
			authenticated:    false,
			expectedLocation: "https://foo.sso.dev/",
			expectedCode:     http.StatusMovedPermanently,
			expectSTS:        true,
		},
		{
			name:          "host validation is applied before https redirect",
			url:           "http://bar.sso.dev/",
			cookieSecure:  true,
			authenticated: false,
			expectedCode:  statusInvalidHost,
			expectSTS:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewOptions()
			opts.ClientID = "bazquux"
			opts.ClientSecret = "foobar"
			opts.CookieSecret = testEncodedCookieSecret
			opts.CookieSecure = tc.cookieSecure
			opts.provider = provider
			opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
			opts.Validate()

			proxy, _ := NewOAuthProxy(opts, testValidatorFunc(true))

			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", tc.url, nil)

			for key, val := range tc.requestHeaders {
				req.Header.Set(key, val)
			}

			if tc.host != "" {
				req.Host = tc.host
			}

			if tc.authenticated {
				value, err := providers.MarshalSession(state, proxy.CookieCipher)
				if err != nil {
					t.Fatalf("unexpected err encoding session err:%s", err)
				}
				cookie := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
				req.AddCookie(cookie)
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
		defaultTimeout     time.Duration
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
			defaultTimeout:     time.Duration(100) * time.Millisecond,
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
			defaultTimeout:     time.Duration(100) * time.Millisecond,
			globalTimeout:      time.Duration(100) * time.Millisecond,
			ExpectedStatusCode: 503,
			ExpectedBody:       fmt.Sprintf("service-test failed to respond within the 10ms timeout period"),
		},
		{
			name: "times out using default upstream config timeout",
			config: &UpstreamConfig{
				Service: "service-test",
			},
			defaultTimeout:     time.Duration(10) * time.Millisecond,
			globalTimeout:      time.Duration(100) * time.Millisecond,
			ExpectedStatusCode: 503,
			ExpectedBody:       fmt.Sprintf("service-test failed to respond within the 10ms timeout period"),
		},
		{
			name: "times out using global write timeout",
			config: &UpstreamConfig{
				Service: "service-test",
			},
			defaultTimeout: time.Duration(100) * time.Millisecond,
			globalTimeout:  time.Duration(10) * time.Millisecond,
			ExpectedErr: &url.Error{
				Err: io.EOF,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewOptions()
			opts.DefaultUpstreamTimeout = tc.defaultTimeout

			baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				timer := time.NewTimer(time.Duration(50) * time.Millisecond)
				<-timer.C
				w.Write([]byte("OK"))
			})
			timeoutHandler := NewTimeoutHandler(baseHandler, opts, tc.config)

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

func generateTestRewriteUpstreamConfigs(fromRegex, toTemplate string) []*UpstreamConfig {
	templateVars := map[string]string{
		"root_domain": "dev",
		"cluster":     "sso",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(fmt.Sprintf(`
- service: foo
  default:
    from: %s
    to: %s
    type: rewrite
`, fromRegex, toTemplate)), "sso", "http", templateVars)
	if err != nil {
		panic(err)
	}
	return upstreamConfigs
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
		Session          *providers.SessionState
		TestHost         string
		FromRegex        string
		ToTemplate       string
		ExpectedCode     int
		ExpectedResponse *response
	}{
		{
			Name:     "everything should work in the normal case",
			TestHost: "foo.sso.dev",
			Session: &providers.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(1) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
			},
			FromRegex:    "(.*)",
			ToTemplate:   parsedUpstreamURL.Host,
			ExpectedCode: http.StatusOK,
			ExpectedResponse: &response{
				Host:           parsedUpstreamURL.Host,
				XForwardedHost: "foo.sso.dev",
			},
		},
		{
			Name:     "it should not match a non-matching regex",
			TestHost: "foo.sso.dev",
			Session: &providers.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(1) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
			},
			FromRegex:    "bar",
			ToTemplate:   parsedUpstreamURL.Host,
			ExpectedCode: statusInvalidHost,
		},
		{
			Name:     "it should match and replace using regex/template to find port in embeded domain",
			TestHost: fmt.Sprintf("somedomain--%s", upstreamPort),
			Session: &providers.SessionState{
				LifetimeDeadline: time.Now().Add(time.Duration(1) * time.Hour),
				RefreshDeadline:  time.Now().Add(time.Duration(1) * time.Hour),
				ValidDeadline:    time.Now().Add(time.Duration(1) * time.Hour),
			},
			FromRegex:    "somedomain--(.*)",                 // capture port
			ToTemplate:   fmt.Sprintf("%s:$1", upstreamHost), // add port to dest
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
			opts.SkipAuthPreflight = true
			opts.CookieSecret = testEncodedCookieSecret
			opts.CookieExpire = time.Duration(72) * time.Hour
			opts.ClientID = "client ID"
			opts.ClientSecret = "client secret"
			opts.ProviderURLString = "https://auth.sso.dev"
			opts.upstreamConfigs = generateTestRewriteUpstreamConfigs(tc.FromRegex, tc.ToTemplate)
			opts.Validate()
			proxy, err := NewOAuthProxy(opts, testValidatorFunc(true))
			if err != nil {
				t.Fatalf("unexpected err provisioning oauth proxy err:%q", err)
			}

			// save our session
			value, err := providers.MarshalSession(tc.Session, proxy.CookieCipher)
			if err != nil {
				t.Fatalf("unexpected err encoding session err:%s", err)
			}

			req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", tc.TestHost), strings.NewReader(""))
			if err != nil {
				t.Fatalf("unexpected err creating request err:%s", err)
			}
			c := proxy.MakeSessionCookie(req, value, proxy.CookieExpire, time.Now())
			req.AddCookie(c)

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
