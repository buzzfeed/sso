package devproxy

import (
	"encoding/json"
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

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

}

func testValidatorFunc(valid bool) func(*DevProxy) error {
	return func(p *DevProxy) error {
		return nil
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
		// XForwardedEmail string `json:"x-forwarded-email"`
		// XForwardedUser string `json:"x-forwarded-user"`
		// XForwardedGroups string `json:"x-forwarded-groups"`
		// XForwardedAccessToken string `json:"x-forwarded-access-token"`
	}

	to := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(
			&respStruct{
				Host:           r.Host,
				XForwardedHost: r.Header.Get("X-Forwarded-Host"),
				// XForwardedEmail: r.Header.Get(`json:"x-forwarded-email"`),
				// XForwardedUser:  r.Header.Get(`json:"x-forwarded-user"`),
				// XForwardedGroups:  r.Header.Get(`json:"x-forwarded-groups"`),
				// XForwardedAccessToken: r.Header.Get(`json:"x-forwarded-access-token"`),
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
`, parsed)), "DevProxy", "http", templateVars)
	if err != nil {
		panic(err)
	}
	return upstreamConfigs
}

func TestRobotsTxt(t *testing.T) {
	opts := NewOptions()
	opts.upstreamConfigs = generateTestUpstreamConfigs("httpheader.net/")
	opts.Validate()

	proxy, err := NewDevProxy(opts)
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
	opts.upstreamConfigs = generateTestUpstreamConfigs("httpheader.net/")
	opts.Validate()

	proxy, _ := NewDevProxy(opts)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "https://foo.sso.dev/favicon.ico", nil)
	proxy.Handler().ServeHTTP(rw, req)
	testutil.Equal(t, http.StatusOK, rw.Code)
}

type SignatureTest struct {
	opts         *Options
	upstream     *httptest.Server
	upstreamHost string
	header       http.Header
	rw           *httptest.ResponseRecorder
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
`, parsed)), "DevProxy", "http", templateVars)
	if err != nil {
		panic(err)
	}

	return upstreamConfigs
}

func (st *SignatureTest) Close() {
	st.upstream.Close()
}

func TestPing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	opts := NewOptions()

	opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
	opts.Validate()

	proxy, _ := NewDevProxy(opts)

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
	opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
	opts.Validate()

	proxy, _ := NewDevProxy(opts, testValidatorFunc(true))

	testCases := []struct {
		name            string
		path            string
		expectedCode    int
		expectedHeaders map[string]string
	}{
		{
			name:            "security headers are added to authenticated requests",
			path:            "/",
			expectedCode:    http.StatusOK,
			expectedHeaders: securityHeaders,
		},
		// {
		// 	name:            "security headers are added to unauthenticated requests",
		// 	path:            "/",
		// 	expectedCode:    http.StatusFound,
		// 	expectedHeaders: securityHeaders,
		// },
		{
			name:         "additional headers set by upstream are proxied",
			path:         "/add-header",
			expectedCode: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Test-Header": "true",
			},
		},
		{
			name:         "security headers may NOT be overridden by upstream",
			path:         "/override-security-header",
			expectedCode: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Frame-Options": "SAMEORIGIN",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://foo.sso.dev%s", tc.path), nil)

			proxy.Handler().ServeHTTP(rw, req)

			if tc.expectedCode != rw.Code {
				t.Errorf("expected code %d, got %d", tc.expectedCode, rw.Code)
				out, _ := json.Marshal(tc)
				fmt.Println(string(out))
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
    to: httpheader.net/

- service: bar
  default:
    from: bar.sso.dev
    to: bar-internal.sso.dev
`)), "DevProxy", "http", templateVars)
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
			opts.upstreamConfigs = makeUpstreamConfigWithHeaderOverrides(tc.overrides)
			opts.Validate()

			proxy, _ := NewDevProxy(opts, testValidatorFunc(true))

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

// func TestHTTPSRedirect(t *testing.T) {
// 	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Write([]byte(r.URL.String()))
// 	}))
// 	defer upstream.Close()

// 	testCases := []struct {
// 		name                 string
// 		url                  string
// 		host                 string
// 		requestHeaders       map[string]string
// 		expectedCode         int
// 		expectedLocation     string // must match entire Location header
// 		expectedLocationHost string // just match hostname of Location header
// 		expectSTS            bool   // should we get a Strict-Transport-Security header?
// 	}{
// 		{
// 			name:         "no https redirect with http ",
// 			url:          "http://foo.sso.dev/",
// 			expectedCode: http.StatusOK,
// 			expectSTS:    false,
// 		},
// 		{
// 			name:         "no https redirect with https ",
// 			url:          "https://foo.sso.dev/",
// 			expectedCode: http.StatusOK,
// 			expectSTS:    false,
// 		},
// 		{
// 			name:             "https redirect ",
// 			url:              "http://foo.sso.dev/",
// 			expectedCode:     http.StatusOK,
// 			expectedLocation: "https://foo.sso.dev/",
// 			expectSTS:        true,
// 		},
// 		{
// 			name:             "https redirect",
// 			url:              "http://foo.sso.dev/",
// 			expectedCode:     http.StatusOK,
// 			expectedLocation: "https://foo.sso.dev/",
// 			expectSTS:        true,
// 		},
// 		{
// 			name:         "no https redirect ",
// 			url:          "https://foo.sso.dev/",
// 			expectedCode: http.StatusOK,
// 			expectSTS:    true,
// 		},
// 		{
// 			name:         "no https redirect ",
// 			url:          "https://foo.sso.dev/",
// 			expectedCode: http.StatusOK,
// 			expectSTS:    true,
// 		},
// 		{
// 			name:             "request path and query are preserved in redirect",
// 			url:              "http://foo.sso.dev/foo/bar.html?a=1&b=2&c=3",
// 			expectedCode:     http.StatusOK,
// 			expectedLocation: "https://foo.sso.dev/foo/bar.html?a=1&b=2&c=3",
// 			expectSTS:        true,
// 		},
// 		{
// 			name:           "no https redirect with http and X-Forwarded-Proto=https",
// 			url:            "http://foo.sso.dev/",
// 			requestHeaders: map[string]string{"X-Forwarded-Proto": "https"},
// 			expectedCode:   http.StatusOK,
// 			expectSTS:      true,
// 		},
// 		{
// 			name:             "correct host name with relative URL",
// 			url:              "/",
// 			host:             "foo.sso.dev",
// 			expectedLocation: "https://foo.sso.dev/",
// 			expectedCode:     http.StatusOK,
// 			expectSTS:        true,
// 		},
// 		{
// 			name:         "host validation is applied before https redirect",
// 			url:          "http://bar.sso.dev/",
// 			expectedCode: statusInvalidHost,
// 			expectSTS:    false,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			opts := NewOptions()
// 			opts.upstreamConfigs = generateTestUpstreamConfigs(upstream.URL)
// 			opts.Validate()

// 			proxy, _ := NewDevProxy(opts, testValidatorFunc(true))

// 			rw := httptest.NewRecorder()
// 			req, _ := http.NewRequest("GET", tc.url, nil)

// 			for key, val := range tc.requestHeaders {
// 				req.Header.Set(key, val)
// 			}

// 			if tc.host != "" {
// 				req.Host = tc.host
// 			}

// 			proxy.Handler().ServeHTTP(rw, req)

// 			if tc.expectedCode != rw.Code {
// 				t.Errorf("expected code %d, got %d", tc.expectedCode, rw.Code)
// 			}

// 			location := rw.Header().Get("Location")
// 			locationURL, err := url.Parse(location)
// 			if err != nil {
// 				t.Errorf("error parsing location %q: %s", location, err)
// 			}
// 			if tc.expectedLocation != "" && location != tc.expectedLocation {
// 				t.Errorf("expected Location=%q, got Location=%q", tc.expectedLocation, location)
// 			}
// 			if tc.expectedLocationHost != "" && locationURL.Hostname() != tc.expectedLocationHost {
// 				t.Errorf("expected location host = %q, got %q", tc.expectedLocationHost, locationURL.Hostname())
// 			}

// 			stsKey := http.CanonicalHeaderKey("Strict-Transport-Security")
// 			if tc.expectSTS {
// 				val := rw.Header().Get(stsKey)
// 				expectedVal := "max-age=31536000"
// 				if val != expectedVal {
// 					t.Errorf("expected %s=%q, got %q", stsKey, expectedVal, val)
// 				}
// 			} else {
// 				_, found := rw.HeaderMap[stsKey]
// 				if found {
// 					t.Errorf("%s header should not be present, got %q", stsKey, rw.Header().Get(stsKey))
// 				}
// 			}
// 		})
// 	}
// }

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
`, fromRegex, toTemplate)), "DevProxy", "http", templateVars)
	if err != nil {
		panic(err)
	}
	return upstreamConfigs
}

func TestRewriteRoutingHandling(t *testing.T) {
	type response struct {
		Host                  string `json:"host"`
		XForwardedHost        string `json:"x-forwarded-host"`
		XForwardedEmail       string `json:"x-forwarded-email"`
		XForwardedUser        string `json:"x-forwarded-user"`
		XForwardedGroups      string `json:"x-forwarded-groups"`
		XForwardedAccessToken string `json:"x-forwarded-access-token"`
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(
			&response{
				Host:                  r.Host,
				XForwardedHost:        r.Header.Get("X-Forwarded-Host"),
				XForwardedEmail:       r.Header.Get(`json:"x-forwarded-email"`),
				XForwardedUser:        r.Header.Get(`json:"x-forwarded-user"`),
				XForwardedGroups:      r.Header.Get(`json:"x-forwarded-groups"`),
				XForwardedAccessToken: r.Header.Get(`json:"x-forwarded-access-token"`),
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
		TestUser         string
		TestEmail        string
		TestGroups       string
		TestAccessToken  string
		FromRegex        string
		ToTemplate       string
		ExpectedCode     int
		ExpectedResponse *response
	}{
		{
			Name:         "everything should work in the normal case",
			TestHost:     "foo.sso.dev",
			FromRegex:    "(.*)",
			ToTemplate:   parsedUpstreamURL.Host,
			ExpectedCode: http.StatusOK,
			ExpectedResponse: &response{
				Host:           parsedUpstreamURL.Host,
				XForwardedHost: "foo.sso.dev",
			},
		},
		{
			Name:         "it should not match a non-matching regex",
			TestHost:     "foo.sso.dev",
			FromRegex:    "bar",
			ToTemplate:   parsedUpstreamURL.Host,
			ExpectedCode: statusInvalidHost,
		},
		{
			Name:         "it should match and replace using regex/template to find port in embeded domain",
			TestHost:     fmt.Sprintf("somedomain--%s", upstreamPort),
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
			opts.upstreamConfigs = generateTestRewriteUpstreamConfigs(tc.FromRegex, tc.ToTemplate)
			opts.Validate()
			proxy, err := NewDevProxy(opts, testValidatorFunc(true))
			if err != nil {
				t.Fatalf("unexpected err provisioning dev proxy err:%q", err)
			}

			req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", tc.TestHost), strings.NewReader(""))
			if err != nil {
				t.Fatalf("unexpected err creating request err:%s", err)
			}

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
