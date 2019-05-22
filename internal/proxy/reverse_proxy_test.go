package proxy

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
)

func TestDeleteCookie(t *testing.T) {
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
			deleteCookie(req, "_sso_proxy")
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
	b, _ := url.Parse(backend.URL)

	config := &UpstreamConfig{
		Route: &SimpleRoute{
			ToURL: b,
		},
		TLSSkipVerify: false,
		PreserveHost:  false,
	}

	reverseProxy, err := NewUpstreamReverseProxy(config, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	frontend := httptest.NewServer(reverseProxy)
	defer frontend.Close()

	f, _ := url.Parse(frontend.URL)
	encodedPath := "/a%2Fb/?c=1"
	getReq := &http.Request{URL: &url.URL{Scheme: "http", Host: f.Host, Opaque: encodedPath}}
	_, err = http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	if seen != encodedPath {
		t.Errorf("got bad request %q expected %q", seen, encodedPath)
	}
}

func TestNewRewriteReverseProxy(t *testing.T) {
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

			config := &UpstreamConfig{
				Route: &RewriteRoute{
					FromRegex: regexp.MustCompile("(.*)"),
					ToTemplate: &url.URL{
						Scheme: parsedUpstreamURL.Scheme,
						Opaque: parsedUpstreamURL.Host,
					},
				},
				TLSSkipVerify: tc.skipVerify,
				PreserveHost:  tc.preserveHost,
			}

			rewriteProxy, err := NewUpstreamReverseProxy(config, nil)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

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

			config := &UpstreamConfig{
				Route: &SimpleRoute{
					ToURL: toURL,
				},
				TLSSkipVerify: tc.skipVerify,
				PreserveHost:  tc.preserveHost,
			}
			reverseProxy, err := NewUpstreamReverseProxy(config, nil)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
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
			timeoutHandler := newTimeoutHandler(baseHandler, tc.config)

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
	upstreamURL, close := testHTTPBin(t)
	defer close()

	upstreamHost, upstreamPort, err := net.SplitHostPort(upstreamURL.Host)
	if err != nil {
		t.Fatalf("expected to split host/hort err:%q", err)
	}

	testCases := []struct {
		Name             string
		TestHost         string
		FromRegex        string
		ToTemplate       string
		ExpectedCode     int
		ExpectedResponse map[string][]string
	}{
		{
			Name:         "everything should work in the normal case",
			TestHost:     "localhost",
			FromRegex:    "(.*)",
			ToTemplate:   upstreamURL.Host,
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string][]string{
				"Host":             []string{upstreamURL.Host},
				"X-Forwarded-Host": []string{"localhost"},
			},
		},
		{
			Name:         "it should match and replace using regex/template to find port in embedded domain",
			TestHost:     fmt.Sprintf("somedomain--%s", upstreamPort),
			FromRegex:    "somedomain--(.*)",                 // capture port
			ToTemplate:   fmt.Sprintf("%s:$1", upstreamHost), // add port to dest
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string][]string{
				"Host":             []string{upstreamURL.Host},
				"X-Forwarded-Host": []string{fmt.Sprintf("somedomain--%s", upstreamPort)},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			config := &UpstreamConfig{
				Route: &RewriteRoute{
					FromRegex: regexp.MustCompile(tc.FromRegex),
					ToTemplate: &url.URL{
						Scheme: "http",
						Opaque: tc.ToTemplate,
					},
				},
			}

			reverseProxy, err := NewUpstreamReverseProxy(config, nil)
			if err != nil {
				t.Fatalf("could not construct reverse proxy: %v", err)
			}

			req := httptest.NewRequest("GET", fmt.Sprintf("https://%s/headers", tc.TestHost), strings.NewReader(""))
			rw := httptest.NewRecorder()

			reverseProxy.ServeHTTP(rw, req)

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

			type response struct {
				Headers http.Header `json:"headers"`
			}

			got := &response{}
			err = json.Unmarshal(body, got)
			if err != nil {
				t.Fatalf("expected to decode json: %s", err)
			}

			if !reflect.DeepEqual(tc.ExpectedResponse["Host"], got.Headers["Host"]) {
				t.Logf(" got host: %v", got.Headers["Host"])
				t.Logf("want host: %v", tc.ExpectedResponse["Host"])
				t.Errorf("got unexpected response for Hostheader")
			}

			if !reflect.DeepEqual(tc.ExpectedResponse["X-Forwarded-Host"], got.Headers["X-Forwarded-Host"]) {
				t.Logf(" got X-Forwarded-Host: %v", got.Headers["X-Forwarded-Host"])
				t.Logf("want X-Forwarded-Host: %v", tc.ExpectedResponse["X-Forwarded-Host"])
				t.Errorf("got unexpected response for X-Forwarded-Host")
			}
		})
	}
}

func TestSkipSigningRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := []string{"Sso-Signature", "kid"}

		for _, header := range headers {
			val, ok := r.Header[header]
			if ok {
				t.Errorf("found unexpected header in request %s:%s", header, val)
			}
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	b, _ := url.Parse(backend.URL)

	config := &UpstreamConfig{
		Route: &SimpleRoute{
			ToURL: b,
		},
		SkipRequestSigning: true,
	}

	signingKey, err := ioutil.ReadFile("testdata/private_key.pem")
	if err != nil {
		t.Fatalf("could not read private key from testdata: %v", err)
	}

	signer, err := NewRequestSigner(string(signingKey))
	if err != nil {
		t.Fatalf("unexpected err creating request signer: %v", err)
	}

	reverseProxy, err := NewUpstreamReverseProxy(config, signer)
	if err != nil {
		t.Fatalf("unexpected err creating upstream reverse proxy: %v", err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://localhost/endpoint", nil)

	reverseProxy.ServeHTTP(rw, req)

	if http.StatusOK != rw.Code {
		t.Errorf("want: %v", http.StatusOK)
		t.Errorf("have: %v", rw.Code)
		t.Errorf("expected status codes to be equal")
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
				Route: &SimpleRoute{
					ToURL: upstreamURL,
				},
			}

			reverseProxy, err := NewUpstreamReverseProxy(upstreamConfig, nil)
			if err != nil {
				t.Fatalf("unexpected error creating upstream reverse proxy: %v", err)
			}

			proxyServer := httptest.NewServer(reverseProxy)
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
