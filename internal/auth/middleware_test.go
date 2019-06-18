package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// createTestHandler returns a http.HandlerFunc for testing http middleware
func createTestHandler() http.HandlerFunc {
	fn := func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}
	return http.HandlerFunc(fn)
}

func TestWithMethods(t *testing.T) {
	testCases := []struct {
		name            string
		acceptedMethods []string
		requestMethod   string
		expectedCode    int
	}{
		{
			name:            "no methods should always fail",
			acceptedMethods: []string{},
			requestMethod:   "GET",
			expectedCode:    http.StatusMethodNotAllowed,
		},
		{
			name:            "request with method in accepted methods should continue",
			acceptedMethods: []string{"GET"},
			requestMethod:   "GET",
			expectedCode:    http.StatusOK,
		},
		{
			name:            "request with method not in methods should fail",
			acceptedMethods: []string{"GET"},
			requestMethod:   "POST",
			expectedCode:    http.StatusMethodNotAllowed,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.requestMethod, "/test", nil)
			rw := httptest.NewRecorder()

			config := testConfiguration(t)
			p, err := NewAuthenticator(config)
			if err != nil {
				t.Fatalf("unexpected err creating authenticator: %v", err)
			}

			p.withMethods(createTestHandler(), tc.acceptedMethods...)(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedCode {
				t.Errorf("expected response status code to be %v but was %v", tc.expectedCode, resp.StatusCode)
			}
		})
	}
}

func TestValidateClientID(t *testing.T) {
	testCases := []struct {
		name                string
		requestURL          string
		requestBodyClientID string
		method              string
		expectedClientID    string
		displayPage         bool
		expectedStatusCode  int
	}{
		{
			name:               "valid client id",
			requestURL:         "/test?client_id=test",
			expectedClientID:   "test",
			method:             "GET",
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "invalid client id",
			requestURL:         "/test",
			expectedClientID:   "test",
			method:             "GET",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "not matching client ids",
			requestURL:         "/test?client_id=client",
			expectedClientID:   "test",
			method:             "GET",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:                "client id in request body works",
			requestURL:          "/test",
			requestBodyClientID: "test",
			expectedClientID:    "test",
			method:              "POST",
			expectedStatusCode:  http.StatusOK,
		},
		{
			name:                "when request body client id is wrong, fails",
			requestURL:          "/test?client_id=test",
			requestBodyClientID: "wrong",
			expectedClientID:    "test",
			method:              "POST",
			expectedStatusCode:  http.StatusUnauthorized,
		},
		{
			name:                "when query parameters of client id are wrong, passes",
			requestURL:          "/test?client_id=blah",
			requestBodyClientID: "test",
			expectedClientID:    "test",
			method:              "POST",
			expectedStatusCode:  http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			config.ClientConfigs["proxy"] = ClientConfig{
				ID:     tc.expectedClientID,
				Secret: config.ClientConfigs["proxy"].Secret,
			}

			p, err := NewAuthenticator(config)
			if err != nil {
				t.Fatalf("unexpected err creating authenticator: %v", err)
			}

			params := url.Values{}
			if tc.requestBodyClientID != "" {
				params.Add("client_id", tc.requestBodyClientID)
			}
			req := httptest.NewRequest(tc.method, tc.requestURL, bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			p.validateClientID(createTestHandler())(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected response status code to be %v but was %v", tc.expectedStatusCode, resp.StatusCode)
			}

		})
	}
}

func TestValidateClientSecret(t *testing.T) {
	testCases := []struct {
		name                 string
		requestURL           string
		requestHeader        string
		expectedClientSecret string
		clientSecretBody     string
		method               string
		expectedStatusCode   int
	}{
		{
			name:                 "successful auth",
			requestURL:           "/test",
			requestHeader:        "clientsecret",
			expectedClientSecret: "clientsecret",
			method:               "GET",
			expectedStatusCode:   http.StatusOK,
		},
		{
			name:                 "no secret in header",
			requestURL:           "/test",
			expectedClientSecret: "clientsecret",
			method:               "GET",
			expectedStatusCode:   http.StatusUnauthorized,
		},
		{
			name:                 "wrong secret in header",
			requestURL:           "/test",
			requestHeader:        "nope",
			expectedClientSecret: "clientSecret",
			method:               "GET",
			expectedStatusCode:   http.StatusUnauthorized,
		},
		{
			name:                 "secret in request body works as well",
			requestURL:           "/test",
			requestHeader:        "nope",
			clientSecretBody:     "clientSecret",
			expectedClientSecret: "clientSecret",
			method:               "POST",
			expectedStatusCode:   http.StatusOK,
		},
		{
			name:                 "secret is first checked in request body then header",
			requestURL:           "/test",
			requestHeader:        "clientSecret",
			clientSecretBody:     "nope",
			expectedClientSecret: "clientSecret",
			method:               "POST",
			expectedStatusCode:   http.StatusUnauthorized,
		},
		{
			name:                 "secret is first checked in request body then header",
			requestURL:           "/test",
			requestHeader:        "nope",
			expectedClientSecret: "clientSecret",
			method:               "POST",
			clientSecretBody:     "clientSecret",
			expectedStatusCode:   http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			config.ClientConfigs["proxy"] = ClientConfig{
				ID:     config.ClientConfigs["proxy"].ID,
				Secret: tc.expectedClientSecret,
			}

			p, err := NewAuthenticator(config)
			if err != nil {
				t.Fatalf("unexpected err creating authenticator: %v", err)
			}

			params := url.Values{}
			if tc.clientSecretBody != "" {
				params.Add("client_secret", tc.clientSecretBody)
			}
			req := httptest.NewRequest(tc.method, tc.requestURL, bytes.NewBufferString(params.Encode()))
			if tc.requestHeader != "" {
				req.Header.Add("X-Client-Secret", tc.requestHeader)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			p.validateClientSecret(createTestHandler())(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected response status code to be %v but was %v", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}

func TestValidateRedirectURI(t *testing.T) {
	testCases := []struct {
		name               string
		redirectURI        string
		expectedStatusCode int
		signatureSecret    string
	}{
		{
			name:               "empty redirect uri",
			redirectURI:        "",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "only a relative path",
			redirectURI:        "/path/to/endpoint",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "no hostname",
			redirectURI:        "http://:8888",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "malicious hostname",
			redirectURI:        "http://evil.badexample.com/path/to/badness",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "malicious hostname that looks like our hostname",
			redirectURI:        "http://very.badexample.com/ultimate/badness",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "malicious hostname that contains our hostname",
			redirectURI:        "http://example.com.evil.com",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "benign hostname",
			redirectURI:        "http://foo.example.com",
			expectedStatusCode: http.StatusOK,
			signatureSecret:    "clientSecret",
		},
		{
			name:               "benign hostname with path",
			redirectURI:        "http://foo.example.io/path/to/redirect",
			expectedStatusCode: http.StatusOK,
			signatureSecret:    "clientSecret",
		},
		{
			name:               "benign root hostname",
			redirectURI:        "http://example.com",
			expectedStatusCode: http.StatusOK,
			signatureSecret:    "clientSecret",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			config.AuthorizeConfig.ProxyConfig.Domains = []string{"example.com", "example.io"}
			p, err := NewAuthenticator(config)
			if err != nil {
				t.Fatalf("unexpected err creating authenticator: %v", err)
			}

			params := url.Values{}
			if tc.redirectURI != "" {
				params.Add("redirect_uri", tc.redirectURI)
			}
			req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()

			p.validateRedirectURI(createTestHandler())(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected response status code to be %v but was %v", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}

func TestValidateSignature(t *testing.T) {
	type sigComponents struct {
		redirectURI string
		timestamp   time.Time
		secret      string
	}

	now := time.Now()
	testCases := []struct {
		name               string
		request            *sigComponents
		querySig           *sigComponents
		expectedStatusCode int
	}{
		{
			name: "bad path",
			request: &sigComponents{
				redirectURI: "http://foo.example.com?foo=bar",
				timestamp:   now,
				secret:      "clientSecret",
			},
			querySig: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now,
				secret:      "clientSecret",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "bad query",
			request: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing",
				timestamp:   now,
				secret:      "clientSecret",
			},
			querySig: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now,
				secret:      "clientSecret",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "no signature",
			request: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing",
				timestamp:   now,
				secret:      "clientSecret",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "bad signature",
			request: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now,
				secret:      "clientSecret",
			},
			querySig: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now,
				secret:      "badSecret",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "signature expired",
			request: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now.Add(-time.Hour),
				secret:      "clientSecret",
			},
			querySig: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now.Add(-time.Hour),
				secret:      "clientSecret",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "all is well",
			request: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now,
				secret:      "clientSecret",
			},
			querySig: &sigComponents{
				redirectURI: "http://foo.example.com/path/to/thing?foo=bar",
				timestamp:   now,
				secret:      "clientSecret",
			},
			expectedStatusCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			config.ClientConfigs["proxy"] = ClientConfig{
				ID:     config.ClientConfigs["proxy"].ID,
				Secret: tc.request.secret,
			}

			p, err := NewAuthenticator(config)
			if err != nil {
				t.Fatalf("unexpected err creating authenticator: %v", err)
			}
			params := url.Values{}
			params.Add("redirect_uri", tc.request.redirectURI)
			params.Add("ts", fmt.Sprint(tc.request.timestamp.Unix()))
			if tc.querySig != nil {
				querySig := redirectURLSignature(tc.querySig.redirectURI, tc.querySig.timestamp, tc.querySig.secret)
				b64sig := base64.URLEncoding.EncodeToString(querySig)
				params.Add("sig", b64sig)
			}
			req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			p.validateSignature(createTestHandler())(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected response status code to be %v but was %v", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}
