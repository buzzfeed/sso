package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
	"github.com/buzzfeed/sso/internal/proxy/providers"
)

func TestStaticFiles(t *testing.T) {
	testCases := []struct {
		name            string
		uri             string
		expectedStatus  int
		expectedContent string
	}{
		{
			name:            "static css ok",
			uri:             "https://localhost/static/sso.css",
			expectedStatus:  http.StatusOK,
			expectedContent: "body {",
		},
		{
			name:           "nonexistent file not found",
			uri:            "https://localhost/static/missing.css",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "no directory listing",
			uri:            "https://localhost/static/",
			expectedStatus: http.StatusNotFound,
		},
		{
			// this will result in a 301 -> /config.yml
			name:           "no directory escape",
			uri:            "https://localhost/static/../config.yml",
			expectedStatus: http.StatusMovedPermanently,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// create backend server
			backend := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				},
			))
			defer backend.Close()

			backendURL, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatalf("unexpected err parsing backend url: %v", err)
			}

			// create base opts, provider, upstream config and other
			// components required to create an OAuthProxy
			opts := NewOptions()
			providerURL, _ := url.Parse("http://localhost/")
			provider := providers.NewTestProvider(providerURL, "")

			upstreamConfig := &UpstreamConfig{
				Route: &SimpleRoute{
					ToURL: backendURL,
				},
			}

			reverseProxy, err := NewUpstreamReverseProxy(upstreamConfig, nil)
			if err != nil {
				t.Fatalf("unexpected error creating upstream reverse proxy: %v", err)
			}

			optFuncs := []func(*OAuthProxy) error{
				SetProvider(provider),
				setSessionStore(&sessions.MockSessionStore{}),
				SetUpstreamConfig(upstreamConfig),
				SetProxyHandler(reverseProxy),
				setCSRFStore(&sessions.MockCSRFStore{}),
				setCookieCipher(&aead.MockCipher{}),
			}

			proxy, err := NewOAuthProxy(opts, optFuncs...)
			testutil.Assert(t, err == nil, "could not create upstream reverse proxy: %v", err)

			// make requests and check responses
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.uri, nil)

			proxy.Handler().ServeHTTP(rw, req)
			if rw.Code != tc.expectedStatus {
				t.Logf("expected response: %v", tc.expectedStatus)
				t.Logf("         got code: %v", rw.Code)
				t.Logf("          headers: %v", rw.HeaderMap)
				t.Errorf("unexpected response returned")
			}

			if tc.expectedContent != "" && !strings.Contains(rw.Body.String(), tc.expectedContent) {
				t.Logf("expected body to contain: %v", tc.expectedContent)
				t.Logf("                     got: %v", rw.Body.String())
				t.Errorf("unexpected body returned")
			}
		})
	}
}
