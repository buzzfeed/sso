package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticFiles(t *testing.T) {
	config := testConfiguration(t)
	authMux, err := NewAuthenticatorMux(config, nil)
	if err != nil {
		t.Fatalf("unexpected error creating auth mux: %v", err)
	}

	testCases := []struct {
		name            string
		uri             string
		expectedStatus  int
		expectedContent string
	}{
		{
			name:            "static css ok",
			uri:             "http://localhost/static/sso.css",
			expectedStatus:  http.StatusOK,
			expectedContent: "body {",
		},
		{
			name:           "nonexistent file not found",
			uri:            "http://localhost/static/missing.css",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "no directory listing",
			uri:            "http://localhost/static/",
			expectedStatus: http.StatusNotFound,
		},
		{
			// this will result in a 301 -> /config.yml
			name:           "no directory escape",
			uri:            "http://localhost/static/../config.yml",
			expectedStatus: http.StatusMovedPermanently,
		},
		{
			// this should NOT result in a 301, since escaped-paths are propagated as-is.
			name:           "no directory escape",
			uri:            "http://localhost/static/https:%2F%2Fexample.com",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.uri, nil)

			authMux.ServeHTTP(rw, req)
			if rw.Code != tc.expectedStatus {
				t.Errorf("expected response %v, got %v\n%v", tc.expectedStatus, rw.Code, rw.HeaderMap)
			}

			if tc.expectedContent != "" && !strings.Contains(rw.Body.String(), tc.expectedContent) {
				t.Errorf("substring %q not found in response body:\n%s", tc.expectedContent, rw.Body.String())
			}
		})
	}
}
