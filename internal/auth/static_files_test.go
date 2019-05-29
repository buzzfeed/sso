package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticFiles(t *testing.T) {
	opts := testOpts(t, "abced", "testtest")
	opts.Validate()
	authMux, err := NewAuthenticatorMux(opts, nil)
	if err != nil {
		t.Fatalf("unexpected error creating auth mux: %v", err)
	}

	testCases := []struct {
		name            string
		path            string
		expectedStatus  int
		expectedContent string
	}{
		{
			name:            "static css ok",
			path:            "/static/sso.css",
			expectedStatus:  http.StatusOK,
			expectedContent: "body {",
		},
		{
			name:           "nonexistent file not found",
			path:           "/static/missing.css",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "no directory listing",
			path:           "/static/",
			expectedStatus: http.StatusNotFound,
		},
		{
			// this will result in a 301 -> /config.yml
			name:           "no directory escape",
			path:           "/static/../config.yml",
			expectedStatus: http.StatusMovedPermanently,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tc.path, nil)

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
