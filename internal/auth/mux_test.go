package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHostHeader(t *testing.T) {
	testCases := []struct {
		Name               string
		Host               string
		RequestHost        string
		Path               string
		ExpectedStatusCode int
	}{
		{
			Name:               "reject requests with an invalid hostname",
			Host:               "example.com",
			RequestHost:        "unknown.com",
			Path:               "/static/sso.css",
			ExpectedStatusCode: http.StatusNotFound,
		},
		{
			Name:               "allow requests to any hostname to /ping",
			Host:               "example.com",
			RequestHost:        "unknown.com",
			Path:               "/ping",
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:               "allow requests with a valid hostname",
			Host:               "example.com",
			RequestHost:        "example.com",
			Path:               "/static/sso.css",
			ExpectedStatusCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			opts := testOpts(t, "abced", "testtest")
			opts.Host = tc.Host
			err := opts.Validate()
			if err != nil {
				t.Fatalf("unexpected opts error: %v", err)
			}

			opts.redirectURL = &url.URL{
				Host:   tc.Host,
				Path:   "/callback",
				Scheme: "https",
			}

			authMux, err := NewAuthenticatorMux(opts, nil)
			if err != nil {
				t.Fatalf("unexpected err creating auth mux: %v", err)
			}

			uri := fmt.Sprintf("http://%s%s", tc.RequestHost, tc.Path)

			rw := httptest.NewRecorder()
			req := httptest.NewRequest("GET", uri, nil)

			authMux.ServeHTTP(rw, req)
			if rw.Code != tc.ExpectedStatusCode {
				t.Errorf("got unexpected status code")
				t.Errorf("want %v", tc.ExpectedStatusCode)
				t.Errorf(" got %v", rw.Code)
				t.Errorf(" headers %v", rw)
				t.Errorf(" body: %q", rw.Body)
			}
		})
	}
}
