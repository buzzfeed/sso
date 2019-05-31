package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
			ExpectedStatusCode: http.StatusMisdirectedRequest,
		},
		{
			Name:               "allow requests to any hostname to /ping",
			Host:               "example.com",
			RequestHost:        "unknown.com",
			Path:               "/ping",
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:               "allow requests to specified hostname to /ping",
			Host:               "example.com",
			RequestHost:        "example.com",
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

func TestDefaultProvider(t *testing.T) {
	testCases := []struct {
		Name               string
		Host               string
		ExpectedStatusCode int
	}{
		{
			Name:               "similar requests to default path should get same results as slug path",
			Host:               "example.com",
			ExpectedStatusCode: http.StatusBadRequest,
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

			authMux, err := NewAuthenticatorMux(opts, nil)
			if err != nil {
				t.Fatalf("unexpected err creating auth mux: %v", err)
			}

			for _, path := range []string{"/callback", "/google/callback"} {
				uri := fmt.Sprintf("http://%s%s", tc.Host, path)

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
			}
		})
	}
}

func TestRobotsTxt(t *testing.T) {
	opts := testOpts(t, "abced", "testtest")
	opts.Host = "example.com"
	opts.Validate()
	authMux, err := NewAuthenticatorMux(opts, nil)
	if err != nil {
		t.Fatalf("unexpected err creating auth mux: %v", err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://example.com/robots.txt", nil)
	authMux.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("expected status code %d, but got %d", http.StatusOK, rw.Code)
	}
	if rw.Body.String() != "User-agent: *\nDisallow: /" {
		t.Errorf("expected response body to be %s but was %s", "User-agent: *\nDisallow: /", rw.Body.String())
	}
}
