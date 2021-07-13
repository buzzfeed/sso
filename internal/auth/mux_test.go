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
			config := testConfiguration(t)
			config.ServerConfig.Host = tc.Host
			authMux, err := NewAuthenticatorMux(config, nil)
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

func TestSetCookieSameSite(t *testing.T) {
	testCases := []struct {
		Name             string
		SameSite         string
		Secure           bool
		ExpectedSameSite http.SameSite
		ExpectedErr      string
	}{
		{
			Name:        "(invalid) samesite: none, secure: false",
			SameSite:    "none",
			Secure:      false,
			ExpectedErr: "if sameSite is none, cookie must be Secure",
		},
		{
			Name:             "(valid) samesite: none, secure: true",
			SameSite:         "none",
			Secure:           true,
			ExpectedSameSite: http.SameSiteNoneMode,
		},
		{
			Name:             "(valid) samesite: lax",
			SameSite:         "lax",
			ExpectedSameSite: http.SameSiteLaxMode,
		},
		{
			Name:             "(valid) samesite: strict",
			SameSite:         "strict",
			ExpectedSameSite: http.SameSiteStrictMode,
		},
		{
			Name:             "(valid) samesite: nil",
			ExpectedSameSite: http.SameSiteDefaultMode,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			config := testConfiguration(t)
			config.SessionConfig.CookieConfig.SameSite = tc.SameSite
			config.SessionConfig.CookieConfig.Secure = tc.Secure

			authMux, err := NewAuthenticatorMux(config, nil)
			if err == nil && tc.ExpectedErr != "" {
				t.Logf(" got error: %#v", err)
				t.Logf("want error: %#v", tc.ExpectedErr)
				t.Error("unexpected error value")
			}
			if err != nil {
				if err.Error() != tc.ExpectedErr {
					t.Logf(" got error: %#v", err.Error())
					t.Logf("want error: %#v", tc.ExpectedErr)
					t.Error("unexpected error value")
				}
			}
			if err == nil {
				for _, authenticator := range authMux.authenticators {
					if authenticator.cookieSameSite != tc.ExpectedSameSite {
						// https://golang.org/src/net/http/cookie.go
						t.Logf(" got authenticator.CookieSameSite=%v", authenticator.cookieSameSite)
						t.Logf("want authenticator.CookieSameSite=%v", tc.ExpectedSameSite)
						t.Error("unexpected authenticator.CookieSameSite value")
					}
				}
			}
		})
	}
}

func TestRobotsTxt(t *testing.T) {
	config := testConfiguration(t)
	authMux, err := NewAuthenticatorMux(config, nil)
	if err != nil {
		t.Fatalf("unexpected err creating auth mux: %v", err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", fmt.Sprintf("https://%s/robots.txt", config.ServerConfig.Host), nil)
	authMux.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("expected status code %d, but got %d", http.StatusOK, rw.Code)
	}
	if rw.Body.String() != "User-agent: *\nDisallow: /" {
		t.Errorf("expected response body to be %s but was %s", "User-agent: *\nDisallow: /", rw.Body.String())
	}
}
