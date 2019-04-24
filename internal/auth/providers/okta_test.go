package providers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func newOktaProviderServer(body []byte, code int) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(code)
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}
func newOktaProvider(providerData *ProviderData, t *testing.T) *OktaProvider {
	if providerData == nil {
		providerData = &ProviderData{
			ProviderName: "",
			ClientID:     "",
			ClientSecret: "",
			SignInURL:    &url.URL{},
			RedeemURL:    &url.URL{},
			RevokeURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""}
	}
	provider, err := NewOktaProvider(providerData, "test.okta.com", "default")
	if err != nil {
		t.Fatalf("new okta provider returns unexpected error: %q", err)
	}
	return provider
}

func TestOktaProviderDefaults(t *testing.T) {
	expectedResults := []struct {
		name         string
		providerData *ProviderData
		signInURL    string
		redeemURL    string
		revokeURL    string
		profileURL   string
		userInfoURL  string
		validateURL  string
		scope        string
	}{
		{
			name:        "defaults",
			signInURL:   "https://test.okta.com/oauth2/default/v1/authorize",
			redeemURL:   "https://test.okta.com/oauth2/default/v1/token",
			revokeURL:   "https://test.okta.com/oauth2/default/v1/revoke",
			profileURL:  "https://test.okta.com/oauth2/default/v1/userinfo",
			validateURL: "https://test.okta.com/oauth2/default/v1/introspect",
			scope:       "openid profile email groups offline_access",
		},
		{
			name: "with provider overrides",
			providerData: &ProviderData{
				SignInURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/auth"},
				RedeemURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/token"},
				RevokeURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/deauth"},
				ProfileURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/profile"},
				ValidateURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/tokeninfo"},
				Scope: "profile"},
			signInURL:   "https://example.com/oauth/auth",
			redeemURL:   "https://example.com/oauth/token",
			revokeURL:   "https://example.com/oauth/deauth",
			profileURL:  "https://example.com/oauth/profile",
			userInfoURL: "https://example.com/oauth/userinfo",
			validateURL: "https://example.com/oauth/tokeninfo",
			scope:       "profile",
		},
	}
	for _, expected := range expectedResults {
		t.Run(expected.name, func(t *testing.T) {
			p := newOktaProvider(expected.providerData, t)
			if p == nil {
				t.Errorf("Okta provider was nil")
			}
			if p.Data().ProviderName != "Okta" {
				t.Errorf("expected provider name Okta, got %q", p.Data().ProviderName)
			}
			if p.Data().SignInURL.String() != expected.signInURL {
				t.Logf("expected %q", expected.signInURL)
				t.Logf("     got %q", p.Data().SignInURL.String())
				t.Errorf("unexpected signin url")
			}
			if p.Data().RedeemURL.String() != expected.redeemURL {
				t.Logf("expected %q", expected.redeemURL)
				t.Logf("     got %q", p.Data().RedeemURL.String())
				t.Errorf("unexpected redeem url")
			}

			if p.Data().RevokeURL.String() != expected.revokeURL {
				t.Logf("expected %q", expected.revokeURL)
				t.Logf("     got %q", p.Data().RevokeURL.String())
				t.Errorf("unexpected revoke url")
			}

			if p.Data().ValidateURL.String() != expected.validateURL {
				t.Logf("expected %q", expected.validateURL)
				t.Logf("     got %q", p.Data().ValidateURL.String())
				t.Errorf("unexpected validate url")
			}

			if p.Data().ProfileURL.String() != expected.profileURL {
				t.Logf("expected %q", expected.profileURL)
				t.Logf("     got %q", p.Data().ProfileURL.String())
				t.Errorf("unexpected profile url")
			}

			if p.Data().Scope != expected.scope {
				t.Logf("expected %q", expected.scope)
				t.Logf("     got %q", p.Data().Scope)
				t.Errorf("unexpected scope")
			}
		})

	}
}

type oktaProviderRedeemResponse struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	EmailAddress  string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	ExpiresIn     int64  `json:"expires_in"`
}

func TestOktaProviderRedeem(t *testing.T) {
	testCases := []struct {
		name            string
		resp            oktaProviderRedeemResponse
		expectedError   bool
		expectedSession *sessions.SessionState
	}{
		{
			name: "redeem",
			resp: oktaProviderRedeemResponse{
				AccessToken:   "a1234",
				EmailAddress:  "michael.bland@gsa.gov",
				EmailVerified: true,
				ExpiresIn:     10,
				RefreshToken:  "refresh12345",
			},
			expectedSession: &sessions.SessionState{
				Email:        "michael.bland@gsa.gov",
				AccessToken:  "a1234",
				RefreshToken: "refresh12345",
			},
		},
		{
			name: "missing email",
			resp: oktaProviderRedeemResponse{
				AccessToken: "a1234",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOktaProvider(nil, t)
			body, err := json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)
			var server *httptest.Server
			p.RedeemURL, server = newOktaProviderServer(body, http.StatusOK)
			p.ProfileURL, server = newOktaProviderServer(body, http.StatusOK)
			defer server.Close()

			session, err := p.Redeem("http://redirect/", "code1234")
			if tc.expectedError && err == nil {
				t.Errorf("expected redeem error but was nil")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("unexpected error %q", err)
			}
			if tc.expectedSession == nil && session != nil {
				t.Errorf("expected session to be nil but it was %q", session)
			}
			if session != nil && tc.expectedSession != nil {
				if session.Email != tc.expectedSession.Email {
					t.Logf("expected email %q", tc.expectedSession.Email)
					t.Logf("           got %q", session.Email)
					t.Errorf("unexpected session email")
				}

				if session.AccessToken != tc.expectedSession.AccessToken {
					t.Logf("expected access token %q", tc.expectedSession.AccessToken)
					t.Logf("                  got %q", session.AccessToken)
					t.Errorf("unexpected access token")
				}

				if session.RefreshToken != tc.expectedSession.RefreshToken {
					t.Logf("expected refresh token %q", tc.expectedSession.RefreshToken)
					t.Logf("                   got %q", session.RefreshToken)
					t.Errorf("unexpected session refresh token")
				}
			}
		})
	}
}

type oktaProviderRevokeErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func TestOktaProviderRevoke(t *testing.T) {
	testCases := []struct {
		name                string
		resp                oktaProviderRevokeErrorResponse
		httpStatus          int
		sessionState        *sessions.SessionState
		expectedError       bool
		expectedErrorString string
	}{
		{
			name: "idempotent revoke",
			resp: oktaProviderRevokeErrorResponse{
				Error:            "invalid_token",
				ErrorDescription: "Token expired or revoked",
			},
			sessionState: &sessions.SessionState{
				AccessToken:     "access1234",
				RefreshDeadline: time.Now(),
				RefreshToken:    "refresh1234",
				Email:           "logged.out@example.com",
			},
			httpStatus: http.StatusBadRequest,
		},
		{
			name: "can still fail",
			resp: oktaProviderRevokeErrorResponse{
				Error:            "not_invalid_token",
				ErrorDescription: "Something else happened internally",
			},
			sessionState: &sessions.SessionState{
				AccessToken:     "access1234",
				RefreshDeadline: time.Now(),
				RefreshToken:    "refresh1234",
				Email:           "logged.out@example.com",
			},
			httpStatus:          http.StatusForbidden,
			expectedErrorString: "SERVICE_UNAVAILABLE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOktaProvider(nil, t)
			body, err := json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)
			var server *httptest.Server
			p.RevokeURL, server = newOktaProviderServer(body, tc.httpStatus)
			defer server.Close()

			err = p.Revoke(tc.sessionState)
			if tc.expectedError && err != nil {
				t.Errorf("unexpected error %q", err)
			}
			if tc.expectedError {
				if err == nil {
					t.Errorf("expected error but err was nil")
				}
				if !strings.Contains(err.Error(), tc.expectedErrorString) {
					t.Logf("expected error string to contain %q", tc.expectedErrorString)
					t.Logf("                             got %q", err)
					t.Errorf("unexpected error string")
				}
			}
		})

	}
}

type oktaProviderValidateGroupMembershipResponse struct {
	Groups []string `json:"groups"`
}

func TestOktaProviderValidateGroupMembership(t *testing.T) {
	testCases := []struct {
		name                string
		inputAllowedGroups  []string
		expectedGroups      []string
		expectedErrorString string
		resp                oktaProviderValidateGroupMembershipResponse
	}{
		{
			name:               "empty input groups should return an empty string",
			inputAllowedGroups: []string{},
			expectedGroups:     []string{},
		},
		{
			name:               "matching groups should be returned",
			inputAllowedGroups: []string{"group1", "group3", "group5", "group7"},
			expectedGroups:     []string{"group1", "group3", "group5"},
			resp: oktaProviderValidateGroupMembershipResponse{
				Groups: []string{"group1", "group3", "group5", "group6"},
			},
		},
		{
			name:                "should error with no group membership found",
			inputAllowedGroups:  []string{"group1", "group3", "group5"},
			expectedErrorString: "no group membership found",
			resp:                oktaProviderValidateGroupMembershipResponse{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			p := newOktaProvider(nil, t)
			body, err := json.Marshal(tc.resp)
			var server *httptest.Server
			p.ProfileURL, server = newOktaProviderServer(body, http.StatusOK)
			defer server.Close()

			groups, err := p.ValidateGroupMembership("email", tc.inputAllowedGroups, "accessToken")
			if err != nil {
				if tc.expectedErrorString != err.Error() {
					t.Errorf("expected error %q but err was %q", tc.expectedErrorString, err)
				}
			}
			if !reflect.DeepEqual(tc.expectedGroups, groups) {
				t.Logf("expected groups %q", tc.expectedGroups)
				t.Logf("     got groups %q", groups)
				t.Errorf("unexpected groups returned")
			}

		})
	}
}

type oktaProviderValidateSessionResponse struct {
	Active bool `json:"active"`
}

func TestOktaProviderValidateSession(t *testing.T) {
	testCases := []struct {
		name          string
		resp          oktaProviderValidateSessionResponse
		expectedError bool
		sessionState  *sessions.SessionState
	}{
		{
			name: "valid session state",
			resp: oktaProviderValidateSessionResponse{
				Active: true,
			},
			sessionState: &sessions.SessionState{
				AccessToken: "a1234",
			},
			expectedError: false,
		},
		{
			name: "invalid session state",
			resp: oktaProviderValidateSessionResponse{
				Active: false,
			},
			sessionState: &sessions.SessionState{
				AccessToken: "a1234",
			},
			expectedError: true,
		},
		{
			name:          "missing access token",
			sessionState:  &sessions.SessionState{},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newOktaProvider(nil, t)
			body, err := json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)
			var server *httptest.Server
			p.ValidateURL, server = newOktaProviderServer(body, http.StatusOK)
			defer server.Close()

			resp := p.ValidateSessionState(tc.sessionState)
			if tc.expectedError && resp {
				t.Errorf("expected false but returned as true")
			}
			if !tc.expectedError && !resp {
				t.Errorf("expected true but returned as false")
			}
		})
	}
}
