package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func newTestServer(status int, body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(status)
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newSSOProvider() *SSOProvider {
	return NewSSOProvider(
		&ProviderData{
			ProviderURL: &url.URL{
				Scheme: "https",
				Host:   "auth.example.com",
			},
			ProviderURLInternal: &url.URL{
				Scheme: "http",
				Host:   "auth-int.example.com",
			},
		}, nil)
}

func TestNewRequest(t *testing.T) {
	testCases := []struct {
		name          string
		url           string
		expectedError bool
		expectedHost  string
	}{
		{
			name:          "error on new request",
			url:           ":",
			expectedError: true,
			expectedHost:  "",
		},
		{
			name:          "optional headers set",
			url:           "/",
			expectedError: false,
			expectedHost:  "auth.example.com",
		},
		{
			name:          "host header set correctly",
			url:           "/",
			expectedError: false,
			expectedHost:  "auth.example.com",
		},
	}
	os.Setenv("RIG_IMAGE_VERSION", "testVersion")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSSOProvider()
			if p == nil {
				t.Fatalf("expected provider to not be nil but was")
			}
			req, err := p.newRequest("GET", tc.url, nil)
			if tc.expectedError && err == nil {
				t.Errorf("expected error but error was nil")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("unexpected error %s", err.Error())
			}
			if err != nil {
				return
			}
			if req.Header.Get("User-Agent") == "testVersion" {
				t.Errorf("expected User-Agent header to be set but it was not")
			}
			if tc.expectedHost != req.Host {
				t.Errorf("expected host header %s, got %s", tc.expectedHost, req.Host)
			}
		})
	}
}

func TestSSOProviderDefaults(t *testing.T) {
	p := newSSOProvider()
	testutil.NotEqual(t, nil, p)

	data := p.Data()
	testutil.Equal(t, "SSO", data.ProviderName)

	base := fmt.Sprintf("%s://%s", data.ProviderURL.Scheme, data.ProviderURL.Host)
	internalBase := fmt.Sprintf("%s://%s", data.ProviderURLInternal.Scheme, data.ProviderURLInternal.Host)

	testutil.Equal(t, fmt.Sprintf("%s/sign_in", base), data.SignInURL.String())
	testutil.Equal(t, fmt.Sprintf("%s/sign_out", base), data.SignOutURL.String())

	testutil.Equal(t, fmt.Sprintf("%s/redeem", internalBase), data.RedeemURL.String())
	testutil.Equal(t, fmt.Sprintf("%s/refresh", internalBase), data.RefreshURL.String())
	testutil.Equal(t, fmt.Sprintf("%s/validate", internalBase), data.ValidateURL.String())
	testutil.Equal(t, fmt.Sprintf("%s/profile", internalBase), data.ProfileURL.String())
}

type redeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Email        string `json:"email"`
}

type refreshResponse struct {
	Code        int
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type profileResponse struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

func TestSSOProviderGroups(t *testing.T) {
	testCases := []struct {
		Name             string
		Email            string
		Groups           []string
		ProxyGroupIds    []string
		ExpectedValid    bool
		ExpectedInGroups []string
		ExpectError      error
		ProfileStatus    int
	}{
		{
			Name:             "valid when no group id set",
			Email:            "michael.bland@gsa.gov",
			Groups:           []string{},
			ProxyGroupIds:    []string{},
			ExpectedValid:    true,
			ExpectedInGroups: []string{},
			ExpectError:      nil,
		},
		{
			Name:             "valid when the group id exists",
			Email:            "michael.bland@gsa.gov",
			Groups:           []string{"user-in-this-group", "random-group"},
			ProxyGroupIds:    []string{"user-in-this-group", "user-not-in-this-group"},
			ExpectedValid:    true,
			ExpectedInGroups: []string{"user-in-this-group"},
			ExpectError:      nil,
		},
		{
			Name:             "valid when the multiple group id exists",
			Email:            "michael.bland@gsa.gov",
			Groups:           []string{"user-in-this-group", "user-also-in-this-group"},
			ProxyGroupIds:    []string{"user-in-this-group", "user-also-in-this-group"},
			ExpectedValid:    true,
			ExpectedInGroups: []string{"user-in-this-group", "user-also-in-this-group"},
			ExpectError:      nil,
		},
		{
			Name:             "invalid when the group id isn't in user groups",
			Email:            "michael.bland@gsa.gov",
			Groups:           []string{},
			ProxyGroupIds:    []string{"test1"},
			ExpectedValid:    false,
			ExpectedInGroups: []string{},
			ExpectError:      nil,
		},
		{
			Name:          "invalid if can't access groups",
			Email:         "michael.bland@gsa.gov",
			Groups:        []string{},
			ProxyGroupIds: []string{"session-group"},
			ProfileStatus: http.StatusTooManyRequests,
			ExpectError:   ErrAuthProviderUnavailable,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			p := newSSOProvider()
			body, err := json.Marshal(profileResponse{
				Email:  tc.Email,
				Groups: tc.Groups,
			})
			testutil.Equal(t, nil, err)
			var server *httptest.Server
			profileStatus := http.StatusOK
			if tc.ProfileStatus != 0 {
				profileStatus = tc.ProfileStatus
			}
			p.ProfileURL, server = newTestServer(profileStatus, body)
			defer server.Close()
			inGroups, valid, err := p.ValidateGroup(tc.Email, tc.ProxyGroupIds)
			testutil.Equal(t, tc.ExpectError, err)
			if err == nil {
				testutil.Equal(t, tc.ExpectedValid, valid)
				testutil.Equal(t, tc.ExpectedInGroups, inGroups)
			}
		})
	}
}

func TestSSOProviderRedeem(t *testing.T) {
	testCases := []struct {
		Name            string
		Code            string
		ExpectedError   string
		RedeemResponse  *redeemResponse
		ProfileResponse *profileResponse
	}{
		{
			Name:          "redeem fails without code",
			ExpectedError: "missing code",
		},
		{
			Name:          "redeem fails if redemption server not responding",
			Code:          "code1234",
			ExpectedError: "got 400",
		},
		{
			Name: "redeem successful",
			Code: "code1234",
			RedeemResponse: &redeemResponse{
				AccessToken:  "a1234",
				ExpiresIn:    10,
				RefreshToken: "refresh12345",
				Email:        "michael.bland@gsa.gov",
			},
			ProfileResponse: &profileResponse{
				Email:  "michael.bland@gsa.gov",
				Groups: []string{"core@gsa.gov"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			p := newSSOProvider()

			var redeemServer *httptest.Server
			// set up redemption resource
			if tc.RedeemResponse != nil {
				body, err := json.Marshal(tc.RedeemResponse)
				testutil.Equal(t, nil, err)
				p.RedeemURL, redeemServer = newTestServer(http.StatusOK, body)
			} else {
				p.RedeemURL, redeemServer = newTestServer(http.StatusBadRequest, []byte{})
			}
			defer redeemServer.Close()

			var profileServer *httptest.Server
			if tc.ProfileResponse != nil {
				body, err := json.Marshal(tc.ProfileResponse)
				testutil.Equal(t, nil, err)
				p.ProfileURL, profileServer = newTestServer(http.StatusOK, body)
			} else {
				p.RedeemURL, profileServer = newTestServer(http.StatusBadRequest, []byte{})
			}
			defer profileServer.Close()

			session, err := p.Redeem("http://redirect/", tc.Code)
			if tc.RedeemResponse != nil {
				testutil.Equal(t, nil, err)
				testutil.NotEqual(t, session, nil)
				testutil.Equal(t, tc.RedeemResponse.Email, session.Email)
				testutil.Equal(t, tc.RedeemResponse.AccessToken, session.AccessToken)
				testutil.Equal(t, tc.RedeemResponse.RefreshToken, session.RefreshToken)
			}
			if tc.ExpectedError != "" && !strings.Contains(err.Error(), tc.ExpectedError) {
				t.Errorf("got unexpected result.\nwant=%v\ngot=%v\n", tc.ExpectedError, err.Error())
			}
		})
	}
}
func TestSSOProviderValidateSessionState(t *testing.T) {
	testCases := []struct {
		Name             string
		SessionState     *sessions.SessionState
		ProviderResponse int
		Groups           []string
		ProxyGroupIds    []string
		ExpectedValid    bool
	}{
		{
			Name: "valid when no group id set",
			SessionState: &sessions.SessionState{
				AccessToken: "abc",
				Email:       "michael.bland@gsa.gov",
			},
			ProviderResponse: http.StatusOK,
			Groups:           []string{},
			ProxyGroupIds:    []string{},
			ExpectedValid:    true,
		},
		{
			Name: "invalid when response is is not 200",
			SessionState: &sessions.SessionState{
				AccessToken: "abc",
				Email:       "michael.bland@gsa.gov",
			},
			ProviderResponse: http.StatusForbidden,
			Groups:           []string{},
			ProxyGroupIds:    []string{},
			ExpectedValid:    false,
		},
		{
			Name: "valid when the group id exists",
			SessionState: &sessions.SessionState{
				AccessToken: "abc",
				Email:       "michael.bland@gsa.gov",
			},
			ProviderResponse: http.StatusOK,
			Groups:           []string{"test1", "test2"},
			ProxyGroupIds:    []string{"test1"},
			ExpectedValid:    true,
		},
		{
			Name: "invalid when the group id isn't in user groups",
			SessionState: &sessions.SessionState{
				AccessToken: "abc",
				Email:       "michael.bland@gsa.gov",
			},
			ProviderResponse: http.StatusOK,
			Groups:           []string{},
			ProxyGroupIds:    []string{"test1"},
			ExpectedValid:    false,
		},
		{
			Name: "valid when provider unavailable, but grace period active",
			SessionState: &sessions.SessionState{
				GracePeriodStart: time.Now().Add(time.Duration(-1) * time.Hour),
			},
			ProviderResponse: http.StatusTooManyRequests,
			ExpectedValid:    true,
		},
		{
			Name: "invalid when provider unavailable and grace period inactive",
			SessionState: &sessions.SessionState{
				GracePeriodStart: time.Now().Add(time.Duration(-4) * time.Hour),
			},
			ProviderResponse: http.StatusServiceUnavailable,
			ExpectedValid:    false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			p := newSSOProvider()
			p.GracePeriodTTL = time.Duration(3) * time.Hour

			// setup group endpoint
			body, err := json.Marshal(profileResponse{
				Email:  tc.SessionState.Email,
				Groups: tc.Groups,
			})
			testutil.Equal(t, nil, err)
			var profileServer *httptest.Server
			p.ProfileURL, profileServer = newTestServer(http.StatusOK, body)
			defer profileServer.Close()

			validateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				accessToken := r.Header.Get("X-Access-Token")
				if accessToken != tc.SessionState.AccessToken {
					t.Logf("want: %v", tc.SessionState.AccessToken)
					t.Logf(" got: %v", accessToken)
					t.Fatalf("unexpected access token value")
				}
				rw.WriteHeader(tc.ProviderResponse)
			}))
			p.ValidateURL, _ = url.Parse(validateServer.URL)
			defer validateServer.Close()

			valid := p.ValidateSessionState(tc.SessionState, tc.ProxyGroupIds)
			if valid != tc.ExpectedValid {
				t.Errorf("got unexpected result. want=%v got=%v", tc.ExpectedValid, valid)
			}
		})
	}
}

func TestSSOProviderRefreshSession(t *testing.T) {
	testCases := []struct {
		Name            string
		SessionState    *sessions.SessionState
		UserGroups      []string
		ProxyGroups     []string
		RefreshResponse *refreshResponse
		ExpectedRefresh bool
		ExpectedError   string
	}{
		{
			Name: "no refresh if no refresh token",
			SessionState: &sessions.SessionState{
				Email:           "user@domain.com",
				AccessToken:     "token1234",
				RefreshDeadline: time.Now().Add(time.Duration(-1) * time.Hour),
			},
			RefreshResponse: &refreshResponse{
				Code: http.StatusBadRequest,
			},
			ExpectedRefresh: false,
		},
		{
			Name: "no refresh if not yet expired",
			SessionState: &sessions.SessionState{
				Email:           "user@domain.com",
				AccessToken:     "token1234",
				RefreshDeadline: time.Now().Add(time.Duration(1) * time.Hour),
				RefreshToken:    "refresh1234",
			},
			RefreshResponse: &refreshResponse{
				Code: http.StatusBadRequest,
			},
			ExpectedRefresh: false,
		},
		{
			Name: "no refresh if redeem not responding",
			SessionState: &sessions.SessionState{
				Email:           "user@domain.com",
				AccessToken:     "token1234",
				RefreshDeadline: time.Now().Add(time.Duration(-1) * time.Hour),
				RefreshToken:    "refresh1234",
			},
			RefreshResponse: &refreshResponse{
				Code: http.StatusBadRequest,
			},
			ExpectedRefresh: false,
			ExpectedError:   "got 400",
		},
		{
			Name: "no refresh if profile not responding",
			SessionState: &sessions.SessionState{
				Email:           "user@domain.com",
				AccessToken:     "token1234",
				RefreshDeadline: time.Now().Add(time.Duration(-1) * time.Hour),
				RefreshToken:    "refresh1234",
			},
			RefreshResponse: &refreshResponse{
				Code:        http.StatusCreated,
				ExpiresIn:   10,
				AccessToken: "newToken1234",
			},
			ProxyGroups:     []string{"test1"},
			ExpectedRefresh: false,
			ExpectedError:   "got 500",
		},
		{
			Name: "no refresh if user no longer in group",
			SessionState: &sessions.SessionState{
				Email:           "user@domain.com",
				AccessToken:     "token1234",
				RefreshDeadline: time.Now().Add(time.Duration(-1) * time.Hour),
				RefreshToken:    "refresh1234",
			},
			UserGroups:  []string{"useless"},
			ProxyGroups: []string{"test1"},
			RefreshResponse: &refreshResponse{
				Code:        http.StatusCreated,
				ExpiresIn:   10,
				AccessToken: "newToken1234",
			},
			ExpectedRefresh: false,
			ExpectedError:   "Group membership revoked",
		},
		{
			Name: "successful refresh if can redeem and user in group",
			SessionState: &sessions.SessionState{
				Email:           "user@domain.com",
				AccessToken:     "token1234",
				RefreshDeadline: time.Now().Add(time.Duration(-1) * time.Hour),
				RefreshToken:    "refresh1234",
			},
			UserGroups:  []string{"test1"},
			ProxyGroups: []string{"test1"},
			RefreshResponse: &refreshResponse{
				Code:        http.StatusCreated,
				ExpiresIn:   10,
				AccessToken: "newToken1234",
			},
			ExpectedRefresh: true,
		},
		{
			Name: "successful refresh if provider unavailable but within grace period",
			SessionState: &sessions.SessionState{
				GracePeriodStart: time.Now().Add(time.Duration(-1) * time.Hour),
				RefreshToken:     "refresh1234",
			},
			RefreshResponse: &refreshResponse{
				Code: http.StatusTooManyRequests,
			},
			ExpectedRefresh: true,
		},
		{
			Name: "failed refresh if provider unavailable and outside grace period",
			SessionState: &sessions.SessionState{
				GracePeriodStart: time.Now().Add(time.Duration(-4) * time.Hour),
				RefreshToken:     "refresh1234",
			},
			RefreshResponse: &refreshResponse{
				Code: http.StatusTooManyRequests,
			},
			ExpectedRefresh: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			p := newSSOProvider()
			p.GracePeriodTTL = time.Duration(3) * time.Hour

			groups := []string{}
			if tc.ProxyGroups != nil {
				groups = tc.ProxyGroups
			}

			// set up redeem resource
			var refreshServer *httptest.Server
			body, err := json.Marshal(tc.RefreshResponse)
			testutil.Equal(t, nil, err)
			p.RefreshURL, refreshServer = newTestServer(tc.RefreshResponse.Code, body)
			defer refreshServer.Close()

			// set up groups resource
			var groupsServer *httptest.Server
			if tc.UserGroups != nil {
				body, err := json.Marshal(profileResponse{
					Email:  tc.SessionState.Email,
					Groups: tc.UserGroups,
				})
				testutil.Equal(t, nil, err)
				p.ProfileURL, groupsServer = newTestServer(http.StatusOK, body)
			} else {
				p.ProfileURL, groupsServer = newTestServer(http.StatusInternalServerError, []byte{})
			}
			defer groupsServer.Close()

			// run the endpoint
			actualRefresh, err := p.RefreshSession(tc.SessionState, groups)
			if tc.ExpectedRefresh != actualRefresh {
				t.Fatalf("got unexpected refresh behavior. want=%v got=%v", tc.ExpectedRefresh, actualRefresh)
			}

			if tc.ExpectedError != "" && err == nil {
				t.Fatalf("expected error: %v got: %v", tc.ExpectedError, err)
			}

			if tc.ExpectedError != "" && !strings.Contains(err.Error(), tc.ExpectedError) {
				t.Fatalf("got unexpected result.\nwant=%v\ngot=%v\n", tc.ExpectedError, err.Error())
			}
		})
	}
}
