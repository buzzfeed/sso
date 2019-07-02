package providers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/groups"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func newProviderServer(body []byte, code int) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newGoogleProvider(providerData *ProviderData) *GoogleProvider {
	if providerData == nil {
		providerData = &ProviderData{
			ProviderName: "",
			SignInURL:    &url.URL{},
			RedeemURL:    &url.URL{},
			RevokeURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""}
	}
	provider, _ := NewGoogleProvider(providerData, "", "", "", "")
	return provider
}

func TestGoogleProviderDefaults(t *testing.T) {
	expectedResults := []struct {
		name         string
		providerData *ProviderData
		signInURL    string
		redeemURL    string
		revokeURL    string
		profileURL   string
		validateURL  string
		scope        string
	}{
		{
			name:        "defaults",
			signInURL:   "https://accounts.google.com/o/oauth2/v2/auth",
			redeemURL:   "https://www.googleapis.com/oauth2/v4/token",
			revokeURL:   "https://accounts.google.com/o/oauth2/revoke",
			validateURL: "https://www.googleapis.com/oauth2/v3/tokeninfo",
			scope:       "profile email",
		},
	}
	for _, expected := range expectedResults {
		t.Run(expected.name, func(t *testing.T) {
			p := newGoogleProvider(expected.providerData)
			if p == nil {
				t.Errorf("google provider was nil")
			}
			if p.Data().ProviderName != "Google" {
				t.Errorf("expected provider name Google, got %s", p.Data().ProviderName)
			}
			if p.Data().SignInURL.String() != expected.signInURL {
				t.Errorf("want: %v", expected.signInURL)
				t.Errorf("have: %v", p.Data().SignInURL.String())
				t.Errorf("unexpected signin url")
			}

			if p.Data().RedeemURL.String() != expected.redeemURL {
				t.Errorf("want: %v", expected.redeemURL)
				t.Errorf("have: %v", p.Data().RedeemURL.String())
				t.Errorf("unexpected redeem url")
			}

			if p.Data().RevokeURL.String() != expected.revokeURL {
				t.Errorf("want: %v", expected.revokeURL)
				t.Errorf("have: %v", p.Data().RevokeURL.String())
				t.Errorf("unexpected revoke url")
			}

			if p.Data().ValidateURL.String() != expected.validateURL {
				t.Errorf("want: %v", expected.validateURL)
				t.Errorf("have: %v", p.Data().ValidateURL.String())
				t.Errorf("unexpected validate url")
			}

			if p.Data().ProfileURL.String() != expected.profileURL {
				t.Errorf("want: %v", expected.profileURL)
				t.Errorf("have: %v", p.Data().ProfileURL.String())
				t.Errorf("unexpected profile url")
			}

			if p.Data().Scope != expected.scope {
				t.Errorf("want: %v", expected.scope)
				t.Errorf("have: %v", p.Data().Scope)
				t.Errorf("unexpected scope")
			}
		})

	}
}

type redeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func TestGoogleProviderRedeem(t *testing.T) {
	testCases := []struct {
		name            string
		resp            redeemResponse
		expectedError   bool
		expectedSession *sessions.SessionState
	}{
		{
			name: "redeem",
			resp: redeemResponse{
				AccessToken:  "a1234",
				ExpiresIn:    10,
				RefreshToken: "refresh12345",
				IDToken:      "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": "michael.bland@gsa.gov", "email_verified":true}`)),
			},
			expectedSession: &sessions.SessionState{
				Email:        "michael.bland@gsa.gov",
				AccessToken:  "a1234",
				RefreshToken: "refresh12345",
			},
		},
		{
			name: "invalid encoding",
			resp: redeemResponse{
				AccessToken: "a1234",
				IDToken:     "ignored prefix." + `{"email": "michael.bland@gsa.gov"}`,
			},
			expectedError: true,
		},
		{
			name: "invalid json",
			resp: redeemResponse{
				AccessToken: "a1234",
				IDToken:     "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": michael.bland@gsa.gov}`)),
			},
			expectedError: true,
		},
		{
			name: "missing email",
			resp: redeemResponse{
				AccessToken: "a1234",
				IDToken:     "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"not_email": "missing"}`)),
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newGoogleProvider(nil)
			body, err := json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)
			var server *httptest.Server
			p.RedeemURL, server = newProviderServer(body, http.StatusOK)
			defer server.Close()

			session, err := p.Redeem("http://redirect/", "code1234")
			if tc.expectedError && err == nil {
				t.Errorf("expected redeem error but was nil")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("unexpected error %s", err)
			}
			if tc.expectedSession == nil && session != nil {
				t.Errorf("expected session to be nil but it was %s", session)
			}
			if session != nil && tc.expectedSession != nil {
				if session.Email != tc.expectedSession.Email {
					log.Printf("expected email %s", tc.expectedSession.Email)
					log.Printf("got %s", session.Email)
					t.Errorf("unexpected session email")
				}

				if session.AccessToken != tc.expectedSession.AccessToken {
					log.Printf("expected access token %s", tc.expectedSession.AccessToken)
					log.Printf("got %s", session.AccessToken)
					t.Errorf("unexpected access token")
				}

				if session.RefreshToken != tc.expectedSession.RefreshToken {
					log.Printf("expected refresh token %s", tc.expectedSession.RefreshToken)
					log.Printf("got %s", session.RefreshToken)
					t.Errorf("unexpected session refresh token")
				}
			}
		})
	}
}

type revokeErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func TestGoogleProviderRevoke(t *testing.T) {
	testCases := []struct {
		name                string
		resp                revokeErrorResponse
		httpStatus          int
		sessionState        *sessions.SessionState
		expectedError       bool
		expectedErrorString string
	}{
		{
			name: "idempotent revoke",
			resp: revokeErrorResponse{
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
			resp: revokeErrorResponse{
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
			p := newGoogleProvider(nil)
			body, err := json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)

			var server *httptest.Server
			p.RevokeURL, server = newProviderServer(body, tc.httpStatus)
			defer server.Close()
			err = p.Revoke(tc.sessionState)
			if tc.expectedError && err != nil {
				t.Errorf("unexpected error %s", err)
			}
			if tc.expectedError {
				if err == nil {
					t.Errorf("expected error but err was nil")
				}
				if !strings.Contains(err.Error(), tc.expectedErrorString) {
					log.Printf("expected error string to contain %s", tc.expectedErrorString)
					log.Printf("got %s", err)
					t.Errorf("unexpected error string")
				}
			}
		})

	}
}

func TestGoogleValidateGroupMembers(t *testing.T) {
	testCases := []struct {
		name                  string
		inputAllowedGroups    []string
		groupsError           error
		checkMembershipGroups []string
		listMembershipsFunc   func(string) (groups.MemberSet, bool)
		expectedGroups        []string
		expectedErrorString   string
	}{
		{
			name:                "empty input groups should return an empty string",
			inputAllowedGroups:  []string{},
			expectedGroups:      []string{},
			listMembershipsFunc: func(string) (groups.MemberSet, bool) { return nil, false },
		},
		{
			name:                "member exists in cache, should not call check membership resource",
			inputAllowedGroups:  []string{"group1"},
			groupsError:         fmt.Errorf("should not get here"),
			listMembershipsFunc: func(string) (groups.MemberSet, bool) { return groups.MemberSet{"email": {}}, true },
			expectedGroups:      []string{"group1"},
		},
		{
			name:                "member does not exist in cache, should still not call check membership resource",
			inputAllowedGroups:  []string{"group1"},
			groupsError:         fmt.Errorf("should not get here"),
			listMembershipsFunc: func(string) (groups.MemberSet, bool) { return groups.MemberSet{}, true },
			expectedGroups:      []string{},
		},
		{
			name:                  "subset of groups are not cached, calls check membership resource",
			inputAllowedGroups:    []string{"group1", "group2"},
			groupsError:           nil,
			checkMembershipGroups: []string{"group1"},
			listMembershipsFunc: func(group string) (groups.MemberSet, bool) {
				switch group {
				case "group1":
					return groups.MemberSet{"email": {}}, true
				default:
					return groups.MemberSet{}, false
				}
			},
			expectedGroups: []string{"group1"},
		},
		{
			name:               "subset of groups are not cached, calls check membership resource with error",
			inputAllowedGroups: []string{"group1", "group2"},
			groupsError:        fmt.Errorf("error"),
			listMembershipsFunc: func(group string) (groups.MemberSet, bool) {
				switch group {
				case "group1":
					return groups.MemberSet{"email": {}}, true
				default:
					return groups.MemberSet{}, false
				}
			},
			expectedErrorString: "error",
		},
		{
			name:               "subset of groups not there, does not call check membership resource",
			inputAllowedGroups: []string{"group1", "group2"},
			groupsError:        fmt.Errorf("should not get here"),
			listMembershipsFunc: func(group string) (groups.MemberSet, bool) {
				switch group {
				case "group1":
					return groups.MemberSet{"email": {}}, true
				default:
					return groups.MemberSet{}, true
				}
			},
			expectedGroups: []string{"group1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := GoogleProvider{
				AdminService: &MockAdminService{Groups: tc.checkMembershipGroups, GroupsError: tc.groupsError},
				GroupsCache:  &groups.MockCache{ListMembershipsFunc: tc.listMembershipsFunc, Refreshed: true},
			}

			groups, err := p.ValidateGroupMembership("email", tc.inputAllowedGroups, "accessToken")

			if err != nil {
				if tc.expectedErrorString != err.Error() {
					t.Errorf("expected error %s but err was %s", tc.expectedErrorString, err)
				}
			}
			if !reflect.DeepEqual(tc.expectedGroups, groups) {
				t.Logf("expected groups %v", tc.expectedGroups)
				t.Logf("got groups %v", groups)
				t.Errorf("unexpected groups returned")
			}

		})
	}
}

func TestGoogleProviderValidateSession(t *testing.T) {
	testCases := []struct {
		name          string
		resp          oktaProviderValidateSessionResponse
		httpStatus    int
		expectedError bool
		sessionState  *sessions.SessionState
	}{
		{
			name: "valid session state",
			sessionState: &sessions.SessionState{
				AccessToken: "a1234",
			},
			httpStatus:    http.StatusOK,
			expectedError: false,
		},
		{
			name: "invalid session state",
			sessionState: &sessions.SessionState{
				AccessToken: "a1234",
			},
			httpStatus:    http.StatusBadRequest,
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
			p := newGoogleProvider(nil)
			body, err := json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)
			var server *httptest.Server
			p.ValidateURL, server = newProviderServer(body, tc.httpStatus)
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
