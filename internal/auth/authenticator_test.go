package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/auth/providers"
	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/templates"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

}

func setMockCSRFStore(store *sessions.MockCSRFStore) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.csrfStore = store
		return nil
	}
}

func setMockSessionStore(store *sessions.MockSessionStore) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.sessionStore = store
		return nil
	}
}

func setMockTempl() func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.templates = &templates.MockTemplate{}
		return nil
	}
}

func setMockAuthCodeCipher(cipher *aead.MockCipher, s interface{}) func(*Authenticator) error {
	marshaled, _ := json.Marshal(s)
	if len(marshaled) > 0 && cipher != nil {
		cipher.UnmarshalBytes = marshaled
	}
	return func(a *Authenticator) error {
		a.AuthCodeCipher = cipher
		return nil
	}
}

func setTestProvider(provider *providers.TestProvider) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.provider = provider
		return nil
	}
}

func setRedirectURL(redirectURL *url.URL) func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.redirectURL = redirectURL
		return nil
	}
}

func setMockRedirectURL() func(*Authenticator) error {
	return func(a *Authenticator) error {
		a.redirectURL = &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/",
		}
		return nil
	}
}

func assignProvider(pc ProviderConfig) func(*Authenticator) error {
	return func(a *Authenticator) error {
		var err error
		a.provider, err = newProvider(pc, SessionConfig{SessionLifetimeTTL: 1 * time.Hour})
		return err
	}
}

func newRevokeServer(accessToken string) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		token := r.Form.Get("token")

		if token == accessToken {
			rw.WriteHeader(http.StatusOK)
		} else {
			rw.WriteHeader(http.StatusBadRequest)
		}
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

const redirectInputPattern = `<input type="hidden" name="redirect_uri" value="([^"]+)">`
const revokeErrorMessagePattern = `An error occurred during sign out\. Please try again\.`

type providerRefreshResponse struct {
	OK    bool
	Error error
}

type errResponse struct {
	Error string
}

func TestSignIn(t *testing.T) {
	testCases := []struct {
		name                   string
		paramsMap              map[string]string
		mockCSRFStore          *sessions.MockCSRFStore
		mockSessionStore       *sessions.MockSessionStore
		mockAuthCodeCipher     *aead.MockCipher
		refreshResponse        providerRefreshResponse
		providerValidToken     bool
		validEmail             bool
		expectedSignInPage     bool
		expectedDestinationURL string
		expectedCode           int
		expectedErrorResponse  *errResponse
	}{
		{
			name: "err no cookie calls proxy oauth redirect, no params map redirects to sign in page",
			mockSessionStore: &sessions.MockSessionStore{
				LoadError: http.ErrNoCookie,
			},
			expectedSignInPage:     true,
			expectedDestinationURL: "",
			expectedCode:           http.StatusOK,
		},
		{
			name: "err no cookie calls proxy oauth redirect, with redirect url redirects to sign in page",
			mockSessionStore: &sessions.MockSessionStore{
				LoadError: http.ErrNoCookie,
			},
			paramsMap: map[string]string{
				"redirect_uri": "http://foo.example.com",
			},
			expectedSignInPage:     true,
			expectedDestinationURL: "foo.example.com",
			expectedCode:           http.StatusOK,
		},
		{
			name: "another error that isn't no cookie",
			mockSessionStore: &sessions.MockSessionStore{
				LoadError: fmt.Errorf("another error"),
				Session: &sessions.SessionState{
					Email: "emailaddress",
				},
			},
			expectedCode:          http.StatusInternalServerError,
			expectedErrorResponse: &errResponse{"another error"},
		},
		{
			name: "expired lifetime of session clears session and redirects to sign in",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(-time.Hour),
					RefreshDeadline:  time.Now().Add(time.Hour),
				},
			},
			expectedSignInPage:     true,
			expectedDestinationURL: "",
			expectedCode:           http.StatusOK,
		},
		{
			name: "refresh period expired, provider error",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			refreshResponse: providerRefreshResponse{
				Error: fmt.Errorf("provider error"),
			},
			expectedCode:          http.StatusInternalServerError,
			expectedErrorResponse: &errResponse{"provider error"},
		},
		{
			name: "refresh period expired, not refreshed - unauthorized user",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			refreshResponse:       providerRefreshResponse{},
			expectedCode:          http.StatusUnauthorized,
			expectedErrorResponse: &errResponse{ErrUserNotAuthorized.Error()},
		},
		{
			name: "refresh period expired, refresh ok, save session error",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
				SaveError: fmt.Errorf("save error"),
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			expectedCode:          http.StatusInternalServerError,
			expectedErrorResponse: &errResponse{"save error"},
		},
		{
			name: "refresh period expired, successful refresh, invalid email",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			expectedCode:          http.StatusUnauthorized,
			expectedErrorResponse: &errResponse{ErrUserNotAuthorized.Error()},
		},
		{
			name: "valid session state, save session error",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(time.Hour),
				},
				SaveError: fmt.Errorf("save error"),
			},
			providerValidToken:    true,
			expectedCode:          http.StatusInternalServerError,
			expectedErrorResponse: &errResponse{"save error"},
		},
		{
			name: "invalid session state, invalid email",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(time.Hour),
				},
			},
			expectedCode:          http.StatusUnauthorized,
			expectedErrorResponse: &errResponse{ErrUserNotAuthorized.Error()},
		},
		{
			name: "refresh period expired, successful refresh, no state in params",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			validEmail:            true,
			expectedCode:          http.StatusForbidden,
			expectedErrorResponse: &errResponse{"no state parameter supplied"},
		},
		{
			name: "refresh period expired, successful refresh, no redirect in params",
			paramsMap: map[string]string{
				"state": "state",
			},
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			validEmail:            true,
			expectedCode:          http.StatusForbidden,
			expectedErrorResponse: &errResponse{"no redirect_uri parameter supplied"},
		},
		{
			name: "refresh period expired, successful refresh, malformed redirect in params",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": ":",
			},
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			validEmail:            true,
			expectedCode:          http.StatusBadRequest,
			expectedErrorResponse: &errResponse{"malformed redirect_uri parameter passed"},
		},
		{
			name: "refresh period expired, unsuccessful marshal",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://foo.example.com",
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			mockAuthCodeCipher: &aead.MockCipher{
				MarshalError: fmt.Errorf("error marshal"),
			},
			validEmail:            true,
			expectedCode:          http.StatusInternalServerError,
			expectedErrorResponse: &errResponse{"error marshal"},
		},
		{
			name: "refresh period expired, successful refresh",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(-time.Hour),
				},
			},
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://foo.example.com",
			},
			refreshResponse: providerRefreshResponse{
				OK: true,
			},
			mockAuthCodeCipher: &aead.MockCipher{
				MarshalString: "abcdefg",
			},
			validEmail:   true,
			expectedCode: http.StatusFound,
		},
		{
			name: "valid session state, successful save",
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:            "email",
					AccessToken:      "accesstoken",
					RefreshToken:     "refresh",
					LifetimeDeadline: time.Now().Add(time.Hour),
					RefreshDeadline:  time.Now().Add(time.Hour),
				},
			},
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://foo.example.com",
			},
			validEmail:         true,
			providerValidToken: true,
			mockAuthCodeCipher: &aead.MockCipher{
				MarshalString: "abcdefg",
			},

			expectedCode: http.StatusFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			auth, err := NewAuthenticator(config,
				SetValidators([]options.Validator{options.NewMockValidator(tc.validEmail)}),
				setMockSessionStore(tc.mockSessionStore),
				setMockTempl(),
				setMockRedirectURL(),
				setMockAuthCodeCipher(tc.mockAuthCodeCipher, nil),
			)
			testutil.Ok(t, err)

			// set test provider
			u, _ := url.Parse("http://example.com/")
			provider := providers.NewTestProvider(u)
			provider.Refresh = tc.refreshResponse.OK
			provider.RefreshError = tc.refreshResponse.Error
			provider.ValidToken = tc.providerValidToken
			auth.provider = provider

			params, _ := url.ParseQuery(u.RawQuery)
			for paramKey, val := range tc.paramsMap {
				params.Set(paramKey, val)
			}
			u.RawQuery = params.Encode()

			req := httptest.NewRequest("GET", u.String(), nil)
			req.Header.Add("Accept", "application/json")
			rw := httptest.NewRecorder()
			auth.SignIn(rw, req)

			testutil.Equal(t, tc.expectedCode, rw.Code)
			resp := rw.Result()
			respBytes, err := ioutil.ReadAll(resp.Body)
			testutil.Ok(t, err)
			if tc.expectedSignInPage {
				expectedSignInResp := &signInResp{
					ProviderName: provider.Data().ProviderName,
					ProviderSlug: "test",
					EmailDomains: auth.EmailDomains,
					Redirect:     u.String(),
					Destination:  tc.expectedDestinationURL,
					Version:      VERSION,
				}
				actualSignInResp := &signInResp{}
				err := json.Unmarshal(respBytes, actualSignInResp)
				testutil.Ok(t, err)
				testutil.Equal(t, expectedSignInResp, actualSignInResp)
			}

			if tc.expectedErrorResponse != nil {
				actualErrorResponse := &errResponse{}
				err := json.Unmarshal(respBytes, actualErrorResponse)
				testutil.Ok(t, err)
				testutil.Equal(t, tc.expectedErrorResponse, actualErrorResponse)
			}
			// TODO: add a cleared session cookie check for errored stuff

		})
	}
}

func TestSignOutPage(t *testing.T) {
	testCases := []struct {
		Name                string
		ExpectedStatusCode  int
		paramsMap           map[string]string
		RedirectURI         string
		Method              string
		mockSessionStore    *sessions.MockSessionStore
		RevokeError         error
		expectedSignOutResp *signOutResp
	}{
		{
			Name: "successful sign out page",
			paramsMap: map[string]string{
				"redirect_uri": "http://service.example.com",
			},
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:           "test@example.com",
					RefreshDeadline: time.Now().Add(time.Hour),
					AccessToken:     "accessToken",
					RefreshToken:    "refreshToken",
				},
			},
			ExpectedStatusCode: http.StatusOK,
			Method:             "GET",
			expectedSignOutResp: &signOutResp{
				ProviderSlug: "test",
				Version:      VERSION,
				Redirect:     "http://service.example.com",
				Destination:  "service.example.com",
				Email:        "test@example.com",
			},
		},
		{
			Name:               "redirect if no session exists on GET",
			ExpectedStatusCode: http.StatusFound,
			mockSessionStore: &sessions.MockSessionStore{
				LoadError: http.ErrNoCookie,
			},
			paramsMap: map[string]string{
				"redirect_uri": "http://service.example.com",
			},
			Method: "GET",
		},
		{
			Name:               "redirect if no session exists on POST",
			ExpectedStatusCode: http.StatusFound,
			mockSessionStore: &sessions.MockSessionStore{
				LoadError: http.ErrNoCookie,
			},
			paramsMap: map[string]string{
				"redirect_uri": "http://service.example.com",
			},
			Method: "POST",
		},
		{
			Name:               "sign out page also used to POST",
			ExpectedStatusCode: http.StatusFound,
			mockSessionStore:   &sessions.MockSessionStore{},
			RedirectURI:        "http://service.example.com",
			Method:             "POST",
		},
		{
			Name:               "sign out page shows error message if revoke fails",
			ExpectedStatusCode: http.StatusInternalServerError,
			mockSessionStore: &sessions.MockSessionStore{
				Session: &sessions.SessionState{
					Email:           "test@example.com",
					RefreshDeadline: time.Now().Add(time.Hour),
					AccessToken:     "accessToken",
					RefreshToken:    "refreshToken",
				},
			},
			RevokeError: fmt.Errorf("error revoking"),
			RedirectURI: "http://service.example.com",
			Method:      "POST",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

			u, _ := url.Parse("/sign_out")
			config := testConfiguration(t)

			provider := providers.NewTestProvider(u)
			provider.RevokeError = tc.RevokeError

			p, _ := NewAuthenticator(config,
				SetValidators([]options.Validator{options.NewMockValidator(true)}),
				setMockSessionStore(tc.mockSessionStore),
				setMockTempl(),
				setTestProvider(provider),
			)

			params, _ := url.ParseQuery(u.RawQuery)

			for paramKey, val := range tc.paramsMap {
				params.Set(paramKey, val)
			}
			u.RawQuery = params.Encode()

			rw := httptest.NewRecorder()
			req, _ := http.NewRequest(tc.Method, u.String(), nil)

			p.SignOut(rw, req)

			testutil.Equal(t, tc.ExpectedStatusCode, rw.Code)
			resp := rw.Result()
			respBytes, err := ioutil.ReadAll(resp.Body)
			testutil.Ok(t, err)

			if tc.expectedSignOutResp != nil {
				actualSignOutResp := &signOutResp{}
				err := json.Unmarshal(respBytes, actualSignOutResp)
				testutil.Ok(t, err)
				testutil.Equal(t, tc.expectedSignOutResp, actualSignOutResp)
			}

		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	proxyClientID, proxyClientSecret := "abced", "testtest"
	testCases := []struct {
		Name               string
		Endpoint           string
		ExpectedStatusCode int
		ProviderStatusCode int
		AccessToken        string
		Method             string
	}{
		{
			Name:               "successful validate request",
			Endpoint:           "/validate",
			ExpectedStatusCode: http.StatusOK,
			ProviderStatusCode: http.StatusOK,
			AccessToken:        "xyz123",
			Method:             "GET",
		},
		{
			Name:               "failed provider validate request",
			Endpoint:           "/validate",
			ExpectedStatusCode: http.StatusUnauthorized,
			ProviderStatusCode: http.StatusForbidden,
			AccessToken:        "xyz123",
			Method:             "GET",
		},
		{
			Name:               "missing access token",
			Endpoint:           "/validate",
			ExpectedStatusCode: http.StatusBadRequest,
			Method:             "GET",
		},
		{
			Name:               "bad method",
			Endpoint:           "/validate",
			ExpectedStatusCode: http.StatusMethodNotAllowed,
			AccessToken:        "xyz123",
			Method:             "POST",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(tc.ProviderStatusCode)
			}))
			defer s.Close()
			validateURL, _ := url.Parse(s.URL)

			config := testConfiguration(t)
			config.ClientConfigs["proxy"] = ClientConfig{
				ID:     proxyClientID,
				Secret: proxyClientSecret,
			}
			provider := &providers.ProviderData{
				ValidateURL: validateURL,
			}
			authenticator, _ := NewAuthenticator(config,
				SetProvider(provider),
			)

			u, _ := url.Parse(tc.Endpoint)
			params, _ := url.ParseQuery(u.RawQuery)
			params.Set("client_id", proxyClientID)
			u.RawQuery = params.Encode()

			req, _ := http.NewRequest(tc.Method, u.String(), strings.NewReader(""))
			req.Header.Add("X-Client-Secret", proxyClientSecret)
			req.Header.Add("X-Access-Token", tc.AccessToken)

			rw := httptest.NewRecorder()
			authenticator.ServeMux.ServeHTTP(rw, req)

			if rw.Code != tc.ExpectedStatusCode {
				t.Errorf("expected status code %v but response status code is %v", tc.ExpectedStatusCode, rw.Code)
			}

		})
	}
}

func TestGetAuthCodeRedirectURL(t *testing.T) {
	testCases := []struct {
		name        string
		redirectURI string
		expectedURI string
		scheme      string
	}{
		{
			name:        "url scheme included",
			scheme:      "http",
			redirectURI: "http://example.com",
			expectedURI: "http://example.com?code=code&state=state",
		},
		{
			name:        "url scheme not included",
			scheme:      "https",
			redirectURI: "example.com",
			expectedURI: "https://example.com?code=code&state=state",
		},
		{
			name:        "auth code is overwritten",
			scheme:      "http",
			redirectURI: "http://example.com?code=different",
			expectedURI: "http://example.com?code=code&state=state",
		},
		{
			name:        "state is overwritten",
			scheme:      "https",
			redirectURI: "https://example.com?state=different",
			expectedURI: "https://example.com?code=code&state=state",
		},
		{
			name:        "scheme is overwritten",
			scheme:      "https",
			redirectURI: "http://example.com?state=different",
			expectedURI: "https://example.com?code=code&state=state",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			redirectURL, err := url.Parse(tc.redirectURI)
			rString := redirectURL.String()
			if err != nil {
				t.Fatalf("error parsing redirect uri %s", err.Error())
			}

			uri, err := getAuthCodeRedirectURL(redirectURL, "state", "code", tc.scheme)
			if err != nil {
				t.Fatalf("unexpected err generating auth code redirect url: %v", err)
			}

			if uri != tc.expectedURI {
				t.Errorf("expected redirect uri to be %s but was %s", tc.expectedURI, uri)
			}

			if redirectURL.String() != rString {
				t.Errorf("expected original redirect url to be unchanged - expected %s but got %s", redirectURL.String(), rString)
			}

		})
	}
}

func TestProxyOAuthRedirect(t *testing.T) {
	testCases := []struct {
		name               string
		paramsMap          map[string]string
		mockCipher         *aead.MockCipher
		expectedStatusCode int
	}{
		{
			name: "successful case",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://example.com",
			},
			mockCipher: &aead.MockCipher{
				MarshalString: "abced",
			},
			expectedStatusCode: http.StatusFound,
		},
		{
			name:               "empty state",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name: "empty redirect uri",
			paramsMap: map[string]string{
				"state": "state",
			},
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name: "malformed redirect uri",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": ":",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "save session error",
			paramsMap: map[string]string{
				"state":        "state",
				"redirect_uri": "http://example.com",
			},
			mockCipher:         &aead.MockCipher{MarshalError: fmt.Errorf("error")},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()

			config := testConfiguration(t)

			proxy, _ := NewAuthenticator(config, setMockAuthCodeCipher(tc.mockCipher, nil))
			params := url.Values{}
			for paramKey, val := range tc.paramsMap {
				params.Set(paramKey, val)
			}
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			sessionState := &sessions.SessionState{
				AccessToken:     "accessToken",
				RefreshDeadline: now.Add(time.Hour),
				RefreshToken:    "refreshToken",
				Email:           "emailaddress",
			}
			proxy.ProxyOAuthRedirect(rw, req, sessionState, []string{})
			if rw.Code != tc.expectedStatusCode {
				t.Errorf("expected status to be %d but was %d", tc.expectedStatusCode, rw.Code)
			}

		})
	}
}

type testRefreshProvider struct {
	*providers.ProviderData
	refreshFunc func(string) (string, time.Duration, error)
}

func (trp *testRefreshProvider) RefreshAccessToken(a string) (string, time.Duration, error) {
	return trp.refreshFunc(a)
}

func TestRefreshEndpoint(t *testing.T) {
	testCases := []struct {
		name                string
		refreshToken        string
		refreshFunc         func(string) (string, time.Duration, error)
		expectedStatusCode  int
		expectedRefreshResp *refreshResponse
	}{
		{
			name:               "no refresh token in request",
			refreshToken:       "",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "successful return new access token",
			refreshToken:       "refresh",
			refreshFunc:        func(a string) (string, time.Duration, error) { return "access", 1 * time.Hour, nil },
			expectedStatusCode: http.StatusCreated,
			expectedRefreshResp: &refreshResponse{
				AccessToken: "access",
				ExpiresIn:   int64((1 * time.Hour).Seconds()),
			},
		},
		{
			name:               "returns correct seconds value",
			refreshToken:       "refresh",
			refreshFunc:        func(a string) (string, time.Duration, error) { return "access", 367 * time.Second, nil },
			expectedStatusCode: http.StatusCreated,
			expectedRefreshResp: &refreshResponse{
				AccessToken: "access",
				ExpiresIn:   367,
			},
		},
		{
			name:               "error calling upstream provider with refresh token",
			refreshToken:       "refresh",
			refreshFunc:        func(a string) (string, time.Duration, error) { return "", 0, fmt.Errorf("upstream error") },
			expectedStatusCode: http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)

			p, _ := NewAuthenticator(config)
			p.provider = &testRefreshProvider{refreshFunc: tc.refreshFunc}
			params := url.Values{}
			params.Set("refresh_token", tc.refreshToken)
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			rw := httptest.NewRecorder()
			p.Refresh(rw, req)
			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected status code to be %d but was %d", tc.expectedStatusCode, rw.Code)
				return
			}

			respBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response body: %s", err.Error())
			}
			if resp.StatusCode == http.StatusOK {
				refreshResp := &refreshResponse{}
				err = json.Unmarshal(respBytes, refreshResp)
				if err != nil {
					t.Fatalf("error unmarshaling response: %s", err.Error())
				}

				if !reflect.DeepEqual(refreshResp, tc.expectedRefreshResp) {
					t.Logf("want: %#v", tc.expectedRefreshResp)
					t.Logf(" got: %#v", refreshResp)
					t.Errorf("got unexpected response")
					return
				}
			}
		})
	}
}

func TestGetProfile(t *testing.T) {
	testCases := []struct {
		name                string
		email               string
		groupEmails         []string
		providerGroupError  error
		expectedStatusCode  int
		expectedErrorString string
	}{
		{
			name:                "email not in request",
			expectedStatusCode:  http.StatusBadRequest,
			expectedErrorString: "no email address included\n",
		},
		{
			name:                "provider GroupResource function returns an error",
			email:               "emailAddress",
			providerGroupError:  fmt.Errorf("error retrieving groups"),
			expectedStatusCode:  http.StatusInternalServerError,
			expectedErrorString: "error retrieving groups",
		},
		{
			name:               "email included and no error",
			groupEmails:        []string{"email"},
			email:              "emailAddress",
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			p, _ := NewAuthenticator(config,
				SetValidators([]options.Validator{options.NewMockValidator(true)}),
			)
			u, _ := url.Parse("http://example.com")
			testProvider := providers.NewTestProvider(u)
			testProvider.Groups = tc.groupEmails
			testProvider.GroupsError = tc.providerGroupError
			p.provider = testProvider

			req := httptest.NewRequest("GET", fmt.Sprintf("/?email=%s", tc.email), nil)
			req.Header.Set("Accept", "application/json")
			rw := httptest.NewRecorder()
			p.GetProfile(rw, req)

			resp := rw.Result()
			if resp.StatusCode != tc.expectedStatusCode {
				t.Errorf("expected response status code to be %d but was %d", tc.expectedStatusCode, resp.StatusCode)
			}
			respBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response: %s", err.Error())
			}
			if resp.StatusCode != http.StatusOK {
				got := string(respBytes)
				if !strings.Contains(got, tc.expectedErrorString) {
					t.Logf("want: %#v", tc.expectedErrorString)
					t.Logf(" got: %#v", got)
					t.Errorf("got unexpected error string")
				}
			}

			if resp.StatusCode == http.StatusOK {
				profileResponse := getProfileResponse{}
				err := json.Unmarshal(respBytes, &profileResponse)
				if err != nil {
					t.Fatalf("error unmarshalling response to a getProfileResponse: %s", err.Error())
				}
				if profileResponse.Email != tc.email {
					t.Errorf("expected email in response to be %s but was %s", tc.email, profileResponse.Email)
				}
				var found bool
				for _, testGroup := range tc.groupEmails {
					for _, actualGroup := range profileResponse.Groups {
						if testGroup == actualGroup {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected to find group %s in response group slice but did not", testGroup)
						return
					}
					found = false
				}
			}

		})
	}
}

func TestRedeemCode(t *testing.T) {
	testCases := []struct {
		name                 string
		code                 string
		email                string
		providerRedeemError  error
		expectedSessionState *sessions.SessionState
		expectedSessionEmail string
		expectedError        bool
		expectedErrorString  string
	}{
		{
			name:                "with provider Redeem function returning an error",
			code:                "code",
			providerRedeemError: fmt.Errorf("error redeeming"),
			expectedError:       true,
			expectedErrorString: "error redeeming",
		},
		{
			name:                 "no error provider Redeem function, empty email in session state, error on retrieving email address from provider",
			code:                 "code",
			expectedSessionState: &sessions.SessionState{},
			expectedError:        true,
			expectedErrorString:  "no email included in session",
		},
		{
			name: "no error provider Redeem function, email in session state",
			code: "code",
			expectedSessionState: &sessions.SessionState{
				Email:           "emailAddress",
				AccessToken:     "accessToken",
				RefreshDeadline: time.Now(),
				RefreshToken:    "refreshToken",
			},
			expectedSessionEmail: "emailAddress",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)

			proxy, _ := NewAuthenticator(config,
				SetValidators([]options.Validator{options.NewMockValidator(true)}),
			)

			testURL, err := url.Parse("example.com")
			if err != nil {
				t.Fatalf("error parsing url %s", err.Error())
			}
			proxy.redirectURL = testURL
			testProvider := providers.NewTestProvider(testURL)
			testProvider.RedeemError = tc.providerRedeemError
			testProvider.Session = tc.expectedSessionState
			proxy.provider = testProvider
			sessionState, err := proxy.redeemCode(testURL.Host, tc.code)
			if tc.expectedError && err == nil {
				t.Errorf("expected error with message %s but no error was returned", tc.expectedErrorString)
			}
			if !tc.expectedError && err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}
			if err != nil {
				if tc.expectedErrorString != err.Error() {
					t.Errorf("expected error %s but got error %s", tc.expectedErrorString, err.Error())
				}
				return
			}
			if sessionState.Email != tc.expectedSessionEmail {
				t.Errorf("expected session state email to be %s but was %s", tc.expectedSessionState.Email, sessionState.Email)
			}
			if sessionState.AccessToken != tc.expectedSessionState.AccessToken {
				t.Errorf("expected session state access token to be %s but was %s", tc.expectedSessionState.AccessToken, sessionState.AccessToken)
			}
			if sessionState.RefreshDeadline != tc.expectedSessionState.RefreshDeadline {
				t.Errorf("expected session state email to be %s but was %s", tc.expectedSessionState.RefreshDeadline, sessionState.RefreshDeadline)
			}
			if sessionState.RefreshToken != tc.expectedSessionState.RefreshToken {
				t.Errorf("expected session state refresh token to be %s but was %s", tc.expectedSessionState.RefreshToken, sessionState.RefreshToken)
			}

		})
	}
}

func TestRedeemEndpoint(t *testing.T) {
	testCases := []struct {
		name                        string
		paramsMap                   map[string]string
		sessionState                *sessions.SessionState
		mockCipher                  *aead.MockCipher
		expectedGAPAuthHeader       string
		expectedStatusCode          int
		expectedResponseEmail       string
		expectedResponseAccessToken string
	}{
		{
			name:               "cipher error",
			mockCipher:         &aead.MockCipher{UnmarshalError: fmt.Errorf("mock cipher error")},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "refresh deadline expired for session state",
			mockCipher: &aead.MockCipher{},
			paramsMap: map[string]string{
				"code": "code",
			},
			sessionState: &sessions.SessionState{
				Email:            "email",
				RefreshToken:     "refresh",
				AccessToken:      "accesstoken",
				RefreshDeadline:  time.Now().Add(-time.Hour),
				LifetimeDeadline: time.Now().Add(time.Hour),
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "lifetime deadline expired for session state",
			mockCipher: &aead.MockCipher{},
			paramsMap: map[string]string{
				"code": "code",
			},
			sessionState: &sessions.SessionState{
				Email:            "email",
				RefreshToken:     "refresh",
				AccessToken:      "accesstoken",
				RefreshDeadline:  time.Now().Add(time.Hour),
				LifetimeDeadline: time.Now().Add(-time.Hour),
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "empty session returned",
			mockCipher:         &aead.MockCipher{},
			expectedStatusCode: http.StatusUnauthorized,
		},

		{
			name:       "all valid",
			mockCipher: &aead.MockCipher{},
			sessionState: &sessions.SessionState{
				RefreshDeadline:  time.Now().Add(time.Hour),
				Email:            "example@test.com",
				LifetimeDeadline: time.Now().Add(time.Hour),
				AccessToken:      "authToken",
				RefreshToken:     "",
			},
			expectedStatusCode:          http.StatusOK,
			expectedGAPAuthHeader:       "example@test.com",
			expectedResponseEmail:       "example@test.com",
			expectedResponseAccessToken: "authToken",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			p, _ := NewAuthenticator(config,
				setMockAuthCodeCipher(tc.mockCipher, tc.sessionState),
				setMockSessionStore(&sessions.MockSessionStore{}),
			)

			params := url.Values{}
			for k, v := range tc.paramsMap {
				params.Set(k, v)
			}

			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(params.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			p.Redeem(rw, req)
			resp := rw.Result()
			testutil.Equal(t, tc.expectedStatusCode, resp.StatusCode)

			respBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("error reading response body: %s", err.Error())
			}

			if resp.StatusCode == http.StatusOK {
				redeemResp := redeemResponse{}
				err = json.Unmarshal(respBytes, &redeemResp)
				if err != nil {
					t.Fatalf("error unmarshaling response: %s", err.Error())
				}
				if redeemResp.Email != tc.expectedResponseEmail {
					t.Errorf("expected redeem response email to be %s but was %s",
						tc.expectedResponseEmail, redeemResp.Email)
				}

				if redeemResp.AccessToken != tc.expectedResponseAccessToken {
					t.Errorf("expected redeem access token  to be %s but was %s",
						tc.expectedResponseAccessToken, redeemResp.AccessToken)
				}

				if resp.Header.Get("GAP-Auth") != tc.expectedGAPAuthHeader {
					t.Errorf("expected GAP-Auth response header to be %s but was %s", tc.expectedGAPAuthHeader, resp.Header.Get("GAP-Auth"))
				}
			}
		})
	}
}

type testRedeemResponse struct {
	SessionState *sessions.SessionState
	Error        error
}

func TestOAuthCallback(t *testing.T) {
	testCases := []struct {
		name               string
		paramsMap          map[string]string
		expectedError      error
		testRedeemResponse testRedeemResponse
		validEmail         bool
		csrfResp           *sessions.MockCSRFStore
		sessionStore       *sessions.MockSessionStore
		expectedRedirect   string
	}{
		{
			name: "error string in request",
			paramsMap: map[string]string{
				"error": "request error",
			},
			expectedError: HTTPError{Code: http.StatusForbidden, Message: "request error"},
		},
		{
			name:          "no code in request",
			paramsMap:     map[string]string{},
			expectedError: HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"},
		},
		{
			name: "no state in request",
			paramsMap: map[string]string{
				"code": "authCode",
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			expectedError: HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"},
		},
		{
			name: "redeem response error",
			paramsMap: map[string]string{
				"code": "authCode",
			},
			testRedeemResponse: testRedeemResponse{
				Error: fmt.Errorf("redeem error"),
			},
			expectedError: fmt.Errorf("redeem error"),
		},
		{
			name: "invalid state in request, not base64 encoded",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": "invalidState",
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			expectedError: HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"},
		},
		{
			name: "invalid state in request, not in format nonce:redirect_uri",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("invalidState")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			expectedError: HTTPError{Code: http.StatusInternalServerError, Message: "Invalid State"},
		},
		{
			name: "CSRF cookie not present",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				GetError: http.ErrNoCookie,
			},
			expectedError: HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"},
		},
		{
			name: "CSRF cookie value doesn't match state nonce",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},

			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "notstate",
				},
			},
			expectedError: HTTPError{Code: http.StatusForbidden, Message: "csrf failed"},
		},

		{
			name: "invalid email address",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:http://www.example.com/something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			expectedError: HTTPError{Code: http.StatusForbidden,
				Message: "We ran into some issues while validating your account: \"MockValidator error\""},
		},
		{
			name: "valid email, invalid redirect",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			validEmail:    true,
			expectedError: HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI"},
		},
		{
			name: "valid email, valid redirect, save error",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:http://www.example.com/something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			sessionStore: &sessions.MockSessionStore{
				SaveError: fmt.Errorf("saveError"),
			},
			validEmail:    true,
			expectedError: HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"},
		},
		{
			name: "valid email, valid redirect, valid save",
			paramsMap: map[string]string{
				"code":  "authCode",
				"state": base64.URLEncoding.EncodeToString([]byte("state:http://www.example.com/something")),
			},
			testRedeemResponse: testRedeemResponse{
				SessionState: &sessions.SessionState{
					Email:           "example@email.com",
					AccessToken:     "accessToken",
					RefreshDeadline: time.Now().Add(time.Hour),
					RefreshToken:    "refresh",
				},
			},
			csrfResp: &sessions.MockCSRFStore{
				Cookie: &http.Cookie{
					Name:  "something_csrf",
					Value: "state",
				},
			},
			sessionStore:     &sessions.MockSessionStore{},
			validEmail:       true,
			expectedRedirect: "http://www.example.com/something",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfiguration(t)
			proxy, _ := NewAuthenticator(config,
				SetValidators([]options.Validator{options.NewMockValidator(tc.validEmail)}),
				setMockCSRFStore(tc.csrfResp),
				setMockSessionStore(tc.sessionStore),
			)

			testURL, err := url.Parse("http://example.com")
			if err != nil {
				t.Fatalf("error parsing test url: %s", err.Error())
			}
			proxy.redirectURL = testURL
			testProvider := providers.NewTestProvider(testURL)
			testProvider.Session = tc.testRedeemResponse.SessionState
			testProvider.RedeemError = tc.testRedeemResponse.Error
			proxy.provider = testProvider

			params := &url.Values{}
			for param, val := range tc.paramsMap {
				params.Set(param, val)
			}

			rawQuery := params.Encode()
			req := httptest.NewRequest("GET", fmt.Sprintf("/?%s", rawQuery), nil)

			rw := httptest.NewRecorder()
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			redirect, err := proxy.getOAuthCallback(rw, req)
			testutil.Equal(t, tc.expectedError, err)
			if err == nil {
				testutil.Equal(t, tc.expectedRedirect, redirect)
				switch store := proxy.csrfStore.(type) {
				case *sessions.MockCSRFStore:
					testutil.Equal(t, store.ResponseCSRF, "")
				default:
					t.Errorf("invalid csrf store with type %t", store)
				}
			}
		})

	}
}

func TestGlobalHeaders(t *testing.T) {
	config := testConfiguration(t)
	proxy, _ := NewAuthenticator(config, setMockCSRFStore(&sessions.MockCSRFStore{}))

	// see middleware.go
	expectedHeaders := securityHeaders

	testCases := []struct {
		path string
	}{
		{"/callback"},
		{"/ping"},
		{"/profile"},
		{"/redeem"},
		{"/robots.txt"},
		{"/sign_in"},
		{"/sign_out"},
		{"/start"},
		{"/validate"},
		// even 404s get headers set
		{"/unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			rw := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", tc.path, nil)
			proxy.ServeMux.ServeHTTP(rw, req)
			for key, expectedVal := range expectedHeaders {
				gotVal := rw.Header().Get(key)
				if gotVal != expectedVal {
					t.Errorf("expected %s=%q, got %s=%q", key, expectedVal, key, gotVal)
				}
			}
		})
	}
}

func TestOAuthStart(t *testing.T) {
	testCases := []struct {
		Name               string
		RedirectURI        string
		ProxyRedirectURI   string
		ExpectedStatusCode int
	}{
		{
			Name:               "reject requests without a redirect",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "reject requests with a malicious auth",
			RedirectURI:        "https://auth.evil.com/sign_in",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "reject requests without a nested redirect",
			RedirectURI:        "https://auth.example.com/sign_in",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "reject requests with a malicious proxy",
			RedirectURI:        "https://auth.example.com/sign_in",
			ProxyRedirectURI:   "https://proxy.evil.com/path/to/badness",
			ExpectedStatusCode: http.StatusBadRequest,
		},
		{
			Name:               "accept requests with good redirect_uris",
			RedirectURI:        "https://auth.example.com/sign_in",
			ProxyRedirectURI:   "https://proxy.example.com/oauth/callback",
			ExpectedStatusCode: http.StatusFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			config := testConfiguration(t)
			provider := providers.NewTestProvider(nil)
			proxy, _ := NewAuthenticator(config,
				setTestProvider(provider),
				SetValidators([]options.Validator{options.NewMockValidator(true)}),
				setMockRedirectURL(),
				setMockCSRFStore(&sessions.MockCSRFStore{}),
			)

			params := url.Values{}
			if tc.RedirectURI != "" {
				redirectURL, _ := url.Parse(tc.RedirectURI)
				if tc.ProxyRedirectURI != "" {
					// NOTE: redirect signatures tested in middleware_test.go
					now := time.Now()
					sig := redirectURLSignature(tc.ProxyRedirectURI, now, config.ClientConfigs["proxy"].Secret)
					b64sig := base64.URLEncoding.EncodeToString(sig)
					redirectParams := url.Values{}
					redirectParams.Add("redirect_uri", tc.ProxyRedirectURI)
					redirectParams.Add("sig", b64sig)
					redirectParams.Add("ts", fmt.Sprint(now.Unix()))
					redirectURL.RawQuery = redirectParams.Encode()
				}
				params.Add("redirect_uri", redirectURL.String())
			}

			req := httptest.NewRequest("GET", "/start?"+params.Encode(), nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rw := httptest.NewRecorder()
			proxy.ServeMux.ServeHTTP(rw, req)

			if rw.Code != tc.ExpectedStatusCode {
				t.Errorf("expected status code %v but response status code is %v", tc.ExpectedStatusCode, rw.Code)
			}

		})
	}
}
