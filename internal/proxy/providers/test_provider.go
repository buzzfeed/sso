package providers

import (
	"net/url"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

// TestProvider is a mock provider
type TestProvider struct {
	RefreshSessionFunc  func(*sessions.SessionState, []string) (bool, error)
	ValidateSessionFunc func(*sessions.SessionState, []string) bool
	RedeemFunc          func(string, string) (*sessions.SessionState, error)
	UserGroupsFunc      func(string, []string, string) ([]string, error)
	ValidateGroupsFunc  func(string, []string, string) ([]string, bool, error)
	*ProviderData
}

// NewTestProvider returns a new TestProvider
func NewTestProvider(_ *url.URL, _ string) *TestProvider {
	host := "localhost"
	return &TestProvider{
		ProviderData: &ProviderData{
			ProviderName: "Test Provider",
			SignInURL: &url.URL{
				Scheme: "http",
				Host:   host,
				Path:   "/oauth/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   host,
				Path:   "/oauth/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   host,
				Path:   "/api/v1/profile",
			},
			SignOutURL: &url.URL{
				Scheme: "http",
				Host:   host,
				Path:   "/oauth/sign_out",
			},
			Scope: "profile.email",
		},
	}
}

// ValidateSessionState mocks the ValidateSessionState function
func (tp *TestProvider) ValidateSessionState(s *sessions.SessionState, groups []string) bool {
	return tp.ValidateSessionFunc(s, groups)
}

// Redeem mocks the provider Redeem function
func (tp *TestProvider) Redeem(redirectURL string, token string) (*sessions.SessionState, error) {
	return tp.RedeemFunc(redirectURL, token)
}

// RefreshSession mocks the RefreshSession function
func (tp *TestProvider) RefreshSession(s *sessions.SessionState, g []string) (bool, error) {
	return tp.RefreshSessionFunc(s, g)
}

// UserGroups mocks the UserGroups function
func (tp *TestProvider) UserGroups(email string, groups []string, accessToken string) ([]string, error) {
	return tp.UserGroupsFunc(email, groups, accessToken)
}

// ValidateGroup mocks the ValidateGroup function
func (tp *TestProvider) ValidateGroup(email string, groups []string, accessToken string) ([]string, bool, error) {
	return tp.ValidateGroupsFunc(email, groups, accessToken)
}

// GetSignOutURL mocks GetSignOutURL function
func (tp *TestProvider) GetSignOutURL(redirectURL *url.URL) *url.URL {
	return tp.Data().SignOutURL
}

// GetSignInURL mocks GetSignInURL
func (tp *TestProvider) GetSignInURL(redirectURL *url.URL, state string) *url.URL {
	a := *tp.Data().SignInURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return &a
}
