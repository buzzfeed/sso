package providers

import (
	"net/url"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

// TestProvider is a mock provider
type TestProvider struct {
	RefreshSessionTokenFunc  func(*sessions.SessionState) (bool, error)
	ValidateSessionTokenFunc func(*sessions.SessionState) bool
	RedeemFunc               func(string, string) (*sessions.SessionState, error)
	UserGroupsFunc           func(string, []string, string) ([]string, error)
	ValidateGroupsFunc       func(string, []string, string) ([]string, bool, error)
	*ProviderData
}

// NewTestProvider returns a new TestProvider
func NewTestProvider(providerURL *url.URL, emailAddress string) *TestProvider {
	return &TestProvider{
		ProviderData: &ProviderData{
			ProviderName: "Test Provider",
			SignInURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/api/v1/profile",
			},
			SignOutURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/sign_out",
			},
			Scope: "profile.email",
		},
	}
}

// ValidateSessionState mocks the ValidateSessionState function
func (tp *TestProvider) ValidateSessionToken(s *sessions.SessionState) bool {
	return tp.ValidateSessionTokenFunc(s)
}

// Redeem mocks the provider Redeem function
func (tp *TestProvider) Redeem(redirectURL string, token string) (*sessions.SessionState, error) {
	return tp.RedeemFunc(redirectURL, token)
}

// RefreshSessionToken mocks the RefreshSessionToken function
func (tp *TestProvider) RefreshSessionToken(s *sessions.SessionState) (bool, error) {
	return tp.RefreshSessionTokenFunc(s)
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
