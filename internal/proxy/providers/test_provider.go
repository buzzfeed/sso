package providers

import (
	"net/url"
)

// TestProvider is a mock provider
type TestProvider struct {
	RefreshSessionFunc  func(*SessionState, []string) (bool, error)
	ValidateSessionFunc func(*SessionState, []string) bool
	RedeemFunc          func(string, string) (*SessionState, error)
	UserGroupsFunc      func(string, []string) ([]string, error)
	ValidateGroupsFunc  func(string, []string) ([]string, bool, error)
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
func (tp *TestProvider) ValidateSessionState(s *SessionState, groups []string) bool {
	return tp.ValidateSessionFunc(s, groups)
}

// Redeem mocks the provider Redeem function
func (tp *TestProvider) Redeem(redirectURL string, token string) (*SessionState, error) {
	return tp.RedeemFunc(redirectURL, token)
}

// RefreshSession mocks the RefreshSession function
func (tp *TestProvider) RefreshSession(s *SessionState, g []string) (bool, error) {
	return tp.RefreshSessionFunc(s, g)
}

// UserGroups mocks the UserGroups function
func (tp *TestProvider) UserGroups(email string, groups []string) ([]string, error) {
	return tp.UserGroupsFunc(email, groups)
}

// ValidateGroup mocks the ValidateGroup function
func (tp *TestProvider) ValidateGroup(email string, groups []string) ([]string, bool, error) {
	return tp.ValidateGroupsFunc(email, groups)
}

// GetSignOutURL mocks GetSignOutURL function
func (tp *TestProvider) GetSignOutURL(redirectURL *url.URL) *url.URL {
	a := *tp.Data().SignOutURL
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("redirect_uri", rawRedirect)
	a.RawQuery = params.Encode()
	return &a
}

// GetSignInURL mocks GetSignInURL
func (tp *TestProvider) GetSignInURL(redirectURL *url.URL, state string) *url.URL {
	return tp.Data().SignInURL
}
