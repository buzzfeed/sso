package providers

import (
	"net/url"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

// TestProvider is a test implementation of the Provider interface.
type TestProvider struct {
	*ProviderData

	ValidToken   bool
	ValidGroup   bool
	SignInURL    string
	Refresh      bool
	RefreshFunc  func(string) (string, time.Duration, error)
	RefreshError error
	Session      *sessions.SessionState
	RedeemError  error
	RevokeError  error
	Groups       []string
	GroupsError  error
	GroupsCall   int
}

// NewTestProvider creates a new mock test provider.
func NewTestProvider(providerURL *url.URL) *TestProvider {
	return &TestProvider{
		ProviderData: &ProviderData{
			ProviderSlug: "",
			ProviderName: "Test Provider",
			SignInURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/profile",
			},
			ValidateURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/validate",
			},
			Scope: "profile.email",
		},
	}
}

// ValidateSessionState returns the mock provider's ValidToken field value.
func (tp *TestProvider) ValidateSessionState(*sessions.SessionState) bool {
	return tp.ValidToken
}

// GetSignInURL returns the mock provider's SignInURL field value.
func (tp *TestProvider) GetSignInURL(redirectURI, finalRedirect string) string {
	return tp.SignInURL
}

// RefreshSessionIfNeeded returns the mock provider's Refresh value, or an error.
func (tp *TestProvider) RefreshSessionIfNeeded(*sessions.SessionState) (bool, error) {
	return tp.Refresh, tp.RefreshError
}

// RefreshAccessToken returns the mock provider's refresh access token information
func (tp *TestProvider) RefreshAccessToken(s string) (string, time.Duration, error) {
	return tp.RefreshFunc(s)
}

// Revoke returns nil
func (tp *TestProvider) Revoke(*sessions.SessionState) error {
	return tp.RevokeError
}

// ValidateGroupMembership returns the mock provider's GroupsError if not nil, or the Groups field value.
func (tp *TestProvider) ValidateGroupMembership(string, []string, string) ([]string, error) {
	return tp.Groups, tp.GroupsError
}

// Redeem returns the mock provider's Session and RedeemError field value.
func (tp *TestProvider) Redeem(redirectURI, code string) (*sessions.SessionState, error) {
	return tp.Session, tp.RedeemError

}

// Stop fulfills the Provider interface
func (tp *TestProvider) Stop() {
	return
}

func (tp *TestProvider) AssignStatsdClient(_ *statsd.Client) {
	return
}

func (tp *TestProvider) Data() *ProviderData {
	return tp.ProviderData
}
