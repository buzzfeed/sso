package providers

import (
	"net/url"

	"github.com/datadog/datadog-go/statsd"
)

// Provider is an interface exposing functions necessary to authenticate with a given provider.
type Provider interface {
	Data() *ProviderData
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(string, []string) ([]string, bool, error)
	UserGroups(string, []string) ([]string, error)
	ValidateSessionState(*SessionState, []string) bool
	RefreshSession(*SessionState, []string) (bool, error)
	GetSignInURL(redirectURL *url.URL, state string) *url.URL
	GetSignOutURL(redirectURL *url.URL) *url.URL
}

// New returns a new sso Provider
func New(provider string, p *ProviderData, sc *statsd.Client) Provider {
	return NewSSOProvider(p, sc)
}
