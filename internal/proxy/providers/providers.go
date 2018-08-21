package providers

import (
	"net/url"

	"github.com/datadog/datadog-go/statsd"
)

// Provider is an interface exposing functions necessary to authenticate with a given provider.
type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*SessionState) (string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(string, []string) ([]string, bool, error)
	UserGroups(string, []string) ([]string, error)
	ValidateSessionState(*SessionState, []string) bool
	GetSignInURL(redirectURL *url.URL, finalRedirect string) *url.URL
	GetSignOutURL(redirectURL *url.URL) *url.URL
	RefreshSession(*SessionState, []string) (bool, error)
}

// New returns a new sso Provider
func New(provider string, p *ProviderData, sc *statsd.Client) Provider {
	return NewSSOProvider(p, sc)
}
