package providers

import (
	"net/url"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

// Provider is an interface exposing functions necessary to authenticate with a given provider.
type Provider interface {
	Data() *ProviderData
	Redeem(string, string) (*sessions.SessionState, error)
	ValidateGroup(string, []string, string) ([]string, bool, error)
	UserGroups(string, []string, string) ([]string, error)
	ValidateSessionToken(*sessions.SessionState) bool
	RefreshSessionToken(*sessions.SessionState) (bool, error)
	GetSignInURL(redirectURL *url.URL, finalRedirect string) *url.URL
	GetSignOutURL(redirectURL *url.URL) *url.URL
}

// New returns a new sso Provider
func New(provider string, p *ProviderData, sc *statsd.Client) Provider {
	return NewSSOProvider(p, sc)
}
