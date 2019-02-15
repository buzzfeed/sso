package providers

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/singleflight"

	"github.com/datadog/datadog-go/statsd"
)

var (
	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/golang-tip-compile-time-checks-to-ensure-your-type-satisfies-an-interface-c167afed3aae
	_ Provider = &SingleFlightProvider{}
)

// Error message for ErrUnexpectedReturnType
var (
	ErrUnexpectedReturnType = errors.New("received unexpected return type from single flight func call")
)

// SingleFlightProvider middleware provider that multiple requests for the same object
// to be processed as a single request. This is often called request collpasing or coalesce.
// This middleware leverages the golang singlelflight provider, with modifications for metrics.
//
// It's common among HTTP reverse proxy cache servers such as nginx, Squid or Varnish - they all call it something else but works similarly.
//
// * https://www.varnish-cache.org/docs/3.0/tutorial/handling_misbehaving_servers.html
// * http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock
// * http://wiki.squid-cache.org/Features/CollapsedForwarding
type SingleFlightProvider struct {
	StatsdClient *statsd.Client

	provider Provider

	single *singleflight.Group
}

// NewSingleFlightProvider instatiates a SingleFlightProvider given a provider and statsdClient
func NewSingleFlightProvider(provider Provider, StatsdClient *statsd.Client) *SingleFlightProvider {
	return &SingleFlightProvider{
		provider:     provider,
		single:       &singleflight.Group{},
		StatsdClient: StatsdClient,
	}
}

func (p *SingleFlightProvider) do(endpoint, key string, fn func() (interface{}, error)) (interface{}, error) {
	compositeKey := fmt.Sprintf("%s/%s", endpoint, key)
	resp, shared, err := p.single.Do(compositeKey, fn)
	if shared > 0 {
		tags := []string{fmt.Sprintf("endpoint:%s", endpoint)}
		p.StatsdClient.Incr("provider.singleflight", tags, float64(shared))
	}
	return resp, err
}

// Data calls the provider's Data function
func (p *SingleFlightProvider) Data() *ProviderData {
	return p.provider.Data()
}

// Redeem takes the redirectURL and a code and calls the provider function Redeem
func (p *SingleFlightProvider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	return p.provider.Redeem(redirectURL, code)
}

// ValidateGroup takes an email, allowedGroups, and userGroups and passes it to the provider's ValidateGroup function and returns the response
func (p *SingleFlightProvider) ValidateGroup(email string, allowedGroups []string) ([]string, bool, error) {
	return p.provider.ValidateGroup(email, allowedGroups)
}

// UserGroups takes an email and passes it to the provider's UserGroups function and returns the response
func (p *SingleFlightProvider) UserGroups(email string, groups []string) ([]string, error) {
	// sort the groups so that other requests may be able to use the cached request
	sort.Strings(groups)
	response, err := p.do("UserGroups", fmt.Sprintf("%s:%s", email, strings.Join(groups, ",")), func() (interface{}, error) {
		return p.provider.UserGroups(email, groups)
	})
	if err != nil {
		return nil, err
	}

	groups, ok := response.([]string)
	if !ok {
		return nil, ErrUnexpectedReturnType
	}

	return groups, nil
}

// ValidateSessionState calls the provider's ValidateSessionState function and returns the response
func (p *SingleFlightProvider) ValidateSessionState(s *sessions.SessionState, allowedGroups []string) bool {
	response, err := p.do("ValidateSessionState", s.AccessToken, func() (interface{}, error) {
		valid := p.provider.ValidateSessionState(s, allowedGroups)
		return valid, nil
	})
	if err != nil {
		return false
	}

	valid, ok := response.(bool)
	if !ok {
		return false
	}

	return valid
}

// RefreshSession takes in a SessionState and allowedGroups and
// returns false if the session is not refreshed and true if it is.
func (p *SingleFlightProvider) RefreshSession(s *sessions.SessionState, allowedGroups []string) (bool, error) {
	response, err := p.do("RefreshSession", s.RefreshToken, func() (interface{}, error) {
		return p.provider.RefreshSession(s, allowedGroups)
	})
	if err != nil {
		return false, err
	}

	r, ok := response.(bool)
	if !ok {
		return false, ErrUnexpectedReturnType
	}

	return r, nil
}

// GetSignInURL calls the GetSignInURL for the provider, which will return the sign in url
func (p *SingleFlightProvider) GetSignInURL(redirectURI *url.URL, finalRedirect string) *url.URL {
	return p.provider.GetSignInURL(redirectURI, finalRedirect)
}

// GetSignOutURL calls the GetSignOutURL for the provider, which will return the sign out url
func (p *SingleFlightProvider) GetSignOutURL(redirectURI *url.URL) *url.URL {
	return p.provider.GetSignOutURL(redirectURI)
}
