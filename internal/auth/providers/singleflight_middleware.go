package providers

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/singleflight"

	"github.com/datadog/datadog-go/statsd"
)

var (
	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/golang-tip-compile-time-checks-to-ensure-your-type-satisfies-an-interface-c167afed3aae
	_ Provider = &SingleFlightProvider{}
)

// ErrUnexpectedReturnType is an error for an unexpected return type
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

// NewSingleFlightProvider returns a new SingleFlightProvider
func NewSingleFlightProvider(provider Provider) *SingleFlightProvider {
	return &SingleFlightProvider{
		provider: provider,
		single:   &singleflight.Group{},
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

// SetStatsdClient calls the provider's SetStatsdClient function.
func (p *SingleFlightProvider) SetStatsdClient(StatsdClient *statsd.Client) {
	p.StatsdClient = StatsdClient
	p.provider.SetStatsdClient(StatsdClient)
}

// Data returns the provider data
func (p *SingleFlightProvider) Data() *ProviderData {
	return p.provider.Data()
}

// Redeem wraps the provider's Redeem function.
func (p *SingleFlightProvider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	return p.provider.Redeem(redirectURL, code)
}

// ValidateSessionState wraps the provider's ValidateSessionState in a single flight call.
func (p *SingleFlightProvider) ValidateSessionState(s *sessions.SessionState) bool {
	response, err := p.do("ValidateSessionState", s.AccessToken, func() (interface{}, error) {
		valid := p.provider.ValidateSessionState(s)
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

// GetSignInURL calls the provider's GetSignInURL function.
func (p *SingleFlightProvider) GetSignInURL(redirectURI, finalRedirect string) string {
	return p.provider.GetSignInURL(redirectURI, finalRedirect)
}

// RefreshSessionIfNeeded wraps the provider's RefreshSessionIfNeeded function in a single flight
// call.
func (p *SingleFlightProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	response, err := p.do("RefreshSessionIfNeeded", s.RefreshToken, func() (interface{}, error) {
		return p.provider.RefreshSessionIfNeeded(s)
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

// ValidateGroupMembership wraps the provider's GroupsResource function in a single flight call.
func (p *SingleFlightProvider) ValidateGroupMembership(email string, allowedGroups []string, accessToken string) ([]string, error) {
	sort.Strings(allowedGroups)
	response, err := p.do("ValidateGroupMembership", fmt.Sprintf("%s:%s", email, strings.Join(allowedGroups, ",")),
		func() (interface{}, error) {
			return p.provider.ValidateGroupMembership(email, allowedGroups, accessToken)
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

// Revoke wraps the provider's Revoke function in a single flight call.
func (p *SingleFlightProvider) Revoke(s *sessions.SessionState) error {
	_, err := p.do("Revoke", s.AccessToken, func() (interface{}, error) {
		err := p.provider.Revoke(s)
		return nil, err
	})
	return err
}

// RefreshAccessToken wraps the provider's RefreshAccessToken function in a single flight call.
func (p *SingleFlightProvider) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	type Response struct {
		AccessToken string
		ExpiresIn   time.Duration
	}
	response, err := p.do("RefreshAccessToken", refreshToken, func() (interface{}, error) {
		accessToken, expiresIn, err := p.provider.RefreshAccessToken(refreshToken)
		if err != nil {
			return nil, err
		}

		return &Response{
			AccessToken: accessToken,
			ExpiresIn:   expiresIn,
		}, nil
	})
	if err != nil {
		return "", 0, err
	}

	r, ok := response.(*Response)
	if !ok {
		return "", 0, ErrUnexpectedReturnType
	}

	return r.AccessToken, r.ExpiresIn, nil
}

// Stop calls the provider's stop function
func (p *SingleFlightProvider) Stop() {
	p.provider.Stop()
}
