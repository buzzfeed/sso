package providers

import (
	"sort"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/groups"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

var (
	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/golang-tip-compile-time-checks-to-ensure-your-type-satisfies-an-interface-c167afed3aae
	_ Provider = &GroupCache{}
)

type Cache interface {
	Get(key groups.CacheKey) (groups.CacheEntry, bool)
	Set(key groups.CacheKey, val groups.CacheEntry)
	Purge(key groups.CacheKey)
}

// GroupCache is designed to act as a provider while wrapping subsequent provider's functions,
// while also offering a caching mechanism (specifically used for group caching at the moment).
type GroupCache struct {
	statsdClient *statsd.Client
	provider     Provider
	cache        Cache
}

// NewGroupCache returns a new GroupCache (which includes a LocalCache from the groups package)
func NewGroupCache(provider Provider, ttl time.Duration, statsdClient *statsd.Client, tags []string) *GroupCache {
	return &GroupCache{
		statsdClient: statsdClient,
		provider:     provider,
		cache:        groups.NewLocalCache(ttl, statsdClient, tags),
	}
}

// SetStatsdClient calls the provider's SetStatsdClient function.
func (p *GroupCache) SetStatsdClient(statsdClient *statsd.Client) {
	p.statsdClient = statsdClient
	p.provider.SetStatsdClient(statsdClient)
}

// Data returns the provider Data
func (p *GroupCache) Data() *ProviderData {
	return p.provider.Data()
}

// Redeem wraps the provider's Redeem function
func (p *GroupCache) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	return p.provider.Redeem(redirectURL, code)
}

// ValidateSessionState wraps the provider's ValidateSessionState function.
func (p *GroupCache) ValidateSessionState(s *sessions.SessionState) bool {
	return p.provider.ValidateSessionState(s)
}

// GetSignInURL wraps the provider's GetSignInURL function.
func (p *GroupCache) GetSignInURL(redirectURI, finalRedirect string) string {
	return p.provider.GetSignInURL(redirectURI, finalRedirect)
}

// RefreshSessionIfNeeded wraps the provider's RefreshSessionIfNeeded function.
func (p *GroupCache) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	return p.provider.RefreshSessionIfNeeded(s)
}

// ValidateGroupMembership wraps the provider's ValidateGroupMembership around calls to check local cache for group membership information.
func (p *GroupCache) ValidateGroupMembership(email string, allowedGroups []string, accessToken string) ([]string, error) {
	// Create a cache key and check to see if it's in the cache. If not, call the provider's
	// ValidateGroupMembership function and cache the result.
	sort.Strings(allowedGroups)
	key := groups.CacheKey{
		Email:         email,
		AllowedGroups: strings.Join(allowedGroups, ","),
	}

	val, ok := p.cache.Get(key)
	if ok {
		p.statsdClient.Incr("provider.groupcache",
			[]string{
				"action:ValidateGroupMembership",
				"cache:hit",
			}, 1.0)
		return val.ValidGroups, nil
	}

	// The key isn't in the cache, so pass the call on to the subsequent provider
	p.statsdClient.Incr("provider.groupcache",
		[]string{
			"action:ValidateGroupMembership",
			"cache:miss",
		}, 1.0)

	validGroups, err := p.provider.ValidateGroupMembership(email, allowedGroups, accessToken)
	if err != nil {
		return nil, err
	}

	entry := groups.CacheEntry{
		ValidGroups: validGroups,
	}
	p.cache.Set(key, entry)
	return validGroups, nil
}

// Revoke wraps the provider's Revoke function.
func (p *GroupCache) Revoke(s *sessions.SessionState) error {
	return p.provider.Revoke(s)
}

// RefreshAccessToken wraps the provider's RefreshAccessToken function.
func (p *GroupCache) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	return p.provider.RefreshAccessToken(refreshToken)
}

// Stop calls the providers stop function.
func (p *GroupCache) Stop() {
	p.provider.Stop()
}
