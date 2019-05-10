package providers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/groups"
	"github.com/buzzfeed/sso/internal/pkg/testutil"
	"github.com/datadog/datadog-go/statsd"
)

func newTestProviderServer(body []byte, code int) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(code)
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

// We define an Okta provider because the cache being tested here is currently
// only used by the Okta provider.
func newTestProvider(providerData *ProviderData, t *testing.T) *OktaProvider {
	if providerData == nil {
		providerData = &ProviderData{
			ProviderName: "",
			ClientID:     "",
			ClientSecret: "",
			SignInURL:    &url.URL{},
			RedeemURL:    &url.URL{},
			RevokeURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""}
	}
	provider, err := NewOktaProvider(providerData, "test.okta.com", "default")
	if err != nil {
		t.Fatalf("new okta provider returns unexpected error: %q", err)
	}
	return provider
}

func TestCachedGroupsAreNotUsed(t *testing.T) {

	type serverResp struct {
		Groups []string `json:"groups"`
	}

	//set up the test server
	provider := newTestProvider(nil, t)
	resp := serverResp{
		Groups: []string{"allowedGroup1", "allowedGroup2"},
	}
	body, err := json.Marshal(resp)
	testutil.Equal(t, nil, err)
	var server *httptest.Server
	provider.ProfileURL, server = newTestProviderServer(body, http.StatusOK)
	defer server.Close()

	// set up the cache
	ttl := time.Millisecond * 10
	statsdClient, _ := statsd.New("127.0.0.1:8125")
	tags := []string{"tags:test"}
	GroupsCache := NewGroupCache(provider, ttl, statsdClient, tags)

	// The below cached `MatchedGroups` should not be returned because the list of
	// allowed groups we pass in are different to the cached `AllowedGroups`. It should instead
	// make a call to the Provider (our test server).
	cacheKey := groups.CacheKey{
		Email:         "email@test.com",
		AllowedGroups: "allowedGroup1",
	}
	cacheData := groups.CacheEntry{
		ValidGroups: []string{"allowedGroup1", "allowedGroup2", "allowedGroup3"},
	}
	GroupsCache.cache.Set(cacheKey, cacheData)

	// If the groups stored in the `serverResp` struct are returned, it means the
	// cache was skipped because the allowedGroups that we pass in are different to
	// those stored in the cache. This is the outcome we expect in this test.
	email := "email@test.com"
	actualAllowedGroups := []string{"allowedGroup2", "allowedGroup1"}
	accessToken := "123456"
	actualMatchedGroups, err := GroupsCache.ValidateGroupMembership(email, actualAllowedGroups, accessToken)
	if err != nil {
		t.Fatalf("unexpected error caused while validating group membership: %q", err)
	}
	if !reflect.DeepEqual(actualMatchedGroups, actualAllowedGroups) {
		t.Logf("expected groups to match: %q", actualAllowedGroups)
		t.Logf("  actual groups returned: %q", actualMatchedGroups)
		if reflect.DeepEqual(actualMatchedGroups, cacheData.ValidGroups) {
			t.Fatalf("It looks like the groups in the cache were returned. In this case, the cache should have been skipped")
		}
		t.Fatalf("Unexpected groups returned.")
	}

	// We want to test that the groups returned are *now* cached, so we change the resp
	// that the test server will send. If it matches this new response, we know the cache
	// was skipped, which we do not expect to happen.
	resp = serverResp{
		Groups: []string{"allowedGroup1", "allowedGroup2"},
	}
	body, err = json.Marshal(resp)
	testutil.Equal(t, nil, err)
	provider.ProfileURL, server = newTestProviderServer(body, http.StatusOK)
	defer server.Close()

	actualMatchedGroups, err = GroupsCache.ValidateGroupMembership(email, actualAllowedGroups, accessToken)
	if err != nil {
		t.Fatalf("unexpected error caused while validating group membership: %q", err)
	}
	if !reflect.DeepEqual(actualMatchedGroups, actualAllowedGroups) {
		t.Logf("expected groups to match: %q", actualAllowedGroups)
		t.Logf("  actual groups returned: %q", actualMatchedGroups)
		if reflect.DeepEqual(actualMatchedGroups, resp.Groups) {
			t.Fatalf("It looks like the cache was skipped, and the provider was called. In this case, the cache should have been used")
		}
	}

}

// maybe we can skip this test, as the above test technically tests for the same thing, but just in a slightly more obfuscated way.
func TestCachedGroupsAreUsed(t *testing.T) {
	provider := newTestProvider(nil, t)

	// set up the cache
	ttl := time.Millisecond * 10
	statsdClient, _ := statsd.New("127.0.0.1:8125")
	tags := []string{"tags:test"}
	GroupsCache := NewGroupCache(provider, ttl, statsdClient, tags)

	// In this case, the below `MatchedGroups` should be returned because the list of
	// allowed groups are pass in match them.
	cacheKey := groups.CacheKey{
		Email:         "email@test.com",
		AllowedGroups: "allowedGroup1,allowedGroup2,allowedGroup3",
	}
	cacheData := groups.CacheEntry{
		ValidGroups: []string{"allowedGroup1", "allowedGroup2", "allowedGroup3"},
	}
	GroupsCache.cache.Set(cacheKey, cacheData)

	// We haven't set up a test server in this case because we pass in a list of allowed groups
	// that match the allowed groups in the cache, so the cached matched groups should be used
	// If the cache is skipped, an error will probably be returned when it tries to call the
	// provider endpoint.
	email := "email@test.com"
	actualAllowedGroups := []string{"allowedGroup1", "allowedGroup2", "allowedGroup3"}
	accessToken := "123456"
	actualMatchedGroups, err := GroupsCache.ValidateGroupMembership(email, actualAllowedGroups, accessToken)
	if err != nil {
		t.Fatalf("unexpected error caused while validating group membership: %q", err)
	}
	if !reflect.DeepEqual(actualMatchedGroups, actualAllowedGroups) {
		t.Logf("expected groups to match: %q", actualAllowedGroups)
		t.Logf("  actual groups returned: %q", actualMatchedGroups)
		t.Fatalf("unexpected groups returned")
	}
}
