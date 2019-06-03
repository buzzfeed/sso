package auth

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func testOptions(t *testing.T) map[string]*Options {
	o, err := NewOptions([]string{"authenticator", "provider", "global"})
	if err != nil {
		t.Fatalf("error while instantiating config options: %s", err.Error())
	}

	o["authenticator"].CookieSecret = "foobar"
	o["authenticator"].EmailDomains = []string{"*"}
	o["authenticator"].ProxyClientID = "abcdef"
	o["authenticator"].ProxyClientSecret = "testtest"
	o["authenticator"].ProxyRootDomains = []string{"*"}
	o["authenticator"].Host = "/"
	o["authenticator"].CookieRefresh = time.Hour
	o["authenticator"].CookieSecret = testEncodedCookieSecret

	o["provider"].ClientID = "bazquux"
	o["provider"].ClientSecret = "xyzzyplugh"

	o["global"].StatsdHost = "statsdhost"
	o["global"].StatsdPort = 12344
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o, _ := NewOptions([]string{"authenticator", "provider", "global"})
	o["authenticator"].EmailDomains = []string{"*"}
	err := Validate(o)
	testutil.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: cookie-secret",
		"missing setting: client-id",
		"missing setting: client-secret",
		"missing setting: proxy-root-domain",
		"missing setting: proxy-client-id",
		"missing setting: proxy-client-secret",
		"missing setting: required-host-header",
		"Invalid value for COOKIE_SECRET; must decode to 32 or 64 bytes, but decoded to 0 bytes",
		"missing setting: no host specified for statsd metrics collections",
		"missing setting: no port specified for statsd metrics collections",
	})
	testutil.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions(t)
	testutil.Equal(t, nil, Validate(o))
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions(t)
	o["provider"].RedirectURL = "https://myhost.com/oauth2/callback"
	testutil.Equal(t, nil, Validate(o))
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	testutil.Equal(t, expected, o["authenticator"].redirectURL)
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions(t)
	testutil.Equal(t, nil, Validate(o))

	o["authenticator"].CookieSecret = testEncodedCookieSecret
	o["authenticator"].CookieRefresh = o["authenticator"].CookieExpire
	testutil.NotEqual(t, nil, Validate(o))

	o["authenticator"].CookieRefresh -= time.Duration(1)
	testutil.Equal(t, nil, Validate(o))
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions(t)
	testutil.Equal(t, nil, Validate(o))

	// 32 byte, base64 (urlsafe) encoded key
	o["authenticator"].CookieSecret = testEncodedCookieSecret
	testutil.Equal(t, nil, Validate(o))

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o["authenticator"].CookieSecret = testEncodedCookieSecret
	testutil.Equal(t, nil, Validate(o))
}

func TestValidateCookie(t *testing.T) {
	o := testOptions(t)
	o["authenticator"].CookieName = "_valid_cookie_name"
	testutil.Equal(t, nil, Validate(o))
}

func TestValidateCookieBadName(t *testing.T) {
	o := testOptions(t)
	o["authenticator"].CookieName = "_bad_cookie_name{}"
	err := Validate(o)
	testutil.Equal(t, err.Error(), "Invalid configuration:\n"+
		fmt.Sprintf("  invalid cookie name: %q", o["authenticator"].CookieName))
}
