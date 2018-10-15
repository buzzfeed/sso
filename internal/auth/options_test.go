package auth

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func testOptions() *Options {
	o := NewOptions()
	o.CookieSecret = "foobar"
	o.ClientID = "bazquux"
	o.ClientSecret = "xyzzyplugh"
	o.EmailDomains = []string{"*"}
	o.ProxyClientID = "abcdef"
	o.ProxyClientSecret = "testtest"
	o.ProxyRootDomains = []string{"*"}
	o.StatsdHost = "statsdhost"
	o.StatsdPort = 12344
	o.Host = "/"
	o.CookieRefresh = time.Hour
	o.CookieSecret = testEncodedCookieSecret
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o := NewOptions()
	o.EmailDomains = []string{"*"}
	err := o.Validate()
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
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions()
	o.RedirectURL = "https://myhost.com/oauth2/callback"
	testutil.Equal(t, nil, o.Validate())
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	testutil.Equal(t, expected, o.redirectURL)
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())

	o.CookieSecret = testEncodedCookieSecret
	o.CookieRefresh = o.CookieExpire
	testutil.NotEqual(t, nil, o.Validate())

	o.CookieRefresh -= time.Duration(1)
	testutil.Equal(t, nil, o.Validate())
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key
	o.CookieSecret = testEncodedCookieSecret
	testutil.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = testEncodedCookieSecret
	testutil.Equal(t, nil, o.Validate())
}

func TestValidateCookie(t *testing.T) {
	o := testOptions()
	o.CookieName = "_valid_cookie_name"
	testutil.Equal(t, nil, o.Validate())
}

func TestValidateCookieBadName(t *testing.T) {
	o := testOptions()
	o.CookieName = "_bad_cookie_name{}"
	err := o.Validate()
	testutil.Equal(t, err.Error(), "Invalid configuration:\n"+
		fmt.Sprintf("  invalid cookie name: %q", o.CookieName))
}
