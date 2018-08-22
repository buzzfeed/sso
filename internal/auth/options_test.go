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
	o.StatsdHost = "statsdhost"
	o.StatsdPort = 12344
	o.Host = "/"
	o.CookieRefresh = time.Hour
	o.CookieSecret = testEncodedCookieSecret
	o.OldCookieSecret = testEncodedCookieSecret
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
		"missing setting: proxy-client-id",
		"missing setting: proxy-client-secret",
		"missing setting: required-host-header",
		"cookie_secret must be 32 or 64 bytes to create an AES cipher but is 0 bytes.",
		"missing setting: no host specified for statsd metrics collections",
		"missing setting: no port specified for statsd metrics collections",
	})
	testutil.Equal(t, expected, err.Error())
}

func TestGoogleGroupInvalidFile(t *testing.T) {
	defer func() {
		r := recover()
		panicMsg := "could not read google credentials file"
		if r != panicMsg {
			t.Errorf("expected panic with message %s but got %s", panicMsg, r)
		}
	}()
	o := testOptions()
	o.GoogleAdminEmail = "admin@example.com"
	o.GoogleServiceAccountJSON = "file_doesnt_exist.json"
	o.Validate()

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

func TestDefaultProviderApiSettings(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())
	p := o.provider.Data()
	testutil.Equal(t, "https://accounts.google.com/o/oauth2/auth?access_type=offline",
		p.SignInURL.String())
	testutil.Equal(t, "https://www.googleapis.com/oauth2/v3/token",
		p.RedeemURL.String())
	testutil.Equal(t, "", p.ProfileURL.String())
	testutil.Equal(t, "profile email", p.Scope)
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())

	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	o.CookieRefresh = o.CookieExpire
	testutil.NotEqual(t, nil, o.Validate())

	o.CookieRefresh -= time.Duration(1)
	testutil.Equal(t, nil, o.Validate())
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	testutil.Equal(t, nil, o.Validate())

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
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
