package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func testOptions() *Options {
	o := NewOptions()
	o.CookieSecret = testEncodedCookieSecret
	o.ClientID = "bazquux"
	o.ClientSecret = "xyzzyplugh"
	o.EmailDomains = []string{"*"}
	o.ProviderURLString = "https://www.example.com"
	o.UpstreamConfigsFile = "testdata/upstream_configs.yml"
	o.DefaultProviderSlug = "sso-auth"
	o.Providers = []string{"sso-auth"}
	o.Cluster = "sso"
	o.Scheme = "http"
	o.StatsdHost = "localhost"
	o.StatsdPort = 1234
	o.testTemplateVars = map[string]string{
		"cluster":     "sso",
		"root_domain": "dev",
	}
	o.DefaultUpstreamTimeout = time.Duration(1) * time.Second
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
		"missing setting: cluster",
		"missing setting: provider-url",
		"missing setting: upstream-configs",
		"missing setting: cookie-secret",
		"missing setting: client-id",
		"missing setting: client-secret",
		"missing setting: statsd-host",
		"missing setting: statsd-port",
		"Invalid value for COOKIE_SECRET; must decode to 32 or 64 bytes, but decoded to 0 bytes",
	})
	testutil.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())
}

func TestDefaultProviderApiSettings(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, nil, o.Validate())
	p := o.providers[o.DefaultProviderSlug].Data()
	testutil.Equal(t, "https://www.example.com/sign_in",
		p.SignInURL.String())
	testutil.Equal(t, "https://www.example.com/sign_out",
		p.SignOutURL.String())
	testutil.Equal(t, "https://www.example.com/redeem",
		p.RedeemURL.String())
	testutil.Equal(t, "https://www.example.com/validate",
		p.ValidateURL.String())
	testutil.Equal(t, "https://www.example.com/profile",
		p.ProfileURL.String())
	testutil.Equal(t, "", p.Scope)
}

func TestProviderURLValidation(t *testing.T) {
	testCases := []struct {
		name                              string
		providerURLString                 string
		providerURLInternalString         string
		expectedError                     string
		expectedProviderURLInternalString string
		expectedSignInURL                 string
	}{
		{
			name:              "http scheme preserved",
			providerURLString: "http://provider.example.com",
			expectedSignInURL: "http://provider.example.com/sign_in",
		},
		{
			name:              "https scheme preserved",
			providerURLString: "https://provider.example.com",
			expectedSignInURL: "https://provider.example.com/sign_in",
		},
		{
			name:                              "proxy provider url string based on providerURL",
			providerURLString:                 "https://provider.example.com",
			expectedProviderURLInternalString: "",
		},
		{
			name:                              "proxy provider url string based on proxyProviderURL",
			providerURLString:                 "https://provider.example.com",
			providerURLInternalString:         "https://provider-internal.example.com",
			expectedProviderURLInternalString: "https://provider-internal.example.com",
		},
		{
			name:              "scheme required",
			providerURLString: "//provider.example.com",
			expectedError: errorMsg([]string{
				`invalid value for provider-url: provider-url must include scheme and host`,
			}),
		},
		{
			name:              "scheme and host required",
			providerURLString: "/foo",
			expectedError: errorMsg([]string{
				`invalid value for provider-url: provider-url must include scheme and host`,
			}),
		},
		{
			name:              "invalid url rejected",
			providerURLString: "%ZZZ",
			expectedError: errorMsg([]string{
				`invalid value for provider-url: parse %ZZZ: invalid URL escape "%ZZ"`,
			}),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			o := testOptions()
			o.ProviderURLString = tc.providerURLString
			o.ProviderURLInternalString = tc.providerURLInternalString
			err := o.Validate()
			if tc.expectedError != "" {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if err.Error() != tc.expectedError {
					t.Errorf("expected error %q, got %q", tc.expectedError, err.Error())
				}
			}
			if tc.expectedSignInURL != "" {
				testutil.Equal(t, o.providers[o.DefaultProviderSlug].Data().SignInURL.String(), tc.expectedSignInURL)
			}
			if tc.expectedProviderURLInternalString != "" {
				testutil.Equal(t, o.providers[o.DefaultProviderSlug].Data().ProviderURLInternal.String(), tc.expectedProviderURLInternalString)
			}
		})
	}
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

func TestPassAccessToken(t *testing.T) {
	o := testOptions()
	testutil.Equal(t, false, o.PassAccessToken)
	o.PassAccessToken = true
	testutil.Equal(t, nil, o.Validate())
	testutil.Equal(t, true, o.PassAccessToken)
}
