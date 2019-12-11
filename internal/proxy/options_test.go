package proxy

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
	"github.com/datadog/datadog-go/statsd"
)

func TestSetUpstreamConfigs(t *testing.T) {
	testCases := []struct {
		name            string
		upstreamConfigs *UpstreamConfigs
		serverConfig    ServerConfig
		expectedErrMsg  string
	}{
		{
			name: "missing settings error",
			upstreamConfigs: &UpstreamConfigs{
				upstreamConfigs: []*UpstreamConfig{
					{Service: "invalidUpstream", Timeout: time.Duration(24) * time.Second},
					{Service: "validUpstream", Timeout: time.Duration(24) * time.Second, AllowedGroups: []string{"customGroup"}},
				},
			},
			serverConfig: ServerConfig{
				TimeoutConfig: &TimeoutConfig{Write: time.Duration(5) * time.Second},
			},
			expectedErrMsg: "missing setting: ALLOWED_EMAIL_DOMAINS, ALLOWED_EMAIL_ADDRESSES, ALLOWED_GROUPS default in environment or override in upstream config in the following upstreams: [invalidUpstream]",
		},
		{
			name: "upstream config successfully set",
			upstreamConfigs: &UpstreamConfigs{
				upstreamConfigs: []*UpstreamConfig{
					{
						Service:               "bar",
						Timeout:               time.Duration(24) * time.Second,
						AllowedEmailDomains:   []string{"foo.com"},
						AllowedEmailAddresses: []string{"bar@bar.com"},
						AllowedGroups:         []string{"customGroup"},
					},
				},
			},
			serverConfig: ServerConfig{
				TimeoutConfig: &TimeoutConfig{
					Write: time.Duration(5) * time.Second,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			var serverConfigTimeoutShouldChange bool
			if *&tc.upstreamConfigs.upstreamConfigs[0].Timeout > tc.serverConfig.TimeoutConfig.Write {
				serverConfigTimeoutShouldChange = true
			}

			err := SetUpstreamConfigs(tc.upstreamConfigs, CookieConfig{}, tc.serverConfig)
			if err == nil && tc.expectedErrMsg != "" {
				t.Fatalf("expected error but error was nil")
			}
			if err != nil && tc.expectedErrMsg == "" {
				t.Fatalf("expected no error but got: %v", err)
			}
			if err != nil && err.Error() != tc.expectedErrMsg {
				t.Logf("expected: %q", tc.expectedErrMsg)
				t.Logf("     got: %q", err)
				t.Fatalf("unexpected error while setting upstream configs")
			}

			if serverConfigTimeoutShouldChange {
				if tc.serverConfig.TimeoutConfig.Write != *&tc.upstreamConfigs.upstreamConfigs[0].Timeout {
					t.Logf("server timeout: %v", tc.serverConfig.TimeoutConfig.Write)
					t.Logf("upstream timeout: %v", *&tc.upstreamConfigs.upstreamConfigs[0].Timeout)
					t.Fatalf("expected server timeout to be reset to match upstream timeout")
				}
			}
		})
	}
}

func TestUpstreamConfigsFile(t *testing.T) {
	testCases := []struct {
		name            string
		rawConfig       []byte
		upstreamConfigs *UpstreamConfigs
		serverConfig    ServerConfig
		configFilePath  string
		expectedErrMsg  string

		wantConfig *UpstreamConfig
	}{
		{
			name:           "invalid upstream config file path",
			configFilePath: "foo",
			upstreamConfigs: &UpstreamConfigs{
				DefaultConfig: DefaultConfig{
					AllowedGroups: []string{"defaultGroup"},
					ResetDeadline: time.Duration(5) * time.Second,
				},
				Scheme: "https",
			},
			serverConfig: ServerConfig{
				TimeoutConfig: &TimeoutConfig{
					Write: time.Duration(5) * time.Second,
				},
			},
			wantConfig:     &UpstreamConfig{},
			expectedErrMsg: "error reading upstream configs file: open foo: no such file or directory",
		},

		{
			name: "upstream configs successfully created from file and config vars, with defaults holding",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
    options:
      reset_deadline: 100ms
`),

			upstreamConfigs: &UpstreamConfigs{
				DefaultConfig: DefaultConfig{
					AllowedGroups: []string{"defaultGroup"},
					ResetDeadline: time.Duration(5) * time.Second,
				},
				Scheme: "https",
			},

			serverConfig: ServerConfig{
				TimeoutConfig: &TimeoutConfig{
					Write: time.Duration(5) * time.Second,
				},
			},

			wantConfig: &UpstreamConfig{
				Service: "bar",
				// AllowedGroups: default config value should be used
				AllowedGroups: []string{"defaultGroup"},
				// ResetDeadline: upstream config value should be used, default ignored
				ResetDeadline: time.Duration(100) * time.Millisecond,
				RouteConfig: RouteConfig{
					From: "bar.sso.test",
					To:   "bar-internal.sso.test",
				},
				Route: &SimpleRoute{
					FromURL: &url.URL{
						Scheme: "https",
						Host:   "bar.sso.test",
					},
					ToURL: &url.URL{
						Scheme: "https",
						Host:   "bar-internal.sso.test",
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			os.Setenv("SSO_CONFIG_CLUSTER", "sso")
			os.Setenv("SSO_CONFIG_ROOT_DOMAIN", "test")

			if tc.configFilePath != "" {
				tc.upstreamConfigs.ConfigsFile = tc.configFilePath
			} else {
				tempFile, _ := ioutil.TempFile("", "")
				_, err := tempFile.Write(tc.rawConfig)
				if err != nil {
					t.Fatalf("error writing to file")
				}
				tc.upstreamConfigs.ConfigsFile = tempFile.Name()
			}

			err := SetUpstreamConfigs(tc.upstreamConfigs, CookieConfig{}, tc.serverConfig)
			if err == nil && tc.expectedErrMsg != "" {
				t.Fatalf("expected error but error was nil")
			}
			if err != nil && tc.expectedErrMsg == "" {
				t.Fatalf("expected no error but got: %v", err)
			}
			if err != nil && err.Error() != tc.expectedErrMsg {
				t.Logf("expected: %q", tc.expectedErrMsg)
				t.Logf("     got: %q", err)
				t.Fatalf("unexpected error while setting upstream configs")
			} else if err != nil && err.Error() == tc.expectedErrMsg {
				return
			}

			gotConfigs := &*tc.upstreamConfigs.upstreamConfigs[0]
			if !reflect.DeepEqual(gotConfigs, tc.wantConfig) {
				fmt.Printf("expected config: %+v", *&tc.wantConfig)
				fmt.Printf("     got config: %+v", gotConfigs)
				t.Fatalf("expected configs to be equal")

			}
		})
	}
}

func TestProviderURLValidation(t *testing.T) {
	testCases := []struct {
		name                        string
		providerURLExternal         string
		providerURLInternal         string
		expectedError               string
		expectedProviderURLInternal string
		expectedSignInURL           string
	}{
		{
			name:                "http scheme preserved",
			providerURLExternal: "http://provider.example.com",
			expectedSignInURL:   "http://provider.example.com/idp/sign_in",
		},
		{
			name:                "https scheme preserved",
			providerURLExternal: "https://provider.example.com",
			expectedSignInURL:   "https://provider.example.com/idp/sign_in",
		},
		{
			name:                        "proxy provider url string based on providerURL",
			providerURLExternal:         "https://provider.example.com",
			expectedProviderURLInternal: "",
		},
		{
			name:                        "proxy provider url string based on proxyProviderURL",
			providerURLExternal:         "https://provider.example.com",
			providerURLInternal:         "https://provider-internal.example.com",
			expectedProviderURLInternal: "https://provider-internal.example.com",
		},
		{
			name:                "scheme required",
			providerURLExternal: "//provider.example.com",
			expectedError:       "invalid provider.providerurl config: providerurl.external must include scheme and host",
		},
		{
			name:                "scheme and host required",
			providerURLExternal: "/foo",
			expectedError:       "invalid provider.providerurl config: providerurl.external must include scheme and host",
		},
		{
			name:                "invalid url rejected",
			providerURLExternal: "%ZZZ",
			expectedError:       "invalid provider.providerurl config: parse \"%ZZZ\": invalid URL escape \"%ZZ\"",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultProxyConfig()
			config.ProviderConfig.ProviderURLConfig.External = tc.providerURLExternal
			config.ProviderConfig.ProviderURLConfig.Internal = tc.providerURLInternal
			err := config.ProviderConfig.Validate()

			if tc.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tc.expectedError {
					t.Fatalf("expected error %q, got %q", tc.expectedError, err.Error())
				}
				// our errors have matched, and test has passed
				return
			}

			statsdClient, _ := statsd.New("127.0.0.1:8125")
			config.UpstreamConfigs.DefaultConfig.ProviderSlug = "idp"
			provider, err := newProvider(config.ClientConfig, config.ProviderConfig, config.SessionConfig, config.UpstreamConfigs, statsdClient)
			if err != nil {
				t.Fatalf("unexpected err creating provider: %v", err)
			}
			if tc.expectedSignInURL != "" {
				testutil.Equal(t, provider.Data().SignInURL.String(), tc.expectedSignInURL)
			}
			if tc.expectedProviderURLInternal != "" {
				testutil.Equal(t, provider.Data().ProviderURLInternal.String(), tc.expectedProviderURLInternal)
			}
		})
	}
}
