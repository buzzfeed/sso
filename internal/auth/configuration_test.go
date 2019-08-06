package auth

import (
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/xerrors"
)

func testConfiguration(t *testing.T) Configuration {
	c := Configuration{
		ServerConfig: ServerConfig{
			Host: "localhost",
			Port: 4180,
			TimeoutConfig: TimeoutConfig{
				Write: 30 * time.Second,
				Read:  30 * time.Second,
			},
		},
		SessionConfig: SessionConfig{
			SessionLifetimeTTL: (30 * 24) * time.Hour,
			CookieConfig: CookieConfig{
				Name:     "_sso_auth",
				Secret:   "zaPX2fYMyegfOwwMEaMiphwrjgxz0pxoTbxvQiK9zBY=", // generated using `openssl rand -base64 32`
				Expire:   (7 * 24) * time.Hour,
				Secure:   true,
				HTTPOnly: true,
			},
			Key: "CrYro5Kp6CO2aBbVGoHgnh2/YQaz9cqqRYNbtTSUBDs=", // generated using `openssl rand -base64 32`
		},
		MetricsConfig: MetricsConfig{
			StatsdConfig: StatsdConfig{
				Host: "localhost",
				Port: 8124,
			},
		},
		LoggingConfig: LoggingConfig{
			Enable: true,
		},

		// we provide no defaults for these right now
		ProviderConfigs: map[string]ProviderConfig{
			"foo": ProviderConfig{
				ProviderType: "test",
				ProviderSlug: "foo",
				ClientConfig: ClientConfig{
					ID:     "foo-client-id",
					Secret: "foo-client-secret",
				},
			},
		},
		ClientConfigs: map[string]ClientConfig{
			"proxy": ClientConfig{
				ID:     "proxy-client-id",
				Secret: "proxy-client-secret",
			},
		},
		AuthorizeConfig: AuthorizeConfig{
			ProxyConfig: ProxyConfig{
				Domains: []string{"proxy.local", "root.local", "example.com"},
			},
		},
	}
	err := c.Validate()
	if err != nil {
		t.Fatalf("unexpected err initilaizing test configuration: %v", err)
	}
	return c
}

func assertEq(want, have interface{}, t *testing.T) {
	if !reflect.DeepEqual(want, have) {
		t.Errorf("want: %#v", want)
		t.Errorf("have: %#v", have)
		t.Errorf("expected values to be equal")
	}
}

func TestDefaultConfiguration(t *testing.T) {
	want := DefaultAuthConfig()
	have, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected err loading config: %v", err)
	}
	assertEq(want, have, t)
}

func TestEnvironmentOverridesConfiguration(t *testing.T) {
	testCases := []struct {
		Name         string
		EnvOverrides map[string]string
		CheckFunc    func(c Configuration, t *testing.T)
	}{
		{
			Name: "Test Server Host Overrides",
			EnvOverrides: map[string]string{
				"SERVER_HOST": "example.com",
			},
			CheckFunc: func(c Configuration, t *testing.T) {
				assertEq("example.com", c.ServerConfig.Host, t)
			},
		},
		{
			Name: "Test Request Timeout Overrides",
			EnvOverrides: map[string]string{
				"SERVER_TIMEOUT_WRITE": "60s",
				"SERVER_TIMEOUT_READ":  "60s",
			},
			CheckFunc: func(c Configuration, t *testing.T) {
				assertEq(60*time.Second, c.ServerConfig.TimeoutConfig.Write, t)
				assertEq(60*time.Second, c.ServerConfig.TimeoutConfig.Read, t)
			},
		},
		{
			Name: "Test Providers",
			EnvOverrides: map[string]string{
				"PROVIDER_FOO_SLUG":      "foo-slug",
				"PROVIDER_FOO_TYPE":      "foo-type",
				"PROVIDER_FOO_CLIENT_ID": "foo-client-id",
			},
			CheckFunc: func(c Configuration, t *testing.T) {
				foo := c.ProviderConfigs["foo"]
				assertEq("foo-type", foo.ProviderType, t)
				assertEq("foo-slug", foo.ProviderSlug, t)
				assertEq("foo-client-id", foo.ClientConfig.ID, t)
			},
		},
		{
			Name: "Test Multiple Providers",
			EnvOverrides: map[string]string{
				// foo
				"PROVIDER_FOO_SLUG":      "foo-slug",
				"PROVIDER_FOO_TYPE":      "foo-type",
				"PROVIDER_FOO_CLIENT_ID": "foo-client-id",
				// bar
				"PROVIDER_BAR_SLUG":      "bar-slug",
				"PROVIDER_BAR_TYPE":      "bar-type",
				"PROVIDER_BAR_CLIENT_ID": "bar-client-id",
				// baz
				"PROVIDER_BAZ_SLUG":      "baz-slug",
				"PROVIDER_BAZ_TYPE":      "baz-type",
				"PROVIDER_BAZ_CLIENT_ID": "baz-client-id",
			},
			CheckFunc: func(c Configuration, t *testing.T) {
				foo := c.ProviderConfigs["foo"]
				assertEq("foo-type", foo.ProviderType, t)
				assertEq("foo-slug", foo.ProviderSlug, t)
				assertEq("foo-client-id", foo.ClientConfig.ID, t)

				bar := c.ProviderConfigs["bar"]
				assertEq("bar-type", bar.ProviderType, t)
				assertEq("bar-slug", bar.ProviderSlug, t)
				assertEq("bar-client-id", bar.ClientConfig.ID, t)

				baz := c.ProviderConfigs["baz"]
				assertEq("baz-type", baz.ProviderType, t)
				assertEq("baz-slug", baz.ProviderSlug, t)
				assertEq("baz-client-id", baz.ClientConfig.ID, t)
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tc.EnvOverrides {
				err := os.Setenv(k, v)
				if err != nil {
					t.Fatalf("unexpected err setting env: %v", err)
				}
			}
			have, err := LoadConfig()
			if err != nil {
				t.Fatalf("unexpected err loading config: %v", err)
			}
			tc.CheckFunc(have, t)
		})
	}
}

func TestConfigValidate(t *testing.T) {
	testCases := map[string]struct {
		Validator   Validator
		ExpectedErr error
	}{
		"passing configuration": {
			Validator: Configuration{
				ServerConfig: ServerConfig{
					Host: "localhost",
					Port: 4180,
					TimeoutConfig: TimeoutConfig{
						Write: 30 * time.Second,
						Read:  30 * time.Second,
					},
				},
				SessionConfig: SessionConfig{
					SessionLifetimeTTL: (30 * 24) * time.Hour,
					CookieConfig: CookieConfig{
						Name:     "_sso_auth",
						Secret:   "zaPX2fYMyegfOwwMEaMiphwrjgxz0pxoTbxvQiK9zBY=", // generated using `openssl rand -base64 32`
						Expire:   (7 * 24) * time.Hour,
						Secure:   true,
						HTTPOnly: true,
					},
					Key: "zaPX2fYMyegfOwwMEaMiphwrjgxz0pxoTbxvQiK9zBY=", // generated using `openssl rand -base64 32`
				},
				MetricsConfig: MetricsConfig{
					StatsdConfig: StatsdConfig{
						Host: "localhost",
						Port: 8124,
					},
				},
				LoggingConfig: LoggingConfig{
					Enable: true,
				},
				// we provide no defaults for these right now
				ProviderConfigs: map[string]ProviderConfig{
					"foo": ProviderConfig{
						ProviderType: "test",
						ProviderSlug: "foo",
						ClientConfig: ClientConfig{
							ID:     "foo-client-id",
							Secret: "foo-client-secret",
						},
					},
				},
				ClientConfigs: map[string]ClientConfig{
					"proxy": ClientConfig{
						ID:     "proxy-client-id",
						Secret: "proxy-client-secret",
					},
				},
				AuthorizeConfig: AuthorizeConfig{
					ProxyConfig: ProxyConfig{
						Domains: []string{"proxy.local", "root.local"},
					},
				},
			},
			ExpectedErr: nil,
		},
		"missing host configuration": {
			Validator: ServerConfig{
				Port: 4180,
				TimeoutConfig: TimeoutConfig{
					Write: 30 * time.Second,
					Read:  30 * time.Second,
				},
			},
			ExpectedErr: xerrors.New("no server.host configured"),
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			err := tc.Validator.Validate()
			if err != nil && tc.ExpectedErr != nil {
				assertEq(tc.ExpectedErr.Error(), err.Error(), t)
			} else {
				assertEq(tc.ExpectedErr, err, t)
			}
		})
	}
}
