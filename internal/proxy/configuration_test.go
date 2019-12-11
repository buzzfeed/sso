package proxy

import (
	"errors"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func assertEq(want, have interface{}, t *testing.T) {
	if !reflect.DeepEqual(want, have) {
		t.Errorf("want: %#v", want)
		t.Errorf("have: %#v", have)
		t.Errorf("expected values to be equal")
	}
}

func TestDefaultConfiguration(t *testing.T) {
	// First, check that LoadConfig() returns the expected default config.
	default_config := DefaultProxyConfig()
	loaded_config, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected err loading config: %v", err)
	}
	assertEq(default_config, loaded_config, t)

	// Then, check that DefaultProxyConfig() returns a valid config. A small number of configuration settings
	// are *not* supplied by DefaultProxyConfig(), but *are* required. We add those in below for the sake of testing.
	default_config.ProviderConfig.ProviderURLConfig.External = "https://provider.example.com"
	default_config.SessionConfig.CookieConfig.Secret = "4HG6i5p+/D0e4NrC8AmLeCZ6mGgaYfy8wxgBmAvNWmM="
	default_config.ClientConfig.ID = "foo_id"
	default_config.ClientConfig.Secret = "foo_secret"
	default_config.UpstreamConfigs.Cluster = "foo_cluster"

	err = default_config.Validate()
	if err != nil {
		t.Fatalf("unexpected err validating default config: %v", err)
	}
}

func TestConfigCatchAllValidateErrors(t *testing.T) {
	config := Configuration{}
	err := config.Validate()
	expected := []string{
		"invalid server config: no server.port configured",
		"invalid provider config: invalid provider.providerurl config: no providerurl.external configured",
		"invalid session config: invalid session.cookie config: no cookie.secret configured",
		"invalid client config: no client.id configured",
		"invalid upstream config: invalid upstream.defaultconfig: no defaultconfig.provider configured",
		"invalid metrics config: invalid metrics.statsd config: no statsd.host configured",
	}
	assertEq(expected, strings.Split(err.Error(), "\n"), t)
}

func TestEnvironmentOverridesConfiguration(t *testing.T) {
	testCases := []struct {
		Name         string
		EnvOverrides map[string]string
		CheckFunc    func(c Configuration, t *testing.T)
	}{
		{
			Name: "Test Session Cookie Config Name Overrides",
			EnvOverrides: map[string]string{
				"SESSION_COOKIE_NAME": "foo_cookie_name",
			},
			CheckFunc: func(c Configuration, t *testing.T) {
				assertEq("foo_cookie_name", c.SessionConfig.CookieConfig.Name, t)
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
			Name: "Test Provider Config Overrides",
			EnvOverrides: map[string]string{
				"UPSTREAM_DEFAULT_PROVIDER": "foo-slug",
			},
			CheckFunc: func(c Configuration, t *testing.T) {
				assertEq("foo-slug", c.UpstreamConfigs.DefaultConfig.ProviderSlug, t)
			},
		},
		//{
		//	Name: "some upstream config tests?",
		//},
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
	testCases := []struct {
		Name        string
		Validator   Validator
		ExpectedErr error
	}{
		{
			Name: "config validation should pass",
			Validator: Configuration{
				ServerConfig: ServerConfig{
					Port: 4180,
					TimeoutConfig: &TimeoutConfig{
						Write:    30 * time.Second,
						Read:     30 * time.Second,
						Shutdown: 30 * time.Second,
					},
				},
				ProviderConfig: ProviderConfig{
					ProviderType: "sso",
					Scope:        "test",
					ProviderURLConfig: ProviderURLConfig{
						External: "https://sso-external.com",
						Internal: "https://sso-internal.com",
					},
				},
				ClientConfig: ClientConfig{
					ID:     "foo-id",
					Secret: "bar-secret",
				},
				SessionConfig: SessionConfig{
					CookieConfig: CookieConfig{
						Name:     "_sso_proxy",
						Expire:   168 * time.Hour,
						Secure:   true,
						Secret:   "SMoPfinxNz0fuaGFPUr5vwQpvoG+CGcLd2nkxRVI+H4=",
						HTTPOnly: true,
					},
					TTLConfig: TTLConfig{
						Lifetime:    720 * time.Hour,
						Valid:       60 * time.Second,
						GracePeriod: 3 * time.Hour,
					},
				},
				UpstreamConfigs: UpstreamConfigs{
					DefaultConfig: DefaultConfig{
						Timeout:       10 * time.Second,
						ResetDeadline: 60 * time.Second,
						ProviderSlug:  "google",
					},
					Scheme:  "https",
					Cluster: "foo-cluster",
				},
				LoggingConfig: LoggingConfig{
					Enable: true,
				},
				MetricsConfig: MetricsConfig{
					StatsdConfig: StatsdConfig{
						Port: 8125,
						Host: "localhost",
					},
				},
			},
		},
		// Server Validate() tests
		{
			Name: "ServerConfig: missing server.port configuration",
			Validator: ServerConfig{
				TimeoutConfig: &TimeoutConfig{
					Write:    30 * time.Second,
					Read:     30 * time.Second,
					Shutdown: 30 * time.Second,
				},
			},
			ExpectedErr: errors.New("no server.port configured"),
		},
		// SessionConfig.CookieConfig Validate() tests
		{
			Name: "CookieConfig: invalid cookie.secret",
			Validator: SessionConfig{
				CookieConfig: CookieConfig{
					Secret: "invalid_string_format",
				},
			},
			ExpectedErr: errors.New(
				"invalid session.cookie config: invalid cookie.secret configured; expected base64-encoded bytes, as from `openssl rand 32 -base64`: \"illegal base64 data at input byte 7\""),
		},
		{
			Name: "CookieConfig: invalid cookie.secret value",
			Validator: SessionConfig{
				CookieConfig: CookieConfig{
					// created with `openssl rand 30 -base64`
					Secret: "NXKCLbT+jXZD9Ep5xDo2EsM82F/kv3KZT2vJ7XvV",
				},
			},
			ExpectedErr: errors.New(
				"invalid session.cookie config: invalid value for cookie.secret; must decode to 32 or 64 bytes, but decoded to 30 bytes"),
		},
		{
			Name: "CookieConfig: missing cookie.name",
			Validator: SessionConfig{
				CookieConfig: CookieConfig{
					// created with `openssl rand 32 -base64`
					Secret: "ekVGRbawiXuvVhgyKUIg0KQXw0ubdSd3rE9Pheog1JU=",
					Name:   "",
				},
			},
			ExpectedErr: errors.New(
				"invalid session.cookie config: invalid cc.name: \"\""),
		},
		// ClientConfig Validate() tests
		{
			Name: "ClientConfig: missing client.id",
			Validator: ClientConfig{
				ID: "",
			},
			ExpectedErr: errors.New(
				"no client.id configured"),
		},
		{
			Name: "ClientConfig: missing client.secret",
			Validator: ClientConfig{
				ID:     "foo_id",
				Secret: "",
			},
			ExpectedErr: errors.New(
				"no client.secret configured"),
		},
		// MetricsConfig Validate() tests
		{
			Name: "MetricsConfig: missing metrics.statsd.host",
			Validator: MetricsConfig{
				StatsdConfig: StatsdConfig{
					Host: "",
				},
			},
			ExpectedErr: errors.New(
				"invalid metrics.statsd config: no statsd.host configured"),
		},
		{
			Name: "MetricsConfig: missing metrics.statsd.port",
			Validator: MetricsConfig{
				StatsdConfig: StatsdConfig{
					Host: "foo_host",
					Port: 0,
				},
			},
			ExpectedErr: errors.New(
				"invalid metrics.statsd config: no statsd.port configured"),
		},
		// ProviderConfig Validate() tests
		{
			Name: "ProviderConfig: missing provider.type",
			Validator: ProviderConfig{
				ProviderType: "",
				ProviderURLConfig: ProviderURLConfig{
					Internal: "",
					External: "https://foo.bar.com",
				},
			},
			ExpectedErr: errors.New(
				"no provider.type configured"),
		},
		{
			Name: "ProviderConfig: missing provider.providerurl.external",
			Validator: ProviderConfig{
				ProviderType: "foo",
				ProviderURLConfig: ProviderURLConfig{
					Internal: "",
					External: "",
				},
			},
			ExpectedErr: errors.New(
				"invalid provider.providerurl config: no providerurl.external configured"),
		},
		{
			Name: "ProviderConfig: invalid provider.providerurl.external format",
			Validator: ProviderConfig{
				ProviderType: "foo",
				ProviderURLConfig: ProviderURLConfig{
					Internal: "",
					External: "/simply/a/URL/path",
				},
			},
			ExpectedErr: errors.New(
				"invalid provider.providerurl config: providerurl.external must include scheme and host"),
		},
		{
			Name: "ProviderConfig: provider.providerurl.internal missing scheme or host",
			Validator: ProviderConfig{
				ProviderType: "foo",
				ProviderURLConfig: ProviderURLConfig{
					Internal: "/simply/a/URL/path",
					External: "https://foo.bar.com",
				},
			},
			ExpectedErr: errors.New(
				"invalid provider.providerurl config: providerurl.internal must include scheme and host"),
		},
		{
			Name: "ProviderConfig: invalid provider.providerurl.internal format",
			Validator: ProviderConfig{
				ProviderType: "foo",
				ProviderURLConfig: ProviderURLConfig{
					Internal: "%ZZZ",
					External: "https://foo.bar.com",
				},
			},
			ExpectedErr: errors.New(
				"invalid provider.providerurl config: parse \"%ZZZ\": invalid URL escape \"%ZZ\""),
		},
		// UpstreamConfigs Validate() tests
		{
			Name: "UpstreamConfisg: missing upstreamconfig.defaultconfig.provider",
			Validator: UpstreamConfigs{
				DefaultConfig: DefaultConfig{
					ProviderSlug: "",
				},
				Cluster: "foo_cluster",
			},
			ExpectedErr: errors.New(
				"invalid upstream.defaultconfig: no defaultconfig.provider configured"),
		},
		{
			Name: "UpstreamConfigs: missing upstreamconfig.cluster",
			Validator: UpstreamConfigs{
				DefaultConfig: DefaultConfig{
					ProviderSlug: "foo_provider",
				},
				Cluster: "",
			},
			ExpectedErr: errors.New(
				"no upstream.cluster configured"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Validator.Validate()
			if err != nil && tc.ExpectedErr != nil {
				assertEq(tc.ExpectedErr.Error(), err.Error(), t)
			} else {
				assertEq(tc.ExpectedErr, err, t)
			}
		})
	}
}

func TestUpstreamConfigs(t *testing.T) {
	testCases := []struct {
		Name           string
		CreateTempFile bool
		UpstreamConfig UpstreamConfigs
		ExpectedErr    error
	}{
		{
			Name: "valid upstreamconfig",
			UpstreamConfig: UpstreamConfigs{
				Cluster: "foo_cluster",
				DefaultConfig: DefaultConfig{
					ProviderSlug: "foo_provider",
				},
			},
			CreateTempFile: true,
		},
		{
			Name: "invalid filepath given",
			UpstreamConfig: UpstreamConfigs{
				ConfigsFile: "foo_invalid_file_path",
				Cluster:     "foo_cluster",
				DefaultConfig: DefaultConfig{
					ProviderSlug: "foo_provider",
				},
			},
			ExpectedErr: errors.New(
				"invalid upstream.configfile: open foo_invalid_file_path: no such file or directory"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

			tempFilePath := ""
			if tc.CreateTempFile {
				tmpFile, _ := ioutil.TempFile("", "")
				tempFilePath = tmpFile.Name()
				tc.UpstreamConfig.ConfigsFile = tempFilePath
			}

			err := tc.UpstreamConfig.Validate()
			if err != nil && tc.ExpectedErr != nil {
				assertEq(tc.ExpectedErr.Error(), err.Error(), t)
			} else {
				assertEq(tc.ExpectedErr, err, t)
			}
		})
	}
}
