package proxy

import (
	"net/url"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestUpstreamConfigParsing(t *testing.T) {
	testCases := []struct {
		name      string
		rawConfig []byte

		wantErr     *ErrParsingConfig
		wantConfigs []*UpstreamConfig
	}{
		{
			name: "basic parsing",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
				},
			},
		},
		{
			name: "parse white space in service name correctly",
			rawConfig: []byte(`
- service: bar 	  service 	 
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar_service",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			templateVars := map[string]string{
				"root_domain": "dev",
				"cluster":     "sso",
			}
			gotConfigs, err := loadServiceConfigs(tc.rawConfig, "sso", "http", templateVars)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Logf("got err %v", err)
					t.Logf("want err %v", tc.wantErr)
					t.Fatalf("got unexpected error load service configs")
				}
				return
			}

			if err != nil {
				t.Logf("got err %v", err)
				t.Logf("want err %v", tc.wantErr)
				t.Fatalf("got unexpected error load service configs")
			}

			if !reflect.DeepEqual(gotConfigs, tc.wantConfigs) {
				for _, gotConfig := range gotConfigs {
					t.Logf("got  %#v", gotConfig)
				}
				for _, wantConfig := range tc.wantConfigs {
					t.Logf("want %#v", wantConfig)
				}
				t.Fatalf("expected configs to be equal")
			}
		})
	}
}

func TestUpstreamConfigLoading(t *testing.T) {
	wantFrom := "http://foo.sso.dev"
	wantTo := "http://foo-internal.sso.dev"

	templateVars := map[string]string{
		"root_domain": "dev",
		"cluster":     "sso",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(`
- service: foo
  default:
    from: foo.{{cluster}}.{{root_domain}}
    to: foo-internal.{{cluster}}.{{root_domain}}
`), "sso", "http", templateVars)
	if err != nil {
		t.Fatalf("expected to parse upstream configs: %s", err)
	}

	if len(upstreamConfigs) == 0 {
		t.Fatalf("expected service config")
	}

	upstreamConfig := upstreamConfigs[0]

	route, ok := upstreamConfig.Route.(*SimpleRoute)
	if !ok {
		t.Fatalf("expected service config to have `route` type `*SimpleRoute`, got %#v", upstreamConfig.Route)
	}

	if route.FromURL.String() != wantFrom {
		t.Logf("want: %v", wantFrom)
		t.Logf(" got: %v", route.FromURL.String())
		t.Errorf("got unexpected from")
	}

	if route.ToURL.String() != wantTo {
		t.Logf("want: %v", wantTo)
		t.Logf(" got: %v", route.ToURL.String())
		t.Errorf("got unexpected to")
	}
}

func TestUpstreamConfigOverrides(t *testing.T) {
	wantFrom := "http://foo.sso.dev"
	wantTo := "http://foo-special.sso.dev"

	templateVars := map[string]string{
		"cluster":     "sso",
		"root_domain": "dev",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(`
- service: foo
  default:
    from: foo-ui.{{cluster}}.{{root_domain}}
    to: foo-internal.{{cluster}}.{{root_domain}}
  sso:
    from: foo.{{cluster}}.{{root_domain}}
    to: foo-special.{{cluster}}.{{root_domain}}
`), "sso", "http", templateVars)
	if err != nil {
		t.Fatalf("expected to parse upstream configs: %s", err)
	}

	if len(upstreamConfigs) == 0 {
		t.Fatalf("expected service config")
	}

	upstreamConfig := upstreamConfigs[0]
	route, ok := upstreamConfig.Route.(*SimpleRoute)
	if !ok {
		t.Fatalf("expected service config to have `route` type `*SimpleRoute`, got %#v", upstreamConfig.Route)
	}

	if route.FromURL.String() != wantFrom {
		t.Logf("want: %v", wantFrom)
		t.Logf(" got: %v", route.FromURL.String())
		t.Errorf("got unexpected from")
	}

	if route.ToURL.String() != wantTo {
		t.Logf("want: %v", wantTo)
		t.Logf(" got: %v", route.ToURL.String())
		t.Errorf("got unexpected to")
	}
}

func TestUpstreamConfigSkipAuthRegex(t *testing.T) {
	wantRe := regexp.MustCompile(`^\/github-webhook\/$`)

	templateVars := map[string]string{
		"cluster":     "sso",
		"root_domain": "dev",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(`
- service: foo
  default:
    from: foo.{{cluster}}.{{root_domain}}
    to: foo-internal.{{cluster}}.{{root_domain}}
    options:
      skip_auth_regex:
        - ^\/github-webhook\/$
`), "sso", "http", templateVars)
	if err != nil {
		t.Fatalf("expected to parse upstream configs: %s", err)
	}

	if len(upstreamConfigs) == 0 {
		t.Fatalf("expected service config")
	}

	upstreamConfig := upstreamConfigs[0]

	if len(upstreamConfig.SkipAuthCompiledRegex) != 1 {
		t.Errorf("unexpected number of compiled regexes: %v", upstreamConfig.SkipAuthCompiledRegex)
	}

	gotRe := upstreamConfig.SkipAuthCompiledRegex[0]
	if !reflect.DeepEqual(wantRe, gotRe) {
		t.Logf("want: %v", wantRe)
		t.Logf(" got: %v", gotRe)
		t.Errorf("got unexpected compiled regex")
	}
}

func TestUpstreamConfigTimeout(t *testing.T) {
	wantTimeout := time.Duration(10) * time.Second
	templateVars := map[string]string{
		"cluster":     "sso",
		"root_domain": "dev",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(`
- service: foo
  default:
    from: foo.{{cluster}}.{{root_domain}}
    to: foo-internal.{{cluster}}.{{root_domain}}
    options:
      timeout: 10s
`), "sso", "http", templateVars)
	if err != nil {
		t.Fatalf("expected to parse upstream configs: %s", err)
	}

	if len(upstreamConfigs) == 0 {
		t.Fatalf("expected service config")
	}

	upstreamConfig := upstreamConfigs[0]
	if upstreamConfig.Timeout != wantTimeout {
		t.Logf("want: %v", wantTimeout)
		t.Logf(" got: %v", upstreamConfig.Timeout)
		t.Errorf("got unexpected configured timeout")
	}
}

func TestUpstreamConfigFlushInterval(t *testing.T) {
	wantInterval := time.Duration(100) * time.Millisecond
	templateVars := map[string]string{
		"cluster":     "sso",
		"root_domain": "dev",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(`
- service: foo
  default:
    from: foo.{{cluster}}.{{root_domain}}
    to: foo-internal.{{cluster}}.{{root_domain}}
    options:
      flush_interval: 100ms
`), "sso", "http", templateVars)
	if err != nil {
		t.Fatalf("expected to parse upstream configs: %s", err)
	}

	if len(upstreamConfigs) == 0 {
		t.Fatalf("expected service config")
	}

	upstreamConfig := upstreamConfigs[0]
	if upstreamConfig.FlushInterval != wantInterval {
		t.Logf("want: %v", wantInterval)
		t.Logf(" got: %v", upstreamConfig.FlushInterval)
		t.Errorf("got unexpected configured timeout")
	}
}

func TestUpstreamConfigHeaderOverrides(t *testing.T) {
	wantHeaders := map[string]string{
		"X-Frame-Options": "DENY",
	}
	templateVars := map[string]string{
		"cluster":     "sso",
		"root_domain": "dev",
	}
	upstreamConfigs, err := loadServiceConfigs([]byte(`
- service: foo
  default:
    from: foo.{{cluster}}.{{root_domain}}
    to: foo-internal.{{cluster}}.{{root_domain}}
    options:
      header_overrides:
        X-Frame-Options: DENY
`), "sso", "http", templateVars)
	if err != nil {
		t.Fatalf("expected to parse upstream configs: %s", err)
	}

	if len(upstreamConfigs) == 0 {
		t.Fatalf("expected service config")
	}

	upstreamConfig := upstreamConfigs[0]
	if !reflect.DeepEqual(upstreamConfig.HeaderOverrides, wantHeaders) {
		t.Logf("want: %v", wantHeaders)
		t.Logf(" got: %v", upstreamConfig.HeaderOverrides)
		t.Errorf("got unexpected header overrides")
	}
}

func TestUpstreamConfigErrorParsing(t *testing.T) {
	testCases := []struct {
		Name    string
		Config  []byte
		WantErr *ErrParsingConfig
	}{
		{
			Name:   "error on bad yaml input",
			Config: []byte(`]1)`),
			WantErr: &ErrParsingConfig{
				Message: "failed to parse yaml",
			},
		},
		{
			Name: "error on missing service config",
			Config: []byte(`
- default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
`),
			WantErr: &ErrParsingConfig{
				Message: "missing `service` parameter",
			},
		},
		{
			Name: "error on missing from config",
			Config: []byte(`
- service: bar
  default:
    to: bar-internal.{{cluster}}.{{root_domain}}
`),
			WantErr: &ErrParsingConfig{
				Message: "missing `from` parameter",
			},
		},
		{
			Name: "error on missing to config",
			Config: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
`),
			WantErr: &ErrParsingConfig{
				Message: "missing `to` parameter",
			},
		},
		{
			Name: "error on malformed from url",
			Config: []byte(`
- service: bar
  default:
    from: not\/url
    to: bar-internal.{{cluster}}.{{root_domain}}
`),
			WantErr: &ErrParsingConfig{
				Message: "unable to url parse `from` parameter",
			},
		},
		{
			Name: "error on malformed to url",
			Config: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: not\/url
`),
			WantErr: &ErrParsingConfig{
				Message: "unable to url parse `to` parameter",
			},
		},
		{
			Name: "error on malformed skip auth regex",
			Config: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
    options:
      skip_auth_regex:
        - (
`),
			WantErr: &ErrParsingConfig{
				Message: "unable to compile skip auth regex",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			templateVars := map[string]string{
				"root_domain": "dev",
				"cluster":     "sso",
			}
			_, err := loadServiceConfigs(tc.Config, "sso", "http", templateVars)
			if err == nil {
				t.Fatalf("wanted error %v, got nil", tc.WantErr)
			}

			typedErr, ok := err.(*ErrParsingConfig)
			if !ok {
				t.Logf("want: %v", tc.WantErr)
				t.Logf(" got: %v", err)
				t.Fatalf("got unexpected error type")
			}

			if typedErr.Message != tc.WantErr.Message {
				t.Logf("want: %v", tc.WantErr)
				t.Logf(" got: %v", typedErr)
				t.Errorf("got unexpected error message")
			}
		})
	}
}

func TestUpstreamConfigRoutes(t *testing.T) {
	testCases := []struct {
		name      string
		rawConfig []byte

		wantErr     *ErrParsingConfig
		wantConfigs []*UpstreamConfig
	}{
		{
			name: "handle default route",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
				},
			},
		},
		{
			name: "handle rewrite route",
			rawConfig: []byte(`
- service: bar
  default:
    from: ^bar--(.*).{{cluster}}.{{root_domain}}$
    to: bar--$1.{{cluster}}.{{root_domain}}
    type: rewrite
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "^bar--(.*).sso.dev$",
						To:   "bar--$1.sso.dev",
						Type: "rewrite",
					},
					Route: &RewriteRoute{
						FromRegex: regexp.MustCompile("^bar--(.*).sso.dev$"),
						ToTemplate: &url.URL{
							Scheme: "http",
							Opaque: "bar--$1.sso.dev",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			templateVars := map[string]string{
				"root_domain": "dev",
				"cluster":     "sso",
			}
			gotConfigs, err := loadServiceConfigs(tc.rawConfig, "sso", "http", templateVars)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Logf("got err %v", err)
					t.Logf("want err %v", tc.wantErr)
					t.Fatalf("got unexpected error load service configs")
				}
				return
			}

			if err != nil {
				t.Logf("got err %v", err)
				t.Logf("want err %v", tc.wantErr)
				t.Fatalf("got unexpected error load service configs")
			}

			if !reflect.DeepEqual(gotConfigs, tc.wantConfigs) {
				for i, gotConfig := range gotConfigs {
					t.Logf("got  %#v", gotConfig)
					t.Logf("want %#v", tc.wantConfigs[i])
					t.Fatalf("expectec configs to be equal")
				}
			}
		})
	}
}

func TestUpstreamConfigExtraRoutes(t *testing.T) {
	testCases := []struct {
		name      string
		rawConfig []byte

		wantErr     *ErrParsingConfig
		wantConfigs []*UpstreamConfig
	}{
		{
			name: "handle basic additional route",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
    extra_routes:
      - from: foo.{{cluster}}.{{root_domain}}
        to: foo-internal.{{cluster}}.{{root_domain}}
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
				},
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "foo.sso.dev",
						To:   "foo-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "foo.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "foo-internal.sso.dev",
						},
					},
				},
			},
		},
		{
			name: "handle basic additional rewrite route",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
    extra_routes:
      - from: ^bar--(.*).{{cluster}}.{{root_domain}}$
        to: bar--$1.{{cluster}}.{{root_domain}}
        type: rewrite
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
				},
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "^bar--(.*).sso.dev$",
						To:   "bar--$1.sso.dev",
						Type: "rewrite",
					},
					Route: &RewriteRoute{
						FromRegex: regexp.MustCompile("^bar--(.*).sso.dev$"),
						ToTemplate: &url.URL{
							Scheme: "http",
							Opaque: "bar--$1.sso.dev",
						},
					},
				},
			},
		},
		{
			name: "inherit options from base case",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
    options:
      skip_auth_regex:
        - ^\/github-webhook\/$
      timeout: 3s
      header_overrides:
        X-Frame-Options: DENY
    extra_routes:
      - from: ^bar--(.*).{{cluster}}.{{root_domain}}$
        to: bar--$1.{{cluster}}.{{root_domain}}
        type: rewrite
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
					SkipAuthCompiledRegex: []*regexp.Regexp{
						regexp.MustCompile(`^\/github-webhook\/$`),
					},
					Timeout: time.Duration(3) * time.Second,
					HeaderOverrides: map[string]string{
						"X-Frame-Options": "DENY",
					},
				},
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "^bar--(.*).sso.dev$",
						To:   "bar--$1.sso.dev",
						Type: "rewrite",
					},
					Route: &RewriteRoute{
						FromRegex: regexp.MustCompile("^bar--(.*).sso.dev$"),
						ToTemplate: &url.URL{
							Scheme: "http",
							Opaque: "bar--$1.sso.dev",
						},
					},
					SkipAuthCompiledRegex: []*regexp.Regexp{
						regexp.MustCompile(`^\/github-webhook\/$`),
					},
					Timeout: time.Duration(3) * time.Second,
					HeaderOverrides: map[string]string{
						"X-Frame-Options": "DENY",
					},
				},
			},
		},
		{
			name: "override provided options from base case",
			rawConfig: []byte(`
- service: bar
  default:
    from: bar.{{cluster}}.{{root_domain}}
    to: bar-internal.{{cluster}}.{{root_domain}}
    options:
      skip_auth_regex:
        - ^\/github-webhook\/$
      timeout: 3s
      header_overrides:
        X-Frame-Options: DENY
    extra_routes:
      - from: ^bar--(.*).{{cluster}}.{{root_domain}}$
        to: bar--$1.{{cluster}}.{{root_domain}}
        type: rewrite
        options:
          timeout: 10s
          header_overrides:
            X-Frame-Options: ALLOW
`),
			wantConfigs: []*UpstreamConfig{
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "bar.sso.dev",
						To:   "bar-internal.sso.dev",
					},
					Route: &SimpleRoute{
						FromURL: &url.URL{
							Scheme: "http",
							Host:   "bar.sso.dev",
						},
						ToURL: &url.URL{
							Scheme: "http",
							Host:   "bar-internal.sso.dev",
						},
					},
					SkipAuthCompiledRegex: []*regexp.Regexp{
						regexp.MustCompile(`^\/github-webhook\/$`),
					},
					Timeout: time.Duration(3) * time.Second,
					HeaderOverrides: map[string]string{
						"X-Frame-Options": "DENY",
					},
				},
				{
					Service: "bar",
					RouteConfig: RouteConfig{
						From: "^bar--(.*).sso.dev$",
						To:   "bar--$1.sso.dev",
						Type: "rewrite",
					},
					Route: &RewriteRoute{
						FromRegex: regexp.MustCompile("^bar--(.*).sso.dev$"),
						ToTemplate: &url.URL{
							Scheme: "http",
							Opaque: "bar--$1.sso.dev",
						},
					},
					SkipAuthCompiledRegex: []*regexp.Regexp{
						regexp.MustCompile(`^\/github-webhook\/$`),
					},
					Timeout: time.Duration(10) * time.Second,
					HeaderOverrides: map[string]string{
						"X-Frame-Options": "ALLOW",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			templateVars := map[string]string{
				"root_domain": "dev",
				"cluster":     "sso",
			}
			gotConfigs, err := loadServiceConfigs(tc.rawConfig, "sso", "http", templateVars)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Logf("got err %v", err)
					t.Logf("want err %v", tc.wantErr)
					t.Fatalf("got unexpected error load service configs")
				}
				return
			}

			if err != nil {
				t.Logf("got err %v", err)
				t.Logf("want err %v", tc.wantErr)
				t.Fatalf("got unexpected error load service configs")
			}

			if !reflect.DeepEqual(gotConfigs, tc.wantConfigs) {
				for _, gotConfig := range gotConfigs {
					t.Logf("got  %#v", gotConfig)
				}
				for _, wantConfig := range tc.wantConfigs {
					t.Logf("want %#v", wantConfig)
				}
				t.Fatalf("expected configs to be equal")
			}
		})
	}
}
