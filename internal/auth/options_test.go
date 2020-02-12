package auth

import (
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestGoogleProviderApiSettings(t *testing.T) {
	provider, err := newProvider(
		ProviderConfig{ProviderType: "google"},
		SessionConfig{SessionLifetimeTTL: 1 * time.Hour},
	)
	if err != nil {
		t.Fatalf("unexpected err generating google provider: %v", err)
	}
	p := provider.Data()
	testutil.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth",
		p.SignInURL.String())
	testutil.Equal(t, "https://www.googleapis.com/oauth2/v4/token",
		p.RedeemURL.String())

	testutil.Equal(t, "", p.ProfileURL.String())
	testutil.Equal(t, "profile email", p.Scope)
}

func TestGoogleGroupInvalidFile(t *testing.T) {
	_, err := newProvider(
		ProviderConfig{
			ProviderType: "google",
			GoogleProviderConfig: GoogleProviderConfig{
				Credentials: "file_doesnt_exist.json",
			},
		},
		SessionConfig{
			SessionLifetimeTTL: 1 * time.Hour,
		},
	)
	testutil.NotEqual(t, nil, err)
	testutil.Equal(t, "could not read google credentials file", err.Error())
}

func TestAmazonCognitoProviderSettings(t *testing.T) {
	testCases := []struct {
		Name           string
		ProviderConfig ProviderConfig
	}{
		{
			Name: "with input parameters, default scope",
			ProviderConfig: ProviderConfig{
				ProviderType: "cognito",
				Scope:        "",
				AmazonCognitoProviderConfig: AmazonCognitoProviderConfig{
					OrgURL:     "test.cognito.com",
					UserPoolID: "12345",
					Region:     "test-cognito-region",
					Credentials: CognitoCredentials{
						ID:     "test-credentials-id",
						Secret: "test-credentials-secret",
					},
				},
			},
		},
		{
			Name: "with input parameters, override scope",
			ProviderConfig: ProviderConfig{
				ProviderType: "cognito",
				Scope:        "openid email",
				AmazonCognitoProviderConfig: AmazonCognitoProviderConfig{
					OrgURL:     "test.cognito.com",
					UserPoolID: "12345",
					Region:     "test-cognito-region",
					Credentials: CognitoCredentials{
						ID:     "test-credentials-id",
						Secret: "test-credentials-secret",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			provider, err := newProvider(
				tc.ProviderConfig,
				SessionConfig{SessionLifetimeTTL: 1 * time.Hour},
			)
			if err != nil {
				t.Fatalf("unexpected err generating cognito provider: %q", err)
			}

			p := provider.Data()
			testutil.Equal(t, "https://test.cognito.com/oauth2/authorize", p.SignInURL.String())
			testutil.Equal(t, "https://test.cognito.com/oauth2/token", p.RedeemURL.String())
			testutil.Equal(t, "https://test.cognito.com/oauth2/userInfo", p.ProfileURL.String())
			testutil.Equal(t, "https://test.cognito.com/oauth2/userInfo", p.ValidateURL.String())
			if tc.ProviderConfig.Scope != "" {
				testutil.Equal(t, tc.ProviderConfig.Scope, p.Scope)
			} else {
				testutil.Equal(t, "openid profile email aws.cognito.signin.user.admin", p.Scope)
			}
		})
	}
}

func TestOktaProviderSettings(t *testing.T) {
	testCases := []struct {
		Name           string
		ProviderConfig ProviderConfig
	}{
		{
			Name: "with input parameters, default scope",
			ProviderConfig: ProviderConfig{
				ProviderType: "okta",
				Scope:        "",
				OktaProviderConfig: OktaProviderConfig{
					OrgURL:   "test.okta.com",
					ServerID: "12345",
				},
			},
		},
		{
			Name: "with input parameters, override scope",
			ProviderConfig: ProviderConfig{
				ProviderType: "okta",
				Scope:        "openid email",
				OktaProviderConfig: OktaProviderConfig{
					OrgURL:   "test.okta.com",
					ServerID: "12345",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			provider, err := newProvider(
				tc.ProviderConfig,
				SessionConfig{SessionLifetimeTTL: 1 * time.Hour},
			)
			if err != nil {
				t.Fatalf("unexpected err generating cognito provider: %q", err)
			}

			p := provider.Data()
			testutil.Equal(t, "https://test.okta.com/oauth2/12345/v1/authorize", p.SignInURL.String())
			testutil.Equal(t, "https://test.okta.com/oauth2/12345/v1/token", p.RedeemURL.String())
			testutil.Equal(t, "https://test.okta.com/oauth2/12345/v1/revoke", p.RevokeURL.String())
			testutil.Equal(t, "https://test.okta.com/oauth2/12345/v1/userinfo", p.ProfileURL.String())
			testutil.Equal(t, "https://test.okta.com/oauth2/12345/v1/introspect", p.ValidateURL.String())
			if tc.ProviderConfig.Scope != "" {
				testutil.Equal(t, tc.ProviderConfig.Scope, p.Scope)
			} else {
				testutil.Equal(t, "openid profile email groups offline_access", p.Scope)
			}
		})
	}
}
