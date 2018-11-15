package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/groups"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const MicrosoftTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"
const TestClientID = "a4c35c92-e858-41e8-bd2c-ade04cb622b1"

func newAzureProviderServer(redeemBody *[]byte, redeemCode int, pubKey *rsa.PublicKey) (*url.URL, *httptest.Server) {
	var u *url.URL
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")

		// simple router for the mock IdP server
		switch r.RequestURI {
		case "/.well-known/openid-configuration":
			rw.WriteHeader(200)
			rw.Write([]byte(fmt.Sprintf(`{
				"token_endpoint":"%s/oauth2/token",
				"jwks_uri":"%s/common/discovery/keys",
				"issuer":"%s"
			}`, u, u, u)))
		case "/common/discovery/keys":
			pub := jose.JSONWebKey{Key: pubKey, Algorithm: "RSA", Use: "sig"}
			keyData, err := pub.MarshalJSON()
			if err != nil {
				panic(err)
			}
			rw.WriteHeader(200)
			rw.Write([]byte(fmt.Sprintf(`{
				"keys":[%s]
			}`, keyData)))
		case "/oauth2/token":
			rw.WriteHeader(redeemCode)
			rw.Write(*redeemBody)
		}
	}))
	u, _ = url.Parse(s.URL)
	return u, s
}

func newAzureV2Provider(providerData *ProviderData) *AzureV2Provider {
	if providerData == nil {
		providerData = &ProviderData{
			ProviderName: "",
			SignInURL:    &url.URL{},
			RedeemURL:    &url.URL{},
			RevokeURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""}
	}
	return NewAzureV2Provider(providerData)
}

func TestAzureV2ProviderDefaults(t *testing.T) {
	expectedResults := []struct {
		name         string
		providerData *ProviderData
		signInURL    string
		redeemURL    string
		revokeURL    string
		profileURL   string
		validateURL  string
		scope        string
	}{
		{
			name:        "defaults",
			signInURL:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/authorize",
			redeemURL:   "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/token",
			profileURL:  "https://graph.microsoft.com/oidc/userinfo",
			revokeURL:   "", // does not exist
			validateURL: "", // does not exist
			scope:       "openid email profile offline_access",
		},
		{
			name: "with provider overrides",
			providerData: &ProviderData{
				SignInURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/auth"},
				RedeemURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/token"},
				RevokeURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/deauth"},
				ProfileURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/profile"},
				ValidateURL: &url.URL{
					Scheme: "https",
					Host:   "example.com",
					Path:   "/oauth/tokeninfo"},
				Scope: "profile"},
			signInURL:   "https://example.com/oauth/auth",
			redeemURL:   "https://example.com/oauth/token",
			revokeURL:   "https://example.com/oauth/deauth",
			profileURL:  "https://example.com/oauth/profile",
			validateURL: "https://example.com/oauth/tokeninfo",
			scope:       "profile",
		},
	}
	for _, expected := range expectedResults {
		t.Run(expected.name, func(t *testing.T) {
			p := newAzureV2Provider(expected.providerData)
			err := p.Configure(MicrosoftTenantID)
			if err != nil {
				t.Error(err)
			}
			if p == nil {
				t.Errorf("azure provider was nil")
			}
			if p.Data().ProviderName != "Azure AD" {
				t.Errorf("expected provider name Azure AD, got %s", p.Data().ProviderName)
			}
			if p.Data().SignInURL.String() != expected.signInURL {
				log.Printf("expected %s", expected.signInURL)
				log.Printf("got %s", p.Data().SignInURL.String())
				t.Errorf("unexpected signin url")
			}

			if p.Data().RedeemURL.String() != expected.redeemURL {
				log.Printf("expected %s", expected.redeemURL)
				log.Printf("got %s", p.Data().RedeemURL.String())
				t.Errorf("unexpected redeem url")
			}

			if p.Data().RevokeURL.String() != expected.revokeURL {
				log.Printf("expected %s", expected.revokeURL)
				log.Printf("got %s", p.Data().RevokeURL.String())
				t.Errorf("unexpected revoke url")
			}

			if p.Data().ValidateURL.String() != expected.validateURL {
				log.Printf("expected %s", expected.validateURL)
				log.Printf("got %s", p.Data().ValidateURL.String())
				t.Errorf("unexpected validate url")
			}

			if p.Data().ProfileURL.String() != expected.profileURL {
				log.Printf("expected %s", expected.profileURL)
				log.Printf("got %s", p.Data().ProfileURL.String())
				t.Errorf("unexpected profile url")
			}

			if p.Data().Scope != expected.scope {
				log.Printf("expected %s", expected.scope)
				log.Printf("got %s", p.Data().Scope)
				t.Errorf("unexpected scope")
			}
		})

	}
}

// claims represents public claim values (as specified in RFC 7519).
type claims struct {
	Issuer   string          `json:"iss,omitempty"`
	Audience string          `json:"aud,omitempty"`
	Expiry   jwt.NumericDate `json:"exp,omitempty"`
	Name     string          `json:"name,omitempty"`
	Email    string          `json:"email,omitempty"`
	NotEmail string          `json:"not_email,omitempty"`
}

func TestAzureV2ProviderRedeem(t *testing.T) {
	// For testing create the RSA key pair in the code
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	// create Square.jose signing key
	key := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}

	// create a Square.jose RSA signer, used to sign the JWT
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		t.Error(err)
	}

	testCases := []struct {
		name            string
		claims          *claims
		resp            redeemResponse
		expectedError   bool
		expectedSession *sessions.SessionState
	}{
		{
			name: "redeem",
			claims: &claims{
				Issuer:   "{mock-issuer}",
				Audience: TestClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
			},
			resp: redeemResponse{
				AccessToken:  "a1234",
				ExpiresIn:    10,
				RefreshToken: "refresh12345",
			},
			expectedSession: &sessions.SessionState{
				Email:        "michael.bland@gsa.gov",
				AccessToken:  "a1234",
				RefreshToken: "refresh12345",
			},
		},
		{
			name: "missing issuer",
			claims: &claims{
				Audience: TestClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
			},
			resp: redeemResponse{
				AccessToken:  "a1234",
				ExpiresIn:    10,
				RefreshToken: "refresh12345",
			},
			expectedError: true,
		},
		{
			name: "invalid issuer",
			claims: &claims{
				Issuer:   "https://example.com/bogus/issuer",
				Audience: TestClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
			},
			resp: redeemResponse{
				AccessToken:  "a1234",
				ExpiresIn:    10,
				RefreshToken: "refresh12345",
			},
			expectedError: true,
		},
		{
			name: "invalid encoding",
			resp: redeemResponse{
				AccessToken: "a1234",
				IDToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + `{"name": "Michael Bland","email": "michael.bland@gsa.gov"}` + ".SC_eJ3K04rLOPLLDIWEKwr0DPZqw5KlFySybzmxfM6Y",
			},
			expectedError: true,
		},
		{
			name: "invalid json",
			resp: redeemResponse{
				AccessToken: "a1234",
				IDToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + base64.URLEncoding.EncodeToString([]byte(`{"email": michael.bland@gsa.gov}`)) + ".SC_eJ3K04rLOPLLDIWEKwr0DPZqw5KlFySybzmxfM6Y",
			},
			expectedError: true,
		},
		{
			name: "missing email",
			claims: &claims{
				NotEmail: "missing",
			},
			resp: redeemResponse{
				AccessToken: "a1234",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			var server *httptest.Server
			// pointer to body to bypass chicken/egg issue w/ mock server urls
			providerURL, server := newAzureProviderServer(&body, http.StatusOK, &privKey.PublicKey)
			defer server.Close()
			azureOIDCConfigURL = providerURL.String()

			if tc.claims != nil {
				// create an instance of Builder that uses the rsa signer
				builder := jwt.Signed(rsaSigner)

				// add claims to the Builder
				tc.claims.Issuer = strings.Replace(tc.claims.Issuer, "{mock-issuer}", providerURL.String(), -1)
				builder = builder.Claims(tc.claims)

				// build and inject ID token into response
				idToken, err := builder.CompactSerialize()
				if err != nil {
					t.Error(err)
				}
				tc.resp.IDToken = idToken
			}

			body, err = json.Marshal(tc.resp)
			testutil.Equal(t, nil, err)

			p := newAzureV2Provider(nil)
			p.ClientID = TestClientID
			p.ClientSecret = "456"
			err = p.Configure(MicrosoftTenantID)
			if err != nil {
				t.Error(err)
			}
			// graph service mock has to be set after p.Configure
			p.GraphService = &MockAzureGraphService{}

			session, err := p.Redeem("http://redirect/", "code1234")
			if tc.expectedError && err == nil {
				t.Errorf("expected redeem error but was nil")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("unexpected error %s", err)
			}
			if tc.expectedSession == nil && session != nil {
				t.Errorf("expected session to be nil but it was %s", session)
			}
			if session != nil && tc.expectedSession != nil {
				if session.Email != tc.expectedSession.Email {
					log.Printf("expected email %s", tc.expectedSession.Email)
					log.Printf("got %s", session.Email)
					t.Errorf("unexpected session email")
				}

				if session.AccessToken != tc.expectedSession.AccessToken {
					log.Printf("expected access token %s", tc.expectedSession.AccessToken)
					log.Printf("got %s", session.AccessToken)
					t.Errorf("unexpected access token")
				}

				if session.RefreshToken != tc.expectedSession.RefreshToken {
					log.Printf("expected refresh token %s", tc.expectedSession.RefreshToken)
					log.Printf("got %s", session.RefreshToken)
					t.Errorf("unexpected session refresh token")
				}
			}
		})
	}
}

type groupsClientMock struct {
}

func (c *groupsClientMock) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{}, nil
}

func TestAzureV2ValidateGroupMembers(t *testing.T) {
	testCases := []struct {
		name                string
		inputAllowedGroups  []string
		groups              []string
		groupsError         error
		getMembersFunc      func(string) (groups.MemberSet, bool)
		expectedGroups      []string
		expectedErrorString string
	}{
		{
			name:               "empty input groups should return an empty string",
			inputAllowedGroups: []string{},
			groups:             []string{"group1"},
			expectedGroups:     []string{"group1"},
			getMembersFunc:     func(string) (groups.MemberSet, bool) { return nil, false },
		},
		{
			name:                "empty inputs and error on groups resource should return error",
			inputAllowedGroups:  []string{},
			getMembersFunc:      func(string) (groups.MemberSet, bool) { return nil, false },
			groupsError:         fmt.Errorf("error"),
			expectedErrorString: "error",
		},
		{
			name:               "member exists in cache, should not call groups resource",
			inputAllowedGroups: []string{"group1"},
			groupsError:        fmt.Errorf("should not get here"),
			getMembersFunc:     func(string) (groups.MemberSet, bool) { return groups.MemberSet{"email": {}}, true },
			expectedGroups:     []string{"group1"},
		},
		{
			name:               "member does not exist in cache, should still not call groups resource",
			inputAllowedGroups: []string{"group1"},
			groupsError:        fmt.Errorf("should not get here"),
			getMembersFunc:     func(string) (groups.MemberSet, bool) { return groups.MemberSet{}, true },
			expectedGroups:     []string{},
		},
		{
			name:               "subset of groups are not cached, calls groups resource",
			inputAllowedGroups: []string{"group1", "group2"},
			groups:             []string{"group1", "group2", "group3"},
			groupsError:        nil,
			getMembersFunc: func(group string) (groups.MemberSet, bool) {
				switch group {
				case "group1":
					return groups.MemberSet{"email": {}}, true
				default:
					return groups.MemberSet{}, false
				}
			},
			expectedGroups: []string{"group1", "group2"},
		},
		{
			name:               "subset of groups are not cached, calls groups resource with error",
			inputAllowedGroups: []string{"group1", "group2"},
			groupsError:        fmt.Errorf("error"),
			getMembersFunc: func(group string) (groups.MemberSet, bool) {
				switch group {
				case "group1":
					return groups.MemberSet{"email": {}}, true
				default:
					return groups.MemberSet{}, false
				}
			},
			expectedErrorString: "error",
		},
		{
			name:               "subset of groups not there, does not call groups resource",
			inputAllowedGroups: []string{"group1", "group2"},
			groups:             []string{"group1", "group2", "group3"},
			groupsError:        fmt.Errorf("should not get here"),
			getMembersFunc: func(group string) (groups.MemberSet, bool) {
				switch group {
				case "group1":
					return groups.MemberSet{"email": {}}, true
				default:
					return groups.MemberSet{}, true
				}
			},
			expectedGroups: []string{"group1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newAzureV2Provider(nil)
			p.GraphService = &MockAzureGraphService{Groups: tc.groups, GroupsError: tc.groupsError}

			groups, err := p.ValidateGroupMembership("email", tc.inputAllowedGroups)

			if err != nil {
				if tc.expectedErrorString != err.Error() {
					t.Errorf("expected error %s but err was %s", tc.expectedErrorString, err)
				}
			}
			if !reflect.DeepEqual(tc.expectedGroups, groups) {
				t.Logf("expected groups %v", tc.expectedGroups)
				t.Logf("got groups %v", groups)
				t.Errorf("unexpected groups returned")
			}

		})
	}
}
