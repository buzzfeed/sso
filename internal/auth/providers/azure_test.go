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

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/pkg/testutil"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	microsoftTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"
	testClientID      = "a4c35c92-e858-41e8-bd2c-ade04cb622b1"
	testClientSecret  = "4" // number chosen at random
)

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
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			SignInURL:    &url.URL{},
			RedeemURL:    &url.URL{},
			RevokeURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""}
	}
	provider, err := NewAzureV2Provider(providerData)
	if err != nil {
		panic(err)
	}
	return provider
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
				ClientID:     "1234",
				ClientSecret: "4", // Number chosen at random
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
				Scope: "profile",
			},
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
			err := p.Configure(microsoftTenantID)
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
	Issuer   string           `json:"iss,omitempty"`
	Audience string           `json:"aud,omitempty"`
	Expiry   *jwt.NumericDate `json:"exp,omitempty"`
	Name     string           `json:"name,omitempty"`
	Email    string           `json:"email,omitempty"`
	Nonce    string           `json:"nonce,omitempty"`
	NotEmail string           `json:"not_email,omitempty"`
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
				Audience: testClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
				Nonce:    "{mock-nonce}",
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
				Audience: testClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
				Nonce:    "{mock-nonce}",
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
				Audience: testClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
				Nonce:    "{mock-nonce}",
			},
			resp: redeemResponse{
				AccessToken:  "a1234",
				ExpiresIn:    10,
				RefreshToken: "refresh12345",
			},
			expectedError: true,
		},
		{
			name: "missing nonce",
			claims: &claims{
				Issuer:   "{mock-issuer}",
				Audience: testClientID,
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
			name: "invalid nonce",
			claims: &claims{
				Issuer:   "{mock-issuer}",
				Audience: testClientID,
				Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
				Name:     "Michael Bland",
				Email:    "michael.bland@gsa.gov",
				Nonce:    "123456789",
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
			// swap the global OIDC URL template for a test provider URL
			azureOIDCConfigURLTemplate = providerURL.String()

			p := newAzureV2Provider(nil)
			err = p.Configure(microsoftTenantID)
			if err != nil {
				t.Error(err)
			}

			if tc.claims != nil {
				// create an instance of Builder that uses the rsa signer
				builder := jwt.Signed(rsaSigner)

				// add claims to the Builder
				tc.claims.Issuer = strings.Replace(tc.claims.Issuer, "{mock-issuer}", providerURL.String(), -1)
				tc.claims.Nonce = strings.Replace(tc.claims.Nonce, "{mock-nonce}", p.calculateNonce("1234"), -1)
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

			// graph service mock has to be set after p.Configure
			p.GraphService = &MockMSGraphService{}

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

func TestAzureV2GetSignInURL(t *testing.T) {
	testCases := []struct {
		name           string
		redirectURI    string
		state          string
		expectedParams url.Values
	}{
		{
			name:        "nonce values passed to azure should validate, pass one",
			redirectURI: "https://example.com/oauth/callback",
			state:       "1234",
			expectedParams: url.Values{
				"redirect_uri":  []string{"https://example.com/oauth/callback"},
				"response_mode": []string{"form_post"},
				"response_type": []string{"id_token code"},
				"scope":         []string{"openid email profile offline_access"},
				"state":         []string{"1234"},
				"client_id":     []string{testClientID},
				"prompt":        []string{"consent"},
			},
		},
		{
			name:        "nonce values passed to azure should validate, pass two",
			redirectURI: "https://example.com/oauth/callback",
			state:       "1234",
			expectedParams: url.Values{
				"redirect_uri":  []string{"https://example.com/oauth/callback"},
				"response_mode": []string{"form_post"},
				"response_type": []string{"id_token code"},
				"scope":         []string{"openid email profile offline_access"},
				"state":         []string{"1234"},
				"client_id":     []string{testClientID},
				"prompt":        []string{"consent"},
			},
		},
		{
			name:        "nonce values passed to azure should validate, pass three",
			redirectURI: "https://example.com/oauth/callback",
			state:       "4321",
			expectedParams: url.Values{
				"redirect_uri":  []string{"https://example.com/oauth/callback"},
				"response_mode": []string{"form_post"},
				"response_type": []string{"id_token code"},
				"scope":         []string{"openid email profile offline_access"},
				"state":         []string{"4321"},
				"client_id":     []string{testClientID},
				"prompt":        []string{"consent"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newAzureV2Provider(nil)
			p.Scope = "openid email profile offline_access"

			signInURL := p.GetSignInURL(tc.redirectURI, tc.state)
			parsedURL, err := url.Parse(signInURL)
			if err != nil {
				t.Error(err)
			}

			for k := range tc.expectedParams {
				if tc.expectedParams.Get(k) != parsedURL.Query().Get(k) {
					t.Logf("expected param %s: %+v", k, tc.expectedParams.Get(k))
					t.Logf("got      param %s: %+v", k, parsedURL.Query().Get(k))
				}
			}

			nonce := parsedURL.Query().Get("nonce")
			if p.validateNonce(nonce) != true {
				t.Logf("expected valid nonce, got: %+v", nonce)
			}
		})
	}
}

func TestAzureV2ValidateGroupMembers(t *testing.T) {
	testCases := []struct {
		name                string
		allowedGroups       []string
		mockedGroups        []string
		mockedError         error
		expectedGroups      []string
		expectedErrorString string
	}{
		{
			name:           "allowed groups and groups resource output exactly match should return all groups",
			allowedGroups:  []string{"group1", "group2", "group3"},
			mockedGroups:   []string{"group1", "group2", "group3"},
			expectedGroups: []string{"group1", "group2", "group3"},
		},
		{
			name:           "allowed groups should restrict to subset of groups",
			allowedGroups:  []string{"group1", "group2"},
			mockedGroups:   []string{"group1", "group2", "group3"},
			expectedGroups: []string{"group1", "group2"},
		},
		{
			name:           "allowed groups superset should not restrict to subset of groups",
			allowedGroups:  []string{"group1", "group2", "group3"},
			mockedGroups:   []string{"group1", "group2"},
			expectedGroups: []string{"group1", "group2"},
		},
		{
			name:           "groups allowed zero value should default to return all groups",
			allowedGroups:  []string{},
			mockedGroups:   []string{"group1"},
			expectedGroups: []string{"group1"},
		},
		{
			name:                "empty inputs and error on groups resource should return error",
			allowedGroups:       []string{},
			mockedError:         fmt.Errorf("error"),
			expectedErrorString: "error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := newAzureV2Provider(nil)
			p.GraphService = &MockMSGraphService{
				Groups:      tc.mockedGroups,
				GroupsError: tc.mockedError,
			}

			groups, err := p.ValidateGroupMembership("test@example.com", tc.allowedGroups, "")

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
