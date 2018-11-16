package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
	"golang.org/x/oauth2"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	oidc "github.com/coreos/go-oidc"
)

var (
	azureOIDCConfigURL  = "https://login.microsoftonline.com/{tenant}/v2.0"
	azureOIDCProfileURL = "https://graph.microsoft.com/oidc/userinfo"
)

// AzureV2Provider is an Azure AD v2 specific implementation of the Provider interface.
type AzureV2Provider struct {
	*ProviderData
	*OIDCProvider

	Tenant string

	StatsdClient *statsd.Client

	GraphService GraphService
}

// NewAzureV2Provider creates a new AzureV2Provider struct
func NewAzureV2Provider(p *ProviderData) *AzureV2Provider {
	p.ProviderName = "Azure AD"
	return &AzureV2Provider{
		ProviderData: p,
		OIDCProvider: &OIDCProvider{ProviderData: p},
	}
}

// SetStatsdClient sets the azure provider statsd client
func (p *AzureV2Provider) SetStatsdClient(statsdClient *statsd.Client) {
	p.StatsdClient = statsdClient
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their Azure AD account.
func (p *AzureV2Provider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	// BUG?  rawIDToken is empty string here in current test cases. Test cases
	// are shipping invalid ID tokens, but the Extra function doesn't seem to have
	// code that would be affected by that.
	if !ok || rawIDToken == "" {
		fmt.Printf("token: %+v\n", token)
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// should only happen if oidc autodiscovery is broken
	if p.OIDCProvider.Verifier == nil {
		return nil, fmt.Errorf("oidc verifier missing")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCProvider.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email string `json:"email"`
		UPN   string `json:"upn"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	// TODO: test this w/ an account that uses an alias and compare email claim
	// with UPN claim; UPN has usually been what you want, but I think it's not
	// rendered as a full email address here.

	s = &sessions.SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,

		RefreshDeadline:  token.Expiry,
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),

		Email: claims.Email,
		User:  claims.UPN,
	}

	if p.GraphService != nil {
		groupNames, err := p.GraphService.GetGroups(claims.Email)
		if err != nil {
			return nil, fmt.Errorf("could not get groups: %v", err)
		}
		s.Groups = groupNames
	}
	return
}

// Configure sets the Azure tenant ID value for the provider
func (p *AzureV2Provider) Configure(tenant string) error {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}
	discoveryURL := strings.Replace(azureOIDCConfigURL, "{tenant}", p.Tenant, -1)

	// Configure discoverable provider data.
	oidcProvider, err := oidc.NewProvider(context.Background(), discoveryURL)
	if err != nil {
		// FIXME: this seems like it _should_ work for "common", but it doesn't
		// Does anyone actually want to use this with "common" though?
		return err
	}

	p.OIDCProvider.Verifier = oidcProvider.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})
	// Set these only if they haven't been overridden
	if p.SignInURL == nil || p.SignInURL.String() == "" {
		p.SignInURL, err = url.Parse(oidcProvider.Endpoint().AuthURL)
		if err != nil {
			return err
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL, err = url.Parse(oidcProvider.Endpoint().TokenURL)
		if err != nil {
			return err
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL, err = url.Parse(azureOIDCProfileURL)
	}
	if err != nil {
		return err
	}
	if p.Scope == "" {
		p.Scope = "openid email profile offline_access"
	}
	if p.RedeemURL.String() == "" {
		return errors.New("redeem url must be set")
	}
	p.GraphService = NewAzureGraphService(p.ClientID, p.ClientSecret, p.RedeemURL.String())
	return nil
}

// RefreshSessionIfNeeded takes in a SessionState and
// returns false if the session is not refreshed and true if it is.
func (p *AzureV2Provider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || !s.RefreshPeriodExpired() || s.RefreshToken == "" {
		return false, nil
	}

	newToken, duration, err := p.RefreshAccessToken(s.RefreshToken)
	if err != nil {
		return false, err
	}
	logger := log.NewLogEntry()

	s.AccessToken = newToken

	s.RefreshDeadline = time.Now().Add(duration).Truncate(time.Second)
	logger.WithUser(s.Email).WithRefreshDeadline(s.RefreshDeadline).Info("refreshed access token")

	return true, nil
}

// RefreshAccessToken uses default OAuth2 TokenSource method to get a new
// access token.
func (p *AzureV2Provider) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	if refreshToken == "" {
		return "", 0, errors.New("missing refresh token")
	}
	logger := log.NewLogEntry()
	logger.Info("refreshing access token")

	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := oauth2.Token{
		RefreshToken: refreshToken,
	}
	ts := c.TokenSource(ctx, &t)
	newToken, err := ts.Token()
	if err != nil {
		return "", 0, fmt.Errorf("token exchange: %v", err)
	}

	return newToken.AccessToken, newToken.Expiry.Sub(time.Now()), nil
}

func getAzureHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// ValidateSessionState attempts to validate the session state's access token.
func (p *AzureV2Provider) ValidateSessionState(s *sessions.SessionState) bool {
	// return validateToken(p, s.AccessToken, nil)
	// TODO Validate ID token
	return true
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *AzureV2Provider) GetSignInURL(redirectURI, state string) string {
	var a url.URL
	a = *p.SignInURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "id_token code")
	params.Set("redirect_uri", redirectURI)
	params.Set("response_mode", "form_post")
	params.Add("scope", p.Scope)
	params.Add("state", state)
	params.Set("prompt", p.ApprovalPrompt)
	params.Set("nonce", p.calculateNonce(state)) // required parameter
	a.RawQuery = params.Encode()

	return a.String()
}

// calculateNonce generates a deterministic nonce from the state value.
// We don't have a session state pointer but we need to generate a nonce
// that we can verify statelessly later. We can only use what's in the
// params and provider struct to assemble a nonce. State is guaranteed to be
// indistinguishable from random and will always change.
func (p *AzureV2Provider) calculateNonce(state string) string {
	key := []byte(p.ClientID + p.ClientSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(state))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:8]
}

// ValidateGroupMembership takes in an email and the allowed groups and returns the groups that the email is part of in that list.
// If `allGroups` is an empty list it returns all the groups that the user belongs to.
func (p *AzureV2Provider) ValidateGroupMembership(email string, allGroups []string) ([]string, error) {
	if p.GraphService == nil {
		panic("provider has not been configured")
	}

	userGroups, err := p.GraphService.GetGroups(email)
	if err != nil {
		return nil, err
	}

	// if `allGroups` is empty use the groups resource
	if len(allGroups) == 0 {
		return userGroups, nil
	}

	filtered := []string{}
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allGroups {
			if userGroup == allowedGroup {
				filtered = append(filtered, userGroup)
			}
		}
	}

	return filtered, nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
