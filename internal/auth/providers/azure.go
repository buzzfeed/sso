package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
	"golang.org/x/oauth2"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

var (
	azureOIDCConfigURLTemplate = "https://login.microsoftonline.com/{tenant}/v2.0"
	azureOIDCProfileURL        = "https://graph.microsoft.com/oidc/userinfo"

	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/c167afed3aae
	_ Provider = &AzureV2Provider{}
)

// AzureV2Provider is an Azure AD v2 specific implementation of the Provider interface.
type AzureV2Provider struct {
	*ProviderData
	*OIDCProvider

	Tenant string

	StatsdClient *statsd.Client
	NonceCipher  aead.Cipher
	GraphService GraphService
}

// NewAzureV2Provider creates a new AzureV2Provider struct
func NewAzureV2Provider(p *ProviderData) (*AzureV2Provider, error) {
	if p.ProviderName == "" {
		p.ProviderName = "Azure AD"
	}

	if p.ClientSecret == "" {
		return nil, errors.New("client secret cannot be empty")
	}
	// Can't guarantee the client secret will be 32 or 64 bytes in length,
	// hash to derive a key, error on empty string to avoid silent failure.
	key := sha256.Sum256([]byte(p.ClientSecret))
	nonceCipher, err := aead.NewMiscreantCipher(key[:])
	if err != nil {
		return nil, err
	}

	return &AzureV2Provider{
		ProviderData: p,
		NonceCipher:  nonceCipher,
		OIDCProvider: nil,
	}, nil
}

// SetStatsdClient sets the azure provider statsd client
func (p *AzureV2Provider) SetStatsdClient(statsdClient *statsd.Client) {
	p.StatsdClient = statsdClient
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their Azure AD account.
func (p *AzureV2Provider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
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

	// should only happen if oidc autodiscovery is broken or unconfigured
	if p.OIDCProvider == nil || p.OIDCProvider.Verifier == nil {
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
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	if claims.Nonce == "" {
		return nil, fmt.Errorf("id_token did not contain a nonce")
	}
	if !p.validateNonce(claims.Nonce) {
		return nil, fmt.Errorf("unable to validate id_token nonce")
	}
	// TODO: test this w/ an account that uses an alias and compare email claim
	// with UPN claim; UPN has usually been what you want, but I think it's not
	// rendered as a full email address here.

	s := &sessions.SessionState{
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
	return s, nil
}

// Configure sets the Azure tenant ID value for the provider
func (p *AzureV2Provider) Configure(tenant string) error {
	p.Tenant = tenant
	if p.Tenant == "" {
		// TODO: See below, "common" is the right default value, and while
		// Azure AD docs suggest this should work, it results in an error.
		p.Tenant = "common"
	}
	discoveryURL := strings.Replace(azureOIDCConfigURLTemplate, "{tenant}", p.Tenant, -1)

	// Configure discoverable provider data.
	var err error
	p.OIDCProvider, err = NewOIDCProvider(p.ProviderData, discoveryURL)
	if err != nil {
		return err
	}

	p.GraphService = NewMSGraphService(p.ClientID, p.ClientSecret, p.RedeemURL.String())
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

// RefreshAccessToken uses default OAuth2 TokenSource method to get a new access token.
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

// Revoke does nothing for Azure AD, but needs to be declared to avoid a
// not implemented error which would prevent clearing sessions on sign out.
func (p *AzureV2Provider) Revoke(s *sessions.SessionState) error {
	return nil
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
	params.Set("prompt", "FIXME")
	params.Set("nonce", p.calculateNonce(state)) // required parameter
	a.RawQuery = params.Encode()

	return a.String()
}

// calculateNonce generates a verifiable nonce from the state value.
// A nonce can be subsequently validated by attempting to decrypt it.
func (p *AzureV2Provider) calculateNonce(state string) string {
	rawNonce, err := p.NonceCipher.Encrypt([]byte(state))
	if err != nil {
		// GetSignInURL can't return an error and this shouldn't fail silently
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(rawNonce)
}

// validateNonce attempts to decrypt the nonce value. If it decrypts
// successfully, the nonce is considered valid.
func (p *AzureV2Provider) validateNonce(nonce string) bool {
	rawNonce, err := base64.URLEncoding.DecodeString(nonce)
	if err != nil {
		return false
	}
	state, err := p.NonceCipher.Decrypt(rawNonce)
	if err != nil {
		return false
	}
	// Sanity check to ensure state contains roughly what we expect
	_, err = base64.URLEncoding.DecodeString(string(state))
	if err != nil {
		return false
	}
	return true
}

// ValidateGroupMembership takes in an email and the allowed groups and returns the groups that the email is part of in that list.
// If `allGroups` is an empty list it returns all the groups that the user belongs to.
func (p *AzureV2Provider) ValidateGroupMembership(email string, allGroups []string, _ string) ([]string, error) {
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
