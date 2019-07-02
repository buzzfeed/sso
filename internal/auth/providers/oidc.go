package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	oidc "github.com/coreos/go-oidc"
)

// OIDCProvider is a generic OpenID Connect provider
type OIDCProvider struct {
	*ProviderData

	Verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider creates a new generic OpenID Connect provider
func NewOIDCProvider(p *ProviderData, discoveryURL string) (*OIDCProvider, error) {
	provider := &OIDCProvider{
		ProviderData: p,
	}
	if p.ProviderName == "" {
		p.ProviderName = "OpenID Connect"
	}

	// Configure discoverable provider data.
	oidcProvider, err := oidc.NewProvider(context.Background(), discoveryURL)
	if err != nil {
		// TODO: This seems like it _should_ work for "common", but it doesn't
		// Does anyone actually want to use this with "common" though?
		return nil, err
	}

	provider.Verifier = oidcProvider.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})
	// Set these only if they haven't been overridden
	if p.SignInURL == nil || p.SignInURL.String() == "" {
		p.SignInURL, err = url.Parse(oidcProvider.Endpoint().AuthURL)
		if err != nil {
			return nil, err
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL, err = url.Parse(oidcProvider.Endpoint().TokenURL)
		if err != nil {
			return nil, err
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL, err = url.Parse(azureOIDCProfileURL)
	}
	if err != nil {
		return nil, err
	}
	if p.Scope == "" {
		p.Scope = "openid email profile offline_access"
	}
	if p.RedeemURL.String() == "" {
		return nil, errors.New("redeem url must be set")
	}

	return provider, nil
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their OpenID Connect account.
func (p *OIDCProvider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
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
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	s := &sessions.SessionState{
		AccessToken:      token.AccessToken,
		RefreshToken:     token.RefreshToken,
		RefreshDeadline:  token.Expiry,
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),
		Email:            claims.Email,
	}

	return s, nil
}

// RefreshSessionIfNeeded takes in a SessionState and
// returns false if the session is not refreshed and true if it is.
func (p *OIDCProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
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
func (p *OIDCProvider) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	if refreshToken == "" {
		return "", 0, errors.New("missing refresh token")
	}

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

// ValidateSessionState attempts to validate the session state's access token.
func (p *OIDCProvider) ValidateSessionState(s *sessions.SessionState) bool {
	// return validateToken(p, s.AccessToken, nil)
	// TODO Validate ID token
	return true
}
