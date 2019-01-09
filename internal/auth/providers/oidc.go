package providers

import (
	"context"
	"errors"
	"fmt"
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
func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their OpenID Connect account.
func (p *OIDCProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
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

	s = &sessions.SessionState{
		AccessToken:     token.AccessToken,
		RefreshToken:    token.RefreshToken,
		RefreshDeadline: token.Expiry,
		Email:           claims.Email,
	}

	return
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