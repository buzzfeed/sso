package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bitly/oauth2_proxy/api"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"golang.org/x/oauth2"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	oidc "github.com/coreos/go-oidc"
)

// AzureV2Provider is an Azure AD v2 specific implementation of the Provider interface.
type AzureV2Provider struct {
	*ProviderData
	*OIDCProvider

	Tenant          string
	PermittedGroups []string
}

// NewAzureV2Provider creates a new AzureV2Provider struct
func NewAzureV2Provider(p *ProviderData) *AzureV2Provider {
	p.ProviderName = "Azure v2.0"
	return &AzureV2Provider{ProviderData: p, OIDCProvider: &OIDCProvider{ProviderData: p}}
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
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCProvider.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string   `json:"email"`
		UPN      string   `json:"upn"`
		Roles    []string `json:"roles"`
		Verified *bool    `json:"email_verified"`
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
		User:            claims.UPN,
		Groups:          claims.Roles,
	}

	return
}

// Configure sets the Azure tenant ID value for the provider
func (p *AzureV2Provider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}
	discoveryURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", p.Tenant)

	// Configure discoverable provider data.
	oidcProvider, err := oidc.NewProvider(context.Background(), discoveryURL)
	if err != nil {
		return
	}

	logger := log.NewLogEntry()

	p.OIDCProvider.Verifier = oidcProvider.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})
	p.SignInURL, err = url.Parse(oidcProvider.Endpoint().AuthURL)
	if err != nil {
		logger.Printf("Unable to parse OIDC Authentication URL: %v", err)
		return
	}
	p.RedeemURL, err = url.Parse(oidcProvider.Endpoint().TokenURL)
	if err != nil {
		logger.Printf("Unable to parse OIDC Token URL: %v", err)
		return
	}
	p.ProfileURL, err = url.Parse("https://graph.microsoft.com/oidc/userinfo")
	if err != nil {
		logger.Printf("Unable to parse OIDC UserInfo URL: %v", err)
		return
	}
	if p.Scope == "" {
		p.Scope = "openid email profile"
	}
}

// RefreshSessionIfNeeded takes in a SessionState and
// returns false if the session is not refreshed and true if it is.
func (p *AzureV2Provider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshDeadline.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}
	logger := log.NewLogEntry()

	s.RefreshDeadline = time.Now().Add(time.Second).Truncate(time.Second)
	logger.WithUser(s.Email).WithRefreshDeadline(s.RefreshDeadline).Info("refreshed access token")
	return false, nil
}

func getAzureHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetGroups lists groups user belongs to. Filter the desired names of groups (in case of huge group set)
func (p *AzureV2Provider) GetGroups(s *sessions.SessionState, f string) ([]string, error) {
	logger := log.NewLogEntry()
	logger.Printf("[azure_v2] GetGroups")
	if s.AccessToken == "" {
		return []string{}, errors.New("missing access token")
	}
	logger.Printf("Access Token %v", s.AccessToken)

	if s.IDToken == "" {
		return []string{}, errors.New("missing id token")
	}
	logger.Printf("ID Token %v", s.IDToken)

	groupNames := make([]string, 0)
	requestURL := p.ProfileURL.String()
	for {
		req, err := http.NewRequest("GET", requestURL, nil)

		if err != nil {
			return []string{}, err
		}
		req.Header = getAzureHeader(s.AccessToken)
		req.Header.Add("Content-Type", "application/json")

		groupData, err := api.Request(req)
		if err != nil {
			return []string{}, err
		}
		logger.Printf("Got Graph response: %v", groupData)

		for _, groupInfo := range groupData.Get("value").MustArray() {
			v, ok := groupInfo.(map[string]interface{})
			if !ok {
				continue
			}
			dname := v["displayName"].(string)
			if strings.Contains(dname, f) {
				groupNames = append(groupNames, dname)
			}

		}

		if nextlink := groupData.Get("@odata.nextLink").MustString(); nextlink != "" {
			requestURL = nextlink
		} else {
			break
		}
	}

	return groupNames, nil
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
	params.Set("nonce", "FIXME") // FIXME
	a.RawQuery = params.Encode()

	return a.String()
}

// SetGroupRestriction limits which groups are allowed
func (p *AzureV2Provider) SetGroupRestriction(groups []string) {
	logger := log.NewLogEntry()
	if len(groups) == 1 && strings.Index(groups[0], "|") >= 0 {
		p.PermittedGroups = strings.Split(groups[0], "|")
	} else {
		p.PermittedGroups = groups
	}
	logger.Printf("Set group restrictions. Allowed groups are:")
	for _, pGroup := range p.PermittedGroups {
		logger.Printf("\t'%s'", pGroup)
	}
}

// ValidateGroup ensures that a user is a member of a permitted group
func (p *AzureV2Provider) ValidateGroup(s *sessions.SessionState) bool {
	if len(p.PermittedGroups) != 0 {
		for _, pGroup := range p.PermittedGroups {

			if contains(s.Groups, pGroup) {
				return true
			}
		}
		return false
	}
	return true
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
