package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/buzzfeed/sso/internal/auth/circuit"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

// OktaProvider is an implementation of the Provider interface.
type OktaProvider struct {
	*ProviderData
	StatsdClient *statsd.Client
	cb           *circuit.Breaker
}

type GetUserProfileResponse struct {
	EmailAddress  string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
}

// NewOktaProvider returns a new OktaProvider and sets the provider url endpoints.
func NewOktaProvider(p *ProviderData, OrgURL, providerServerID string) (*OktaProvider, error) {
	if OrgURL != "" || providerServerID != "" {
		if OrgURL == "" {
			return nil, errors.New("missing setting: okta_org_url")
		}
		if providerServerID == "" {
			return nil, errors.New("missing setting: provider_server_id")
		}
	}

	p.ProviderName = "Okta"
	scheme := "https"
	// interact with resource owner and obtain an authorization grant
	if p.SignInURL.String() == "" {
		p.SignInURL = &url.URL{
			Scheme: scheme,
			Host:   OrgURL,
			Path:   fmt.Sprintf("/oauth2/%s/v1/authorize", providerServerID)}
		// to get a refresh token. see https://developer.okta.com/authentication-guide/tokens/refreshing-tokens/
	}
	// returns access tokens, ID tokens or refresh tokens
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: scheme,
			Host:   OrgURL,
			Path:   fmt.Sprintf("/oauth2/%s/v1/token", providerServerID)}
	}
	// revokes an access or refresh token
	if p.RevokeURL.String() == "" {
		p.RevokeURL = &url.URL{
			Scheme: scheme,
			Host:   OrgURL,
			Path:   fmt.Sprintf("/oauth2/%s/v1/revoke", providerServerID)}
	}
	// takes an access token and returns claims for the currently logged-in user
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: scheme,
			Host:   OrgURL,
			Path:   fmt.Sprintf("/oauth2/%s/v1/userinfo", providerServerID)}
	}
	// takes token as a URL query and returns active/inactive, and further info if active.
	if p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: scheme,
			Host:   OrgURL,
			Path:   fmt.Sprintf("/oauth2/%s/v1/introspect", providerServerID)}
	}
	if p.Scope == "" {
		// https://developer.okta.com/docs/api/resources/oidc/#scopes
		p.Scope = "openid profile email groups offline_access"
	}

	oktaProvider := &OktaProvider{
		ProviderData: p,
	}

	oktaProvider.cb = circuit.NewBreaker(&circuit.Options{
		HalfOpenConcurrentRequests: 2,
		OnStateChange:              oktaProvider.cbStateChange,
		OnBackoff:                  oktaProvider.cbBackoff,
		ShouldTripFunc:             func(c circuit.Counts) bool { return c.ConsecutiveFailures >= 3 },
		ShouldResetFunc:            func(c circuit.Counts) bool { return c.ConsecutiveSuccesses >= 6 },
		BackoffDurationFunc: circuit.ExponentialBackoffDuration(
			time.Duration(200)*time.Second, time.Duration(500)*time.Millisecond,
		),
	})
	return oktaProvider, nil
}

// Sets the providers StatsdClient
func (p *OktaProvider) SetStatsdClient(statsdClient *statsd.Client) {
	p.StatsdClient = statsdClient
}

// ValidateSessionState attempts to validate the session state's access token.
func (p *OktaProvider) ValidateSessionState(s *sessions.SessionState) bool {
	if s.AccessToken == "" {
		return false
	}

	var response struct {
		Active bool `json:"active"`
	}

	form := url.Values{}
	form.Add("token", s.AccessToken)
	form.Add("token_type_hint", "access_token")
	form.Add("client_id", p.ClientID)
	form.Add("client_secret", p.ClientSecret)

	err := p.oktaRequest("POST", p.ValidateURL.String(), form, []string{"action:validate"}, nil, &response)
	if err != nil {
		return false
	}
	if !response.Active {
		return false
	}

	return true
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *OktaProvider) GetSignInURL(redirectURI, state string) string {
	// https://developer.okta.com/docs/api/resources/oidc/#authorize
	var a url.URL
	a = *p.SignInURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Add("response_mode", "query")
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

func (p *OktaProvider) oktaRequest(method, endpoint string, params url.Values, tags []string, header http.Header, response interface{}) error {
	logger := log.NewLogEntry()

	startTS := time.Now()
	var body io.Reader

	tags = append(tags, "provider:okta")
	switch method {
	case "POST":
		body = bytes.NewBufferString(params.Encode())
	case "GET":
		// error checking skipped because we are just parsing in
		// order to make a copy of an existing URL
		u, _ := url.Parse(endpoint)
		u.RawQuery = params.Encode()
		endpoint = u.String()
	default:
		// ¯\_(ツ)_/¯
		return ErrBadRequest
	}

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return err
	}
	if header != nil {
		req.Header = header
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.StatsdClient.Incr("provider.request", tags, 1.0)
	resp, err := httpClient.Do(req)
	if err != nil {
		tags = append(tags, "error:http_client_error")
		p.StatsdClient.Incr("provider.internal_error", tags, 1.0)
		return err
	}
	tags = append(tags, fmt.Sprintf("status_code:%d", resp.StatusCode))
	p.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
	p.StatsdClient.Incr("provider.response", tags, 1.0)

	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		tags = append(tags, "error:invalid_body")
		p.StatsdClient.Incr("provider.internal_error", tags, 1.0)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		p.StatsdClient.Incr("provider.error", tags, 1.0)
		logger.WithHTTPStatus(resp.StatusCode).WithEndpoint(stripToken(endpoint)).WithResponseBody(
			respBody).Info()
		switch resp.StatusCode {
		case 400:
			var response struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			e := json.Unmarshal(respBody, &response)
			if e == nil && response.ErrorDescription == "Token expired or revoked" {
				p.StatsdClient.Incr("provider.token_revoked", tags, 1.0)
				return ErrTokenRevoked
			}
			return ErrBadRequest
		case 429:
			return ErrRateLimitExceeded
		default:
			return ErrServiceUnavailable
		}
	}

	if response != nil {
		err := json.Unmarshal(respBody, &response)
		if err != nil {
			p.StatsdClient.Incr("provider.internal_error", tags, 1.0)
			return err
		}
	}

	return nil
}

func (p *OktaProvider) cbBackoff(duration time.Duration, reset time.Time) {
	logger := log.NewLogEntry()

	p.StatsdClient.Timing("provider.backoff", duration, nil, 1.0)
	logger.WithBackoffDuration(duration).WithBackoffReset(reset).Info(
		"circuit breaker backoff set")
}

func (p *OktaProvider) cbStateChange(from, to circuit.State) {
	logger := log.NewLogEntry()

	p.StatsdClient.Incr("provider.circuit_change", []string{fmt.Sprintf("from_state:%s", from), fmt.Sprintf("to_state:%s", to)}, 1.0)
	logger.WithCircuitChangeFrom(from).WithCircuitChangeTo(to).Info("circuit breaker trigger")
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their Okta account.
// The code is redeemed for an access token and refresh token
// 1. POSTs the code and grant_type to https://developer.okta.com/docs/api/resources/oidc/#token
// 2. If the request fails, the authenticator will return a 500 and display an error page (see oauth_proxy.go#OAuthCallback)
// 3. If the request succeeds, the data from Okta contains:
//     - the access token which we use to get data from Okta
//     - the refresh token which we can use to get a new access_token
//     - the expiration time of the access token
//     - a Base64 encoded id token which contains the user's email
//       address and whether or not that email address is verified
func (p *OktaProvider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrBadRequest
	}
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	params.Add("scope", p.Scope)

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}
	err := p.oktaRequest("POST", p.RedeemURL.String(), params, []string{"action:redeem"}, nil, &response)
	if err != nil {
		return nil, err
	}
	var email string
	email, err = p.verifyEmailWithAccessToken(response.AccessToken)
	if err != nil {
		return nil, err
	}
	return &sessions.SessionState{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,

		RefreshDeadline:  sessions.ExtendDeadline(time.Duration(response.ExpiresIn) * time.Second),
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),
		Email:            email,
	}, nil
}

// verifyEmailWithAccessToken takes in an access token and
// checks if it is verified with Okta. Conditionally returns
// an empty string, or if validated the email address in question.
func (p *OktaProvider) verifyEmailWithAccessToken(AccessToken string) (string, error) {
	if AccessToken == "" {
		return "", ErrBadRequest
	}

	userinfo, err := p.GetUserProfile(AccessToken)
	if err != nil {
		return "", err
	}
	if userinfo.EmailAddress == "" {
		return "", errors.New("missing email")
	}
	if !userinfo.EmailVerified {
		return "", errors.New("email not verified")
	}

	return userinfo.EmailAddress, nil
}

// ValidateGroupMembership takes in an email, a list of allowed groups an access token
// - sends a request to the /userinfo endpoint to return a slice of users' group membership
// - compares allowed groups to users' groups.
// Conditionally returns an empty (nil) slice or a slice of the matching groups.
func (p *OktaProvider) ValidateGroupMembership(email string, allowedGroups []string, accessToken string) ([]string, error) {
	if accessToken == "" {
		return nil, ErrBadRequest
	}

	if len(allowedGroups) == 0 {
		return []string{}, nil
	}
	userinfo, err := p.GetUserProfile(accessToken)
	if err != nil {
		return nil, err
	}
	if len(userinfo.Groups) == 0 {
		return nil, errors.New("no group membership found")
	}

	matchingGroups := []string{}
	for _, x := range allowedGroups {
		for _, y := range userinfo.Groups {
			if x == y {
				matchingGroups = append(matchingGroups, x)
				break
			}
		}
	}
	return matchingGroups, nil
}

// GetUserProfile takes in an access token and sends a request to the /userinfo endpoint.
// Conditionally returns nil response or a struct of specified claims.
func (p *OktaProvider) GetUserProfile(AccessToken string) (*GetUserProfileResponse, error) {
	// https://developer.okta.com/docs/api/resources/oidc/#userinfo
	response := &GetUserProfileResponse{}

	if AccessToken == "" {
		return nil, ErrBadRequest
	}
	bearer := fmt.Sprintf("Bearer %s", AccessToken)
	header := http.Header{}
	header.Set("Authorization", bearer)

	err := p.oktaRequest("GET", p.ProfileURL.String(), nil, []string{"action:userinfo"}, header, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// RefreshSessionIfNeeded takes in a SessionState and
// returns false if the session is not refreshed and true if it is.
func (p *OktaProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
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

// RefreshAccessToken takes in a refresh token and returns the new access token along with an expiration date.
func (p *OktaProvider) RefreshAccessToken(refreshToken string) (token string, expires time.Duration, err error) {
	// https://developer.okta.com/docs/api/resources/oidc/#token

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")

	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	err = p.oktaRequest("POST", p.RedeemURL.String(), params, []string{"action:refresh"}, nil, &response)
	if err != nil {
		return
	}

	token = response.AccessToken
	expires = time.Duration(response.ExpiresIn) * time.Second
	return
}

// Revoke revokes the access token a given session state.
func (p *OktaProvider) Revoke(s *sessions.SessionState) error {
	// https://developer.okta.com/docs/api/resources/oidc/#revoke
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("token", s.AccessToken)

	err := p.oktaRequest("POST", p.RevokeURL.String(), params, []string{"action:revoke"}, nil, nil)

	if err != nil && err != ErrTokenRevoked {
		return err
	}
	logger := log.NewLogEntry()

	logger.WithUser(s.Email).Info("revoked access token")
	return nil
}
