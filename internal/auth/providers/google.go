package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/auth/circuit"
	"github.com/buzzfeed/sso/internal/pkg/groups"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

// GoogleProvider is an implementation of the Provider interface.
type GoogleProvider struct {
	*ProviderData
	StatsdClient *statsd.Client
	AdminService AdminService
	cb           *circuit.Breaker
	GroupsCache  groups.MemberSetCache

	Prompt       string
	HostedDomain string
}

// NewGoogleProvider returns a new GoogleProvider and sets the provider url endpoints.
func NewGoogleProvider(p *ProviderData, prompt, hd, impersonate, credentials string) (*GoogleProvider, error) {
	p.ProviderName = "Google"
	p.SignInURL = &url.URL{Scheme: "https",
		Host: "accounts.google.com",
		Path: "/o/oauth2/v2/auth",
	}
	p.RedeemURL = &url.URL{Scheme: "https",
		Host: "www.googleapis.com",
		Path: "/oauth2/v4/token",
	}
	p.RevokeURL = &url.URL{Scheme: "https",
		Host: "accounts.google.com",
		Path: "/o/oauth2/revoke",
	}
	p.ValidateURL = &url.URL{Scheme: "https",
		Host: "www.googleapis.com",
		Path: "/oauth2/v3/tokeninfo",
	}
	p.ProfileURL = &url.URL{}

	if p.Scope == "" {
		p.Scope = "profile email"
	}

	if prompt == "" {
		prompt = "consent"
	}

	googleProvider := &GoogleProvider{
		ProviderData: p,
		Prompt:       prompt,
		HostedDomain: hd,
	}

	googleProvider.cb = circuit.NewBreaker(&circuit.Options{
		HalfOpenConcurrentRequests: 2,
		OnStateChange:              googleProvider.cbStateChange,
		OnBackoff:                  googleProvider.cbBackoff,
		ShouldTripFunc:             func(c circuit.Counts) bool { return c.ConsecutiveFailures >= 3 },
		ShouldResetFunc:            func(c circuit.Counts) bool { return c.ConsecutiveSuccesses >= 6 },
		BackoffDurationFunc: circuit.ExponentialBackoffDuration(
			time.Duration(200)*time.Second, time.Duration(500)*time.Millisecond,
		),
	})

	if credentials != "" {
		credsReader, err := os.Open(credentials)
		if err != nil {
			return nil, errors.New("could not read google credentials file")
		}

		googleProvider.AdminService = &GoogleAdminService{
			adminService: getAdminService(impersonate, credsReader),
			cb:           googleProvider.cb,
		}
	}

	return googleProvider, nil
}

// SetStatsdClient sets the google provider and admin service statsd client
func (p *GoogleProvider) SetStatsdClient(statsdClient *statsd.Client) {
	logger := log.NewLogEntry()

	p.StatsdClient = statsdClient

	switch s := p.AdminService.(type) {
	case *GoogleAdminService:
		s.StatsdClient = statsdClient
	default:
		logger.Info("admin service does not have statsd client")
	}

	switch g := p.GroupsCache.(type) {
	case *groups.FillCache:
		g.StatsdClient = statsdClient
	default:
		logger.Info("groups cache does not have statsd client")
	}
}

// ValidateSessionState attempts to validate the session state's access token.
func (p *GoogleProvider) ValidateSessionState(s *sessions.SessionState) bool {
	if s.AccessToken == "" {
		return false
	}

	params := url.Values{}
	params.Set("access_token", s.AccessToken)

	err := p.googleRequest("POST", p.ValidateURL.String(), params, []string{"action:validate"}, nil)
	if err != nil {
		return false
	}

	return true
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *GoogleProvider) GetSignInURL(redirectURI, state string) string {
	var a url.URL
	a = *p.SignInURL

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", p.Scope)
	params.Set("access_type", "offline")
	params.Set("state", state)
	params.Set("prompt", p.Prompt)

	if p.HostedDomain != "" {
		params.Set("hd", p.HostedDomain)
	}

	a.RawQuery = params.Encode()
	return a.String()
}

func (p *GoogleProvider) googleRequest(method, endpoint string, params url.Values, tags []string, response interface{}) error {
	logger := log.NewLogEntry()

	startTS := time.Now()
	var body io.Reader

	tags = append(tags, "provider:google")
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
			respBody).Error("non-200 response code returned from request to Google")
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

func emailFromIDToken(idToken string) (string, error) {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	b, err := jwtDecodeSegment(jwt[1])
	if err != nil {
		return "", err
	}

	var email struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
	if !email.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified", email.Email)
	}
	return email.Email, nil
}

func jwtDecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func (p *GoogleProvider) cbBackoff(duration time.Duration, reset time.Time) {
	logger := log.NewLogEntry()

	p.StatsdClient.Timing("provider.backoff", duration, nil, 1.0)
	logger.WithBackoffDuration(duration).WithBackoffReset(reset).Info(
		"circuit breaker backoff set")
}

func (p *GoogleProvider) cbStateChange(from, to circuit.State) {
	logger := log.NewLogEntry()

	p.StatsdClient.Incr("provider.circuit_change", []string{fmt.Sprintf("from_state:%s", from), fmt.Sprintf("to_state:%s", to)}, 1.0)
	logger.WithCircuitChangeFrom(from).WithCircuitChangeTo(to).Info("circuit breaker trigger")
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their Google account.
// The code is redeemed for an access token and refresh token
// 1. POSTs the code and grant_type to https://www.googleapis.com/oauth2/v3/token
// 2. If the request fails, the authenticator will return a 500 and display an error page (see oauth_proxy.go#OAuthCallback)
// 3. If the request succeeds, the data from Google contains:
//     - the access token which we use to get data from Google
//     - the refresh token which we can use to get a new access_token
//     - the expiration time of the access token
//     - a Base64 encoded id token which contains the user's email
//       address and whether or not that email address is verified
func (p *GoogleProvider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrBadRequest
	}

	params := url.Values{}
	params.Add("code", code)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("redirect_uri", redirectURL)
	params.Add("grant_type", "authorization_code")

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}

	err := p.googleRequest("POST", p.RedeemURL.String(), params, []string{"action:redeem"}, &response)
	if err != nil {
		return nil, err
	}

	var email string
	email, err = emailFromIDToken(response.IDToken)
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

// PopulateMembers is the fill function for the groups cache
func (p *GoogleProvider) PopulateMembers(group string) (groups.MemberSet, error) {
	members, err := p.AdminService.ListMemberships(group, 4)
	if err != nil {
		return nil, err
	}
	memberSet := map[string]struct{}{}
	for _, member := range members {
		memberSet[member] = struct{}{}
	}
	return memberSet, nil
}

// ValidateGroupMembership takes in an email and the allowed groups and returns the groups that the email is part of in that list.
// If `allGroups` is an empty list, returns an empty list.
func (p *GoogleProvider) ValidateGroupMembership(email string, allGroups []string, _ string) ([]string, error) {
	logger := log.NewLogEntry()

	groups := []string{}
	var useGroupsResource bool

	// if `allGroups` is empty, we return an empty list
	if len(allGroups) == 0 {
		return []string{}, nil
	}

	// iterate over the groups, if a set isn't populated only call the GroupsResource once and check all groups
	for _, group := range allGroups {
		memberSet, ok := p.GroupsCache.Get(group)
		if !ok {
			useGroupsResource = true
			if started := p.GroupsCache.RefreshLoop(group); started {
				logger.WithUserGroup(group).Info(
					"no member set cached for group; refresh loops started")
				p.StatsdClient.Incr("cache_refresh_loop", []string{"action:profile", fmt.Sprintf("group:%s", group)}, 1.0)
			}
		}
		if _, exists := memberSet[email]; exists {
			groups = append(groups, group)
		}
	}

	// if a cached member set was not populated, use the groups resource to get all the groups and filter out the ones that are in `allGroups`
	if useGroupsResource {
		return p.AdminService.CheckMemberships(allGroups, email)
	}

	return groups, nil

}

// RefreshSessionIfNeeded takes in a SessionState and
// returns false if the session is not refreshed and true if it is.
func (p *GoogleProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
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
func (p *GoogleProvider) RefreshAccessToken(refreshToken string) (token string, expires time.Duration, err error) {
	// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("client_secret", p.ClientSecret)
	params.Set("refresh_token", refreshToken)
	params.Set("grant_type", "refresh_token")

	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	err = p.googleRequest("POST", p.RedeemURL.String(), params, []string{"action:redeem"}, &response)
	if err != nil {
		return
	}

	token = response.AccessToken
	expires = time.Duration(response.ExpiresIn) * time.Second
	return
}

// Revoke revokes the access token a given session state.
func (p *GoogleProvider) Revoke(s *sessions.SessionState) error {
	params := url.Values{}
	params.Set("token", s.AccessToken)

	err := p.googleRequest("GET", p.RevokeURL.String(), params, []string{"action:revoke"}, nil)

	if err != nil && err != ErrTokenRevoked {
		return err
	}
	logger := log.NewLogEntry()

	logger.WithUser(s.Email).Info("revoked access token")
	return nil
}

// Stop calls stop on the groups cache
func (p *GoogleProvider) Stop() {
	p.GroupsCache.Stop()
}
