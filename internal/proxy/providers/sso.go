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
	"os"
	"strings"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/datadog/datadog-go/statsd"
)

var (
	// This is a compile-time check to make sure our types correctly implement the interface:
	// https://medium.com/@matryer/golang-tip-compile-time-checks-to-ensure-your-type-satisfies-an-interface-c167afed3aae
	_ Provider = &SSOProvider{}
)

// Errors
var (
	ErrMissingRefreshToken     = errors.New("missing refresh token")
	ErrAuthProviderUnavailable = errors.New("auth provider unavailable")
)

var userAgentString string

// SSOProvider holds the data associated with the SSOProviders
// necessary to implement a SSOProvider interface.
type SSOProvider struct {
	*ProviderData

	StatsdClient *statsd.Client
}

func init() {
	version := os.Getenv("RIG_IMAGE_VERSION")
	if version == "" {
		version = "HEAD"
	} else {
		version = strings.Trim(version, `"`)
	}
	userAgentString = fmt.Sprintf("sso_proxy/%s", version)
}

// NewSSOProvider instantiates a new SSOProvider with provider data and
// a statsd client.
func NewSSOProvider(p *ProviderData, sc *statsd.Client) *SSOProvider {
	p.ProviderName = "SSO"
	base := p.ProviderURL
	p.SignInURL = base.ResolveReference(&url.URL{Path: "/sign_in"})
	p.SignOutURL = base.ResolveReference(&url.URL{Path: "/sign_out"})
	p.RedeemURL = base.ResolveReference(&url.URL{Path: "/redeem"})
	p.RefreshURL = base.ResolveReference(&url.URL{Path: "/refresh"})
	p.ValidateURL = base.ResolveReference(&url.URL{Path: "/validate"})
	p.ProfileURL = base.ResolveReference(&url.URL{Path: "/profile"})
	p.ProxyRedeemURL = p.ProxyProviderURL.ResolveReference(&url.URL{Path: "/redeem"})
	return &SSOProvider{
		ProviderData: p,
		StatsdClient: sc,
	}
}

func newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgentString)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func isProviderUnavailable(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable
}

func extendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}

func (p *SSOProvider) withinGracePeriod(s *SessionState) bool {
	if s.GracePeriodStart.IsZero() {
		s.GracePeriodStart = time.Now()
	}
	return s.GracePeriodStart.Add(p.GracePeriodTTL).After(time.Now())
}

// Redeem takes a redirectURL and code and redeems the SessionState
func (p *SSOProvider) Redeem(redirectURL, code string) (*SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}

	// TODO: remove "grant_type" and "redirect_uri", unused by authenticator
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	req, err := newRequest("POST", p.ProxyRedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Host = p.RedeemURL.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isProviderUnavailable(resp.StatusCode) {
			return nil, ErrAuthProviderUnavailable
		}
		return nil, fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Email        string `json:"email"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return nil, err
	}

	user := strings.Split(jsonResponse.Email, "@")[0]
	return &SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,

		RefreshDeadline:  extendDeadline(time.Duration(jsonResponse.ExpiresIn) * time.Second),
		LifetimeDeadline: extendDeadline(p.SessionLifetimeTTL),
		ValidDeadline:    extendDeadline(p.SessionValidTTL),

		Email: jsonResponse.Email,
		User:  user,
	}, nil
}

// ValidateGroup does a GET request to the profile url and returns true if the user belongs to
// an authorized group.
func (p *SSOProvider) ValidateGroup(email string, allowedGroups []string) ([]string, bool, error) {
	logger := log.NewLogEntry()

	logger.WithUser(email).WithAllowedGroups(allowedGroups).Info("validating groups")
	inGroups := []string{}
	if len(allowedGroups) == 0 {
		return inGroups, true, nil
	}

	userGroups, err := p.UserGroups(email, allowedGroups)
	if err != nil {
		return nil, false, err
	}

	allowed := false
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allowedGroups {
			if userGroup == allowedGroup {
				inGroups = append(inGroups, userGroup)
				allowed = true
			}
		}
	}

	return inGroups, allowed, nil
}

// UserGroups takes an email and returns the UserGroups for that email
func (p *SSOProvider) UserGroups(email string, groups []string) ([]string, error) {
	params := url.Values{}
	params.Add("email", email)
	params.Add("client_id", p.ClientID)
	params.Add("groups", strings.Join(groups, ","))

	req, err := newRequest("GET", fmt.Sprintf("%s?%s", p.ProfileURL.String(), params.Encode()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Client-Secret", p.ClientSecret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isProviderUnavailable(resp.StatusCode) {
			return nil, ErrAuthProviderUnavailable
		}
		return nil, fmt.Errorf("got %d from %q %s", resp.StatusCode, p.ProfileURL.String(), body)
	}

	var jsonResponse struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return nil, err
	}

	return jsonResponse.Groups, nil
}

// RefreshSession takes a SessionState and allowedGroups and refreshes the session access token,
// returns `true` on success, and `false` on error
func (p *SSOProvider) RefreshSession(s *SessionState, allowedGroups []string) (bool, error) {
	logger := log.NewLogEntry()

	if s.RefreshToken == "" {
		return false, ErrMissingRefreshToken
	}

	newToken, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we refresh and continue
		// as normal during the "grace period"
		if err == ErrAuthProviderUnavailable && p.withinGracePeriod(s) {
			tags := []string{"action:refresh_session", "error:redeem_token_failed"}
			p.StatsdClient.Incr("provider_error_fallback", tags, 1.0)
			s.RefreshDeadline = extendDeadline(p.SessionValidTTL)
			return true, nil
		}
		return false, err
	}

	inGroups, validGroup, err := p.ValidateGroup(s.Email, allowedGroups)
	if err != nil {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we refresh and continue
		// as normal during the "grace period"
		if err == ErrAuthProviderUnavailable && p.withinGracePeriod(s) {
			tags := []string{"action:refresh_session", "error:user_groups_failed"}
			p.StatsdClient.Incr("provider_error_fallback", tags, 1.0)
			s.RefreshDeadline = extendDeadline(p.SessionValidTTL)
			return true, nil
		}
		return false, err
	}
	if !validGroup {
		return false, errors.New("Group membership revoked")
	}
	s.Groups = inGroups

	s.AccessToken = newToken
	s.RefreshDeadline = extendDeadline(duration)
	s.GracePeriodStart = time.Time{}
	logger.WithUser(s.Email).WithRefreshDeadline(s.RefreshDeadline).Info("refreshed session access token")
	return true, nil
}

func (p *SSOProvider) redeemRefreshToken(refreshToken string) (token string, expires time.Duration, err error) {
	// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	var req *http.Request
	req, err = newRequest("POST", p.RefreshURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusCreated {
		if isProviderUnavailable(resp.StatusCode) {
			err = ErrAuthProviderUnavailable
		} else {
			err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RefreshURL.String(), body)
		}
		return
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}

// ValidateSessionState takes a sessionState and allowedGroups and validates the session state
func (p *SSOProvider) ValidateSessionState(s *SessionState, allowedGroups []string) bool {
	logger := log.NewLogEntry()

	// we validate the user's access token is valid
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	req, err := newRequest("GET", fmt.Sprintf("%s?%s", p.ValidateURL.String(), params.Encode()), nil)
	if err != nil {
		logger.WithUser(s.Email).Error(err, "error validating session state")
		return false
	}
	req.Header.Set("X-Client-Secret", p.ClientSecret)
	req.Header.Set("X-Access-Token", s.AccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.WithUser(s.Email).Error("error making request to validate access token")
		return false
	}

	if resp.StatusCode != 200 {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we validate and continue
		// as normal during the "grace period"
		if isProviderUnavailable(resp.StatusCode) && p.withinGracePeriod(s) {
			tags := []string{"action:validate_session", "error:validation_failed"}
			p.StatsdClient.Incr("provider_error_fallback", tags, 1.0)
			s.ValidDeadline = extendDeadline(p.SessionValidTTL)
			return true
		}
		logger.WithUser(s.Email).WithHTTPStatus(resp.StatusCode).Info(
			"could not validate user access token")
		return false
	}

	// check the user is in the proper group(s)
	inGroups, validGroup, err := p.ValidateGroup(s.Email, allowedGroups)
	if err != nil {
		// When we detect that the auth provider is not explicitly denying
		// authentication, and is merely unavailable, we validate and continue
		// as normal during the "grace period"
		if err == ErrAuthProviderUnavailable && p.withinGracePeriod(s) {
			tags := []string{"action:validate_session", "error:user_groups_failed"}
			p.StatsdClient.Incr("provider_error_fallback", tags, 1.0)
			s.ValidDeadline = extendDeadline(p.SessionValidTTL)
			return true
		}
		logger.WithUser(s.Email).Error(err, "error fetching group memberships")
		return false
	}

	if !validGroup {
		logger.WithUser(s.Email).WithAllowedGroups(allowedGroups).Info(
			"user is no longer in valid groups")
		return false
	}
	s.Groups = inGroups

	s.ValidDeadline = extendDeadline(p.SessionValidTTL)
	s.GracePeriodStart = time.Time{}

	logger.WithUser(s.Email).WithSessionValid(s.ValidDeadline).Info("validated session")

	return true
}
