package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

// SetStatsdClient fulfills the Provider interface
func (p *ProviderData) SetStatsdClient(*statsd.Client) {
	return
}

// Redeem takes in a redirect url and code and calls the redeem url endpoint, returning a session state if a valid
// access token is redeemed.
func (p *ProviderData) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	logger := log.NewLogEntry()
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		logger.WithHTTPStatus(resp.StatusCode).WithRedeemURL(
			p.RedeemURL.String()).WithResponseBody(body).Info()
		switch resp.StatusCode {
		case 400:
			err = ErrBadRequest
		case 429:
			err = ErrRateLimitExceeded
		default:
			err = ErrServiceUnavailable
		}
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &sessions.SessionState{AccessToken: a}
	} else {
		logger.WithResponseBody(body).Info("no access token found")
	}
	return
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *ProviderData) GetSignInURL(redirectURI, state string) string {
	var a url.URL
	a = *p.SignInURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

// GetEmailAddress returns the email address associated with a session.
func (p *ProviderData) GetEmailAddress(s *sessions.SessionState) (string, error) {
	return "", ErrNotImplemented
}

// ValidateGroup validates that the provided email exists in the configured provider email group(s).
func (p *ProviderData) ValidateGroup(email string) bool {
	return true
}

// ValidateSessionState attempts to validate the session state's access token.
func (p *ProviderData) ValidateSessionState(s *sessions.SessionState) bool {
	logger := log.NewLogEntry()
	if s.AccessToken == "" {
		return false
	}

	form := url.Values{}
	form.Add("token", s.AccessToken)
	form.Add("token_type_hint", "access_token")
	form.Add("client_id", p.ClientID)
	form.Add("client_secret", p.ClientSecret)

	var req *http.Request
	req, err := http.NewRequest("POST", p.ValidateURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = httpClient.Do(req)
	if err != nil {
		return false
	}
	var body []byte
	_, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false
	}

	if resp.StatusCode != 200 {
		logger.WithHTTPStatus(resp.StatusCode).WithRedeemURL(
			p.ValidateURL.String()).WithResponseBody(body).Info()
		switch resp.StatusCode {
		case 400:
			err = ErrBadRequest
		case 429:
			err = ErrRateLimitExceeded
		default:
			err = ErrServiceUnavailable
		}
		return false
	}

	return true
}

// RefreshSessionIfNeeded refreshes a session
func (p *ProviderData) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	return false, nil
}

// RefreshAccessToken returns a nont implemented error.
func (p *ProviderData) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	return "", 0, ErrNotImplemented
}

// Revoke returns an ErrNotImplemented
func (p *ProviderData) Revoke(s *sessions.SessionState) error {
	return ErrNotImplemented
}

// ValidateGroupMembership returns an ErrNotImplemented.
func (p *ProviderData) ValidateGroupMembership(string, []string, string) ([]string, error) {
	return nil, ErrNotImplemented
}

// Stop fulfills the Provider interface
func (p *ProviderData) Stop() {
	return
}
