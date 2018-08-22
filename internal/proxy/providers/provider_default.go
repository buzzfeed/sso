package providers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// Redeem takes a redirectURL and code, creates some params and redeems the request
func (p *ProviderData) Redeem(redirectURL, code string) (s *SessionState, err error) {
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
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

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
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &SessionState{
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
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

// GetSignInURL with typical oauth parameters
func (p *ProviderData) GetSignInURL(redirectURL *url.URL, state string) *url.URL {
	var a url.URL
	a = *p.SignInURL
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", rawRedirect)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return &a
}

// GetSignOutURL creates and returns the sign out URL, given a redirectURL
func (p *ProviderData) GetSignOutURL(redirectURL *url.URL) *url.URL {
	var a url.URL
	a = *p.SignOutURL
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("redirect_uri", rawRedirect)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return &a
}

// signRedirectURL signs the redirect url string, given a timestamp, and returns it
func (p *ProviderData) signRedirectURL(rawRedirect string, timestamp time.Time) string {
	h := hmac.New(sha256.New, []byte(p.ClientSecret))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// GetEmailAddress returns an email address or error
func (p *ProviderData) GetEmailAddress(s *SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// ValidateGroup validates that the provided email exists in the configured provider email group(s).
func (p *ProviderData) ValidateGroup(_ string, _ []string) ([]string, bool, error) {
	return []string{}, true, nil
}

// UserGroups returns a list of users
func (p *ProviderData) UserGroups(string, []string) ([]string, error) {
	return []string{}, nil
}

// ValidateSessionState calls to validate the token given the session and groups
func (p *ProviderData) ValidateSessionState(s *SessionState, groups []string) bool {
	return validateToken(p, s.AccessToken, nil)
}

// RefreshSession returns a boolean or error
func (p *ProviderData) RefreshSession(s *SessionState, group []string) (bool, error) {
	return false, nil
}
