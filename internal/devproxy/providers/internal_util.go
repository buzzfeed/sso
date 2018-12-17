package providers

import (
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

// stripToken is a helper function to obfuscate "access_token"
// query parameters
func stripToken(endpoint string) string {
	return stripParam("access_token", endpoint)
}

// stripParam generalizes the obfuscation of a particular
// query parameter - typically 'access_token' or 'client_secret'
// The parameter's second half is replaced by '...' and returned
// as part of the encoded query parameters.
// If the target parameter isn't found, the endpoint is returned
// unmodified.
func stripParam(param, endpoint string) string {
	logger := log.NewLogEntry()

	u, err := url.Parse(endpoint)
	if err != nil {
		logger.WithURLParam(param).Error(err, "error attempting to strip parameter")
		return endpoint
	}

	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			logger.WithURLParam(param).Error("error attempting to strip parameter")
			return u.String()
		}

		if val := values.Get(param); val != "" {
			values.Set(param, val[:(len(val)/2)]+"...")
			u.RawQuery = values.Encode()
			return u.String()
		}
	}

	return endpoint
}

// validateToken returns true if token is valid
func validateToken(p Provider, accessToken string, header http.Header) bool {
	logger := log.NewLogEntry()

	if accessToken == "" || p.Data().ValidateURL == nil {
		return false
	}
	endpoint := p.Data().ValidateURL.String()
	if len(header) == 0 {
		params := url.Values{"access_token": {accessToken}}
		endpoint = endpoint + "?" + params.Encode()
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		logger.Error(err, "token validation request failed")
		return false
	}
	req.Header = header

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error(err, "token validation request failed")
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	logger.Printf("%d GET %s %s", resp.StatusCode, stripToken(endpoint), body)

	if resp.StatusCode == 200 {
		return true
	}
	logger.WithHTTPStatus(resp.StatusCode).WithResponseBody(body).Info(
		"token validation request failed")
	return false
}
