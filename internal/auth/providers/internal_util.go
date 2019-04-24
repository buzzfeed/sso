package providers

import (
	"net/url"

	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

// stripToken is a helper function used to obfuscate "access_token" query parameters
func stripToken(endpoint string) string {
	return stripParam("access_token", endpoint)
}

// stripParam generalizes the obfuscation of a particular
// query parameter - typically 'access_token' or 'client_secret'
// The parameter's second half is replaced by '...' and returned
// as part of the encoded query parameters.
// If the target parameter isn't found, the endpoint is returned unmodified.
func stripParam(param, endpoint string) string {
	logger := log.NewLogEntry()

	u, err := url.Parse(endpoint)
	if err != nil {
		logger.WithURLParam(param).Error(
			err, "error parsing endpoint while stripping param")
		return endpoint
	}

	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			logger.WithURLParam(param).Error(
				err, "error parsing query string while stripping param")
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
