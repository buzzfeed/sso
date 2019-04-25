package providers

import (
	"errors"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

var (
	// ErrBadRequest represents 400 Bad Request errors
	ErrBadRequest = errors.New("BAD_REQUEST")

	// ErrTokenRevoked represents 400 Token Revoked errors
	ErrTokenRevoked = errors.New("TOKEN_REVOKED")

	// ErrGroupNotFound respesnts a 404 Not Found errors for groups
	ErrGroupNotFound = errors.New("GROUP_NOT_FOUND")

	// ErrRateLimitExceeded represents 429 Rate Limit Exceeded errors
	ErrRateLimitExceeded = errors.New("RATE_LIMIT_EXCEEDED")

	// ErrNotImplemented represents 501 Not Implemented errors
	ErrNotImplemented = errors.New("NOT_IMPLEMENTED")

	// ErrServiceUnavailable represents 503 Service Unavailable errors
	ErrServiceUnavailable = errors.New("SERVICE_UNAVAILABLE")
)

const (
	// GoogleProviderName identifies the Google provider
	GoogleProviderName = "google"
	// OktaProviderName identities the Okta provider
	OktaProviderName = "okta"
)

// Provider is an interface exposing functions necessary to authenticate with a given provider.
type Provider interface {
	SetStatsdClient(*statsd.Client)
	Data() *ProviderData
	Redeem(string, string) (*sessions.SessionState, error)
	ValidateSessionState(*sessions.SessionState) bool
	GetSignInURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*sessions.SessionState) (bool, error)
	ValidateGroupMembership(string, []string, string) ([]string, error)
	Revoke(*sessions.SessionState) error
	RefreshAccessToken(string) (string, time.Duration, error)
	Stop()
}
