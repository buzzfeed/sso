package sessions

import (
	"errors"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/aead"
)

var (
	// ErrLifetimeExpired is an error for the lifetime deadline expiring
	ErrLifetimeExpired = errors.New("user lifetime expired")
)

// SessionState is our object that keeps track of a user's session state
type SessionState struct {
	ProviderSlug string `json:"slug"`
	ProviderType string `json:"type"`

	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`

	RefreshDeadline  time.Time `json:"refresh_deadline"`
	LifetimeDeadline time.Time `json:"lifetime_deadline"`
	ValidDeadline    time.Time `json:"valid_deadline"`
	GracePeriodStart time.Time `json:"grace_period_start"`

	Email              string   `json:"email"`
	User               string   `json:"user"`
	Groups             []string `json:"groups"`
	AuthorizedUpstream string   `json:"authorized_upstream"`
}

// LifetimePeriodExpired returns true if the lifetime has expired
func (s *SessionState) LifetimePeriodExpired() bool {
	return isExpired(s.LifetimeDeadline)
}

// RefreshPeriodExpired returns true if the refresh period has expired
func (s *SessionState) RefreshPeriodExpired() bool {
	return isExpired(s.RefreshDeadline)
}

// ValidationPeriodExpired returns true if the validation period has expired
func (s *SessionState) ValidationPeriodExpired() bool {
	return isExpired(s.ValidDeadline)
}

func isExpired(t time.Time) bool {
	if t.Before(time.Now()) {
		return true
	}
	return false
}

// MarshalSession marshals the session state as JSON, encrypts the JSON using the
// given cipher, and base64-encodes the result
func MarshalSession(s *SessionState, c aead.Cipher) (string, error) {
	return c.Marshal(s)
}

// UnmarshalSession takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice using the passed cipher, and unmarshals the resulting JSON into a session state struct
func UnmarshalSession(value string, c aead.Cipher) (*SessionState, error) {
	s := &SessionState{}
	err := c.Unmarshal(value, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ExtendDeadline returns the time extended by a given duration
func ExtendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}
