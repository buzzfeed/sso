package options

import (
	"errors"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/buzzfeed/sso/internal/proxy/providers"
)

var (
	_ Validator = EmailGroupValidator{}

	// These error message should be formatted in such a way that is appropriate
	// for display to the end user.
	ErrGroupMembership = errors.New("Invalid Group Membership")
)

type EmailGroupValidator struct {
	Provider      providers.Provider
	AllowedGroups []string
}

// NewEmailGroupValidator takes in a Provider object and a list of groups, and returns a Validator object.
// The validator can be used to validate that the session.Email:
// - according to the Provider that was passed in, is a member of one of the originally passed in groups.
// If valid, nil is returned in place of an error.
func NewEmailGroupValidator(provider providers.Provider, allowedGroups []string) EmailGroupValidator {
	return EmailGroupValidator{
		Provider:      provider,
		AllowedGroups: allowedGroups,
	}
}

// Flags defines which flows this validator should be ran against.
func (v EmailGroupValidator) Flags() validatorFlag {
	return OAuthCallbackFlow
}

// Validate attempts to validate the session, returning an error for invalid
// sessions, or nil for valid sessions.
func (v EmailGroupValidator) Validate(session *sessions.SessionState) error {
	err := v.validate(session)
	if err != nil {
		return err
	}
	return nil
}

func (v EmailGroupValidator) validate(session *sessions.SessionState) error {
	matchedGroups, valid, err := v.Provider.ValidateGroup(session.Email, v.AllowedGroups, session.AccessToken)
	if err != nil {
		return ErrValidationError
	}

	if valid {
		session.Groups = matchedGroups
		return nil
	}

	return ErrGroupMembership
}
