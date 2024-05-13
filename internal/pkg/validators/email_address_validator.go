package validators

import (
	"errors"
	"strings"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

var (
	_ Validator = EmailAddressValidator{}

	// These error message should be formatted in such a way that is appropriate
	// for display to the end user.
	ErrEmailAddressDenied = errors.New("Unauthorized Email Address")
)

type EmailAddressValidator struct {
	AllowedEmails []string
}

// NewEmailAddressValidator takes in a list of email addresses and returns a Validator object.
// The validator can be used to validate that the session.Email:
//   - is non-empty
//   - matches one of the originally passed in email addresses
//     (case insensitive)
//   - if the originally passed in list of emails consists only of "*", then all emails
//     are considered valid based on their domain.
//
// If valid, nil is returned in place of an error.
func NewEmailAddressValidator(allowedEmails []string) EmailAddressValidator {
	var emailAddresses []string

	for _, email := range allowedEmails {
		emailAddress := strings.ToLower(email)
		emailAddresses = append(emailAddresses, emailAddress)
	}

	return EmailAddressValidator{
		AllowedEmails: emailAddresses,
	}
}

func (v EmailAddressValidator) Validate(session *sessions.SessionState) error {
	if session.Email == "" {
		return ErrInvalidEmailAddress
	}

	if len(v.AllowedEmails) == 0 {
		return ErrEmailAddressDenied
	}

	if len(v.AllowedEmails) == 1 && v.AllowedEmails[0] == "*" {
		return nil
	}

	err := v.validate(session)
	if err != nil {
		return err
	}
	return nil
}

func (v EmailAddressValidator) validate(session *sessions.SessionState) error {
	email := strings.ToLower(session.Email)
	for _, emailItem := range v.AllowedEmails {
		if email == emailItem {
			return nil
		}
	}
	return ErrEmailAddressDenied
}
