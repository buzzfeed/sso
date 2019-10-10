package options

import (
	"errors"
	"fmt"
	"strings"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

var (
	_ Validator = &EmailDomainValidator{}

	// These error message should be formatted in such a way that is appropriate
	// for display to the end user.
	ErrEmailDomainDenied = errors.New("Unauthorized Email Domain")
)

type EmailDomainValidator struct {
	AllowedDomains []string
}

// NewEmailDomainValidator takes in a list of domains and returns a Validator object.
// The validator can be used to validate that the session.Email:
// - is non-empty
// - the domain of the email address matches one of the originally passed in domains.
//   (case insensitive)
// - if the originally passed in list of domains consists only of "*", then all emails
//   are considered valid based on their domain.
// If valid, nil is returned in place of an error.
func NewEmailDomainValidator(allowedDomains []string) *EmailDomainValidator {
	emailDomains := make([]string, 0, len(allowedDomains))

	for _, domain := range allowedDomains {
		if domain == "*" {
			emailDomains = append(emailDomains, domain)
		} else {
			emailDomain := fmt.Sprintf("@%s", strings.ToLower(domain))
			emailDomains = append(emailDomains, emailDomain)
		}
	}
	return &EmailDomainValidator{
		AllowedDomains: emailDomains,
	}
}

func (v *EmailDomainValidator) Validate(session *sessions.SessionState) error {
	if session.Email == "" {
		return ErrInvalidEmailAddress
	}

	if len(v.AllowedDomains) == 0 {
		return ErrEmailDomainDenied
	}

	if len(v.AllowedDomains) == 1 && v.AllowedDomains[0] == "*" {
		return nil
	}

	err := v.validate(session)
	if err != nil {
		return err
	}
	return nil
}

func (v *EmailDomainValidator) validate(session *sessions.SessionState) error {
	email := strings.ToLower(session.Email)
	for _, domain := range v.AllowedDomains {
		if strings.HasSuffix(email, domain) {
			return nil
		}
	}
	return ErrEmailDomainDenied
}
