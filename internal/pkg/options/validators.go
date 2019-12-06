package options

import (
	"errors"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

var (
	// These error message should be formatted in such a way that is appropriate
	// for display to the end user.
	ErrInvalidEmailAddress = errors.New("Invalid Email Address In Session State")
)

type Validator interface {
	Validate(*sessions.SessionState) error
}

// RunValidators runs each passed in validator and returns a slice of errors. If an
// empty slice is returned, it can be assumed all passed in validators were successful.
func RunValidators(validators []Validator, session *sessions.SessionState) []error {
	validatorErrors := make([]error, 0, len(validators))

	for _, validator := range validators {
		err := validator.Validate(session)
		if err != nil {
			validatorErrors = append(validatorErrors, err)
		}
	}
	return validatorErrors
}
