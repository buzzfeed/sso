package options

import (
	"errors"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

var (
	// These error message should be formatted in such a way that is appropriate
	// for display to the end user.
	ErrInvalidEmailAddress = errors.New("Invalid Email Address In Session State")
	ErrValidationError     = errors.New("Error during validation")
)

type validatorFlag int32

// We don't necessarily always want each type of validator to run,
// so this allows us to specify the 'flow' the validator is being used in.
// Which 'flow' the validator will run in is defined within the validator
// itself.
const (
	OAuthCallbackFlow validatorFlag = 1 << iota
	ProxyAuthFlow
	AuthenticatorFlow
)

type Validator interface {
	Validate(*sessions.SessionState) error
	Flags() validatorFlag
}

// RunValidators takes in a list of validators, a flag, and a session. The flag is used
// to prevent certain validators from running during certain flows. If the passed in flag
// deems the validator to be 'active' for this flow, then the validator is ran.
//
// It retuns a slice of errors found within all validators that were ran. If an empty slice
// is returned we can assume all validators passed.
func RunValidators(validators []Validator, flag validatorFlag, session *sessions.SessionState) []error {
	validatorErrors := make([]error, 0, len(validators))

	for _, v := range validators {
		if (v.Flags() & flag) > 0 {
			err := v.Validate(session)
			if err != nil {
				validatorErrors = append(validatorErrors, err)
			}
		}
	}

	return validatorErrors
}
