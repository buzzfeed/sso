package validators

import (
	"errors"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

var (
	_ Validator = EmailAddressValidator{}
)

type MockValidator struct {
	Result bool
	Err    error
}

func NewMockValidator(result bool, err error) MockValidator {
	return MockValidator{
		Result: result,
		Err:    err,
	}
}

func (v MockValidator) Validate(session *sessions.SessionState) error {
	// if we pass in a specific error, return it
	if v.Err != nil {
		return v.Err
	}
	// if result is true, return nil
	if v.Result {
		return nil
	}

	// otherwise, return generic mock validator error
	return errors.New("MockValidator error")
}
