package options

import (
	"errors"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

var (
	_ Validator = EmailAddressValidator{}
)

type MockValidator struct {
	Result bool
}

func NewMockValidator(result bool) MockValidator {
	return MockValidator{
		Result: result,
	}
}

func (v MockValidator) Flags() validatorFlag {
	return OAuthCallbackFlow | ProxyAuthFlow | AuthenticatorFlow
}

func (v MockValidator) Validate(session *sessions.SessionState) error {
	if v.Result {
		return nil
	}

	return errors.New("MockValidator error")
}
