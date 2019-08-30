package options

import (
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

func TestEmailAddressValidatorValidator(t *testing.T) {
	testCases := []struct {
		name          string
		AllowedEmails []string
		email         string
		expectedErr   error
		session       *sessions.SessionState
	}{
		{
			name:          "nothing should validate when address list is empty",
			AllowedEmails: []string(nil),
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: ErrEmailAddressDenied,
		},
		{
			name:          "single address validation",
			AllowedEmails: []string{"foo@example.com"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:          "substring matches are rejected",
			AllowedEmails: []string{"foo@example.com"},
			session: &sessions.SessionState{
				Email: "foo@hackerexample.com",
			},
			expectedErr: ErrEmailAddressDenied,
		},
		{
			name:          "no subdomain rollup happens",
			AllowedEmails: []string{"foo@example.com"},
			session: &sessions.SessionState{
				Email: "foo@bar.example.com",
			},
			expectedErr: ErrEmailAddressDenied,
		},
		{
			name:          "multiple address validation still rejects other addresses",
			AllowedEmails: []string{"foo@abc.com", "foo@xyz.com"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: ErrEmailAddressDenied,
		},
		{
			name:          "multiple address validation still accepts emails from either address",
			AllowedEmails: []string{"foo@abc.com", "foo@xyz.com"},
			session: &sessions.SessionState{
				Email: "foo@abc.com",
			},
			expectedErr: nil,
		},
		{
			name:          "multiple address validation still rejects other addresses",
			AllowedEmails: []string{"foo@abc.com", "bar@xyz.com"},
			session: &sessions.SessionState{
				Email: "bar@xyz.com",
			},
			expectedErr: nil,
		},
		{
			name:          "comparisons are case insensitive-1",
			AllowedEmails: []string{"Foo@Example.Com"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:          "comparisons are case insensitive-2",
			AllowedEmails: []string{"Foo@Example.Com"},
			session: &sessions.SessionState{
				Email: "foo@EXAMPLE.COM",
			},
			expectedErr: nil,
		},
		{
			name:          "comparisons are case insensitive-3",
			AllowedEmails: []string{"foo@example.com"},
			session: &sessions.SessionState{
				Email: "foo@ExAmPLE.CoM",
			},
			expectedErr: nil,
		},
		{
			name:          "single wildcard allows all",
			AllowedEmails: []string{"*"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:          "single wildcard allows all",
			AllowedEmails: []string{"*"},
			session: &sessions.SessionState{
				Email: "bar@gmail.com",
			},
			expectedErr: nil,
		},
		{
			name:          "wildcard is ignored if other domains included",
			AllowedEmails: []string{"foo@example.com", "*"},
			session: &sessions.SessionState{
				Email: "foo@gmail.com",
			},
			expectedErr: ErrEmailAddressDenied,
		},
		{
			name:          "empty email rejected",
			AllowedEmails: []string{"foo@example.com"},
			email:         "",
			session: &sessions.SessionState{
				Email: "",
			},
			expectedErr: ErrInvalidEmailAddress,
		},
		{
			name:          "wildcard still rejects empty emails",
			AllowedEmails: []string{"*"},
			email:         "",
			session: &sessions.SessionState{
				Email: "",
			},
			expectedErr: ErrInvalidEmailAddress,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			emailValidator := NewEmailAddressValidator(tc.AllowedEmails)
			err := emailValidator.Validate(tc.session)
			if err != tc.expectedErr {
				t.Fatalf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}
