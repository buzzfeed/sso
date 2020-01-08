package validators

import (
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/sessions"
)

func TestEmailDomainValidatorValidator(t *testing.T) {
	testCases := []struct {
		name           string
		allowedDomains []string
		email          string
		expectedErr    error
		session        *sessions.SessionState
	}{
		{
			name:           "nothing should validate when domain list is empty",
			allowedDomains: []string(nil),
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: ErrEmailDomainDenied,
		},
		{
			name:           "single domain validation",
			allowedDomains: []string{"example.com"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:           "substring matches are rejected",
			allowedDomains: []string{"example.com"},
			session: &sessions.SessionState{
				Email: "foo@hackerexample.com",
			},
			expectedErr: ErrEmailDomainDenied,
		},
		{
			name:           "no subdomain rollup happens",
			allowedDomains: []string{"example.com"},
			session: &sessions.SessionState{
				Email: "foo@bar.example.com",
			},
			expectedErr: ErrEmailDomainDenied,
		},
		{
			name:           "multiple domain validation still rejects other domains",
			allowedDomains: []string{"abc.com", "xyz.com"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: ErrEmailDomainDenied,
		},
		{
			name:           "multiple domain validation still accepts emails from either domain",
			allowedDomains: []string{"abc.com", "xyz.com"},
			session: &sessions.SessionState{
				Email: "foo@abc.com",
			},
			expectedErr: nil,
		},
		{
			name:           "multiple domain validation still rejects other domains",
			allowedDomains: []string{"abc.com", "xyz.com"},
			session: &sessions.SessionState{
				Email: "bar@xyz.com",
			},
			expectedErr: nil,
		},
		{
			name:           "comparisons are case insensitive",
			allowedDomains: []string{"Example.Com"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:           "comparisons are case insensitive",
			allowedDomains: []string{"Example.Com"},
			session: &sessions.SessionState{
				Email: "foo@EXAMPLE.COM",
			},
			expectedErr: nil,
		},
		{
			name:           "comparisons are case insensitive",
			allowedDomains: []string{"example.com"},
			session: &sessions.SessionState{
				Email: "foo@ExAmPLE.CoM",
			},
			expectedErr: nil,
		},
		{
			name:           "single wildcard allows all",
			allowedDomains: []string{"*"},
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:           "single wildcard allows all",
			allowedDomains: []string{"*"},
			session: &sessions.SessionState{
				Email: "bar@gmail.com",
			},
			expectedErr: nil,
		},
		{
			name:           "wildcard is ignored if other domains are included",
			allowedDomains: []string{"*", "example.com"},
			session: &sessions.SessionState{
				Email: "foo@gmal.com",
			},
			expectedErr: ErrEmailDomainDenied,
		},
		{
			name:           "empty email rejected",
			allowedDomains: []string{"example.com"},
			email:          "",
			session: &sessions.SessionState{
				Email: "foo@example.com",
			},
			expectedErr: nil,
		},
		{
			name:           "wildcard still rejects empty emails",
			allowedDomains: []string{"*"},
			session: &sessions.SessionState{
				Email: "",
			},
			expectedErr: ErrInvalidEmailAddress,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			emailValidator := NewEmailDomainValidator(tc.allowedDomains)
			err := emailValidator.Validate(tc.session)
			if err != tc.expectedErr {
				t.Fatalf("expected %v, got %v", tc.expectedErr, err)
			}
		})
	}
}
