package sessions

import (
	"fmt"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestNewRedisSession(t *testing.T) {
	testCases := []struct {
		name            string
		optFuncs        []func(*RedisStore) error
		expectedError   bool
		expectedClient  bool
		expectedSession *RedisStore
	}{
		{
			name:           "default with no opt funcs set",
			expectedClient: false,
			expectedError:  true,
		},
		{
			name:           "opt func with an error returns an error",
			optFuncs:       []func(*RedisStore) error{func(*RedisStore) error { return fmt.Errorf("error") }},
			expectedClient: false,
			expectedError:  true,
		},
		{
			name: "opt func overrides default values",
			optFuncs: []func(*RedisStore) error{func(s *RedisStore) error {
				s.ConnectionURL = "redis://localhost:6379/"
				s.CookieExpire = time.Hour
				return nil
			}},
			expectedClient: true,
			expectedSession: &RedisStore{
				ConnectionURL: "redis://localhost:6379/",
				CookieStore: CookieStore{
					Name:           "cookieName",
					CookieSecure:   true,
					CookieHTTPOnly: true,
					CookieExpire:   time.Hour,
					CSRFCookieName: "cookieName_csrf",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewRedisStore("cookieName", tc.optFuncs...)
			if tc.expectedError {
				testutil.NotEqual(t, err, nil)
			} else {
				testutil.Ok(t, err)
			}
			if tc.expectedClient {
				testutil.Assert(t, session.client != nil, "test")
			}
			if session != nil {
				// don't include redis client in the equality comparison
				session.client = nil
			}
			testutil.Equal(t, tc.expectedSession, session)
		})
	}
}
