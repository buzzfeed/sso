package providers

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestValidateToken(t *testing.T) {
	testCases := []struct {
		name             string
		validToken       bool
		statusCode       int
		emptyValidateURL bool
		accessToken      string
		expectedValid    bool
	}{
		{
			name:          "valid token",
			accessToken:   "foo",
			expectedValid: true,
			statusCode:    http.StatusOK,
		},

		{
			name:          "token in headers",
			expectedValid: true,
			accessToken:   "foo",
			statusCode:    http.StatusOK,
		},
		{
			name:          "empty accessToken",
			validToken:    true,
			expectedValid: false,
			statusCode:    http.StatusOK,
		},
		{
			name:             "no validate url",
			expectedValid:    false,
			statusCode:       http.StatusOK,
			emptyValidateURL: true,
		},
		{
			name:          "invalid token",
			accessToken:   "foo",
			expectedValid: false,
			statusCode:    http.StatusUnauthorized,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testProvider := NewTestProvider(&url.URL{})
			testProvider.ValidToken = true
			validateURL, server := newProviderServer(nil, tc.statusCode)
			defer server.Close()
			testProvider.ValidateURL = validateURL
			if tc.emptyValidateURL {
				testProvider.ValidateURL = nil
			}
			header := http.Header{}
			header.Set("Authorization", "foo")
			isValid := validateToken(testProvider, tc.accessToken, header)
			if isValid != tc.expectedValid {
				t.Errorf("expected valid to be %v but was %v", tc.expectedValid, isValid)
			}

		})
	}
}

func TestStripTokenNotPresent(t *testing.T) {
	test := "http://local.test/api/test?a=1&b=2"
	testutil.Equal(t, test, stripToken(test))
}

func TestStripToken(t *testing.T) {
	test := "http://local.test/api/test?access_token=deadbeef&b=1&c=2"
	expected := "http://local.test/api/test?access_token=dead...&b=1&c=2"
	testutil.Equal(t, expected, stripToken(test))
}
