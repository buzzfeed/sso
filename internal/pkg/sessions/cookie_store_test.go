package sessions

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

var testEncodedCookieSecret, _ = base64.StdEncoding.DecodeString("qICChm3wdjbjcWymm7PefwtPP6/PZv+udkFEubTeE38=")

func TestCreateMiscreantCookieCipher(t *testing.T) {
	testCases := []struct {
		name          string
		cookieSecret  []byte
		expectedError bool
	}{
		{
			name:         "normal case with base64 encoded secret",
			cookieSecret: testEncodedCookieSecret,
		},

		{
			name:          "error when not base64 encoded",
			cookieSecret:  []byte("abcd"),
			expectedError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCookieStore("cookieName", CreateMiscreantCookieCipher(tc.cookieSecret))
			if !tc.expectedError {
				testutil.Ok(t, err)
			} else {
				testutil.NotEqual(t, err, nil)
			}
		})
	}
}

func TestNewSession(t *testing.T) {
	testCases := []struct {
		name            string
		optFuncs        []func(*CookieStore) error
		expectedError   bool
		expectedSession *CookieStore
	}{
		{
			name: "default with no opt funcs set",
			expectedSession: &CookieStore{
				Name:           "cookieName",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieExpire:   168 * time.Hour,
				CSRFCookieName: "cookieName_csrf",
			},
		},
		{
			name:          "opt func with an error returns an error",
			optFuncs:      []func(*CookieStore) error{func(*CookieStore) error { return fmt.Errorf("error") }},
			expectedError: true,
		},
		{
			name: "opt func overrides default values",
			optFuncs: []func(*CookieStore) error{func(s *CookieStore) error {
				s.CookieExpire = time.Hour
				return nil
			}},
			expectedSession: &CookieStore{
				Name:           "cookieName",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				CookieExpire:   time.Hour,
				CSRFCookieName: "cookieName_csrf",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore("cookieName", tc.optFuncs...)
			if tc.expectedError {
				testutil.NotEqual(t, err, nil)
			} else {
				testutil.Ok(t, err)
			}
			testutil.Equal(t, tc.expectedSession, session)
		})
	}
}

func TestCookieCount(t *testing.T) {
	testCases := []struct {
		name          string
		size          int
		expectedCount int
	}{
		{"zero bytes", 0, 1},
		{"one byte", 1, 1},
		{"max single cookie bytes", CookieMaxLength, 1},
		{"one byte overflow", CookieMaxLength + 1, 2},
		{"max two cookie bytes", CookieMaxLength * 2, 2},
		{"max two cookie bytes with overflow", CookieMaxLength*2 + 1, 3},
		{"a lot of bytes", CookieMaxLength * 600, 600},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testutil.Equal(t, tc.expectedCount, cookieCount(tc.size))
		})
	}
}

func TestCookiePrefix(t *testing.T) {
	testCases := []struct {
		name           string
		size           int
		expectedPrefix string
	}{
		{"zero bytes", 0, "AA==~"},
		{"one byte", 1, "AQ==~"},
		{"max single cookie bytes", CookieMaxLength, "gB4=~"},
		{"one byte overflow", CookieMaxLength + 1, "gR4=~"},
		{"max two cookie bytes", CookieMaxLength * 2, "gDw=~"},
		{"max two cookie bytes with overflow", CookieMaxLength*2 + 1, "gTw=~"},
		{"a lot of bytes", CookieMaxLength * 600, "gNCMAQ==~"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testutil.Equal(t, tc.expectedPrefix, generatePrefix(tc.size))
			testutil.Equal(t, tc.size, parsePrefix(generatePrefix(tc.size)))
		})
	}

	errorCases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"no delimeter", "bogus"},
		{"empty prefix", PrefixDelimiter + "bogus"},
		{"invalid base64", "!@#$%^" + PrefixDelimiter},
		{"unconsumed bytes", "AAA=" + PrefixDelimiter},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			testutil.Equal(t, -1, parsePrefix(tc.input))
		})
	}
}

func TestMakeSessionCookie(t *testing.T) {
	now := time.Now()
	cookieValue := "cookieValue"
	spannedValue := fmt.Sprintf("Cw==~%s", cookieValue)
	expiration := time.Hour
	cookieName := "cookieName"
	testCases := []struct {
		name           string
		optFuncs       []func(*CookieStore) error
		expectedCookie *http.Cookie
	}{
		{
			name: "default cookie domain",
			expectedCookie: &http.Cookie{
				Name:     cookieName + "_0",
				Value:    spannedValue,
				Path:     "/",
				Domain:   "www.example.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
		{
			name: "custom cookie domain set",
			optFuncs: []func(*CookieStore) error{
				func(s *CookieStore) error {
					s.CookieDomain = "buzzfeed.com"
					return nil
				},
			},
			expectedCookie: &http.Cookie{
				Name:     cookieName + "_0",
				Value:    spannedValue,
				Path:     "/",
				Domain:   "buzzfeed.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore(cookieName, tc.optFuncs...)
			testutil.Ok(t, err)
			req := httptest.NewRequest("GET", "http://www.example.com", nil)
			cookies := session.makeSessionCookies(req, cookieValue, expiration, now)
			testutil.Equal(t, tc.expectedCookie, cookies[0])
		})
	}
}

func TestMakeSessionCSRFCookie(t *testing.T) {
	now := time.Now()
	cookieValue := "cookieValue"
	expiration := time.Hour
	cookieName := "cookieName"
	csrfName := "cookieName_csrf"

	testCases := []struct {
		name           string
		optFuncs       []func(*CookieStore) error
		expectedCookie *http.Cookie
	}{
		{
			name: "default cookie domain",
			expectedCookie: &http.Cookie{
				Name:     csrfName,
				Value:    cookieValue,
				Path:     "/",
				Domain:   "www.example.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
		{
			name: "custom cookie domain set",
			optFuncs: []func(*CookieStore) error{
				func(s *CookieStore) error {
					s.CookieDomain = "buzzfeed.com"
					return nil
				},
			},
			expectedCookie: &http.Cookie{
				Name:     csrfName,
				Value:    cookieValue,
				Path:     "/",
				Domain:   "buzzfeed.com",
				HttpOnly: true,
				Secure:   true,
				Expires:  now.Add(expiration),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore(cookieName, tc.optFuncs...)
			testutil.Ok(t, err)
			req := httptest.NewRequest("GET", "http://www.example.com", nil)
			cookie := session.makeCSRFCookie(req, cookieValue, expiration, now)
			testutil.Equal(t, tc.expectedCookie, cookie)
		})
	}
}

func TestSetSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	spannedValue := fmt.Sprintf("Cw==~%s", cookieValue)
	cookieName := "cookieName"

	t.Run("set session cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		rw := httptest.NewRecorder()
		session.setSessionCookies(rw, req, cookieValue)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == fmt.Sprintf("%s_0", cookieName) {
				found = true
				testutil.Equal(t, spannedValue, cookie.Value)
				testutil.Assert(t, cookie.Expires.After(time.Now()), "cookie expires after now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}

func TestSetCSRFSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("set csrf cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		rw := httptest.NewRecorder()
		session.SetCSRF(rw, req, cookieValue)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == fmt.Sprintf("%s_csrf", cookieName) {
				found = true
				testutil.Equal(t, cookieValue, cookie.Value)
				testutil.Assert(t, cookie.Expires.After(time.Now()), "cookie expires after now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}

func TestClearSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("clear session cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		cookies := session.makeSessionCookies(req, cookieValue, time.Hour, time.Now())
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		rw := httptest.NewRecorder()
		session.ClearSession(rw, req)
		var foundPrimary bool
		var foundOverflow bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == fmt.Sprintf("%s_0", cookieName) {
				foundPrimary = true
				testutil.Equal(t, "AA==~", cookie.Value) // zero byte prefix followed by zero bytes
				testutil.Assert(t, cookie.Expires.Before(time.Now()), "cookie expires before now")
			} else if cookie.Name == fmt.Sprintf("%s_1", cookieName) {
				foundOverflow = true
				testutil.Equal(t, "", cookie.Value)
				testutil.Assert(t, cookie.Expires.Before(time.Now()), "cookie expires before now")
			}
		}
		testutil.Assert(t, foundPrimary, "primary cookie present in header")
		testutil.Assert(t, foundOverflow, "overflow cookie present in header")
	})
}

func TestClearCSRFSessionCookie(t *testing.T) {
	cookieValue := "cookieValue"
	cookieName := "cookieName"

	t.Run("clear csrf cookie test", func(t *testing.T) {
		session, err := NewCookieStore(cookieName)
		testutil.Ok(t, err)
		req := httptest.NewRequest("GET", "http://www.example.com", nil)
		req.AddCookie(session.makeCSRFCookie(req, cookieValue, time.Hour, time.Now()))

		rw := httptest.NewRecorder()
		session.ClearCSRF(rw, req)
		var found bool
		for _, cookie := range rw.Result().Cookies() {
			if cookie.Name == fmt.Sprintf("%s_csrf", cookieName) {
				found = true
				testutil.Equal(t, "", cookie.Value)
				testutil.Assert(t, cookie.Expires.Before(time.Now()), "cookie expires before now")
			}
		}
		testutil.Assert(t, found, "cookie in header")
	})
}

func TestLoadCookiedSession(t *testing.T) {
	cookieName := "cookieName"

	testCases := []struct {
		name          string
		optFuncs      []func(*CookieStore) error
		setupCookies  func(*testing.T, *http.Request, *CookieStore, *SessionState)
		expectedError error
		sessionState  *SessionState
	}{
		{
			name:          "no cookie set returns an error",
			setupCookies:  func(*testing.T, *http.Request, *CookieStore, *SessionState) {},
			expectedError: http.ErrNoCookie,
		},
		{
			name:     "cookie set with cipher set",
			optFuncs: []func(*CookieStore) error{CreateMiscreantCookieCipher(testEncodedCookieSecret)},
			setupCookies: func(t *testing.T, req *http.Request, s *CookieStore, sessionState *SessionState) {
				value, err := MarshalSession(sessionState, s.CookieCipher)
				testutil.Ok(t, err)
				cookies := s.makeSessionCookies(req, value, time.Hour, time.Now())
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			},
			sessionState: &SessionState{
				Email:        "example@email.com",
				RefreshToken: "abccdddd",
				AccessToken:  "access",
			},
		},
		{
			name:     "cookie set with invalid value cipher set",
			optFuncs: []func(*CookieStore) error{CreateMiscreantCookieCipher(testEncodedCookieSecret)},
			setupCookies: func(t *testing.T, req *http.Request, s *CookieStore, sessionState *SessionState) {
				value := "574b776a7c934d6b9fc42ec63a389f79"
				cookies := s.makeSessionCookies(req, value, time.Hour, time.Now())
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
			},
			expectedError: ErrInvalidSession,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, err := NewCookieStore(cookieName, tc.optFuncs...)
			testutil.Ok(t, err)
			req := httptest.NewRequest("GET", "https://www.example.com", nil)
			tc.setupCookies(t, req, session, tc.sessionState)
			s, err := session.LoadSession(req)

			testutil.Equal(t, tc.expectedError, err)
			testutil.Equal(t, tc.sessionState, s)

		})
	}
}
