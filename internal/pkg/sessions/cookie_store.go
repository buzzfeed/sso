package sessions

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/aead"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

const (
	// CookieMaxLength controls the byte length where cookie spanning occurs
	// See http://browsercookielimits.squawky.net/
	CookieMaxLength = 4093
	// PrefixDelimiter should be unreserved and not used by any base64 encoding
	PrefixDelimiter = "~"
)

// ErrInvalidSession is an error for invalid sessions.
var ErrInvalidSession = errors.New("invalid session")

// CSRFStore has the functions for setting, getting, and clearing the CSRF cookie
type CSRFStore interface {
	SetCSRF(http.ResponseWriter, *http.Request, string)
	GetCSRF(*http.Request) (*http.Cookie, error)
	ClearCSRF(http.ResponseWriter, *http.Request)
}

// SessionStore has the functions for setting, getting, and clearing the Session cookie
type SessionStore interface {
	ClearSession(http.ResponseWriter, *http.Request)
	LoadSession(*http.Request) (*SessionState, error)
	SaveSession(http.ResponseWriter, *http.Request, *SessionState) error
}

// CookieStore represents all the cookie related configurations
type CookieStore struct {
	Name               string
	CSRFCookieName     string
	CookieExpire       time.Duration
	CookieRefresh      time.Duration
	CookieSecure       bool
	CookieHTTPOnly     bool
	CookieDomain       string
	CookieCipher       aead.Cipher
	SessionLifetimeTTL time.Duration
}

// CreateMiscreantCookieCipher creates a new miscreant cipher with the cookie secret
func CreateMiscreantCookieCipher(cookieSecret []byte) func(s *CookieStore) error {
	return func(s *CookieStore) error {
		cipher, err := aead.NewMiscreantCipher(cookieSecret)
		if err != nil {
			return fmt.Errorf("miscreant cookie-secret error: %s", err.Error())
		}
		s.CookieCipher = cipher
		return nil
	}
}

// NewCookieStore returns a new session with ciphers for each of the cookie secrets
func NewCookieStore(cookieName string, optFuncs ...func(*CookieStore) error) (*CookieStore, error) {
	c := &CookieStore{
		Name:           cookieName,
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieExpire:   168 * time.Hour,
		CSRFCookieName: fmt.Sprintf("%v_%v", cookieName, "csrf"),
	}

	for _, f := range optFuncs {
		err := f(c)
		if err != nil {
			return nil, err
		}
	}

	domain := c.CookieDomain
	if domain == "" {
		domain = "<default>"
	}

	return c, nil
}

// cookieCount calculates the number of cookies needed if spanning at
// the CookieMaxLength boundary.
func cookieCount(size int) int {
	return ((size - 1) / CookieMaxLength) + 1
}

// generatePrefix for the first cookie so that we know how many bytes were expected.
// Users can clear cookies individually and we want to be able to detect that we're
// in an invalid state and clear. It's also possible something could cause extra cookies
// to be left over.
func generatePrefix(size int) string {
	rawPrefix := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(rawPrefix, uint64(size))
	return base64.URLEncoding.EncodeToString(rawPrefix[:n]) + PrefixDelimiter
}

// parsePrefix for the first cookie so that we know how many bytes were expected.
// Returns -1 if prefix is unparseable.
func parsePrefix(cookieValue string) int {
	segments := strings.Split(cookieValue, PrefixDelimiter)
	if len(segments) <= 1 {
		return -1
	}
	prefix := segments[0]
	if prefix == "" {
		return -1
	}
	rawPrefix, err := base64.URLEncoding.DecodeString(prefix)
	if err != nil {
		return -1
	}
	size, n := binary.Uvarint(rawPrefix)
	if n != len(rawPrefix) {
		// input was not fully consumed
		return -1
	}
	return int(size)
}

func (s *CookieStore) makeCookies(req *http.Request, name string, value string, expiration time.Duration, now time.Time) []*http.Cookie {
	logger := log.NewLogEntry()
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if s.CookieDomain != "" {
		if !strings.HasSuffix(domain, s.CookieDomain) {
			logger.WithRequestHost(domain).WithCookieDomain(s.CookieDomain).Warn("Warning: Using configured cookie domain.")
		}
		domain = s.CookieDomain
	}

	prefix := generatePrefix(len(value))
	spannedValue := prefix + value

	var cookies []*http.Cookie
	chunk := make([]byte, CookieMaxLength)
	reader := strings.NewReader(spannedValue)
	for {
		n, err := reader.Read(chunk)
		if err != nil {
			// TODO: figure out if this can happen
			panic(err)
		}
		if n > 0 {
			index := len(cookies)
			cookies = append(cookies, &http.Cookie{
				Name:     fmt.Sprintf("%s_%d", name, index),
				Value:    string(chunk[:n]),
				Path:     "/",
				Domain:   domain,
				HttpOnly: s.CookieHTTPOnly,
				Secure:   s.CookieSecure,
				Expires:  now.Add(expiration),
			})
		}
		if n < CookieMaxLength {
			break
		}
	}
	// Clear the nearest overflow cookie
	cookies = append(cookies, &http.Cookie{
		Name:     fmt.Sprintf("%s_%d", name, len(cookies)),
		Value:    "",
		Path:     "/",
		Domain:   domain,
		HttpOnly: s.CookieHTTPOnly,
		Secure:   s.CookieSecure,
		Expires:  now.Add(expiration),
	})
	return cookies
}

func readSpannedCookies(cookies []*http.Cookie) (string, error) {
	var sb strings.Builder
	for i, cookie := range cookies {
		if i == 0 {
			segments := strings.Split(cookie.Value, PrefixDelimiter)
			if len(segments) <= 1 {
				return "", errors.New("missing size prefix")
			}
			sb.WriteString(segments[1])
		} else {
			sb.WriteString(cookie.Value)
		}
	}
	return sb.String(), nil
}

func setCookies(rw http.ResponseWriter, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		http.SetCookie(rw, cookie)
	}
}

func (s *CookieStore) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	logger := log.NewLogEntry()
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if s.CookieDomain != "" {
		if !strings.HasSuffix(domain, s.CookieDomain) {
			logger.WithRequestHost(domain).WithCookieDomain(s.CookieDomain).Warn("Warning: Using configured cookie domain.")
		}
		domain = s.CookieDomain
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: s.CookieHTTPOnly,
		Secure:   s.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

// makeSessionCookie constructs a session cookie given the request, an expiration time and the current time.
func (s *CookieStore) makeSessionCookies(req *http.Request, value string, expiration time.Duration, now time.Time) []*http.Cookie {
	return s.makeCookies(req, s.Name, value, expiration, now)
}

// makeCSRFCookie creates a CSRF cookie given the request, an expiration time, and the current time.
func (s *CookieStore) makeCSRFCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return s.makeCookie(req, s.CSRFCookieName, value, expiration, now)
}

// ClearCSRF clears the CSRF cookie from the request
func (s *CookieStore) ClearCSRF(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, s.makeCSRFCookie(req, "", time.Hour*-1, time.Now()))
}

// SetCSRF sets the CSRFCookie creates a CSRF cookie in a given request
func (s *CookieStore) SetCSRF(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, s.makeCSRFCookie(req, val, s.CookieExpire, time.Now()))
}

// GetCSRF gets the CSRFCookie creates a CSRF cookie in a given request
func (s *CookieStore) GetCSRF(req *http.Request) (*http.Cookie, error) {
	return req.Cookie(s.CSRFCookieName)
}

// ClearSession clears the session cookie from a request
func (s *CookieStore) ClearSession(rw http.ResponseWriter, req *http.Request) {
	setCookies(rw, s.makeSessionCookies(req, "", time.Hour*-1, time.Now()))
}

func (s *CookieStore) setSessionCookies(rw http.ResponseWriter, req *http.Request, val string) {
	setCookies(rw, s.makeSessionCookies(req, val, s.CookieExpire, time.Now()))
}

// LoadSession returns a SessionState from the cookie in the request.
func (s *CookieStore) LoadSession(req *http.Request) (*SessionState, error) {
	logger := log.NewLogEntry()
	firstCookie, err := req.Cookie(fmt.Sprintf("%s_0", s.Name))
	if err != nil {
		// always http.ErrNoCookie
		return nil, err
	}
	byteSize := parsePrefix(firstCookie.Value)
	if byteSize < 0 {
		return nil, errors.New("could not parse prefixed cookie")
	}
	cookieCount := cookieCount(byteSize)
	cookies := make([]*http.Cookie, 0)
	for i := 0; i < cookieCount; i++ {
		cookie, err := req.Cookie(fmt.Sprintf("%s_%d", s.Name, i))
		if err != nil {
			// always http.ErrNoCookie
			return nil, err
		}
		cookies = append(cookies, cookie)
	}
	value, err := readSpannedCookies(cookies)
	if err != nil {
		return nil, err
	}
	session, err := UnmarshalSession(value, s.CookieCipher)
	if err != nil {
		logger.WithRequestHost(req.Host).WithError(err).Error("error unmarshaling session")
		return nil, ErrInvalidSession
	}
	return session, nil
}

// SaveSession saves a session state to a request sessions.
func (s *CookieStore) SaveSession(rw http.ResponseWriter, req *http.Request, sessionState *SessionState) error {
	value, err := MarshalSession(sessionState, s.CookieCipher)
	if err != nil {
		return err
	}

	s.setSessionCookies(rw, req, value)
	return nil
}
