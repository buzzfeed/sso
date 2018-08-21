package providers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

type ValidateSessionStateTestProvider struct {
	*ProviderData
}

func (tp *ValidateSessionStateTestProvider) GetEmailAddress(s *SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// Note that we're testing the internal validateToken() used to implement
// several Provider's ValidateSessionState() implementations
func (tp *ValidateSessionStateTestProvider) ValidateSessionState(s *SessionState, g []string) bool {
	return false
}

type ValidateSessionStateTest struct {
	backend      *httptest.Server
	responseCode int
	provider     *ValidateSessionStateTestProvider
	header       http.Header
}

func NewValidateSessionStateTest() *ValidateSessionStateTest {
	var vtTest ValidateSessionStateTest

	vtTest.backend = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/oauth/tokeninfo" {
				w.WriteHeader(500)
				w.Write([]byte("unknown URL"))
			}
			tokenParam := r.FormValue("access_token")
			if tokenParam == "" {
				missing := false
				receivedHeaders := r.Header
				for k := range vtTest.header {
					received := receivedHeaders.Get(k)
					expected := vtTest.header.Get(k)
					if received == "" || received != expected {
						missing = true
					}
				}
				if missing {
					w.WriteHeader(500)
					w.Write([]byte("no token param and missing or incorrect headers"))
				}
			}
			w.WriteHeader(vtTest.responseCode)
			w.Write([]byte("only code matters; contents disregarded"))

		}))
	backendURL, _ := url.Parse(vtTest.backend.URL)
	vtTest.provider = &ValidateSessionStateTestProvider{
		ProviderData: &ProviderData{
			ValidateURL: &url.URL{
				Scheme: "http",
				Host:   backendURL.Host,
				Path:   "/oauth/tokeninfo",
			},
		},
	}
	vtTest.responseCode = 200
	return &vtTest
}

func (vtTest *ValidateSessionStateTest) Close() {
	vtTest.backend.Close()
}

func TestValidateSessionStateValidToken(t *testing.T) {
	vtTest := NewValidateSessionStateTest()
	defer vtTest.Close()
	testutil.Equal(t, true, validateToken(vtTest.provider, "foobar", nil))
}

func TestValidateSessionStateValidTokenWithHeaders(t *testing.T) {
	vtTest := NewValidateSessionStateTest()
	defer vtTest.Close()
	vtTest.header = make(http.Header)
	vtTest.header.Set("Authorization", "Bearer foobar")
	testutil.Equal(t, true,
		validateToken(vtTest.provider, "foobar", vtTest.header))
}

func TestValidateSessionStateEmptyToken(t *testing.T) {
	vtTest := NewValidateSessionStateTest()
	defer vtTest.Close()
	testutil.Equal(t, false, validateToken(vtTest.provider, "", nil))
}

func TestValidateSessionStateEmptyValidateURL(t *testing.T) {
	vtTest := NewValidateSessionStateTest()
	defer vtTest.Close()
	vtTest.provider.Data().ValidateURL = nil
	testutil.Equal(t, false, validateToken(vtTest.provider, "foobar", nil))
}

func TestValidateSessionStateRequestNetworkFailure(t *testing.T) {
	vtTest := NewValidateSessionStateTest()
	// Close immediately to simulate a network failure
	vtTest.Close()
	testutil.Equal(t, false, validateToken(vtTest.provider, "foobar", nil))
}

func TestValidateSessionStateExpiredToken(t *testing.T) {
	vtTest := NewValidateSessionStateTest()
	defer vtTest.Close()
	vtTest.responseCode = 401
	testutil.Equal(t, false, validateToken(vtTest.provider, "foobar", nil))
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
