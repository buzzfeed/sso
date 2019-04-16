package hostmux

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func simpleHandler(code int, body string) http.Handler {
	return http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			rw.Header().Set("X-Content-Type-Options", "nosniff")
			rw.WriteHeader(code)
			fmt.Fprintln(rw, body)
		},
	)
}

func TestHostMux(t *testing.T) {
	type expectedResponse struct {
		code int
	}
	testCases := []struct {
		name             string
		url              string
		statics          []*StaticRoute
		regexps          []*RegexpRoute
		expectedResponse expectedResponse
	}{
		{
			name: "default constructor returns misdirected request",
			url:  "http://example.com",
			expectedResponse: expectedResponse{
				code: http.StatusMisdirectedRequest,
			},
		},
		{
			name: "static handler returns code expected",
			url:  "http://example.com",
			statics: []*StaticRoute{
				{
					host:    "example.com",
					handler: simpleHandler(http.StatusAccepted, http.StatusText(http.StatusAccepted)),
				},
			},
			expectedResponse: expectedResponse{
				code: http.StatusAccepted,
			},
		},
		{
			name: "regexp returns code expected",
			url:  "http://example--match.com",
			statics: []*StaticRoute{
				{
					host:    "example.com",
					handler: simpleHandler(http.StatusAccepted, http.StatusText(http.StatusAccepted)),
				},
			},
			regexps: []*RegexpRoute{
				{
					regexp:  regexp.MustCompile(`example--.*\.com`),
					handler: simpleHandler(http.StatusCreated, http.StatusText(http.StatusCreated)),
				},
			},
			expectedResponse: expectedResponse{
				code: http.StatusCreated,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup router
			router := NewRouter()
			for _, s := range tc.statics {
				router.HandleStatic(s.host, s.handler)
			}
			for _, re := range tc.regexps {
				router.HandleRegexp(re.regexp, re.handler)
			}

			// prepare response writer / request
			rw := httptest.NewRecorder()
			req, err := http.NewRequest("GET", tc.url, nil)
			if err != nil {
				t.Fatalf("unexpected err %v", err)
			}

			// execute
			router.ServeHTTP(rw, req)
			resp := rw.Result()

			// verify worked as expected
			if resp.StatusCode != tc.expectedResponse.code {
				t.Errorf("  got: %v", resp.StatusCode)
				t.Errorf("want: %v", tc.expectedResponse.code)
				t.Fatalf("expected status codes to be equal")
			}
		})
	}
}
