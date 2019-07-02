package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/datadog/datadog-go/statsd"
)

func newTestStatsdClient(t *testing.T) (*statsd.Client, string, int) {

	client, err := NewStatsdClient("127.0.0.1", 8125)
	if err != nil {
		t.Fatalf("error starting new statsd client %s", err.Error())
	}
	return client, "127.0.0.1", 8125
}

func TestNewStatsd(t *testing.T) {
	testCases := []struct {
		name                 string
		host                 string
		port                 int
		additionalTags       []string
		expectedGlobalTags   []string
		expectedNamespace    string
		expectedPacketString string
	}{
		{
			name: "normal case no additional tags",
			host: "127.0.0.1",
			port: 8125,
			expectedGlobalTags: []string{
				"service:sso_auth",
			},
			expectedNamespace:    "sso_auth.",
			expectedPacketString: "sso_auth.request:1|c|#service:sso_auth",
		},
		{
			name: "normal case with additional tags",
			host: "127.0.0.1",
			port: 8125,
			expectedGlobalTags: []string{
				"service:sso_auth",
			},
			additionalTags: []string{
				"another:tag",
			},
			expectedNamespace:    "sso_auth.",
			expectedPacketString: "sso_auth.request:1|c|#service:sso_auth,another:tag",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// listen to incoming udp packets
			pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", tc.host, tc.port))
			if err != nil {
				t.Fatalf("error %s", err.Error())
			}
			defer pc.Close()

			client, err := NewStatsdClient(tc.host, tc.port)
			if err != nil {
				t.Fatalf("error starting new statsd client: %s", err.Error())
			}

			if client.Namespace != tc.expectedNamespace {
				t.Errorf("expected client namespace to be %s but was %s", tc.expectedNamespace, client.Namespace)
			}

			if len(client.Tags) != len(tc.expectedGlobalTags) {
				t.Errorf("expected length of global tags to be %d but was %d", len(tc.expectedGlobalTags), len(client.Tags))
			}
			for i, expectedTag := range tc.expectedGlobalTags {
				if client.Tags[i] != tc.expectedGlobalTags[i] {
					t.Errorf("expected tag %d to be %s but was %s", i, expectedTag, client.Tags[i])
				}
			}

			err = client.Incr("request", tc.additionalTags, 1.0)
			if err != nil {
				t.Fatalf("expected error to be nil but was %s", err.Error())
			}

			readBytes := make([]byte, len(tc.expectedPacketString))
			pc.ReadFrom(readBytes)
			packetString := string(readBytes)
			if packetString != tc.expectedPacketString {
				t.Errorf("expected packet string to be %s but was %s", tc.expectedPacketString, packetString)
			}
			pc.Close()
		})

	}
}

func TestLogRequestMetrics(t *testing.T) {
	testCases := []struct {
		name         string
		requestURL   string
		method       string
		status       int
		proxyHost    string
		expectedTags []string
	}{
		{
			name:       "request URL is / with proxyHost set",
			requestURL: "/",
			proxyHost:  "proxyHost",
			method:     "GET",
			status:     http.StatusOK,
			expectedTags: []string{
				"service:sso_auth",
				"method:GET",
				fmt.Sprintf("status_code:%d", http.StatusOK),
				"status_category:2xx",
				"proxy_host:proxyHost",
			},
		},
		{
			name:       "request url is / and no proxyHost set while logging request metrics",
			requestURL: "/",
			method:     "GET",
			status:     http.StatusOK,
			expectedTags: []string{
				"service:sso_auth",
				"method:GET",
				fmt.Sprintf("status_code:%d", http.StatusOK),
				"status_category:2xx",
				"proxy_host:unknown",
			},
		},
		{
			name:       "sign_in path adds action to tags",
			requestURL: "/sign_in?query=parameter",
			method:     "GET",
			status:     http.StatusOK,
			expectedTags: []string{
				"service:sso_auth",
				"method:GET",
				fmt.Sprintf("status_code:%d", http.StatusOK),
				"status_category:2xx",
				"proxy_host:unknown",
				"action:sign_in",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			pc, err := net.ListenPacket("udp", "127.0.0.1:8125")
			if err != nil {
				t.Fatalf("error %s", err.Error())
			}
			defer pc.Close()

			client, _, _ := newTestStatsdClient(t)
			tagString := strings.Join(tc.expectedTags, ",")
			expectedPacketString := fmt.Sprintf("sso_auth.request:5.000000|ms|#%s", tagString)
			// create a request with a url
			// check metrics
			req := httptest.NewRequest(tc.method, tc.requestURL, nil)

			logRequestMetrics(tc.proxyHost, req, time.Millisecond*5, tc.status, client)
			readBytes := make([]byte, len(expectedPacketString))
			pc.ReadFrom(readBytes)
			if expectedPacketString != string(readBytes) {
				t.Errorf("expected packet string to be %s but was %s", expectedPacketString, string(readBytes))
			}

		})
	}
}

func TestGetActionTag(t *testing.T) {
	testCases := []struct {
		name           string
		url            string
		expectedAction string
	}{
		{
			name:           "request with start in the path",
			url:            "/start",
			expectedAction: "start",
		},
		{
			name:           "request with start in the path with query parameters",
			url:            "/start?query=parameter",
			expectedAction: "start",
		},
		{
			name:           "request with sign_in in the path",
			url:            "/sign_in",
			expectedAction: "sign_in",
		},
		{
			name:           "request with sign_in in the path with query parameters",
			url:            "/sign_in?query=parameter",
			expectedAction: "sign_in",
		},
		{
			name:           "request with sign_out in the path",
			url:            "/sign_out",
			expectedAction: "sign_out",
		},
		{
			name:           "request with sign_out in the path with query parameters",
			url:            "/sign_out?query=parameter",
			expectedAction: "sign_out",
		},
		{
			name:           "request with callback in the path",
			url:            "/callback",
			expectedAction: "callback",
		},
		{
			name:           "request with sign_out in the path with query parameters",
			url:            "/callback?query=parameter",
			expectedAction: "callback",
		},
		{
			name:           "request with profile in the path",
			url:            "/profile",
			expectedAction: "profile",
		},
		{
			name:           "request with profile in the path with query parameters",
			url:            "/profile?query=parameter",
			expectedAction: "profile",
		},
		{
			name:           "request with validate in the path",
			url:            "/validate",
			expectedAction: "validate",
		},
		{
			name:           "request with validate in the path with query parameters",
			url:            "/validate?query=parameter",
			expectedAction: "validate",
		},
		{
			name:           "request with redeem in the path",
			url:            "/redeem",
			expectedAction: "redeem",
		},
		{
			name:           "request with redeem in the path with query parameters",
			url:            "/redeem?query=parameter",
			expectedAction: "redeem",
		},
		{
			name:           "request for static",
			url:            "/static/some_file_path",
			expectedAction: "static",
		},
		{
			name:           "unknown action",
			url:            "/omg_what_do_i_do",
			expectedAction: "unknown",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.url, nil)
			action := GetActionTag(req)
			if action != tc.expectedAction {
				t.Errorf("expected action to be %s but was %s", tc.expectedAction, action)
			}
		})
	}
}
