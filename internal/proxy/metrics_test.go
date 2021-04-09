package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
				"service:sso_proxy",
			},
			expectedNamespace:    "sso_proxy.",
			expectedPacketString: "sso_proxy.request:1|c|#service:sso_proxy",
		},
		{
			name: "normal case with additional tags",
			host: "127.0.0.1",
			port: 8125,
			expectedGlobalTags: []string{
				"service:sso_proxy",
			},
			additionalTags: []string{
				"another:tag",
			},
			expectedNamespace:    "sso_proxy.",
			expectedPacketString: "sso_proxy.request:1|c|#service:sso_proxy,another:tag",
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
		})

	}
}

func TestLogRequestMetrics(t *testing.T) {
	testCases := []struct {
		name         string
		requestURL   string
		method       string
		status       int
		expectedTags []string
	}{
		{
			name:       "request URL is /, action is set to proxy",
			requestURL: "/",
			method:     "GET",
			status:     http.StatusOK,
			expectedTags: []string{
				"service:sso_proxy",
				"method:GET",
				fmt.Sprintf("status_code:%d", http.StatusOK),
				"status_category:2xx",
				"action:proxy",
			},
		},
		{
			name:       "sign out path adds action to tags",
			requestURL: "/oauth2/sign_out",
			method:     "GET",
			status:     http.StatusOK,
			expectedTags: []string{
				"service:sso_proxy",
				"method:GET",
				fmt.Sprintf("status_code:%d", http.StatusOK),
				"status_category:2xx",
				"action:sign_out",
			},
		},
		{
			name:       "ping path adds action to tags, and overrides proxyHost",
			requestURL: "/ping",
			method:     "GET",
			status:     http.StatusOK,
			expectedTags: []string{
				"service:sso_proxy",
				"method:GET",
				fmt.Sprintf("status_code:%d", http.StatusOK),
				"status_category:2xx",
				"action:ping",
				"proxy_host:_healthcheck",
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

			client, err := NewStatsdClient("127.0.0.1", 8125)
			if err != nil {
				t.Fatalf("error starting new statsd client: %s", err.Error())
			}

			tagString := strings.Join(tc.expectedTags, ",")
			expectedPacketString := fmt.Sprintf("sso_proxy.request.duration:5.000000|ms|#%s", tagString)

			// create a request with a url
			// check metrics
			req := httptest.NewRequest(tc.method, tc.requestURL, nil)

			logRequestMetrics(req, time.Millisecond*5, tc.status, client)
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
			name:           "request with favicon.ico in the path",
			url:            "/favicon.ico",
			expectedAction: "favicon",
		},
		{
			name:           "request with favicon.ico in the path with query parameters",
			url:            "/favicon.ico?query=parameter",
			expectedAction: "favicon",
		},
		{
			name:           "request with oauth2/sign_out in the path",
			url:            "/oauth2/sign_out",
			expectedAction: "sign_out",
		},
		{
			name:           "request with oauth2/sign_out in the path with query parameters",
			url:            "/oauth2/sign_out?query=parameter",
			expectedAction: "sign_out",
		},
		{
			name:           "request with oauth2/callback in the path",
			url:            "/oauth2/callback",
			expectedAction: "callback",
		},
		{
			name:           "request with oauth2/callback in the path with query parameters",
			url:            "/oauth2/callback?query=parameter",
			expectedAction: "callback",
		},
		{
			name:           "request with oauth2/auth in the path",
			url:            "/oauth2/auth",
			expectedAction: "auth",
		},
		{
			name:           "request with oauth2/auth in the path with query parameters",
			url:            "/oauth2/auth?query=parameter",
			expectedAction: "auth",
		},
		{
			name:           "request with ping in the path",
			url:            "/ping",
			expectedAction: "ping",
		},
		{
			name:           "request with ping in the path with query parameters",
			url:            "/ping?query=parameter",
			expectedAction: "ping",
		},
		{
			name:           "request for robots.txt in the path",
			url:            "/robots.txt",
			expectedAction: "robots",
		},
		{
			name:           "request for robots.txt in the path with query parameters",
			url:            "/robots.txt?query=parameter",
			expectedAction: "robots",
		},
		{
			name:           "unknown action",
			url:            "/omg_what_do_i_do",
			expectedAction: "proxy",
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
