package proxy

import (
	"fmt"
	"net"
	"testing"
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
			opts := NewOptions()
			opts.StatsdHost = tc.host
			opts.StatsdPort = tc.port
			opts.Validate()

			client, err := newStatsdClient(opts)
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
