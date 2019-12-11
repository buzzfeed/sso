package proxy

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func TestPingHandler(t *testing.T) {
	config := DefaultProxyConfig()
	statsdClient, err := NewStatsdClient(
		config.MetricsConfig.StatsdConfig.Host,
		config.MetricsConfig.StatsdConfig.Port)
	if err != nil {
		t.Fatalf("unexpected error creating statsd client: %v", err)
	}

	sso, err := New(config, statsdClient)
	if err != nil {
		t.Fatalf("unexpected err starting sso: %v", err)
	}

	for i := 0; i < 100; i++ {
		uri := fmt.Sprintf("https://host-%s.local/ping", randSeq(i))

		rw := httptest.NewRecorder()
		req := httptest.NewRequest("GET", uri, nil)

		sso.ServeHTTP(rw, req)
		if rw.Code != http.StatusOK {
			t.Errorf("want: %v", http.StatusOK)
			t.Errorf("have: %v", rw.Code)
			t.Fatalf("unexpected response code for ping")
		}
	}
}
