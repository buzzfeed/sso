package auth

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/datadog/datadog-go/statsd"
)

func newStatsdClient(host string, port int) (*statsd.Client, error) {
	client, err := statsd.New(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	client.Namespace = "sso_auth."
	client.Tags = []string{
		"service:sso_auth",
	}
	return client, nil
}

// GetActionTag returns the tag associated with a route
func GetActionTag(req *http.Request) string {
	// only log metrics for these paths and actions
	pathToAction := map[string]string{
		"/robots.txt":      "robots",
		"/start":           "start",
		"/sign_in":         "sign_in",
		"/sign_out":        "sign_out",
		"/oauth2/callback": "callback",
		"/profile":         "profile",
		"/validate":        "validate",
		"/redeem":          "redeem",
		"/refresh":         "refresh",
		"/ping":            "ping",
	}
	// get the action from the url path
	path := req.URL.Path
	if action, ok := pathToAction[path]; ok {
		return action
	}
	if strings.HasPrefix(path, "/static/") {
		return "static"
	}
	return "unknown"

}

// logMetrics logs all metrics surrounding a given request to the metricsWriter
func logRequestMetrics(proxyHost string, req *http.Request, requestDuration time.Duration, status int, StatsdClient *statsd.Client) {

	if proxyHost == "" {
		proxyHost = "unknown"
	}

	tags := []string{
		fmt.Sprintf("method:%s", req.Method),
		fmt.Sprintf("status_code:%d", status),
		fmt.Sprintf("status_category:%dxx", status/100),
		fmt.Sprintf("proxy_host:%s", proxyHost),
		fmt.Sprintf("action:%s", GetActionTag(req)),
	}

	// TODO: eventually make rates configurable
	StatsdClient.Timing("request", requestDuration, tags, 1.0)

}
