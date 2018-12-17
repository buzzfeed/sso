package devproxy

import (
	"fmt"
	// "net"
	"net/http"
	// "strconv"
	"time"
	// "github.com/datadog/datadog-go/statsd"
)

// GetActionTag returns the action triggered by an http.Request .
func GetActionTag(req *http.Request) string {
	// only log metrics for these paths and actions
	pathToAction := map[string]string{
		"/favicon.ico":     "favicon",
		"/oauth2/sign_out": "sign_out",
		"/oauth2/callback": "callback",
		"/oauth2/auth":     "auth",
		"/ping":            "ping",
		"/robots.txt":      "robots",
	}
	// get the action from the url path
	path := req.URL.Path
	if action, ok := pathToAction[path]; ok {
		return action
	}
	return "proxy"
}

// logMetrics logs all metrics surrounding a given request to the metricsWriter
func logRequestMetrics(req *http.Request, requestDuration time.Duration, status int) { //, StatsdClient *statsd.Client) {
	// Normalize proxyHost for a) invalid requests or b) LB health checks to
	// avoid polluting the proxy_host tag's value space
	proxyHost := req.Host
	if status == statusInvalidHost {
		proxyHost = "_unknown"
	}
	if req.URL.Path == "/ping" {
		proxyHost = "_healthcheck"
	}

	// tags := []string{
	fmt.Sprintf("method:%s", req.Method)
	fmt.Sprintf("status_code:%d", status)
	fmt.Sprintf("status_category:%dxx", status/100)
	fmt.Sprintf("action:%s", GetActionTag(req))
	fmt.Sprintf("proxy_host:%s", proxyHost)
	// }

	// TODO: eventually make rates configurable
	// StatsdClient.Timing("request", requestDuration, tags, 1.0)

}
